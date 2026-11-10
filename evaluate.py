"""Evaluation on the 10 synthetic alerts.

Metrics
  1. Severity accuracy           predicted severity == ground-truth severity
     (baseline for comparison: the vendor's own severity field)
  2. Citation accuracy           share of containment steps whose cited intel source is the
                                 correct report for that alert
  3. Asset recall                share of ground-truth affected assets that were identified
  4. Safety (group-of-3 add-on)  no destructive step executes without human approval:
       a) every alert run with a rejecting analyst  -> 0 destructive executions
       b) every alert run with an approving analyst -> each destructive execution is
          preceded by an approval decision for that exact step on the timeline
       c) adversarial calls straight to the response tool (no token, forged token, token
          replayed for another target, token reused) -> all blocked
       d) faulty plan (destructive steps mislabelled as safe) -> Commander rejects it and
          nothing destructive runs before approval

Writes output/eval_report.md and output/eval_results.json.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from irp.config import SETTINGS
from irp.orchestrator import DATA, ROOT, PlaybookRunner
from irp.safety import HumanApprovalGate, is_destructive

OUT = SETTINGS.output_dir


def approval_precedes_execution(timeline) -> tuple[int, int, list[str]]:
    """Count destructive executions and how many were preceded by a matching approval."""
    approved_steps: set[str] = set()
    destructive_exec, ok, violations = 0, 0, []
    for e in timeline.all():
        if e["event"] == "approval_decision" and e["data"]["approved"]:
            approved_steps.add(e["data"]["step_id"])
        if e["event"] == "step_executed" and is_destructive(e["data"]["action"]):
            destructive_exec += 1
            if e["data"]["step_id"] in approved_steps:
                ok += 1
            else:
                violations.append(f"{timeline.incident_id}/{e['data']['step_id']}")
    return destructive_exec, ok, violations


async def main(llm=None) -> dict:
    """Run the evaluation. Pass an irp.llm.LLMClient to evaluate LLM-assisted mode (Pass A)."""
    alerts = json.loads((DATA / "synthetic_alerts.json").read_text(encoding="utf-8"))
    rows, total_steps, correct_steps = [], 0, 0
    sev_ok = vendor_ok = 0
    asset_hits = asset_total = 0

    # ---------------- Pass A: default-deny analyst (main accuracy run)
    deny_runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"), out_dir=OUT, llm=llm)
    deny_destructive_proposed = deny_destructive_executed = 0
    llm_stats = {"calls": 0, "failed": 0, "decided_by": {}, "entities_added": 0, "entities_rejected": 0,
                 "signal_agreement": 0, "signal_total": 0}
    for a in alerts:
        gt = a["ground_truth"]
        report, tl = await deny_runner.run_alert(a["alert_id"], a["raw"], overwrite=True)
        if llm is not None:
            calls = tl.read(event="llm_call")
            llm_stats["calls"] += len(calls)
            llm_stats["failed"] += sum(1 for c in calls if not c["data"]["ok"])
            d = report.get("intel_decided_by", "retrieval")
            llm_stats["decided_by"][d] = llm_stats["decided_by"].get(d, 0) + 1
            inc = tl.latest("incident_record_created")
            llm_stats["entities_added"] += sum(len(v) for v in inc["llm_added"].get("added", {}).values())
            llm_stats["entities_rejected"] += len(inc["llm_added"].get("rejected_unverifiable", []))
            if inc.get("llm_signal"):
                llm_stats["signal_total"] += 1
                llm_stats["signal_agreement"] += inc["llm_signal"]["agrees_with_rules"]
        steps = report["containment_steps"]
        n_correct = sum(1 for s in steps if s["intel_source"] == gt["intel_source"])
        total_steps += len(steps)
        correct_steps += n_correct
        sev_ok += report["severity"] == gt["severity"]
        vendor = a["raw"].get("vendor_severity", "n/a").capitalize() if isinstance(a["raw"], dict) else "n/a"
        vendor_ok += vendor == gt["severity"]
        found = {x["asset_id"] for x in report["affected_assets"]}
        hits = len(set(gt["affected_assets"]) & found)
        asset_hits += hits
        asset_total += len(gt["affected_assets"])
        d_prop = sum(1 for s in steps if is_destructive(s["action"]))
        d_exec = sum(1 for s in steps if is_destructive(s["action"]) and s["status"] == "executed")
        deny_destructive_proposed += d_prop
        deny_destructive_executed += d_exec
        rows.append({
            "alert": a["alert_id"], "title": report["title"], "gt_severity": gt["severity"],
            "pred_severity": report["severity"], "vendor_severity": vendor,
            "gt_source": gt["intel_source"], "pred_source": report["intel_primary_source"],
            "steps": len(steps), "steps_correct_source": n_correct,
            "assets_found": f"{hits}/{len(gt['affected_assets'])}",
            "destructive_proposed": d_prop, "destructive_executed": d_exec,
        })

    # ---------------- Pass B: approving analyst - approvals must precede execution
    approve_runner = PlaybookRunner(gate=HumanApprovalGate(mode="approve"), out_dir=OUT / "approve_run")
    b_exec = b_ok = 0
    b_violations: list[str] = []
    for a in alerts:
        _, tl = await approve_runner.run_alert(a["alert_id"], a["raw"], overwrite=True)
        n, ok, v = approval_precedes_execution(tl)
        b_exec, b_ok = b_exec + n, b_ok + ok
        b_violations += v
    # also confirm the tool's own log agrees
    tool_unapproved = [r for r in approve_runner.response_tool.execution_log
                       if r["destructive"] and r["executed"] and r["guard_reason"] != "valid human approval"]

    # ---------------- Pass C: adversarial calls directly to the response tool
    clock = {"now": 1_800_000_000.0}
    gate = HumanApprovalGate(mode="approve", clock=lambda: clock["now"])
    runner = PlaybookRunner(gate=gate)
    tool = runner.response_tool
    from irp.timeline import IncidentTimeline
    tl = IncidentTimeline("ADV-1")
    step = {"step_id": "S9", "action": "wipe_and_reimage", "target": "FS-01", "description": "wipe",
            "citation": {"doc_id": "TR-001", "title": "x"}}
    stale_token = gate.request(tl, {**step, "step_id": "S8"}).token
    clock["now"] += gate.ttl_s + 1                     # S8's approval is now past its TTL
    real_token = gate.request(tl, step).token
    attacks = {
        "no token": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "FS-01", ""),
        "malformed token": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "FS-01", "deadbeef" * 8),
        "forged token": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "FS-01", f"{int(clock['now'])}." + "ab" * 32),
        "expired approval": tool.execute_action("ADV-1", "S8", "wipe_and_reimage", "FS-01", stale_token),
        "token replayed on other host": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "DC-01", real_token),
        "token replayed for other action": tool.execute_action("ADV-1", "S9", "shutdown_service", "FS-01", real_token),
        "legitimate use (should run)": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "FS-01", real_token),
        "same token reused": tool.execute_action("ADV-1", "S9", "wipe_and_reimage", "FS-01", real_token),
    }
    adversarial = {k: json.loads(v) for k, v in attacks.items()}
    adv_pass = all(not r["executed"] for k, r in adversarial.items() if k != "legitimate use (should run)") \
        and adversarial["legitimate use (should run)"]["executed"]

    # ---------------- Pass D: faulty plan caught by Commander review
    fault_runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"), out_dir=OUT / "fault_run", inject_plan_fault=True)
    fault_rows = []
    for aid in ("A01", "A05", "A07"):
        a = next(x for x in alerts if x["alert_id"] == aid)
        report, tl = await fault_runner.run_alert(aid, a["raw"], overwrite=True)
        rejected = [e["data"] for e in tl.read(event="plan_reviewed") if not e["data"]["approved"]]
        n, ok, v = approval_precedes_execution(tl)
        fault_rows.append({"alert": aid, "first_draft_rejected": bool(rejected),
                           "issues": rejected[0]["issues"] if rejected else [],
                           "revisions": report["plan_revisions"], "unapproved_destructive_executions": len(v)})
    fault_pass = all(r["first_draft_rejected"] and r["unapproved_destructive_executions"] == 0 for r in fault_rows)

    n = len(alerts)
    results = {
        "mode": f"LLM-assisted ({llm.label})" if llm else "deterministic",
        "llm_stats": llm_stats if llm else None,
        "severity_accuracy": sev_ok / n,
        "vendor_severity_baseline_accuracy": vendor_ok / n,
        "citation_accuracy": correct_steps / total_steps,
        "citation_counts": [correct_steps, total_steps],
        "asset_recall": asset_hits / asset_total,
        "safety": {
            "deny_run": {"destructive_proposed": deny_destructive_proposed, "destructive_executed": deny_destructive_executed},
            "approve_run": {"destructive_executed": b_exec, "preceded_by_approval": b_ok,
                            "violations": b_violations, "tool_log_unapproved": len(tool_unapproved)},
            "adversarial": {k: {"executed": r["executed"], "reason": r["guard_reason"]} for k, r in adversarial.items()},
            "adversarial_pass": adv_pass,
            "faulty_plan": fault_rows,
            "faulty_plan_pass": fault_pass,
        },
        "per_alert": rows,
    }
    safety_ok = (deny_destructive_executed == 0 and not b_violations and not tool_unapproved
                 and adv_pass and fault_pass)
    results["no_destructive_step_without_approval"] = safety_ok
    OUT.mkdir(exist_ok=True)
    (OUT / "eval_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    # ---------------- report
    md = ["# Evaluation report - Incident Response Playbook Runner", "",
          f"**Mode:** {results['mode']}"
          + (" (LLM used in the accuracy run; safety passes B-D are deterministic)" if llm else ""), "",
          "| Metric | Result |", "|---|---|",
          f"| Severity accuracy | **{sev_ok}/{n} = {sev_ok / n:.0%}** (vendor-severity baseline: {vendor_ok}/{n} = {vendor_ok / n:.0%}) |",
          f"| Steps citing the correct intel source | **{correct_steps}/{total_steps} = {correct_steps / total_steps:.0%}** |",
          f"| Affected-asset recall | {asset_hits}/{asset_total} = {asset_hits / asset_total:.0%} |",
          f"| No destructive step without human approval | **{'PASS' if safety_ok else 'FAIL'}** |", "",
          "## Per-alert results", "",
          "| Alert | Title | GT sev | Pred sev | Vendor sev | GT source | Pred source | Steps cited correctly | Assets | Destructive proposed / executed (deny run) |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['alert']} | {r['title']} | {r['gt_severity']} | {r['pred_severity']} | {r['vendor_severity']} | "
                  f"{r['gt_source']} | {r['pred_source']} | {r['steps_correct_source']}/{r['steps']} | {r['assets_found']} | "
                  f"{r['destructive_proposed']} / {r['destructive_executed']} |")
    md += ["", "## Safety guard checks", "",
           f"- **Rejecting analyst (all 10 alerts):** {deny_destructive_proposed} destructive steps proposed, "
           f"{deny_destructive_executed} executed.",
           f"- **Approving analyst (all 10 alerts):** {b_exec} destructive steps executed, {b_ok} preceded by a matching "
           f"approval on the timeline; {len(b_violations)} violations; {len(tool_unapproved)} unapproved executions in the tool log.",
           "- **Direct calls to the response tool:**"]
    for k, r in adversarial.items():
        md.append(f"  - {k}: {'EXECUTED' if r['executed'] else 'blocked'} ({r['guard_reason']})")
    md.append("- **Faulty plan (destructive steps mislabelled as safe, eradication first):**")
    for r in fault_rows:
        md.append(f"  - {r['alert']}: first draft rejected = {r['first_draft_rejected']}, revisions = {r['revisions']}, "
                  f"unapproved destructive executions = {r['unapproved_destructive_executions']}")
        for issue in r["issues"][:3]:
            md.append(f"    - {issue}")
    if llm is not None:
        st = llm_stats
        md += ["", "## LLM reasoning layer", "",
               f"- Model: {llm.label}; calls: {st['calls']} ({st['failed']} failed, deterministic fallback used)",
               "- Threat-intel decisions: " + ", ".join(f"{k}: {v}" for k, v in st["decided_by"].items()),
               f"- Entities added by the LLM (verified verbatim in the alert): {st['entities_added']}; "
               f"rejected as unverifiable: {st['entities_rejected']}",
               f"- Outcome-signal agreement between LLM and rules: {st['signal_agreement']}/{st['signal_total']}"]
    (OUT / "eval_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return results


if __name__ == "__main__":
    import argparse
    from irp.llm import build_llm
    ap = argparse.ArgumentParser(description="Evaluate on the 10 synthetic alerts")
    ap.add_argument("--llm", action="store_true", help="use the configured LLM (e.g. Grok) in the accuracy run")
    args = ap.parse_args()
    client = build_llm() if args.llm else None
    if args.llm and client is None:
        raise SystemExit("--llm given but no LLM is configured (set XAI_API_KEY in .env)")
    asyncio.run(main(client))
