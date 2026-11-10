"""Run the Incident Response Playbook Runner on one or more alerts.

Examples
  python main.py --alert A01                      # ask a human at the console for destructive steps
  python main.py --alert A05 --approval deny      # simulated analyst rejects destructive steps
  python main.py --all --approval approve         # run every synthetic alert, auto-approve
  python main.py --alert A07 --inject-plan-fault  # show the Commander rejecting a bad plan
  python main.py --alert-file my_alert.json       # run your own raw alert (JSON or syslog text)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from pathlib import Path

from irp.llm import build_llm
from irp.orchestrator import DATA, ROOT, PlaybookRunner
from irp.safety import HumanApprovalGate

SEV_COLOR = {"Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[96m", "Low": "\033[92m"}
RESET = "\033[0m"


def print_report(report: dict | None, timeline) -> None:
    if report is None:
        esc = timeline.latest("escalated_to_human")
        print(f"\n[{timeline.incident_id}] NOT EXECUTED - escalated to human: {esc}")
        return
    sev = report["severity"]
    print("\n" + "=" * 100)
    print(f" {report['incident_id']}  {report['title']}")
    print("=" * 100)
    print(f" SEVERITY        : {SEV_COLOR.get(sev, '')}{sev}{RESET}   ({report['severity_rationale']})")
    print(f" INTEL SOURCE    : {report['intel_primary_source']} - {report['intel_title']}  [confidence {report['intel_confidence']}]")
    print(f" DECIDED BY      : {report.get('intel_decided_by', 'retrieval')}")
    if report.get("intel_brief"):
        print(f" INTEL BRIEF     : {report['intel_brief']}")
    if (report.get("impact_narrative") or {}).get("business_impact"):
        print(f" BUSINESS IMPACT : {report['impact_narrative']['business_impact']}")
    print(" AFFECTED ASSETS : " + ", ".join(f"{a['asset_id']} ({a['criticality']})" for a in report["affected_assets"]))
    if report["at_risk_assets"]:
        print(" AT-RISK ASSETS  : " + ", ".join(f"{a['asset_id']} - {a['reason']}" for a in report["at_risk_assets"]))
    if report["plan_revisions"] > 1:
        print(f" PLAN REVISIONS  : {report['plan_revisions']} (Commander rejected earlier drafts)")
    print("\n ORDERED CONTAINMENT PLAN")
    print(f" {'#':<3}{'phase':<10}{'action':<22}{'target':<40}{'intel source':<34}status")
    print(" " + "-" * 120)
    for s in report["containment_steps"]:
        flag = " [DESTRUCTIVE]" if s["destructive"] else ""
        src = f"{s['intel_source']} {s['intel_section'].replace('Recommended Containment', 'RC')}"
        target = s["target"] if len(s["target"]) <= 38 else "..." + s["target"][-35:]
        print(f" {s['order']:<3}{s['phase']:<10}{s['action']:<22}{target:<40}{src:<34}{s['status']}{flag}")
        if s.get("rationale"):
            print(f"    why: {s['rationale']}")
    for w in report["review_warnings"]:
        print(f"\n WARNING: {w}")
    if report.get("executive_summary"):
        print("\n EXECUTIVE SUMMARY\n " + report["executive_summary"])


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--alert", help="synthetic alert id, e.g. A01")
    g.add_argument("--all", action="store_true", help="run all 10 synthetic alerts")
    g.add_argument("--alert-file", type=Path, help="file with a raw alert (JSON or a syslog line)")
    ap.add_argument("--approval", choices=["cli", "deny", "approve"], default="cli",
                    help="how destructive steps are approved (default: ask at the console)")
    ap.add_argument("--inject-plan-fault", action="store_true",
                    help="make the planner's first draft unsafe to demonstrate Commander review")
    ap.add_argument("--json", action="store_true", help="print the raw JSON report")
    ap.add_argument("--no-llm", action="store_true", help="force deterministic mode even if an LLM key is set")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    llm = None if args.no_llm else build_llm()
    print(f" Reasoning mode: {'LLM-assisted (' + llm.label + ')' if llm else 'deterministic (no LLM configured)'}")

    alerts = json.loads((DATA / "synthetic_alerts.json").read_text(encoding="utf-8"))
    if args.alert_file:
        text = args.alert_file.read_text(encoding="utf-8").strip()
        safe_id = re.sub(r"[^A-Za-z0-9_\-]", "_", args.alert_file.stem.upper())[:64] or "CUSTOM"
        selected = [{"alert_id": safe_id, "raw": text}]
    elif args.all:
        selected = alerts
    else:
        selected = [a for a in alerts if a["alert_id"] == args.alert.upper()]
        if not selected:
            print(f"unknown alert {args.alert}; choose from {[a['alert_id'] for a in alerts]}")
            return 1

    runner = PlaybookRunner(
        gate=HumanApprovalGate(mode=args.approval, approver="soc-analyst"),
        llm=llm,
        out_dir=ROOT / "output",
        inject_plan_fault=args.inject_plan_fault,
    )
    for a in selected:
        report, timeline = await runner.run_alert(a["alert_id"], a["raw"], overwrite=True)
        print(json.dumps(report, indent=2) if args.json else "", end="")
        if not args.json:
            print_report(report, timeline)
        print(f"\n timeline: output/{a['alert_id']}/timeline.jsonl ({len(timeline.all())} events)")
    return 0


if __name__ == "__main__":
    # LLM output can contain any Unicode (e.g. non-breaking hyphens); never crash while printing it.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if sys.platform == "win32":
        import os
        os.system("")  # enable ANSI colours in Windows terminals
    sys.exit(asyncio.run(main()))
