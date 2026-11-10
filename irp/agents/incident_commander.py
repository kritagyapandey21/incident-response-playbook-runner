"""Incident Commander Agent: reviews and approves the plan, then executes it.

review():  checks the drafted plan and either approves it or returns concrete feedback
           to the Containment Planner (the workflow planner then schedules a revision).
execute(): runs the approved steps in order through the response tool.
           Approval policy:
             * destructive steps always need a human decision (HumanApprovalGate), and the
               response tool's SafetyGuard independently verifies the resulting token;
             * if threat-intel confidence is LOW, every step except evidence preservation
               also needs a human decision, because the plan may be built on the wrong report.
           A recovery step on a target whose destructive step is still held is deferred.
           A failing tool call marks that step "failed"; the rest of the plan continues.
resolve(): applies a later human decision (web console) to a held step.

The Commander only ever works on copies of timeline data and records every change as a
new event, so the timeline stays strictly append-only.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..models import PHASE_ORDER
from ..safety import HumanApprovalGate, is_destructive
from .base import BaseAgent, clean_str

log = logging.getLogger(__name__)

REVIEW_INSTRUCTIONS = """You are the Incident Commander's second-opinion reviewer in a security operations centre.
Review the containment plan below for this incident. You CANNOT approve or reject the plan and you
cannot change it; your notes are shown to the human analyst. Point out real problems only
(missing containment for an affected asset, risky ordering, a step that could destroy evidence,
business-disruption risk). Return a JSON object:
{"verdict": "ok" | "concerns", "concerns": ["up to 3 short, specific concerns"]}"""

SUMMARY_INSTRUCTIONS = """You are an incident commander writing for a CISO. Using ONLY the facts in the
incident report JSON, write a 4-6 sentence executive summary: what happened, severity and why,
affected assets, what was executed, and what is waiting for human approval.
Return a JSON object: {"summary": "..."}"""


class IncidentCommanderAgent(BaseAgent):
    name = "IncidentCommanderAgent"

    def __init__(self, kernel, timeline, gate: HumanApprovalGate, llm=None):
        super().__init__(kernel, timeline, llm)
        self.gate = gate

    # ------------------------------------------------------------------ review
    async def review(self, **_: Any) -> dict:
        draft = self.timeline.latest("containment_plan_drafted")
        intel = self.timeline.latest("intel_retrieved")
        impact = self.timeline.latest("impact_assessed")
        steps = draft["steps"]
        retrieved_ids = {c["doc_id"] for c in intel["candidates"]}
        known_assets = {a["asset_id"] for a in impact["affected_assets"]}
        issues: list[str] = []

        if not steps:
            issues.append("plan is empty (no grounded containment steps)")
        for s in steps:
            if not s.get("citation") or s["citation"]["doc_id"] not in retrieved_ids:
                issues.append(f"{s['step_id']} has no citation to a retrieved threat report")
            if is_destructive(s["action"]) and not s["destructive"]:
                issues.append(f"{s['step_id']} ({s['action']}) is destructive but not flagged as such")
            if s["target_type"] == "host" and s["target"] not in known_assets:
                issues.append(f"{s['step_id']} targets {s['target']} which is not an assessed asset")
        phases = [PHASE_ORDER[s["phase"]] for s in steps]
        if phases != sorted(phases):
            issues.append("steps are not ordered preserve -> contain -> eradicate -> recover")
        pairs = [(s["action"], s["target"]) for s in steps]
        if len(pairs) != len(set(pairs)):
            issues.append("plan contains duplicate steps")

        warnings = []
        if intel["confidence"] == "low":
            warnings.append("threat-intel confidence is LOW: every non-preservation step requires analyst approval")
        elif intel["confidence"] == "medium":
            warnings.append(f"threat-intel match is ambiguous ({intel.get('decided_by', 'retrieval')}); "
                            f"analyst should confirm {intel['primary']['doc_id']}")
        inc = self.timeline.latest("incident_record_created")
        sig = inc.get("llm_signal")
        if sig and not sig["agrees_with_rules"] and sig["evidence_verified"]:
            warnings.append(f"LLM reads the outcome as '{sig['signal']}' (rules: '{inc['status_signal']}'): "
                            f"\"{sig['evidence']}\"")

        llm_review = None
        if self.llm is not None and steps and not issues:   # only review plans that passed the hard checks
            res = await self.think("plan_second_opinion", REVIEW_INSTRUCTIONS, json.dumps({
                "incident": inc.get("summary") or inc["title"], "severity": impact["severity"],
                "affected_assets": [a["asset_id"] for a in impact["affected_assets"]],
                "threat_report": intel["primary"]["doc_id"] if intel["primary"] else None,
                "plan": [{k: s[k] for k in ("step_id", "phase", "action", "target", "description")} for s in steps],
            }))
            if res:
                concerns = res.get("concerns") if isinstance(res.get("concerns"), list) else []
                llm_review = {"verdict": res.get("verdict") if res.get("verdict") in ("ok", "concerns") else None,
                              "concerns": [c for c in (clean_str(x, 220) for x in concerns[:3]) if c]}
                warnings += [f"Reviewer ({self.llm.model}): {c}" for c in llm_review["concerns"]]

        decision = {
            "approved": not issues,          # hard, deterministic checks only; the LLM cannot approve
            "revision_reviewed": draft["revision"],
            "issues": issues,
            "warnings": warnings,
            "llm_review": llm_review,
            "destructive_steps": [s["step_id"] for s in steps if is_destructive(s["action"])],
        }
        self.log("plan_reviewed", decision)
        return decision

    # ----------------------------------------------------------------- policy
    def _approval_reason(self, step: dict, confidence: str) -> str | None:
        if is_destructive(step["action"]):
            return "destructive action"
        if confidence == "low" and step["phase"] != "preserve":
            return "low-confidence threat intel"
        return None

    async def _run_step(self, s: dict, token: str = "") -> None:
        try:
            res = await self.call_tool("response", "execute_action", incident_id=self.timeline.incident_id,
                                       step_id=s["step_id"], action=s["action"], target=s["target"],
                                       approval_token=token)
        except Exception as exc:  # tool outage must not abort the whole incident
            log.exception("response tool failed for %s/%s", self.timeline.incident_id, s["step_id"])
            s["status"], s["result"] = "failed", f"tool error: {type(exc).__name__}"
            self.log("step_failed", {"step_id": s["step_id"], "action": s["action"], "target": s["target"],
                                     "error": f"{type(exc).__name__}: {exc}"})
            return
        s["status"] = "executed" if res["executed"] else "blocked"
        s["result"] = res["result"]
        self.log("step_executed" if res["executed"] else "step_blocked",
                 {"step_id": s["step_id"], "action": s["action"], "target": s["target"], "result": res["result"]})

    # ----------------------------------------------------------------- execute
    async def execute(self, **_: Any) -> dict:
        steps = self.timeline.latest("containment_plan_drafted")["steps"]   # a private copy
        confidence = self.timeline.latest("intel_retrieved")["confidence"]
        held: dict[str, str] = {}   # target -> step_id of a held step
        for s in steps:
            s["approval_reason"] = self._approval_reason(s, confidence)
            if s["phase"] == "recover" and s["target"] in held:
                s["status"] = "deferred"
                s["result"] = f"NOT EXECUTED - depends on held step {held[s['target']]}"
                self.log("step_deferred", {"step_id": s["step_id"], "waiting_on": held[s["target"]]})
                continue
            token = ""
            if s["approval_reason"]:
                decision = self.gate.request(self.timeline, s, why=s["approval_reason"])
                if not decision.approved:
                    s["status"] = "pending_approval"
                    s["result"] = f"NOT EXECUTED - {decision.reason}"
                    held[s["target"]] = s["step_id"]
                    self.log("step_held", {"step_id": s["step_id"], "action": s["action"],
                                           "target": s["target"], "why": s["approval_reason"]})
                    continue
                token = decision.token or ""
                s["approved_by"] = decision.approver
            await self._run_step(s, token)

        report = await self._report(steps)
        self.log("incident_report", report)
        return report

    # ------------------------------------------- human decision on a held step
    async def resolve(self, step_id: str, approved: bool, approver: str) -> dict:
        """Apply a human decision (from the web console) to a step held for approval."""
        report = self.timeline.latest("incident_report")
        if report is None:
            raise ValueError("incident has no report yet")
        step = next((s for s in report["containment_steps"] if s["step_id"] == step_id), None)
        if step is None or step["status"] != "pending_approval":
            raise ValueError(f"{step_id} is not waiting for approval")
        gate_step = {"step_id": step_id, "action": step["action"], "target": step["target"],
                     "description": step["description"],
                     "citation": {"doc_id": step["intel_source"], "title": report["intel_title"]}}
        reason = "approved in web console" if approved else "rejected in web console"
        decision = self.gate.decide(self.timeline, gate_step, approved, approver, reason)

        followers = [s for s in report["containment_steps"]
                     if s["status"] == "deferred" and s["target"] == step["target"]]
        if not approved:
            step["status"], step["result"] = "rejected", f"NOT EXECUTED - {reason} by {decision.approver}"
            self.log("step_rejected", {"step_id": step_id, "approver": decision.approver})
            for f in followers:
                f["status"], f["result"] = "skipped", f"skipped - {step_id} was rejected"
        else:
            step["approved_by"] = decision.approver
            await self._run_step(step, decision.token or "")
            if step["status"] == "executed":
                for f in followers:
                    await self._run_step(f)
        self.log("incident_report", report)
        return report

    async def _report(self, steps: list[dict]) -> dict:
        inc = self.timeline.latest("incident_record_created")
        intel = self.timeline.latest("intel_retrieved")
        impact = self.timeline.latest("impact_assessed")
        review = self.timeline.latest("plan_reviewed")
        primary = intel["primary"] or {}
        report = {
            "incident_id": self.timeline.incident_id,
            "title": inc["title"],
            "severity": impact["severity"],
            "severity_rationale": impact["severity_rationale"],
            "intel_primary_source": primary.get("doc_id"),
            "intel_title": primary.get("title"),
            "intel_confidence": intel["confidence"],
            "affected_assets": impact["affected_assets"],
            "at_risk_assets": impact["at_risk_assets"],
            "containment_steps": [{
                "order": s["order"], "step_id": s["step_id"], "phase": s["phase"], "action": s["action"],
                "target": s["target"], "description": s["description"], "destructive": s["destructive"],
                "intel_source": s["citation"]["doc_id"], "intel_section": s["citation"]["section"],
                "approval_reason": s.get("approval_reason"), "rationale": s.get("rationale"),
                "status": s["status"], "approved_by": s.get("approved_by"), "result": s.get("result"),
            } for s in steps],
            "review_warnings": review["warnings"],
            "plan_revisions": self.timeline.count("containment_plan_drafted"),
            "llm_model": self.llm.label if self.llm else None,
            "incident_summary": inc.get("summary"),
            "intel_brief": intel.get("intel_brief"),
            "intel_decided_by": intel.get("decided_by", "retrieval"),
            "impact_narrative": impact.get("impact_narrative"),
            "executive_summary": None,
        }
        if self.llm is not None:
            res = await self.think("executive_summary", SUMMARY_INSTRUCTIONS, json.dumps(report, default=str))
            report["executive_summary"] = clean_str(res.get("summary"), 1200) if res else None
        return report
