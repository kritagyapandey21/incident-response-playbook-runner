"""Containment Planner Agent: drafts ordered, cited containment steps.

The recommended-containment section of the retrieved threat report is the source of
every step. Each template is bound to concrete targets taken from the incident record
and the impact assessment (both read from the shared timeline), filtered by the
template's minimum severity, and ordered preserve -> contain -> eradicate -> recover.
Every step carries a citation to the report section it came from.
"""
from __future__ import annotations

from typing import Any

from ..models import PHASE_ORDER, Citation, ContainmentStep, severity_rank
from ..safety import is_destructive
from .base import BaseAgent


class ContainmentPlannerAgent(BaseAgent):
    name = "ContainmentPlannerAgent"

    def __init__(self, kernel, timeline, inject_fault: bool = False):
        super().__init__(kernel, timeline)
        # Fault injection for demos/tests: on the first draft, mislabel destructive steps
        # as non-destructive and put eradication first, so the Commander's review (and the
        # safety guard behind it) can be shown catching a bad plan.
        self.inject_fault = inject_fault

    def _targets(self, target_type: str, inc: dict, impact: dict) -> list[str]:
        hosts = [a["asset_id"] for a in impact["affected_assets"] if a["kind"] == "host"]
        users = [a["asset_id"].split(":", 1)[1] for a in impact["affected_assets"] if a["kind"] == "identity"]
        accounts = inc["cloud_accounts"]
        attacker_ips = [ip for ip in inc["external_ips"] if ip not in impact["owned_ips"]]
        return {
            "host": hosts, "user": users, "ip": attacker_ips, "domain": inc["domains"],
            "hash": inc["hashes"], "file": inc["files"], "email_sender": inc["email_senders"],
            "cloud_key": inc["cloud_keys"], "cloud_account": accounts,
        }.get(target_type, [])

    async def run(self, feedback: list[str] | None = None, **_: Any) -> list[dict]:
        inc = self.timeline.latest("incident_record_created")
        intel = self.timeline.latest("intel_retrieved")
        impact = self.timeline.latest("impact_assessed")
        severity = impact["severity"]
        primary = intel["primary"]
        steps: list[ContainmentStep] = []
        skipped: list[dict] = []

        if not primary:
            # No grounded intel: refuse to invent steps. The Commander will reject the empty
            # plan and the planner escalates to a human.
            self.log("containment_plan_drafted", {
                "revision": self.timeline.count("containment_plan_drafted") + 1,
                "addressed_feedback": feedback or [], "steps": [],
                "skipped_templates": [{"action": "*", "reason": "no threat report matched the alert"}],
            })
            return []

        playbook = await self.call_tool("threat_intel", "get_containment", doc_id=primary["doc_id"])
        for tpl in (playbook or {}).get("steps", []):
            min_sev = tpl.get("min_severity")
            if min_sev and severity_rank(severity) < severity_rank(min_sev):
                skipped.append({"action": tpl["action"], "reason": f"requires severity >= {min_sev}, incident is {severity}"})
                continue
            targets = self._targets(tpl["target_type"], inc, impact)
            if not targets:
                skipped.append({"action": tpl["action"], "reason": f"no {tpl['target_type']} entity in incident"})
                continue
            for t in targets:
                steps.append(ContainmentStep(
                    step_id="", order=0, phase=tpl["phase"], action=tpl["action"], target=t,
                    target_type=tpl["target_type"], description=tpl["template"].format(target=t),
                    destructive=is_destructive(tpl["action"]),
                    citation=Citation(primary["doc_id"], primary["title"],
                                      f"Recommended Containment #{tpl['num']}", primary["score"]),
                ))

        first_draft = self.timeline.count("containment_plan_drafted") == 0
        if self.inject_fault and first_draft and not feedback:
            for s in steps:
                if s.destructive:
                    s.destructive = False
            steps.sort(key=lambda s: -PHASE_ORDER[s.phase])
        else:
            steps.sort(key=lambda s: (PHASE_ORDER[s.phase], int(s.citation.section.rsplit("#", 1)[1])))

        # dedupe identical action/target pairs
        seen, unique = set(), []
        for s in steps:
            if (s.action, s.target) not in seen:
                seen.add((s.action, s.target))
                unique.append(s)
        for i, s in enumerate(unique, 1):
            s.order, s.step_id = i, f"S{i}"

        plan = [s.to_dict() for s in unique]
        self.log("containment_plan_drafted", {
            "revision": self.timeline.count("containment_plan_drafted") + 1,
            "addressed_feedback": feedback or [], "steps": plan, "skipped_templates": skipped,
        })
        return plan
