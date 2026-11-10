"""Planner-executor coordination.

WorkflowPlanner  decides WHAT should happen: it builds an ordered task plan (which agent,
                 which goal, which dependencies) and re-plans after every task based on
                 what has been written to the shared timeline (low-confidence intel ->
                 broaden retrieval; plan rejected by the Commander -> revise and re-review;
                 too many rejections or a failed task -> escalate instead of executing).
PlanExecutor     decides HOW: it pops tasks in order, dispatches each one to the agent
                 responsible, records task start/finish/failure on the timeline and asks
                 the planner for follow-up tasks. A hard task budget prevents runaway loops.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from semantic_kernel import Kernel

from .agents import (
    AlertParserAgent,
    ContainmentPlannerAgent,
    ImpactAssessorAgent,
    IncidentCommanderAgent,
    ThreatIntelRetrievalAgent,
)
from .config import ROOT, SETTINGS
from .rag import ThreatReportIndex
from .safety import HumanApprovalGate, SafetyGuard
from .timeline import IncidentTimeline, validate_incident_id
from .tools.asset_inventory import AssetInventoryPlugin
from .tools.response_tool import MockResponsePlugin
from .tools.threat_intel import ThreatIntelPlugin

DATA = SETTINGS.data_dir
log = logging.getLogger(__name__)
__all__ = ["DATA", "ROOT", "PlaybookRunner", "WorkflowPlanner", "PlanExecutor", "Task"]


@dataclass
class Task:
    task_id: str
    agent: str
    method: str
    goal: str
    depends_on: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)


class WorkflowPlanner:
    name = "WorkflowPlanner"

    def __init__(self, timeline: IncidentTimeline):
        self.timeline = timeline
        self._n = 0

    def _task(self, agent: str, method: str, goal: str, deps: list[str] | None = None, **params) -> Task:
        self._n += 1
        return Task(f"T{self._n}", agent, method, goal, deps or [], params)

    def initial_plan(self) -> list[Task]:
        t1 = self._task("AlertParserAgent", "run", "Normalise raw alert into an incident record")
        t2 = self._task("ThreatIntelRetrievalAgent", "run", "Retrieve matching threat intel (RAG)", [t1.task_id])
        t3 = self._task("ImpactAssessorAgent", "run", "Map affected assets and score severity", [t1.task_id, t2.task_id])
        t4 = self._task("ContainmentPlannerAgent", "run", "Draft ordered, cited containment steps", [t2.task_id, t3.task_id])
        t5 = self._task("IncidentCommanderAgent", "review", "Review the containment plan", [t4.task_id])
        plan = [t1, t2, t3, t4, t5]
        self.timeline.write(self.name, "workflow_planned", [asdict(t) for t in plan])
        return plan

    def replan(self, done: Task, result: Any) -> list[Task]:
        new: list[Task] = []
        if done.agent == "ThreatIntelRetrievalAgent" and not done.params.get("broaden"):
            if result["confidence"] == "low":
                new.append(self._task("ThreatIntelRetrievalAgent", "run",
                                      "Low-confidence match: broaden retrieval", [done.task_id], broaden=True))
        if done.agent == "IncidentCommanderAgent" and done.method == "review":
            if result["approved"]:
                new.append(self._task("IncidentCommanderAgent", "execute",
                                      "Execute approved steps (gated steps need human approval)", [done.task_id]))
            elif result["revision_reviewed"] <= SETTINGS.max_plan_revisions:
                t_rev = self._task("ContainmentPlannerAgent", "run", "Revise plan per Commander feedback",
                                   [done.task_id], feedback=result["issues"])
                new += [t_rev, self._task("IncidentCommanderAgent", "review", "Re-review revised plan", [t_rev.task_id])]
            else:
                self.escalate("plan rejected too many times", issues=result["issues"])
        if new:
            self.timeline.write(self.name, "workflow_replanned",
                                {"after": done.task_id, "added": [asdict(t) for t in new]})
        return new

    def escalate(self, reason: str, **details: Any) -> None:
        self.timeline.write(self.name, "escalated_to_human", {"reason": reason, **details})


class PlanExecutor:
    name = "PlanExecutor"

    def __init__(self, planner: WorkflowPlanner, agents: dict[str, Any], timeline: IncidentTimeline):
        self.planner, self.agents, self.timeline = planner, agents, timeline

    async def run(self) -> dict | None:
        queue = self.planner.initial_plan()
        done: set[str] = set()
        executed = 0
        while queue:
            if executed >= SETTINGS.max_tasks_per_incident:
                self.planner.escalate("task budget exhausted", budget=SETTINGS.max_tasks_per_incident)
                return None
            task = queue.pop(0)
            missing = [d for d in task.depends_on if d not in done]
            if missing:
                self.planner.escalate(f"{task.task_id} dependencies not met", missing=missing)
                return None
            self.timeline.write(self.name, "task_started", {"task_id": task.task_id, "agent": task.agent, "goal": task.goal})
            try:
                result = await getattr(self.agents[task.agent], task.method)(**task.params)
            except Exception as exc:
                log.exception("task %s (%s) failed for %s", task.task_id, task.agent, self.timeline.incident_id)
                self.timeline.write(self.name, "task_failed", {"task_id": task.task_id, "agent": task.agent,
                                                               "error": f"{type(exc).__name__}: {exc}"})
                self.planner.escalate(f"{task.agent} failed; no containment executed", task_id=task.task_id)
                return None
            executed += 1
            done.add(task.task_id)
            self.timeline.write(self.name, "task_completed", {"task_id": task.task_id, "agent": task.agent})
            queue = self.planner.replan(task, result) + queue   # follow-ups run next
        return self.timeline.latest("incident_report")


class PlaybookRunner:
    """Builds the kernel, tools and agents once, and runs alerts through them."""

    def __init__(self, gate: HumanApprovalGate | None = None, chat_service=None,
                 out_dir: Path | None = None, inject_plan_fault: bool = False):
        self.gate = gate or HumanApprovalGate(mode="deny")
        self.chat_service = chat_service
        self.out_dir = out_dir
        self.inject_plan_fault = inject_plan_fault
        self.index = ThreatReportIndex(DATA / "threat_reports")
        self.response_tool = MockResponsePlugin(SafetyGuard(self.gate))
        self._sessions: OrderedDict[str, dict] = OrderedDict()   # LRU: incident_id -> timeline + commander
        self._sessions_lock = threading.Lock()

        self.kernel = Kernel()
        self.kernel.add_plugin(AssetInventoryPlugin(DATA / "asset_inventory.json"), plugin_name="assets")
        self.kernel.add_plugin(ThreatIntelPlugin(self.index), plugin_name="threat_intel")
        self.kernel.add_plugin(self.response_tool, plugin_name="response")
        if chat_service is not None:
            self.kernel.add_service(chat_service)

    # ---------------------------------------------------------------- sessions
    def _commander(self, timeline: IncidentTimeline) -> IncidentCommanderAgent:
        return IncidentCommanderAgent(self.kernel, timeline, self.gate, self.chat_service)

    def _remember(self, incident_id: str, session: dict) -> None:
        with self._sessions_lock:
            self._sessions[incident_id] = session
            self._sessions.move_to_end(incident_id)
            while len(self._sessions) > SETTINGS.max_sessions:
                self._sessions.popitem(last=False)

    def _timeline_path(self, incident_id: str) -> Path | None:
        return self.out_dir / validate_incident_id(incident_id) / "timeline.jsonl" if self.out_dir else None

    def get_session(self, incident_id: str) -> dict:
        """Return an incident's session, re-loading it from disk if needed (e.g. after a restart)."""
        validate_incident_id(incident_id)
        with self._sessions_lock:
            if incident_id in self._sessions:
                self._sessions.move_to_end(incident_id)
                return self._sessions[incident_id]
        path = self._timeline_path(incident_id)
        if not path or not path.exists():
            raise KeyError(f"unknown incident {incident_id}")
        timeline = IncidentTimeline.load(path)
        session = {"timeline": timeline, "commander": self._commander(timeline)}
        self._remember(incident_id, session)
        return session

    def list_incidents(self, limit: int = 50) -> list[dict]:
        if not self.out_dir or not self.out_dir.exists():
            return []
        paths = sorted(self.out_dir.glob("*/timeline.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        out = []
        for p in paths[:limit]:
            try:
                tl = IncidentTimeline.load(p)
            except (ValueError, OSError, json.JSONDecodeError):
                continue
            report = tl.latest("incident_report")
            out.append({
                "incident_id": tl.incident_id,
                "title": report["title"] if report else (tl.latest("incident_record_created") or {}).get("title", "?"),
                "severity": report["severity"] if report else None,
                "pending": sum(1 for s in report["containment_steps"] if s["status"] == "pending_approval") if report else 0,
                "escalated": tl.latest("escalated_to_human") is not None,
                "updated": tl.all()[-1]["ts"],
            })
        return out

    # ------------------------------------------------------------------- run
    async def run_alert(self, incident_id: str, raw_alert: Any, overwrite: bool = False) -> tuple[dict | None, IncidentTimeline]:
        if len(json.dumps(raw_alert, default=str)) > SETTINGS.max_alert_bytes:
            raise ValueError(f"alert larger than {SETTINGS.max_alert_bytes} bytes")
        timeline = IncidentTimeline(incident_id, self._timeline_path(incident_id), overwrite=overwrite)
        timeline.write("Intake", "alert_received", {"raw": raw_alert})

        commander = self._commander(timeline)
        agents = {
            "AlertParserAgent": AlertParserAgent(self.kernel, timeline),
            "ThreatIntelRetrievalAgent": ThreatIntelRetrievalAgent(self.kernel, timeline),
            "ImpactAssessorAgent": ImpactAssessorAgent(self.kernel, timeline),
            "ContainmentPlannerAgent": ContainmentPlannerAgent(self.kernel, timeline, self.inject_plan_fault),
            "IncidentCommanderAgent": commander,
        }
        report = await PlanExecutor(WorkflowPlanner(timeline), agents, timeline).run()
        self._remember(incident_id, {"timeline": timeline, "commander": commander})
        if self.out_dir and report:
            (self.out_dir / incident_id / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        log.info("incident %s finished: severity=%s escalated=%s", incident_id,
                 report["severity"] if report else None, report is None)
        return report, timeline

    async def resolve(self, incident_id: str, step_id: str, approved: bool, approver: str) -> tuple[dict, IncidentTimeline]:
        session = self.get_session(incident_id)
        report = await session["commander"].resolve(step_id, approved, approver)
        if self.out_dir:
            (self.out_dir / incident_id / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report, session["timeline"]
