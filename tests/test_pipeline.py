"""Integration tests: the full multi-agent pipeline, policies, failure handling, resume."""
import asyncio
import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from irp.config import SETTINGS
from irp.orchestrator import PlaybookRunner
from irp.safety import HumanApprovalGate, is_destructive

ALERTS = {a["alert_id"]: a for a in json.loads((SETTINGS.data_dir / "synthetic_alerts.json").read_text(encoding="utf-8"))}


def run(coro):
    return asyncio.run(coro)


class PipelineTests(unittest.TestCase):
    def test_destructive_held_and_recovery_deferred(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"))
        report, tl = run(runner.run_alert("A01", ALERTS["A01"]["raw"]))
        status = {s["action"]: s["status"] for s in report["containment_steps"]}
        self.assertEqual(report["severity"], "Critical")
        self.assertEqual(status["wipe_and_reimage"], "pending_approval")
        self.assertEqual(status["restore_from_backup"], "deferred")
        self.assertEqual(status["isolate_host"], "executed")
        executed = [r for r in runner.response_tool.execution_log if r["executed"]]
        self.assertFalse(any(is_destructive(r["action"]) for r in executed))

    def test_timeline_history_is_not_rewritten_by_execution(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"))
        _, tl = run(runner.run_alert("A05", ALERTS["A05"]["raw"]))
        draft = tl.latest("containment_plan_drafted")
        self.assertTrue(all(s["status"] == "planned" for s in draft["steps"]))

    def test_unmatched_alert_escalates_without_executing(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="approve"))
        report, tl = run(runner.run_alert("JUNK", "qqqq zzzz xxxx"))
        self.assertIsNone(report)
        self.assertIsNotNone(tl.latest("escalated_to_human"))
        self.assertEqual(runner.response_tool.execution_log, [])
        self.assertTrue(any(e["event"] == "workflow_replanned" for e in tl.all()))   # broadened retrieval first

    def test_low_confidence_gates_every_non_preservation_step(self):
        strict = dataclasses.replace(SETTINGS, low_confidence_score=99.0)
        with mock.patch("irp.agents.threat_intel.SETTINGS", strict):
            runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"))
            report, _ = run(runner.run_alert("A07", ALERTS["A07"]["raw"]))
        for s in report["containment_steps"]:
            expected = "executed" if s["phase"] == "preserve" else ("pending_approval", "deferred")
            if s["phase"] == "preserve":
                self.assertEqual(s["status"], expected)
            else:
                self.assertIn(s["status"], expected, s)

    def test_tool_failure_marks_step_failed_and_continues(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="deny"))
        real = runner.response_tool.guard

        class FlakyGuard:
            def check(self, incident_id, step_id, action, target, token):
                if action == "isolate_host":
                    raise ConnectionError("EDR API unreachable")
                return real.check(incident_id, step_id, action, target, token)

        runner.response_tool.guard = FlakyGuard()
        report, tl = run(runner.run_alert("A07", ALERTS["A07"]["raw"]))
        status = {s["action"]: s["status"] for s in report["containment_steps"]}
        self.assertEqual(status["isolate_host"], "failed")
        self.assertEqual(status["block_ip"], "executed")
        self.assertIsNotNone(tl.latest("step_failed"))

    def test_agent_crash_escalates(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="approve"))
        with mock.patch("irp.agents.impact_assessor.ImpactAssessorAgent.run", side_effect=RuntimeError("boom")):
            report, tl = run(runner.run_alert("A01", ALERTS["A01"]["raw"]))
        self.assertIsNone(report)
        self.assertIsNotNone(tl.latest("task_failed"))
        self.assertEqual(runner.response_tool.execution_log, [])

    def test_oversized_alert_rejected(self):
        runner = PlaybookRunner()
        with self.assertRaises(ValueError):
            run(runner.run_alert("BIG", "x" * (SETTINGS.max_alert_bytes + 10)))

    def test_resume_approval_after_restart(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            first = PlaybookRunner(gate=HumanApprovalGate(mode="defer"), out_dir=out)
            run(first.run_alert("A01-RESUME", ALERTS["A01"]["raw"]))
            # simulate a process restart: brand-new runner, new gate secret, same output dir
            second = PlaybookRunner(gate=HumanApprovalGate(mode="defer"), out_dir=out)
            report, tl = run(second.resolve("A01-RESUME", "S5", True, "Gaurav Tiwari"))
            status = {s["step_id"]: s["status"] for s in report["containment_steps"]}
            self.assertEqual(status["S5"], "executed")
            self.assertEqual(status["S6"], "executed")      # deferred restore released
            self.assertEqual(tl.latest("approval_decision")["approver"], "Gaurav Tiwari")
            with self.assertRaises(ValueError):
                run(second.resolve("A01-RESUME", "S5", True, "Gaurav Tiwari"))   # no double decision
            self.assertEqual(second.list_incidents()[0]["incident_id"], "A01-RESUME")

    def test_rejection_skips_dependent_recovery(self):
        runner = PlaybookRunner(gate=HumanApprovalGate(mode="defer"))
        run(runner.run_alert("A01-REJ", ALERTS["A01"]["raw"]))
        report, _ = run(runner.resolve("A01-REJ", "S5", False, "Khushi Dogra"))
        status = {s["step_id"]: s["status"] for s in report["containment_steps"]}
        self.assertEqual((status["S5"], status["S6"]), ("rejected", "skipped"))


if __name__ == "__main__":
    unittest.main()
