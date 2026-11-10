"""Unit tests: timeline, safety gate, alert parser, retrieval."""
import json
import tempfile
import unittest
from pathlib import Path

from irp.agents.alert_parser import AlertParserAgent, extract_domains, is_internal_ip, registered_domain
from irp.config import SETTINGS
from irp.rag import ThreatReportIndex, _ioc_in
from irp.safety import HumanApprovalGate, SafetyGuard, validate_approver
from irp.timeline import IncidentTimeline, new_incident_id, validate_incident_id

ALERTS = json.loads((SETTINGS.data_dir / "synthetic_alerts.json").read_text(encoding="utf-8"))


class TimelineTests(unittest.TestCase):
    def test_reads_are_isolated_copies(self):
        tl = IncidentTimeline("T1")
        data = {"steps": [{"status": "planned"}]}
        tl.write("A", "plan", data)
        data["steps"][0]["status"] = "mutated-by-writer"
        got = tl.latest("plan")
        got["steps"][0]["status"] = "mutated-by-reader"
        self.assertEqual(tl.latest("plan")["steps"][0]["status"], "planned")
        tl.read()[0]["data"]["steps"].clear()
        self.assertEqual(len(tl.latest("plan")["steps"]), 1)

    def test_persist_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "INC-1" / "timeline.jsonl"
            tl = IncidentTimeline("INC-1", p)
            tl.write("A", "x", {"n": 1})
            tl.write("B", "y", {"n": 2})
            loaded = IncidentTimeline.load(p)
            self.assertEqual(loaded.all(), tl.all())
            loaded.write("C", "z", None)
            self.assertEqual(len(IncidentTimeline.load(p).all()), 3)

    def test_refuses_to_clobber_unless_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "INC-2" / "timeline.jsonl"
            IncidentTimeline("INC-2", p).write("A", "x")
            with self.assertRaises(FileExistsError):
                IncidentTimeline("INC-2", p)
            IncidentTimeline("INC-2", p, overwrite=True)
            self.assertEqual(p.read_text(), "")

    def test_incident_id_validation(self):
        for bad in ["../etc", "a/b", "", "x" * 65, "a b", "..\\x"]:
            with self.assertRaises(ValueError):
                validate_incident_id(bad)
        self.assertTrue(validate_incident_id(new_incident_id("A01")).startswith("A01-"))


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000.0
        self.gate = HumanApprovalGate(mode="approve", clock=lambda: self.now, ttl_s=60)
        self.guard = SafetyGuard(self.gate)
        self.tl = IncidentTimeline("SAFE-1")
        self.step = {"step_id": "S1", "action": "wipe_and_reimage", "target": "FS-01",
                     "description": "wipe", "citation": {"doc_id": "TR-001"}}

    def token(self):
        return self.gate.request(self.tl, self.step).token

    def test_non_destructive_needs_no_token(self):
        self.assertTrue(self.guard.check("SAFE-1", "S1", "block_ip", "1.2.3.4", None)[0])

    def test_valid_token_works_exactly_once(self):
        t = self.token()
        self.assertEqual(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", t), (True, "valid human approval"))
        self.assertEqual(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", t)[1], "token already used")

    def test_token_bound_to_incident_step_action_target(self):
        t = self.token()
        for args in [("SAFE-2", "S1", "wipe_and_reimage", "FS-01"), ("SAFE-1", "S2", "wipe_and_reimage", "FS-01"),
                     ("SAFE-1", "S1", "shutdown_service", "FS-01"), ("SAFE-1", "S1", "wipe_and_reimage", "DC-01")]:
            self.assertFalse(self.guard.check(*args, t)[0], args)

    def test_token_expires(self):
        t = self.token()
        self.now += 61
        self.assertEqual(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", t)[1], "approval token expired")

    def test_forged_and_malformed_tokens(self):
        self.assertFalse(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", "")[0])
        self.assertFalse(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", "garbage")[0])
        self.assertFalse(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", f"{int(self.now)}." + "0" * 64)[0])
        other_gate = HumanApprovalGate(mode="approve", clock=lambda: self.now)   # different secret
        foreign = other_gate.request(self.tl, self.step).token
        self.assertFalse(self.guard.check("SAFE-1", "S1", "wipe_and_reimage", "FS-01", foreign)[0])

    def test_rejection_mints_no_token(self):
        gate = HumanApprovalGate(mode="deny")
        self.assertIsNone(gate.request(self.tl, self.step).token)

    def test_approver_validation(self):
        self.assertEqual(validate_approver("  Khushi Dogra "), "Khushi Dogra")
        for bad in ["", "x", "<script>", "a" * 65]:
            with self.assertRaises(ValueError):
                validate_approver(bad)


class ParserTests(unittest.TestCase):
    def parse(self, raw):
        return AlertParserAgent(None, IncidentTimeline("P-1")).parse(raw)

    def test_signals_on_synthetic_alerts(self):
        expected = {"A01": "confirmed", "A02": "confirmed", "A03": "blocked", "A04": "confirmed",
                    "A05": "confirmed", "A06": "confirmed", "A07": "unknown", "A08": "unknown",
                    "A09": "unknown", "A10": "blocked"}
        for a in ALERTS:
            self.assertEqual(self.parse(a["raw"]).status_signal, expected[a["alert_id"]], a["alert_id"])

    def test_partial_success_beats_blocked(self):
        rec = self.parse("Nov 10 02:14:33 VPN-GW-01 authd[1]: 900 failed logins; 10 successful authentications")
        self.assertEqual(rec.status_signal, "confirmed")

    def test_negation_is_ignored(self):
        rec = self.parse({"title": "x", "details": "payload was not executed; connection blocked"})
        self.assertEqual(rec.status_signal, "blocked")

    def test_ip_validation_and_classification(self):
        rec = self.parse({"details": "from 999.1.1.1 and 1.2.3.4.5 and 10.0.0.9 to 198.51.100.7 via 45.9.148.3"})
        self.assertEqual(rec.ips, ["10.0.0.9", "198.51.100.7", "45.9.148.3"])
        self.assertEqual(rec.internal_ips, ["10.0.0.9"])
        self.assertFalse(is_internal_ip("198.51.100.7"))   # documentation range is not "internal" to us

    def test_domains(self):
        self.assertEqual(registered_domain("a.b.evil.co.uk"), "evil.co.uk")
        self.assertEqual(registered_domain("d4t4.exfil-cdn.example"), "exfil-cdn.example")
        found = extract_domains("ran C:\\x\\vlt.exe, wrote img_cache.php and README_RESTORE.txt, called bad.example.de")
        self.assertEqual(found, ["example.de"])

    def test_known_hosts_and_users(self):
        rec = self.parse(ALERTS[1]["raw"])
        self.assertEqual(rec.users, ["asmith"])
        self.assertIn("micros0ft-login.example", rec.domains)
        self.assertNotIn("corp.example", rec.domains)


class RetrievalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = ThreatReportIndex(SETTINGS.data_dir / "threat_reports")

    def test_ioc_boundary_matching(self):
        self.assertTrue(_ioc_in("1.2.3.4", "seen 1.2.3.4 today"))
        self.assertFalse(_ioc_in("1.2.3.4", "seen 11.2.3.45 today"))
        self.assertTrue(_ioc_in("exfil-cdn.example", "to d4t4.exfil-cdn.example now"))
        self.assertFalse(_ioc_in("vlt.exe", "xvlt.exe"))

    def test_each_alert_retrieves_its_report(self):
        for a in ALERTS:
            q = json.dumps(a["raw"]) if isinstance(a["raw"], dict) else a["raw"]
            self.assertEqual(self.index.search(q, 1)[0]["doc_id"], a["ground_truth"]["intel_source"])

    def test_gibberish_scores_zero(self):
        self.assertTrue(all(h["score"] == 0 for h in self.index.search("qqqq zzzz xxxx", 3)))


if __name__ == "__main__":
    unittest.main()
