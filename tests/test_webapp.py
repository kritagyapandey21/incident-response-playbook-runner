"""HTTP-level tests for the web console's security controls and API."""
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import webapp

TOKEN = "test-token-123"


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        app = webapp.ConsoleApp(Path(cls.tmp.name), TOKEN)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        cls.port = cls.server.server_address[1]
        cls.server.RequestHandlerClass = webapp.make_handler(app, cls.port)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, token=TOKEN, host=None, ctype="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": host or f"localhost:{self.port}"}
        if token:
            headers["X-Console-Token"] = token
        data = None
        if body is not None:
            data = body if isinstance(body, (bytes, str)) else json.dumps(body)
            headers["Content-Type"] = ctype
        conn.request(method, path, body=data, headers=headers)
        res = conn.getresponse()
        raw = res.read()
        conn.close()
        try:
            return res.status, json.loads(raw), res
        except json.JSONDecodeError:
            return res.status, raw, res

    def test_static_page_has_security_headers(self):
        status, _, res = self.req("GET", "/", token=None)
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", res.getheader("Content-Security-Policy"))
        self.assertIn("script-src 'self'", res.getheader("Content-Security-Policy"))
        self.assertEqual(res.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(res.getheader("X-Content-Type-Options"), "nosniff")

    def test_api_requires_token(self):
        self.assertEqual(self.req("GET", "/api/alerts", token=None)[0], 401)
        self.assertEqual(self.req("GET", "/api/alerts", token="wrong")[0], 401)
        self.assertEqual(self.req("GET", "/api/alerts")[0], 200)

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.req("GET", "/api/alerts", host="evil.example")[0], 421)

    def test_csrf_simple_form_post_rejected(self):
        status, _, _ = self.req("POST", "/api/decide", body="incident_id=x", ctype="text/plain")
        self.assertEqual(status, 415)

    def test_oversized_body_rejected(self):
        status, _, _ = self.req("POST", "/api/run", body={"raw": "x" * 300_000})
        self.assertEqual(status, 413)

    def test_run_decide_flow(self):
        status, data, _ = self.req("POST", "/api/run", body={"alert_id": "A01"})
        self.assertEqual(status, 200)
        inc = data["incident_id"]
        self.assertEqual(data["report"]["severity"], "Critical")
        bad = self.req("POST", "/api/decide", body={"incident_id": inc, "step_id": "S5", "approved": True, "approver": "<x>"})
        self.assertEqual(bad[0], 400)
        not_bool = self.req("POST", "/api/decide", body={"incident_id": inc, "step_id": "S5", "approved": "yes", "approver": "Kritagya"})
        self.assertEqual(not_bool[0], 400)
        ok = self.req("POST", "/api/decide", body={"incident_id": inc, "step_id": "S5", "approved": True, "approver": "Kritagya"})
        self.assertEqual(ok[0], 200)
        steps = {s["step_id"]: s for s in ok[1]["report"]["containment_steps"]}
        self.assertEqual(steps["S5"]["approved_by"], "Kritagya")
        again = self.req("POST", "/api/decide", body={"incident_id": inc, "step_id": "S5", "approved": True, "approver": "Kritagya"})
        self.assertEqual(again[0], 409)
        listed = self.req("GET", "/api/incidents")[1]
        self.assertIn(inc, [x["incident_id"] for x in listed])
        self.assertEqual(self.req("GET", f"/api/incidents/{inc}")[0], 200)

    def test_path_traversal_ids_rejected(self):
        self.assertEqual(self.req("GET", "/api/incidents/..%2F..%2Fetc")[0], 404)
        status, _, _ = self.req("POST", "/api/decide", body={"incident_id": "../x", "step_id": "S1", "approved": True, "approver": "abc"})
        self.assertEqual(status, 400)

    def test_errors_do_not_leak_internals(self):
        status, data, _ = self.req("POST", "/api/run", body="{not json")
        self.assertEqual(status, 400)
        self.assertNotIn("Traceback", json.dumps(data))


if __name__ == "__main__":
    unittest.main()
