"""Web console for the Incident Response Playbook Runner.

    python webapp.py                 -> opens http://localhost:8000/#token=...

Standard library only. Runs the real multi-agent pipeline; destructive (and policy-gated)
steps are held until the analyst approves or rejects them in the browser.

Security model (local analyst console)
  * Binds to 127.0.0.1 by default.
  * Every /api/* call needs the per-launch console token (X-Console-Token header). The
    token is handed to the browser in the URL *fragment*, which is never sent to the
    server or written to access logs. Set IRP_CONSOLE_TOKEN to use a fixed token.
    This also defeats CSRF: other websites cannot read or attach the token.
  * Host header must be localhost/127.0.0.1 (blocks DNS-rebinding attacks).
  * POST bodies must be application/json (forces a CORS preflight, which is refused).
  * Request/alert size limits; strict CSP; frame-ancestors 'none' (no clickjacking).
  * Internal errors return an opaque error id; details go to the server log only.

API (all JSON, all require X-Console-Token except /api/health)
  GET  /api/health
  GET  /api/alerts                        the 10 synthetic alerts (+ ground truth)
  POST /api/run       {alert_id} | {raw}  run the pipeline -> report + timeline
  POST /api/decide    {incident_id, step_id, approved: bool, approver}
  GET  /api/incidents                     recent incidents (survives restarts)
  GET  /api/incidents/<id>                report + timeline of one incident
  GET  /api/intel/<TR-xxx>                full text of a threat report
  GET  /api/eval / POST /api/eval         last / fresh evaluation results
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from irp.config import SETTINGS
from irp.orchestrator import DATA, ROOT, PlaybookRunner
from irp.safety import HumanApprovalGate, validate_approver
from irp.timeline import new_incident_id, validate_incident_id

log = logging.getLogger("irp.web")
WEB = ROOT / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8")}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class ConsoleApp:
    """Application logic, independent of the HTTP layer (and unit-testable)."""

    def __init__(self, out_dir: Path, token: str):
        self.token = token
        self.alerts = json.loads((DATA / "synthetic_alerts.json").read_text(encoding="utf-8"))
        self.runner = PlaybookRunner(gate=HumanApprovalGate(mode="defer", approver="web-console"), out_dir=out_dir)
        self.lock = threading.Lock()   # the pipeline is cheap; serialise for simplicity

    @staticmethod
    def alert_summary(a: dict) -> dict:
        raw = a["raw"]
        if isinstance(raw, dict):
            title = raw.get("title") or raw.get("eventName") or "alert"
            source, vendor = raw.get("source", "?"), raw.get("vendor_severity")
        else:
            title = raw.split(";")[-1].strip().capitalize()
            source, vendor = "syslog", None
        return {"alert_id": a["alert_id"], "title": title, "source": source,
                "vendor_severity": vendor, "ground_truth": a["ground_truth"], "raw": raw}

    def run(self, body: dict) -> dict:
        if body.get("alert_id"):
            a = next((x for x in self.alerts if x["alert_id"] == body["alert_id"]), None)
            if not a:
                raise HttpError(404, "unknown alert")
            alert_id, raw = a["alert_id"], a["raw"]
        else:
            raw = body.get("raw")
            if not isinstance(raw, str) or not raw.strip():
                raise HttpError(400, "provide alert_id or a non-empty raw alert")
            if len(raw.encode()) > SETTINGS.max_alert_bytes:
                raise HttpError(413, f"alert larger than {SETTINGS.max_alert_bytes} bytes")
            alert_id, raw = "CUSTOM", raw.strip()
        incident_id = new_incident_id(alert_id)
        with self.lock:
            report, timeline = asyncio.run(self.runner.run_alert(incident_id, raw))
        return self._incident_payload(incident_id, report, timeline, alert_id)

    def decide(self, body: dict) -> dict:
        try:
            incident_id = validate_incident_id(body.get("incident_id", ""))
            approver = validate_approver(body.get("approver", ""))
        except ValueError as exc:
            raise HttpError(400, str(exc)) from exc
        step_id, approved = body.get("step_id"), body.get("approved")
        if not isinstance(step_id, str) or not isinstance(approved, bool):
            raise HttpError(400, "step_id (string) and approved (boolean) are required")
        with self.lock:
            try:
                report, timeline = asyncio.run(self.runner.resolve(incident_id, step_id, approved, approver))
            except KeyError as exc:
                raise HttpError(404, "unknown incident") from exc
            except ValueError as exc:
                raise HttpError(409, str(exc)) from exc
        log.info("decision incident=%s step=%s approved=%s approver=%s", incident_id, step_id, approved, approver)
        return self._incident_payload(incident_id, report, timeline)

    def incident(self, incident_id: str) -> dict:
        try:
            validate_incident_id(incident_id)
            session = self.runner.get_session(incident_id)
        except (ValueError, KeyError) as exc:
            raise HttpError(404, "unknown incident") from exc
        tl = session["timeline"]
        return self._incident_payload(incident_id, tl.latest("incident_report"), tl)

    @staticmethod
    def _incident_payload(incident_id, report, timeline, alert_id=None) -> dict:
        return {"incident_id": incident_id, "alert_id": alert_id or incident_id.split("-", 1)[0],
                "report": report, "timeline": timeline.all(),
                "escalated": timeline.latest("escalated_to_human")}

    def intel(self, doc_id: str) -> dict:
        doc = self.runner.index.docs.get(doc_id)
        if not doc:
            raise HttpError(404, "no such report")
        return {"doc_id": doc_id, "title": doc.title, "text": Path(doc.path).read_text(encoding="utf-8")}

    def eval_results(self, rerun: bool) -> dict | None:
        path = SETTINGS.output_dir / "eval_results.json"
        if rerun:
            import evaluate
            with self.lock:
                asyncio.run(evaluate.main())
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def make_handler(app: ConsoleApp, port: int):
    allowed_hosts = {f"localhost:{port}", f"127.0.0.1:{port}", f"[::1]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "PlaybookRunner"
        sys_version = ""

        def log_message(self, fmt, *args):   # routed through logging in _send instead
            pass

        # ------------------------------------------------------------ helpers
        def _send(self, status: int, body, ctype: str = "application/json; charset=utf-8") -> None:
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            log.info("%s %s %d %.0fms", self.command, self.path.split("?")[0], status,
                     (time.perf_counter() - self._t0) * 1000)

        def _guard(self, needs_token: bool) -> None:
            if self.headers.get("Host", "") not in allowed_hosts:
                raise HttpError(421, "unexpected Host header")
            if needs_token:
                supplied = self.headers.get("X-Console-Token", "")
                if not hmac.compare_digest(supplied.encode(), app.token.encode()):
                    raise HttpError(401, "missing or invalid console token")

        def _json_body(self) -> dict:
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                raise HttpError(415, "Content-Type must be application/json")
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise HttpError(400, "bad Content-Length")
            if n > SETTINGS.max_request_bytes:
                # Drain moderately oversized bodies so the client receives a clean 413 instead of a
                # connection reset; for absurd sizes just drop the connection after replying.
                if n <= 16 * SETTINGS.max_request_bytes:
                    self.rfile.read(n)
                self.close_connection = True
                raise HttpError(413, "request body too large")
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise HttpError(400, "body is not valid JSON")
            if not isinstance(body, dict):
                raise HttpError(400, "body must be a JSON object")
            return body

        def _dispatch(self, fn) -> None:
            self._t0 = time.perf_counter()
            try:
                fn()
            except HttpError as exc:
                self._send(exc.status, {"error": exc.message})
            except Exception:
                err = uuid.uuid4().hex[:8]
                log.exception("unhandled error %s on %s %s", err, self.command, self.path)
                self._send(500, {"error": f"internal error (id {err}); see server log"})

        # ------------------------------------------------------------- routes
        def do_GET(self):
            self._dispatch(self._get)

        def do_POST(self):
            self._dispatch(self._post)

        def _get(self):
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            if path in STATIC:
                self._guard(needs_token=False)
                fname, ctype = STATIC[path]
                return self._send(200, (WEB / fname).read_bytes(), ctype)
            if path == "/api/health":
                self._guard(needs_token=False)
                return self._send(200, {"status": "ok"})
            if not path.startswith("/api/"):
                raise HttpError(404, "not found")
            self._guard(needs_token=True)
            if path == "/api/alerts":
                return self._send(200, [app.alert_summary(a) for a in app.alerts])
            if path == "/api/incidents":
                return self._send(200, app.runner.list_incidents())
            if path.startswith("/api/incidents/"):
                return self._send(200, app.incident(path.rsplit("/", 1)[1]))
            if path.startswith("/api/intel/"):
                return self._send(200, app.intel(path.rsplit("/", 1)[1]))
            if path == "/api/eval":
                return self._send(200, app.eval_results(rerun=False))
            raise HttpError(404, "not found")

        def _post(self):
            path = self.path.split("?", 1)[0]
            self._guard(needs_token=True)
            body = self._json_body()
            if path == "/api/run":
                return self._send(200, app.run(body))
            if path == "/api/decide":
                return self._send(200, app.decide(body))
            if path == "/api/eval":
                return self._send(200, app.eval_results(rerun=True))
            raise HttpError(404, "not found")

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description="Incident Response Playbook Runner web console")
    ap.add_argument("--port", type=int, default=int(os.getenv("IRP_PORT", 8000)))
    ap.add_argument("--host", default=os.getenv("IRP_HOST", "127.0.0.1"))
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=os.getenv("IRP_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if not ipaddress.ip_address(args.host if args.host != "localhost" else "127.0.0.1").is_loopback:
        log.warning("binding to non-loopback address %s: the console will be reachable from the network", args.host)
    token = os.getenv("IRP_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
    app = ConsoleApp(SETTINGS.output_dir / "web", token)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(app, args.port))
    url = f"http://localhost:{args.port}/#token={token}"
    print(f"\nIncident Response console: {url}\n(open this exact link; Ctrl+C to stop)\n", flush=True)
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
