"""Safety guard: destructive containment steps cannot run without human approval.

Two independent layers enforce this:

1. ``HumanApprovalGate`` is the only component that can mint approval tokens. A token is
   ``<issued_at>.<hmac>`` where the HMAC covers (incident, step, action, target, issued_at)
   and is keyed with a secret only the gate holds. Tokens are single-use and expire
   after ``approval_token_ttl_s``.
2. ``SafetyGuard`` sits inside the response tool. Before any destructive action runs it
   verifies the token with the gate. An agent that skips approval, forges a token,
   replays one for another host/action, reuses one, or uses an expired one is refused
   at the tool itself, regardless of what the calling agent believes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .config import SETTINGS
from .timeline import IncidentTimeline

# Actions that destroy data or take production services offline.
DESTRUCTIVE_ACTIONS = frozenset({
    "wipe_and_reimage",
    "terminate_instances",
    "shutdown_service",
    "purge_emails",
})
APPROVER_RE = re.compile(r"^[\w.@\- ]{2,64}$")


def is_destructive(action: str) -> bool:
    return action in DESTRUCTIVE_ACTIONS


def validate_approver(approver: str) -> str:
    approver = (approver or "").strip()
    if not APPROVER_RE.match(approver):
        raise ValueError("approver must be 2-64 characters (letters, digits, space, . _ @ -)")
    return approver


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    approver: str
    reason: str
    token: str | None
    decided_at: str


class HumanApprovalGate:
    """Human-in-the-loop approval for destructive (or policy-gated) steps.

    mode:
      "cli"      ask the analyst on the terminal
      "deny"     simulated analyst who rejects every step (safe default)
      "approve"  simulated analyst who approves every step (tests only)
      "defer"    hold the step; a human decides later via decide() (web console)
      callable   custom decider(step_dict) -> (approved: bool, reason: str)
    """

    def __init__(self, mode: str | Callable = "deny", approver: str = "soc-analyst",
                 ttl_s: int | None = None, clock: Callable[[], float] = time.time):
        self.mode = mode
        self.approver = validate_approver(approver)
        self.ttl_s = SETTINGS.approval_token_ttl_s if ttl_s is None else ttl_s
        self._clock = clock
        self._secret = os.urandom(32)
        self._used: dict[str, float] = {}   # token -> expiry (pruned once expired)
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- tokens
    def _mac(self, incident_id: str, step_id: str, action: str, target: str, issued_at: int) -> str:
        msg = "\x1f".join([incident_id, step_id, action, target, str(issued_at)]).encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _mint(self, incident_id: str, step_id: str, action: str, target: str) -> str:
        issued_at = int(self._clock())
        return f"{issued_at}.{self._mac(incident_id, step_id, action, target, issued_at)}"

    def verify_and_consume(self, token: str, incident_id: str, step_id: str, action: str, target: str) -> tuple[bool, str]:
        if not token:
            return False, "no approval token"
        issued_str, _, mac = token.partition(".")
        if not issued_str.isdigit() or not mac:
            return False, "malformed approval token"
        issued_at = int(issued_str)
        expected = self._mac(incident_id, step_id, action, target, issued_at)
        if not hmac.compare_digest(mac, expected):
            return False, "token does not match this incident/step/action/target"
        now = self._clock()
        if now - issued_at > self.ttl_s:
            return False, "approval token expired"
        with self._lock:
            self._used = {t: exp for t, exp in self._used.items() if exp > now}   # prune
            if token in self._used:
                return False, "token already used"
            self._used[token] = issued_at + self.ttl_s
        return True, "valid human approval"

    # -------------------------------------------------------------- decisions
    def request(self, timeline: IncidentTimeline, step: dict, why: str = "destructive action") -> ApprovalDecision:
        timeline.write("HumanApprovalGate", "approval_requested", {
            "step_id": step["step_id"], "action": step["action"], "target": step["target"],
            "description": step["description"], "citation": step["citation"]["doc_id"], "why": why,
        })
        if callable(self.mode):
            approved, reason = self.mode(step)
        elif self.mode == "cli":
            print("\n" + "!" * 72)
            print(f"  HUMAN APPROVAL REQUIRED  [{timeline.incident_id} / {step['step_id']}]  ({why})")
            print(f"  Action       : {step['action']} -> {step['target']}")
            print(f"  Description  : {step['description']}")
            print(f"  Intel source : {step['citation']['doc_id']} ({step['citation'].get('title', '')})")
            print("!" * 72)
            try:
                answer = input("  Approve this step? [y/N]: ").strip().lower()
            except EOFError:
                answer = ""
            approved = answer in ("y", "yes")
            reason = "approved at console" if approved else "rejected at console"
        elif self.mode == "approve":
            approved, reason = True, "simulated analyst approval"
        elif self.mode == "defer":
            return ApprovalDecision(False, self.approver, "awaiting analyst decision in web console",
                                    None, datetime.now(timezone.utc).isoformat())
        else:
            approved, reason = False, "simulated analyst rejection (default deny)"
        return self.decide(timeline, step, approved, self.approver, reason)

    def decide(self, timeline: IncidentTimeline, step: dict, approved: bool,
               approver: str, reason: str) -> ApprovalDecision:
        """Record a human decision; mint a single-use, time-limited token only if approved."""
        approver = validate_approver(approver)
        token = self._mint(timeline.incident_id, step["step_id"], step["action"], step["target"]) if approved else None
        decision = ApprovalDecision(approved, approver, reason, token, datetime.now(timezone.utc).isoformat())
        timeline.write("HumanApprovalGate", "approval_decision", {
            "step_id": step["step_id"], "action": step["action"], "target": step["target"],
            "approved": approved, "approver": approver, "reason": reason,
        })
        return decision


class SafetyGuard:
    def __init__(self, gate: HumanApprovalGate):
        self.gate = gate

    def check(self, incident_id: str, step_id: str, action: str, target: str, token: str | None) -> tuple[bool, str]:
        if not is_destructive(action):
            return True, "non-destructive action"
        return self.gate.verify_and_consume(token or "", incident_id, step_id, action, target)
