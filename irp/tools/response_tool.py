"""Mock response tool (EDR / firewall / IAM / cloud actions), exposed as an SK plugin.

Nothing real is touched: each call is recorded in an execution log and returns a
simulated result. Every call passes through the SafetyGuard first, so a destructive
action without a valid human-approval token is refused here regardless of which agent
called it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated

from semantic_kernel.functions import kernel_function

from ..safety import SafetyGuard, is_destructive

_RESULT_TEXT = {
    "snapshot_host": "memory + disk snapshot stored in evidence vault",
    "snapshot_cloudtrail": "CloudTrail export written to evidence bucket",
    "capture_pcap": "packet capture running (60 min)",
    "isolate_host": "host network-isolated via EDR",
    "disable_account": "account disabled in directory",
    "block_hash": "hash added to EDR blocklist",
    "block_ip": "address added to perimeter deny list",
    "block_domain": "domain sinkholed in DNS / blocked at proxy",
    "reset_credentials": "password reset forced",
    "revoke_sessions": "sessions and refresh tokens revoked",
    "disable_access_key": "access key deactivated",
    "quarantine_file": "file quarantined",
    "block_usb": "device-control policy applied",
    "wipe_and_reimage": "host wiped and reimaged from golden image",
    "terminate_instances": "attacker instances terminated",
    "shutdown_service": "service stopped",
    "purge_emails": "matching messages purged from all mailboxes",
}


class MockResponsePlugin:
    def __init__(self, guard: SafetyGuard):
        self.guard = guard
        self.execution_log: list[dict] = []

    @kernel_function(name="execute_action", description="Execute a containment action against a target.")
    def execute_action(
        self,
        incident_id: Annotated[str, "Incident id"],
        step_id: Annotated[str, "Plan step id"],
        action: Annotated[str, "Action name"],
        target: Annotated[str, "Target entity"],
        approval_token: Annotated[str, "Human approval token for destructive actions"] = "",
    ) -> str:
        allowed, reason = self.guard.check(incident_id, step_id, action, target, approval_token)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "incident_id": incident_id, "step_id": step_id, "action": action, "target": target,
            "destructive": is_destructive(action), "executed": allowed, "guard_reason": reason,
        }
        if allowed:
            record["result"] = f"[SIMULATED] {_RESULT_TEXT.get(action, 'action completed')} ({target})"
        else:
            record["result"] = f"BLOCKED by safety guard: {reason}"
        self.execution_log.append(record)
        return json.dumps(record)
