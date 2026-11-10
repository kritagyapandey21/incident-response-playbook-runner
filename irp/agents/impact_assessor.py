"""Impact Assessor Agent: maps affected assets via the asset-inventory tool and scores severity.

Severity score = base severity of the matched threat report (from RAG)
               + asset modifier  (+1 if any directly affected asset is high/critical,
                                  -1 if all are low, else 0)
               + signal modifier (+1 if the alert shows the attack succeeded,
                                  -1 if it was blocked/failed, else 0)
Mapped: <=1 Low, 2 Medium, 3 High, >=4 Critical.
"""
from __future__ import annotations

from typing import Any

from ..models import SEVERITY_LEVELS
from .base import BaseAgent

CRIT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def score_to_severity(score: int) -> str:
    if score <= 1:
        return "Low"
    return SEVERITY_LEVELS[min(score, 4) - 1]


class ImpactAssessorAgent(BaseAgent):
    name = "ImpactAssessorAgent"

    async def run(self, **_: Any) -> dict:
        inc = self.timeline.latest("incident_record_created")
        intel = self.timeline.latest("intel_retrieved")

        affected: dict[str, dict] = {}
        at_risk: dict[str, dict] = {}
        owned_ips: list[str] = []

        def add(store: dict, asset: dict, kind: str, reason: str) -> None:
            if asset and asset["asset_id"] not in affected:
                store.setdefault(asset["asset_id"], {
                    "asset_id": asset["asset_id"], "kind": kind,
                    "criticality": asset.get("criticality", "medium"),
                    "description": asset.get("type") or asset.get("role") or asset.get("name"),
                    "reason": reason,
                })

        for h in inc["hosts"]:
            add(affected, await self.call_tool("assets", "lookup_host", hostname=h), "host", "named in alert")
        for ip in inc["ips"]:
            host = await self.call_tool("assets", "lookup_ip", ip=ip)
            if host:
                owned_ips.append(ip)
                add(affected, host, "host", f"owns IP {ip}")
        for u in inc["users"]:
            add(affected, await self.call_tool("assets", "lookup_user", user=u), "identity", "named in alert")
        for ident in inc["cloud_keys"] + inc["cloud_accounts"]:
            acct = await self.call_tool("assets", "lookup_cloud", identifier=ident)
            if acct:
                add(affected, acct, "cloud_account", f"matched {ident}")
                if acct.get("matched_key_identity"):
                    user = await self.call_tool("assets", "lookup_user", user=acct["matched_key_identity"])
                    add(affected, user, "identity", f"owner of access key {ident}")

        # Second-order exposure: dependencies and owners of directly affected hosts
        for a in list(affected.values()):
            if a["kind"] != "host":
                continue
            host = await self.call_tool("assets", "lookup_host", hostname=a["asset_id"])
            for dep in host.get("depends_on", []):
                add(at_risk, await self.call_tool("assets", "lookup_host", hostname=dep), "host",
                    f"{a['asset_id']} depends on it")
            if host.get("owner"):
                owner = await self.call_tool("assets", "lookup_user", user=host["owner"])
                add(at_risk, owner, "identity", f"primary user of {a['asset_id']}")

        # ---- severity scoring
        # No intel match -> assume Medium-equivalent base so the incident is not under-rated.
        base = intel["primary"]["base_severity"] if intel and intel["primary"] else 2
        crits = [CRIT_RANK.get(a["criticality"], 1) for a in affected.values()]
        if crits and max(crits) >= 2:
            asset_mod = 1
        elif crits and max(crits) == 0:
            asset_mod = -1
        else:
            asset_mod = 0
        signal_mod = {"confirmed": 1, "blocked": -1}.get(inc["status_signal"], 0)
        score = base + asset_mod + signal_mod
        severity = score_to_severity(score)

        out = {
            "affected_assets": list(affected.values()),
            "at_risk_assets": list(at_risk.values()),
            "owned_ips": owned_ips,
            "severity": severity,
            "severity_score": score,
            "severity_rationale": (
                f"base {base} from {intel['primary']['doc_id'] if intel and intel['primary'] else 'n/a'}"
                f" {asset_mod:+d} asset criticality {signal_mod:+d} signal ({inc['status_signal']}) = {score}"
            ),
        }
        self.log("impact_assessed", out)
        return out
