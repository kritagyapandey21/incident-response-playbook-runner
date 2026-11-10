"""Threat Intel Retrieval Agent: RAG over the threat-report set."""
from __future__ import annotations

import os
from typing import Any

from ..config import SETTINGS
from .base import BaseAgent


class ThreatIntelRetrievalAgent(BaseAgent):
    name = "ThreatIntelRetrievalAgent"

    async def run(self, broaden: bool = False, **_: Any) -> dict:
        inc = self.timeline.latest("incident_record_created")
        parts = [inc["title"], inc["description"], inc["source"]]
        parts += inc["domains"] + inc["hashes"] + inc["external_ips"] + inc["email_senders"]
        parts += [os.path.basename(f.replace("\\", "/")) for f in inc["files"]]
        if broaden:
            # second attempt: add the raw alert text and look further down the ranking
            parts.append(str(self.timeline.latest("alert_received")["raw"]))
        query = " ".join(p for p in parts if p)[: SETTINGS.max_alert_bytes]

        hits = await self.call_tool("threat_intel", "search_reports", query=query, top_k=5 if broaden else 3)
        hits = [h for h in hits if h["score"] > 0]
        primary = hits[0] if hits else None
        margin = round(hits[0]["score"] - hits[1]["score"], 4) if len(hits) > 1 else None
        if not primary or primary["score"] < SETTINGS.low_confidence_score:
            confidence = "low"
        elif margin is not None and margin < SETTINGS.ambiguous_margin:
            confidence = "medium"
        else:
            confidence = "high"

        out = {
            "query": query,
            "primary": primary,
            "candidates": hits,
            "confidence": confidence,
            "margin_over_next": margin,
            "broadened": broaden,
        }
        self.log("intel_retrieved", out)
        return out
