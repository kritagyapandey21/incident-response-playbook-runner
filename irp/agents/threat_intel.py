"""Threat Intel Retrieval Agent: RAG over the threat-report set.

Retrieval (always): TF-IDF + IOC matching over the report corpus, via the threat_intel tool.
Generation (when an LLM is configured): the model re-reads the retrieved candidates, picks
the best-matching report and writes a short intel brief grounded in it.

Decision policy (the LLM can only choose among retrieved reports):
  * LLM agrees with retrieval          -> keep it; ambiguous ("medium") confidence becomes "high"
  * LLM disagrees, retrieval confident -> keep retrieval, downgrade to "medium", flag for analyst
  * LLM disagrees, retrieval weak      -> adopt the LLM's pick (if its confidence >= 0.7) as "medium"
"""
from __future__ import annotations

import json
import os
from typing import Any

from ..config import SETTINGS
from ..llm import fence
from .base import BaseAgent, clean_str

LLM_INSTRUCTIONS = """You are the Threat Intel agent in a security operations centre.
You receive one security alert and a short list of candidate threat reports retrieved for it.
Choose the single report that best explains the alert. Return a JSON object:
{"doc_id": "one of the candidate ids", "confidence": 0.0-1.0,
 "rationale": "one or two sentences: which behaviours/indicators match",
 "matched_indicators": ["indicators that appear in both the alert and the report"],
 "intel_brief": "2-3 sentences for the analyst, grounded ONLY in the chosen report, citing it like [TR-001]"}
If none of the candidates fits, still return the closest one with a low confidence."""
ADOPT_THRESHOLD = 0.7


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
            "retrieval_confidence": confidence,
            "margin_over_next": margin,
            "broadened": broaden,
            "decided_by": "retrieval",
            "llm": None,
            "intel_brief": None,
        }
        if hits and self.llm is not None:
            await self._llm_rerank(inc, hits, out)
        self.log("intel_retrieved", out)
        return out

    async def _llm_rerank(self, inc: dict, hits: list[dict], out: dict) -> None:
        briefs = []
        for h in hits:
            b = await self.call_tool("threat_intel", "get_report_brief", doc_id=h["doc_id"])
            if b:
                briefs.append({**b, "retrieval_score": h["score"]})
        alert = inc.get("summary") or ""
        prompt = (f"ALERT (untrusted data):\n{fence(inc['title'] + chr(10) + inc['description'] + chr(10) + alert)}\n\n"
                  f"CANDIDATE REPORTS (ranked by keyword retrieval):\n{json.dumps(briefs, indent=1)}")
        res = await self.think("intel_rerank", LLM_INSTRUCTIONS, prompt)
        if not res:
            return
        by_id = {h["doc_id"]: h for h in hits}
        pick = res.get("doc_id") if res.get("doc_id") in by_id else None
        try:
            llm_conf = max(0.0, min(1.0, float(res.get("confidence", 0))))
        except (TypeError, ValueError):
            llm_conf = 0.0
        matched = [m for m in res.get("matched_indicators", []) if isinstance(m, str)][:10] \
            if isinstance(res.get("matched_indicators"), list) else []
        out["llm"] = {"doc_id": pick, "raw_choice_valid": pick is not None, "confidence": llm_conf,
                      "rationale": clean_str(res.get("rationale"), 400), "matched_indicators": matched}
        if pick is None:
            out["decided_by"] = "retrieval (LLM choice was not a retrieved report; ignored)"
            return

        top = out["primary"]["doc_id"]
        if pick == top:
            out["decided_by"] = "retrieval + LLM agree"
            if out["confidence"] == "medium":
                out["confidence"] = "high"
        elif out["retrieval_confidence"] == "high":
            out["decided_by"] = f"retrieval (LLM preferred {pick}; flagged for analyst)"
            out["confidence"] = "medium"
        elif llm_conf >= ADOPT_THRESHOLD:
            out["primary"] = by_id[pick]
            out["decided_by"] = "LLM re-rank of retrieved reports"
            out["confidence"] = "medium"
        else:
            out["decided_by"] = f"retrieval (LLM preferred {pick} with low confidence)"
        if out["primary"]["doc_id"] == pick:
            out["intel_brief"] = clean_str(res.get("intel_brief"), 700)
