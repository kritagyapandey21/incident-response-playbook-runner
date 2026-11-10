"""Threat-intel search tool (RAG retriever) exposed as a Semantic Kernel plugin."""
from __future__ import annotations

import json
from typing import Annotated

from semantic_kernel.functions import kernel_function

from ..rag import ThreatReportIndex


class ThreatIntelPlugin:
    def __init__(self, index: ThreatReportIndex):
        self.index = index

    @kernel_function(name="search_reports", description="Retrieve the threat reports most relevant to a query.")
    def search_reports(self, query: Annotated[str, "Free-text query"], top_k: Annotated[int, "Results"] = 3) -> str:
        return json.dumps(self.index.search(query, top_k=top_k))

    @kernel_function(name="get_containment", description="Get the recommended containment section of a report.")
    def get_containment(self, doc_id: Annotated[str, "Report id, e.g. TR-001"]) -> str:
        doc = self.index.docs.get(doc_id)
        if not doc:
            return json.dumps(None)
        return json.dumps({"doc_id": doc.doc_id, "title": doc.title, "steps": doc.containment})
