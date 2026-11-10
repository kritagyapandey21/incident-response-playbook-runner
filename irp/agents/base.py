"""Common base for all agents: Semantic Kernel tool calls, shared-timeline access, LLM reasoning."""
from __future__ import annotations

import json
from typing import Any

from semantic_kernel import Kernel
from semantic_kernel.functions import KernelArguments

from ..timeline import IncidentTimeline


class BaseAgent:
    name = "BaseAgent"

    def __init__(self, kernel: Kernel, timeline: IncidentTimeline, llm=None):
        self.kernel = kernel
        self.timeline = timeline
        self.llm = llm          # irp.llm.LLMClient or None (deterministic mode)

    async def call_tool(self, plugin: str, function: str, **kwargs: Any) -> Any:
        """Invoke a tool registered on the Semantic Kernel and decode its JSON result."""
        result = await self.kernel.invoke(
            plugin_name=plugin, function_name=function, arguments=KernelArguments(**kwargs)
        )
        safe_args = {k: v for k, v in kwargs.items() if k != "approval_token"}
        if "approval_token" in kwargs:
            safe_args["approval_token"] = "<present>" if kwargs["approval_token"] else "<none>"
        self.timeline.write(self.name, "tool_call", {"tool": f"{plugin}.{function}", "args": safe_args})
        return json.loads(str(result.value))

    async def think(self, purpose: str, instructions: str, prompt: str) -> dict | None:
        """Ask the LLM for a JSON answer. Returns None in deterministic mode or on any failure."""
        if self.llm is None:
            return None
        return await self.llm.complete_json(self.name, purpose, instructions, prompt, self.timeline)

    def log(self, event: str, data: Any = None) -> None:
        self.timeline.write(self.name, event, data)

    async def run(self, **params: Any) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError


def clean_str(value: Any, limit: int = 600) -> str | None:
    """Normalise an LLM-produced string field (or reject non-strings)."""
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    return value[:limit] or None
