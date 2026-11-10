"""Optional LLM backing for agents (Semantic Kernel chat-completion service).

The playbook runner is fully deterministic without an LLM, which keeps the evaluation
reproducible. If credentials are present in the environment, the Incident Commander
additionally uses a Semantic Kernel ChatCompletionAgent to write an executive summary.

Supported environment variables (first match wins):
  AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_CHAT_DEPLOYMENT_NAME
  OPENAI_API_KEY [, OPENAI_CHAT_MODEL_ID]          (default model gpt-4o-mini)
  ANTHROPIC_API_KEY [, ANTHROPIC_CHAT_MODEL_ID]    (needs `pip install anthropic`)
"""
from __future__ import annotations

import os


def build_chat_service():
    try:
        if os.getenv("AZURE_OPENAI_ENDPOINT") and os.getenv("AZURE_OPENAI_API_KEY"):
            from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
            return AzureChatCompletion(
                deployment_name=os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME", "gpt-4o-mini"),
                endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
                api_key=os.environ["AZURE_OPENAI_API_KEY"],
            )
        if os.getenv("OPENAI_API_KEY"):
            from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
            return OpenAIChatCompletion(ai_model_id=os.getenv("OPENAI_CHAT_MODEL_ID", "gpt-4o-mini"))
        if os.getenv("ANTHROPIC_API_KEY"):
            from semantic_kernel.connectors.ai.anthropic import AnthropicChatCompletion
            return AnthropicChatCompletion(ai_model_id=os.getenv("ANTHROPIC_CHAT_MODEL_ID", "claude-sonnet-5-5"))
    except Exception as exc:  # missing optional package or bad config -> run without LLM
        print(f"[llm] chat service unavailable ({exc}); continuing in deterministic mode")
    return None


async def summarise(service, prompt: str) -> str | None:
    if service is None:
        return None
    try:
        from semantic_kernel.agents import ChatCompletionAgent
        agent = ChatCompletionAgent(
            service=service,
            name="IncidentCommanderSummary",
            instructions=(
                "You are an incident commander. Write a 4-6 sentence executive summary of the "
                "incident for a CISO. Use only the facts given. Mention severity, affected "
                "assets, what was executed and what is waiting for human approval."
            ),
        )
        response = await agent.get_response(messages=prompt)
        return str(response.content)
    except Exception as exc:
        return f"(LLM summary failed: {exc})"
