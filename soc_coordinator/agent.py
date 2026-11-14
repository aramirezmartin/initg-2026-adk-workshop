"""Self-contained root SOC Coordinator for `adk web`."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.models import LlmRequest
from google.adk.planners import BuiltInPlanner
from google.genai import types
import httpx

load_dotenv()

SPECIALIST_CARDS = {
    "deobfuscator_agent": (
        "http://localhost:8001/.well-known/agent-card.json",
        "Deobfuscates suspicious scripts in an isolated Python sandbox.",
    ),
    "vt_intel_agent": (
        "http://localhost:8002/.well-known/agent-card.json",
        "Queries VirusTotal MCP (ai.virustotal.com/mcp) for IOC reputation.",
    ),
    "secops_auditor_agent": (
        "http://localhost:8003/.well-known/agent-card.json",
        "Audits SKILL.md packages, WAF logs, and enforces SSRF guardrails.",
    ),
}


def decode_inline_attachments(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> None:
    """Converts binary `adk web` file uploads (e.g. .js/.b64/.log) into readable text."""
    del callback_context
    for content in llm_request.contents or []:
        for idx, part in enumerate(content.parts or []):
            inline = getattr(part, "inline_data", None)
            if not inline or not getattr(inline, "data", None):
                continue
            mime = (getattr(inline, "mime_type", "") or "").lower()
            if mime.startswith("image/") or mime.startswith("audio/") or mime.startswith("video/"):
                continue
            raw: bytes = inline.data
            sha256 = hashlib.sha256(raw).hexdigest()
            decoded = raw.decode("utf-8", errors="replace")
            content.parts[idx] = types.Part(
                text=(
                    f"[Attached File ({mime or 'application/octet-stream'}, "
                    f"{len(raw)} bytes, sha256={sha256})]\n"
                    f"```\n{decoded}\n```"
                )
            )


def discover_a2a_subagents(timeout: float = 1.0) -> list[RemoteA2aAgent]:
    """Probes specialist A2A cards and wraps every online agent as a RemoteA2aAgent."""
    discovered: list[RemoteA2aAgent] = []
    for name, (url, desc) in SPECIALIST_CARDS.items():
        try:
            resp = httpx.get(url, timeout=timeout)
            if resp.status_code == 200:
                discovered.append(
                    RemoteA2aAgent(name=name, description=desc, agent_card=url)
                )
        except httpx.RequestError:
            continue
    return discovered


_subagents: list[Any] = discover_a2a_subagents()

root_agent = LlmAgent(
    name="soc_coordinator",
    model=os.getenv("ADK_MODEL", "gemini-4-hydrogen"),
    description="Root SOC coordinator delegating tasks to A2A specialist agents.",
    instruction=(
        "You are soc_coordinator, leading an A2A security investigation team.\n"
        + (
            "Delegate sandbox deobfuscation to deobfuscator_agent, threat lookups to "
            "vt_intel_agent, and skill/WAF audits to secops_auditor_agent. "
            "When the user attaches a file, pass its full content or extracted indicators "
            "to the appropriate specialist."
            if _subagents
            else "No A2A specialist servers are online right now. Tell the user to run `make start` first."
        )
    ),
    before_model_callback=decode_inline_attachments,
    sub_agents=_subagents,
    # planner=BuiltInPlanner(thinking_config=types.ThinkingConfig(include_thoughts=True, thinking_level=types.ThinkingLevel.HIGH))
)
