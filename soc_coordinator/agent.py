"""Self-contained root SOC Coordinator for `adk web`.

Discovers online A2A specialist agents (`:8001`–`:8003`), converts binary
`adk web` file uploads into readable UTF-8 parts before model invocation, and
exposes `root_agent` for ADK Web UI.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.models import LlmRequest
from google.adk.planners import BuiltInPlanner
from google.adk.tools.agent_tool import AgentTool
from google.genai import types
import httpx

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
DEFAULT_MODEL = os.getenv("ADK_MODEL", "gemini-4-hydrogen")
_MEDIA_PREFIXES: tuple[str, ...] = ("image/", "audio/", "video/")


@dataclass(frozen=True, slots=True)
class SpecialistEndpoint:
    """Static A2A registration metadata for a remote specialist agent."""

    name: str
    card_url: str
    description: str


SPECIALIST_ENDPOINTS: tuple[SpecialistEndpoint, ...] = (
    SpecialistEndpoint(
        name="deobfuscator_agent",
        card_url="http://localhost:8001/.well-known/agent-card.json",
        description="Deobfuscates suspicious scripts in a local Python subprocess.",
    ),
    SpecialistEndpoint(
        name="vt_intel_agent",
        card_url="http://localhost:8002/.well-known/agent-card.json",
        description="Queries VirusTotal MCP (ai.virustotal.com/mcp) for IOC reputation.",
    ),
    SpecialistEndpoint(
        name="secops_auditor_agent",
        card_url="http://localhost:8003/.well-known/agent-card.json",
        description="Audits SKILL.md packages, WAF logs, and enforces SSRF guardrails.",
    ),
)


def _format_attachment_part(raw: bytes, mime_type: str) -> types.Part:
    """Decode raw attachment bytes into a fenced UTF-8 text part with SHA-256."""
    sha256 = hashlib.sha256(raw).hexdigest()
    decoded = raw.decode("utf-8", errors="replace")
    label = mime_type or "application/octet-stream"
    return types.Part(
        text=(
            f"[Attached File ({label}, {len(raw)} bytes, sha256={sha256})]\n"
            f"```\n{decoded}\n```"
        )
    )


def decode_inline_attachments(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> None:
    """Convert binary `adk web` file uploads (`.js`, `.b64`, `.log`) into text.

    Args:
        callback_context: ADK callback context (unused).
        llm_request: Outgoing model request whose `inline_data` parts are rewritten.
    """
    del callback_context
    for content in llm_request.contents or []:
        parts = content.parts or []
        for idx, part in enumerate(parts):
            inline = getattr(part, "inline_data", None)
            raw: bytes | None = getattr(inline, "data", None) if inline else None
            if not raw:
                continue
            mime = (getattr(inline, "mime_type", "") or "").lower()
            if mime.startswith(_MEDIA_PREFIXES):
                continue
            parts[idx] = _format_attachment_part(raw, mime)


def discover_a2a_subagents(timeout: float = 1.0) -> list[RemoteA2aAgent]:
    """Probe specialist A2A agent cards and wrap online agents as `RemoteA2aAgent`.

    Args:
        timeout: HTTP GET timeout in seconds per specialist endpoint.

    Returns:
        List of reachable `RemoteA2aAgent` instances ready for delegation.
    """
    discovered: list[RemoteA2aAgent] = []
    for spec in SPECIALIST_ENDPOINTS:
        try:
            resp = httpx.get(spec.card_url, timeout=timeout)
        except httpx.RequestError:
            continue
        if resp.status_code == 200:
            discovered.append(
                RemoteA2aAgent(
                    name=spec.name,
                    description=spec.description,
                    agent_card=spec.card_url,
                )
            )
    return discovered


def list_samples() -> list[str]:
    """List all artifact file paths available under `samples/`.

    Returns:
        Sorted list of relative file paths inside `samples/`.
    """
    if not SAMPLES_DIR.is_dir():
        return []
    return sorted(
        str(path.relative_to(SAMPLES_DIR))
        for path in SAMPLES_DIR.rglob("*")
        if path.is_file()
    )


def _build_coordinator_instruction(subagents: list[Any]) -> str:
    """Build the coordinator system instruction based on discovered specialists."""
    header = "You are soc_coordinator, leading an A2A security investigation team.\n"
    if not subagents:
        return (
            f"{header}No A2A specialist servers are online right now. "
            "Tell the user to run `soc-start` first."
        )
    return (
        f"{header}"
        "Use `list_samples` to discover files in `samples/` when investigating the workspace. "
        "Orchestrate your A2A specialist tools (`deobfuscator_agent` for script deobfuscation, "
        "`secops_auditor_agent` for SKILL.md/WAF/advisory audits, and `vt_intel_agent` for "
        "VirusTotal enrichment of all extracted IPs, domains, and hashes), then synthesize a "
        "single executive incident report."
    )


_SAFETY_CONFIG = types.GenerateContentConfig(
    safety_settings=[
        types.SafetySetting(category=category, threshold=types.HarmBlockThreshold.OFF)
        for category in (
            types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            types.HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY,
        )
    ]
)

_subagents: list[Any] = discover_a2a_subagents()

root_agent = LlmAgent(
    name="soc_coordinator",
    model=DEFAULT_MODEL,
    description="Root SOC coordinator orchestrating A2A specialist agents.",
    instruction=_build_coordinator_instruction(_subagents),
    generate_content_config=_SAFETY_CONFIG,
    planner=BuiltInPlanner(
        thinking_config=types.ThinkingConfig(
            include_thoughts=True,
            thinking_level=types.ThinkingLevel.MEDIUM,
        )
    ),
    before_model_callback=decode_inline_attachments,
    tools=[list_samples, *(AgentTool(agent=sa) for sa in _subagents)],
)
