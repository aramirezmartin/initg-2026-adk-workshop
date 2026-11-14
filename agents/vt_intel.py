"""Self-contained VirusTotal MCP A2A specialist server (port 8002).

Connects to the remote VirusTotal MCP endpoint (`https://ai.virustotal.com/mcp`)
and enforces a `before_tool_callback` guardrail that blocks active public
submissions unless explicitly authorized in session state.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.tools import BaseTool, ToolContext
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from pydantic import BaseModel, ConfigDict
import uvicorn

load_dotenv()

DEFAULT_MODEL = os.getenv("ADK_MODEL", "gemini-4-hydrogen")
A2A_HOST = "localhost"
A2A_PORT = 8002
VT_MCP_URL = "https://ai.virustotal.com/mcp"
VT_MCP_TIMEOUT_S = 20.0
VT_TOKEN_FILE = Path.home() / ".config" / "vt-mcp" / "token"

_BLOCKED_SUBMISSION_TOOLS = frozenset({
    "submit_file",
    "submit_attachment",
    "submit_url",
    "reanalyze_domain",
    "reanalyze_ip",
})


class VtGuardrailBlock(BaseModel):
    """Payload returned when the VT guardrail blocks an active submission."""

    model_config = ConfigDict(frozen=True)

    status: Literal["blocked_by_guardrail"] = "blocked_by_guardrail"
    blocked_tool: str
    reason: str


def _resolve_vt_headers() -> dict[str, str]:
    """Resolve VirusTotal MCP auth headers from env vars or local token file."""
    if os.getenv("VT_MCP_OFFLINE", "").lower() == "true":
        return {}
    if token := os.getenv("VTAI_AGENT_TOKEN", "").strip():
        return {"Authorization": f"Bearer {token}"}
    if VT_TOKEN_FILE.is_file() and (token := VT_TOKEN_FILE.read_text(encoding="utf-8").strip()):
        return {"Authorization": f"Bearer {token}"}
    if api_key := os.getenv("VT_API_KEY", "").strip():
        return {"x-apikey": api_key}
    return {}


def _build_vt_mcp_toolset() -> McpToolset | None:
    """Create the VirusTotal `McpToolset` when credentials are available."""
    headers = _resolve_vt_headers()
    if not headers:
        return None
    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=VT_MCP_URL,
            headers=headers,
            timeout=VT_MCP_TIMEOUT_S,
        )
    )


def guard_vt_public_submissions(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
) -> dict[str, Any] | None:
    """Block active VirusTotal submission tools unless explicitly opted in.

    Args:
        tool: Tool about to be executed by ADK.
        args: Arguments supplied by the model for the tool call.
        tool_context: ADK tool execution context carrying session state.

    Returns:
        Serialized `VtGuardrailBlock` dict to short-circuit the call, or `None` to allow.
    """
    del args
    if tool.name in _BLOCKED_SUBMISSION_TOOLS and not tool_context.state.get("allow_public_vt_submission"):
        return VtGuardrailBlock(
            blocked_tool=tool.name,
            reason="Public VT submissions require state['allow_public_vt_submission']=True.",
        ).model_dump()
    return None


vt_mcp = _build_vt_mcp_toolset()

agent = Agent(
    name="vt_intel_agent",
    model=DEFAULT_MODEL,
    description="Threat intelligence specialist connected to VirusTotal MCP.",
    instruction=(
        "Use passive VirusTotal MCP lookups (get_domain_report, get_ip_report, "
        "get_file_report, get_url_report) to assess indicators. Never submit files/URLs."
    ),
    tools=[vt_mcp] if vt_mcp else [],
    before_tool_callback=guard_vt_public_submissions,
)

app = to_a2a(agent, host=A2A_HOST, port=A2A_PORT)


def main() -> None:
    """Start the VirusTotal Intel A2A HTTP server."""
    uvicorn.run(app, host=A2A_HOST, port=A2A_PORT)


if __name__ == "__main__":
    main()
