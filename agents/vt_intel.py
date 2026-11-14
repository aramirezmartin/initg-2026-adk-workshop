"""Self-contained VirusTotal MCP A2A specialist server (port 8002)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.tools import BaseTool, ToolContext
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
import uvicorn

load_dotenv()

_BLOCKED_TOOLS = frozenset({
    "submit_file", "submit_attachment", "submit_url",
    "reanalyze_domain", "reanalyze_ip",
})


def _vt_headers() -> dict[str, str]:
    """Resolves VirusTotal MCP auth headers from env or ~/.config/vt-mcp/token."""
    if tok := os.getenv("VTAI_AGENT_TOKEN", "").strip():
        return {"Authorization": f"Bearer {tok}"}
    token_file = Path.home() / ".config" / "vt-mcp" / "token"
    if token_file.is_file() and (tok := token_file.read_text(encoding="utf-8").strip()):
        return {"Authorization": f"Bearer {tok}"}
    if key := os.getenv("VT_API_KEY", "").strip():
        return {"x-apikey": key}
    return {}


def guard_vt_public_submissions(
    tool: BaseTool, args: dict[str, Any], tool_context: ToolContext
) -> dict[str, Any] | None:
    """Blocks active VT submission tools unless explicitly opted in via state."""
    if tool.name in _BLOCKED_TOOLS and not tool_context.state.get("allow_public_vt_submission"):
        return {
            "status": "blocked_by_guardrail",
            "blocked_tool": tool.name,
            "reason": "Public VT submissions require state['allow_public_vt_submission']=True.",
        }
    return None


_headers = {} if os.getenv("VT_MCP_OFFLINE", "").lower() == "true" else _vt_headers()
vt_mcp = (
    McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url="https://ai.virustotal.com/mcp", headers=_headers, timeout=20.0
        )
    )
    if _headers
    else None
)

agent = Agent(
    name="vt_intel_agent",
    model=os.getenv("ADK_MODEL", "gemini-4-hydrogen"),
    description="Threat intelligence specialist connected to VirusTotal MCP.",
    instruction=(
        "Use passive VirusTotal MCP lookups (get_domain_report, get_ip_report, "
        "get_file_report, get_url_report) to assess indicators. Never submit files/URLs."
    ),
    tools=[vt_mcp] if vt_mcp else [],
    before_tool_callback=guard_vt_public_submissions,
)
app = to_a2a(agent, host="localhost", port=8002)

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8002)
