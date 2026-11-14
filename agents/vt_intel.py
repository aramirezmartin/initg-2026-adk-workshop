"""Self-contained VirusTotal MCP A2A specialist server (port 8002).

Connects to the remote VirusTotal MCP endpoint (`https://ai.virustotal.com/mcp`)
and enforces a `before_tool_callback` guardrail that blocks active public
submissions unless explicitly authorized in session state.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Literal

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.skills import load_skills_from_dir
from google.adk.tools import BaseTool, ToolContext
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from google.adk.tools.skill_toolset import SkillToolset
from google.genai import types
import httpx
from pydantic import BaseModel, ConfigDict
import uvicorn

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = BASE_DIR / "skills"

DEFAULT_MODEL = os.getenv("ADK_MODEL", "gemini-4-hydrogen")
A2A_HOST = "localhost"
A2A_PORT = 8002
VT_MCP_URL = "https://ai.virustotal.com/mcp"
VT_REGISTER_URL = "https://ai.virustotal.com/api/v3/agents/register"
VT_MCP_TIMEOUT_S = 20.0
VT_TOKEN_FILE = Path.home() / ".config" / "vt-mcp" / "token"
_VT_TOKEN_RE = re.compile(r"vtai_[A-Za-z0-9_-]{1,507}")

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


def _register_vtai_token(token_path: Path = VT_TOKEN_FILE) -> str | None:
    """Register a free VTAI Agent Token once and persist it with 0600 permissions."""
    if token_path.exists() or token_path.is_symlink():
        return None
    try:
        resp = httpx.post(
            VT_REGISTER_URL,
            json={"agent_family": "vt-mcp-other", "agent_version": "0.9.9"},
            timeout=VT_MCP_TIMEOUT_S,
            follow_redirects=False,
        )
        resp.raise_for_status()
        token = resp.json().get("agent_token", "")
        if not isinstance(token, str) or not _VT_TOKEN_RE.fullmatch(token):
            return None
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.parent.chmod(0o700)
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
        return token
    except (httpx.HTTPError, ValueError, OSError):
        return None


def _resolve_vt_headers() -> dict[str, str]:
    """Resolve VirusTotal MCP auth headers, auto-registering a free token if missing."""
    if os.getenv("VT_MCP_OFFLINE", "").lower() == "true":
        return {}
    if token := os.getenv("VTAI_AGENT_TOKEN", "").strip():
        return {"Authorization": f"Bearer {token}"}
    if VT_TOKEN_FILE.is_file() and (token := VT_TOKEN_FILE.read_text(encoding="utf-8").strip()):
        return {"Authorization": f"Bearer {token}"}
    if api_key := os.getenv("VT_API_KEY", "").strip():
        return {"x-apikey": api_key}
    if token := _register_vtai_token():
        return {"Authorization": f"Bearer {token}"}
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
skills = SkillToolset(skills=load_skills_from_dir(SKILLS_DIR / "vt_intel"))

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

agent = Agent(
    name="vt_intel_agent",
    model=DEFAULT_MODEL,
    description="Threat intelligence specialist connected to VirusTotal MCP.",
    instruction=(
        "Use passive VirusTotal MCP lookups (get_domain_report, get_ip_report, "
        "get_file_report, get_url_report) to assess indicators. Never submit files/URLs."
    ),
    generate_content_config=_SAFETY_CONFIG,
    tools=[t for t in (vt_mcp, skills) if t is not None],
    before_tool_callback=guard_vt_public_submissions,
)

app = to_a2a(agent, host=A2A_HOST, port=A2A_PORT)


def main() -> None:
    """Start the VirusTotal Intel A2A HTTP server."""
    uvicorn.run(app, host=A2A_HOST, port=A2A_PORT)


if __name__ == "__main__":
    main()
