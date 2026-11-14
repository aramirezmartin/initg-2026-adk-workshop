"""Self-contained SecOps Auditor A2A specialist server (port 8003)."""

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.agents.context import Context
from google.adk.tools.base_tool import BaseTool
import uvicorn

load_dotenv()

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
_TRUSTED_PREFIX = "https://security.internal.corp/"
_ADVISORY_URL = f"{_TRUSTED_PREFIX}advisories/GHSA-glassworm-trojan-skills"
_SUSPICIOUS = ("curl", "bash", "sudo", "base64", "rm -rf")


def _read_sample(relpath: str) -> str | dict[str, Any]:
    target = (SAMPLES_DIR / relpath).resolve()
    if not target.is_relative_to(SAMPLES_DIR.resolve()):
        return {"status": "error", "error": f"Path traversal denied: {relpath}"}
    if not target.is_file():
        return {"status": "error", "error": f"File not found: {relpath}"}
    return target.read_text(encoding="utf-8", errors="replace")


def audit_skill_package(skill_relpath: str = "poisoned_skill_package/SKILL.md") -> dict[str, Any]:
    """Audit a skill file inside samples/ for suspicious supply-chain patterns."""
    res = _read_sample(skill_relpath)
    if isinstance(res, dict):
        return res
    findings = [p for p in _SUSPICIOUS if p in res.lower()]
    return {"status": "malicious" if findings else "clean", "file": skill_relpath, "findings": findings, "content": res}


def read_waf_log(log_filename: str = "waf_incident.log") -> dict[str, Any]:
    """Safely read a WAF incident log inside samples/."""
    res = _read_sample(log_filename)
    return res if isinstance(res, dict) else {"status": "ok", "file": log_filename, "content": res}


def fetch_security_advisory(url: str) -> dict[str, Any]:
    """Fetch internal security advisory metadata for a trusted advisory URL."""
    if url.strip() == _ADVISORY_URL:
        return {"status": "ok", "id": "GHSA-glassworm-trojan-skills", "campaign": "GLASSWORM-TROJAN-SKILLS"}
    return {"status": "not_found", "url": url}


def ssrf_guardrail(tool: BaseTool, args: dict[str, Any], tool_context: Context) -> dict[str, Any] | None:
    """Block fetch_security_advisory calls targeting untrusted URLs."""
    if getattr(tool, "name", "") == "fetch_security_advisory":
        url = str(args.get("url", "")).strip()
        if not url.startswith(_TRUSTED_PREFIX):
            return {"status": "blocked", "reason": f"SSRF guardrail blocked untrusted URL: {url}"}
    return None


agent = Agent(
    name="secops_auditor",
    model=os.getenv("ADK_MODEL", "gemini-4-hydrogen"),
    description="SecOps auditor for skill packages, WAF logs, and internal advisories.",
    instruction="Audit skill packages, inspect WAF logs, and fetch internal security advisories.",
    tools=[audit_skill_package, read_waf_log, fetch_security_advisory],
    before_tool_callback=ssrf_guardrail,
)
app = to_a2a(agent, host="localhost", port=8003)

def main() -> None:
    """Run the SecOps Auditor A2A server."""
    uvicorn.run(app, host="localhost", port=8003)


if __name__ == "__main__":
    main()
