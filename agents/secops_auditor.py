"""Self-contained SecOps Auditor A2A specialist server (port 8003).

Provides supply-chain skill auditing, WAF log inspection, and internal advisory
lookups guarded by an SSRF `before_tool_callback`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.agents.context import Context
from google.adk.skills import load_skills_from_dir
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.skill_toolset import SkillToolset
from google.genai import types
from pydantic import BaseModel, ConfigDict
import uvicorn

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
SKILLS_DIR = BASE_DIR / "skills"
DEFAULT_MODEL = os.getenv("ADK_MODEL", "gemini-4-hydrogen")
A2A_HOST = "localhost"
A2A_PORT = 8003

_TRUSTED_ADVISORY_PREFIX = "https://security.internal.corp/"
_KNOWN_ADVISORIES: dict[str, dict[str, str]] = {
    f"{_TRUSTED_ADVISORY_PREFIX}advisories/GHSA-glassworm-trojan-skills": {
        "id": "GHSA-glassworm-trojan-skills",
        "campaign": "GLASSWORM-TROJAN-SKILLS",
    },
}
_SUSPICIOUS_PATTERNS: tuple[str, ...] = ("curl", "bash", "sudo", "base64", "rm -rf")


class SkillAuditResult(BaseModel):
    """Structured result for `audit_skill_package`."""

    model_config = ConfigDict(frozen=True)

    status: Literal["malicious", "clean", "error"]
    file: str | None = None
    findings: list[str] = []
    content: str | None = None
    error: str | None = None


class WafLogResult(BaseModel):
    """Structured result for `read_waf_log`."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "error"]
    file: str | None = None
    content: str | None = None
    error: str | None = None


class AdvisoryResult(BaseModel):
    """Structured result for `fetch_security_advisory`."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "not_found"]
    id: str | None = None
    campaign: str | None = None
    url: str | None = None


class SsrfGuardrailBlock(BaseModel):
    """Payload returned when the SSRF guardrail blocks an untrusted URL."""

    model_config = ConfigDict(frozen=True)

    status: Literal["blocked"] = "blocked"
    reason: str


def _resolve_sample_path(relpath: str) -> Path:
    """Resolve `relpath` inside `SAMPLES_DIR`, rejecting path traversal."""
    samples_root = SAMPLES_DIR.resolve()
    cleaned = relpath.strip().removeprefix("samples/")
    target = (samples_root / cleaned).resolve()
    if not target.is_relative_to(samples_root):
        raise ValueError(f"Path traversal denied: {relpath}")
    if not target.is_file():
        raise FileNotFoundError(f"File not found: {relpath}")
    return target


def _read_sample_text(relpath: str) -> str:
    """Read a UTF-8 sample file confined to `SAMPLES_DIR`."""
    return _resolve_sample_path(relpath).read_text(encoding="utf-8", errors="replace")


def audit_skill_package(
    skill_relpath: str = "poisoned_skill_package/SKILL.md",
) -> dict[str, Any]:
    """Audit a skill file inside `samples/` for suspicious supply-chain patterns.

    Args:
        skill_relpath: Relative path to the `SKILL.md` file under `samples/`.

    Returns:
        Serialized `SkillAuditResult` with verdict, matched patterns, and raw text.
    """
    try:
        content = _read_sample_text(skill_relpath)
    except (ValueError, FileNotFoundError) as exc:
        return SkillAuditResult(status="error", error=str(exc)).model_dump(exclude_none=True)

    lowered = content.lower()
    findings = [pattern for pattern in _SUSPICIOUS_PATTERNS if pattern in lowered]
    return SkillAuditResult(
        status="malicious" if findings else "clean",
        file=skill_relpath,
        findings=findings,
        content=content,
    ).model_dump(exclude_none=True)


def read_waf_log(log_filename: str = "waf_incident.log") -> dict[str, Any]:
    """Safely read a WAF incident log inside `samples/`.

    Args:
        log_filename: Relative log filename under `samples/`.

    Returns:
        Serialized `WafLogResult` with log content or error message.
    """
    try:
        content = _read_sample_text(log_filename)
    except (ValueError, FileNotFoundError) as exc:
        return WafLogResult(status="error", error=str(exc)).model_dump(exclude_none=True)

    return WafLogResult(status="ok", file=log_filename, content=content).model_dump(exclude_none=True)


def fetch_security_advisory(url: str) -> dict[str, Any]:
    """Fetch internal security advisory metadata for a trusted advisory URL.

    Args:
        url: Internal advisory URL under `https://security.internal.corp/`.

    Returns:
        Serialized `AdvisoryResult` with advisory metadata if known.
    """
    normalized = url.strip()
    if advisory := _KNOWN_ADVISORIES.get(normalized):
        return AdvisoryResult(status="ok", **advisory).model_dump(exclude_none=True)
    return AdvisoryResult(status="not_found", url=normalized).model_dump(exclude_none=True)


def ssrf_guardrail(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: Context,
) -> dict[str, Any] | None:
    """Block `fetch_security_advisory` calls targeting untrusted URLs.

    Args:
        tool: Tool about to be executed by ADK.
        args: Arguments supplied by the model for the tool call.
        tool_context: ADK callback context.

    Returns:
        Serialized `SsrfGuardrailBlock` dict when blocked, or `None` to allow.
    """
    del tool_context
    if getattr(tool, "name", "") == "fetch_security_advisory":
        url = str(args.get("url", "")).strip()
        if not url.startswith(_TRUSTED_ADVISORY_PREFIX):
            return SsrfGuardrailBlock(
                reason=f"SSRF guardrail blocked untrusted URL: {url}",
            ).model_dump()
    return None


skills = SkillToolset(skills=load_skills_from_dir(SKILLS_DIR / "secops_auditor"))

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
    name="secops_auditor",
    model=DEFAULT_MODEL,
    description="SecOps auditor for skill packages, WAF logs, and internal advisories.",
    instruction="Audit skill packages, inspect WAF logs, and fetch internal security advisories.",
    generate_content_config=_SAFETY_CONFIG,
    tools=[audit_skill_package, read_waf_log, fetch_security_advisory, skills],
    before_tool_callback=ssrf_guardrail,
)

app = to_a2a(agent, host=A2A_HOST, port=A2A_PORT)


def main() -> None:
    """Start the SecOps Auditor A2A HTTP server."""
    uvicorn.run(app, host=A2A_HOST, port=A2A_PORT)


if __name__ == "__main__":
    main()
