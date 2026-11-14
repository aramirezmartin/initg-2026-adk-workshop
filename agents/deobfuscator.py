"""Self-contained A2A Deobfuscator specialist server (port 8001).

Exposes tools to safely read repository samples, execute deterministic Python
decoders in an isolated temporary directory, and expose the agent via A2A.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Literal

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.skills import load_skills_from_dir
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
A2A_PORT = 8001
EXECUTION_TIMEOUT_S = 5
MAX_STDOUT_CHARS = 4000
MAX_STDERR_CHARS = 2000


class SampleArtifactResult(BaseModel):
    """Structured result returned when reading a sample artifact from disk."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "error"]
    filename: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    content: str | None = None
    error: str | None = None


class PythonExecutionResult(BaseModel):
    """Structured result returned by the Python decoder subprocess."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "runtime_error", "error"]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


def _resolve_sample_path(sample_filename: str) -> Path:
    """Resolve a relative sample path and enforce confinement to `SAMPLES_DIR`.

    Args:
        sample_filename: Relative path (with or without a leading `samples/`).

    Returns:
        Resolved absolute path inside `SAMPLES_DIR`.

    Raises:
        ValueError: If the path escapes `SAMPLES_DIR`.
        FileNotFoundError: If the target file does not exist.
    """
    samples_root = SAMPLES_DIR.resolve()
    relpath = sample_filename.strip().removeprefix("samples/")
    target = (samples_root / relpath).resolve()
    if not target.is_relative_to(samples_root):
        raise ValueError(f"Path traversal denied: '{sample_filename}'.")
    if not target.is_file():
        raise FileNotFoundError(f"File not found: '{sample_filename}'.")
    return target


def _run_python_subprocess(python_code: str, sample_text: str) -> PythonExecutionResult:
    """Execute decoder code in a temporary directory with `SAMPLE_TEXT` bound."""
    with tempfile.TemporaryDirectory(prefix="adk_py_") as tmpdir:
        (Path(tmpdir) / "sample.txt").write_text(sample_text, encoding="utf-8")
        runner_script = (
            "from pathlib import Path\n"
            "SAMPLE_TEXT = Path('sample.txt').read_text(encoding='utf-8')\n"
            f"{python_code}"
        )
        proc = subprocess.run(
            [sys.executable, "-c", runner_script],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=EXECUTION_TIMEOUT_S,
            check=False,
        )
    return PythonExecutionResult(
        status="ok" if proc.returncode == 0 else "runtime_error",
        exit_code=proc.returncode,
        stdout=proc.stdout[:MAX_STDOUT_CHARS],
        stderr=proc.stderr[:MAX_STDERR_CHARS],
    )


def read_sample_artifact(sample_filename: str) -> dict[str, Any]:
    """Read a sample file confined to the repository `samples/` directory.

    Args:
        sample_filename: Sample filename or relative path under `samples/`.

    Returns:
        Serialized `SampleArtifactResult` with SHA-256, byte size, and UTF-8 text.
    """
    try:
        target = _resolve_sample_path(sample_filename)
    except (ValueError, FileNotFoundError) as exc:
        return SampleArtifactResult(status="error", error=str(exc)).model_dump(exclude_none=True)

    raw = target.read_bytes()
    return SampleArtifactResult(
        status="ok",
        filename=sample_filename,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        content=raw.decode("utf-8", errors="replace"),
    ).model_dump(exclude_none=True)


def execute_python_sandbox(
    python_code: str,
    sample_filename: str = "",
    sample_text: str = "",
) -> dict[str, Any]:
    """Execute Python decoder code in a subprocess with `SAMPLE_TEXT` loaded.

    Args:
        python_code: Python snippet that reads `SAMPLE_TEXT` and prints decoded output.
        sample_filename: Optional path under `samples/` loaded when `sample_text` is empty.
        sample_text: Optional inline payload text passed directly by the caller.

    Returns:
        Serialized `PythonExecutionResult` containing exit code, stdout, and stderr.
    """
    loaded_text = sample_text
    if sample_filename and not loaded_text:
        artifact = read_sample_artifact(sample_filename)
        if artifact.get("status") != "ok":
            return artifact
        loaded_text = str(artifact["content"])

    return _run_python_subprocess(python_code, loaded_text).model_dump(exclude_none=True)


skills = SkillToolset(skills=load_skills_from_dir(SKILLS_DIR / "deobfuscator"))

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
    name="deobfuscator_agent",
    model=DEFAULT_MODEL,
    description=(
        "Specialist agent that deobfuscates script-based malware and extracts "
        "structured Indicators of Compromise (IOCs) using local Python execution."
    ),
    instruction=(
        "You are deobfuscator_agent, a malware deobfuscation specialist.\n"
        "1. Read files in samples/ with read_sample_artifact, or use the inline text passed to you.\n"
        "2. Load your procedural skills ('layered-deobfuscation', 'ioc-extraction') via SkillToolset.\n"
        "3. Never guess XOR, Base64, or zlib outputs; decode deterministically using execute_python_sandbox.\n"
        "4. Return a structured IOC table (C2 domains, IPs, ports, URLs, campaign tags, SHA-256)."
    ),
    generate_content_config=_SAFETY_CONFIG,
    tools=[read_sample_artifact, execute_python_sandbox, skills],
)

app = to_a2a(agent, host=A2A_HOST, port=A2A_PORT)


def main() -> None:
    """Start the Deobfuscator A2A HTTP server."""
    uvicorn.run(app, host=A2A_HOST, port=A2A_PORT)


if __name__ == "__main__":
    main()
