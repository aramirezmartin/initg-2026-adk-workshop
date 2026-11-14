"""Self-contained A2A Deobfuscator specialist server (port 8001)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

from dotenv import load_dotenv
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.skills import load_skills_from_dir
from google.adk.tools.skill_toolset import SkillToolset
import uvicorn

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
SKILLS_DIR = BASE_DIR / "skills"


def read_sample_artifact(sample_filename: str) -> dict[str, Any]:
    """Read a sample file confined to the repository samples directory."""
    name = sample_filename.strip().removeprefix("samples/")
    target = (SAMPLES_DIR / name).resolve()
    if not target.is_relative_to(SAMPLES_DIR.resolve()):
        return {"status": "error", "error": f"Path traversal denied: '{sample_filename}'."}
    if not target.is_file():
        return {"status": "error", "error": f"File not found: '{sample_filename}'."}
    raw = target.read_bytes()
    return {
        "status": "ok",
        "filename": sample_filename,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "content": raw.decode("utf-8", errors="replace"),
    }


def execute_python_sandbox(
    python_code: str,
    sample_filename: str = "",
    sample_text: str = "",
) -> dict[str, Any]:
    """Execute Python decoder code in a subprocess with `SAMPLE_TEXT` loaded."""
    loaded_text = sample_text
    if sample_filename and not loaded_text:
        res = read_sample_artifact(sample_filename)
        if res.get("status") != "ok":
            return res
        loaded_text = str(res["content"])

    with tempfile.TemporaryDirectory(prefix="adk_py_") as tmpdir:
        (Path(tmpdir) / "sample.txt").write_text(loaded_text, encoding="utf-8")
        runner = (
            "from pathlib import Path\n"
            "SAMPLE_TEXT = Path('sample.txt').read_text(encoding='utf-8')\n"
            + python_code
        )
        proc = subprocess.run(
            [sys.executable, "-c", runner],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    return {
        "status": "ok" if proc.returncode == 0 else "runtime_error",
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:4000],
        "stderr": proc.stderr[:2000],
    }


skills = SkillToolset(skills=load_skills_from_dir(SKILLS_DIR / "deobfuscator"))

agent = Agent(
    name="deobfuscator_agent",
    model=os.getenv("ADK_MODEL", "gemini-4-hydrogen"),
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
    tools=[read_sample_artifact, execute_python_sandbox, skills],
)

app = to_a2a(agent, host="localhost", port=8001)

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8001)
