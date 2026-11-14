"""Cross-platform CLI entrypoints declared in `pyproject.toml` `[project.scripts]`."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from google.adk.cli import main as adk_main
import httpx

_PID_DIR = Path(".pids")


@dataclass(frozen=True, slots=True)
class SpecialistProcessSpec:
    """Runtime process definition for an A2A specialist server."""

    name: str
    module: str
    port: int

    @property
    def card_url(self) -> str:
        """Return the local A2A discovery card URL for this specialist."""
        return f"http://localhost:{self.port}/.well-known/agent-card.json"


_SPECIALISTS: tuple[SpecialistProcessSpec, ...] = (
    SpecialistProcessSpec(name="deobfuscator", module="agents.deobfuscator", port=8001),
    SpecialistProcessSpec(name="vt_intel", module="agents.vt_intel", port=8002),
    SpecialistProcessSpec(name="secops_auditor", module="agents.secops_auditor", port=8003),
)


def _spawn_specialist(spec: SpecialistProcessSpec) -> int:
    """Launch a specialist module in the background and return its PID."""
    log_file = (_PID_DIR / f"{spec.name}.log").open("w", encoding="utf-8")
    popen_kwargs: dict[str, object] = {
        "stdout": log_file,
        "stderr": subprocess.STDOUT,
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen([sys.executable, "-m", spec.module], **popen_kwargs)
    (_PID_DIR / f"{spec.name}.pid").write_text(str(proc.pid), encoding="utf-8")
    return proc.pid


def _wait_until_ready(
    spec: SpecialistProcessSpec,
    attempts: int = 50,
    interval_s: float = 0.3,
) -> None:
    """Poll a specialist's A2A card URL until HTTP 200 or exit with error."""
    for _ in range(attempts):
        try:
            if httpx.get(spec.card_url, timeout=1.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(interval_s)
    print(f"Timed out waiting for {spec.name} on port {spec.port}", file=sys.stderr)
    sys.exit(1)


def start() -> None:
    """Start all 3 A2A specialist servers in the background and wait until ready."""
    _PID_DIR.mkdir(parents=True, exist_ok=True)
    print("Starting A2A specialist servers (:8001, :8002, :8003)...")

    for spec in _SPECIALISTS:
        _spawn_specialist(spec)
    for spec in _SPECIALISTS:
        _wait_until_ready(spec)

    print("All 3 A2A specialists ready.")


def stop() -> None:
    """Stop any running A2A specialist servers tracked in `.pids/`."""
    if not _PID_DIR.is_dir():
        print("No active servers (.pids not found).")
        return

    print("Stopping A2A specialist servers...")
    for pidfile in _PID_DIR.glob("*.pid"):
        try:
            pid = int(pidfile.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError):
            pass
        pidfile.unlink(missing_ok=True)

    shutil.rmtree(_PID_DIR, ignore_errors=True)
    print("Stopped.")


def web() -> None:
    """Launch ADK Web UI on port 8000 for `soc_coordinator`."""
    sys.argv = ["adk", "web", "--port", "8000", "--reload_agents", ".", *sys.argv[1:]]
    sys.exit(adk_main())
