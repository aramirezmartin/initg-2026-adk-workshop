"""Cross-platform CLI entrypoints declared in pyproject.toml [project.scripts]."""

from __future__ import annotations

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
_SPECIALISTS: tuple[tuple[str, str, int], ...] = (
    ("deobfuscator", "agents.deobfuscator", 8001),
    ("vt_intel", "agents.vt_intel", 8002),
    ("secops_auditor", "agents.secops_auditor", 8003),
)


def start() -> None:
    """Start all 3 A2A specialist servers in the background and wait until ready."""
    _PID_DIR.mkdir(parents=True, exist_ok=True)
    print("Starting A2A specialist servers (:8001, :8002, :8003)...")

    for name, module, _port in _SPECIALISTS:
        log_file = (_PID_DIR / f"{name}.log").open("w", encoding="utf-8")
        popen_kwargs: dict[str, object] = {
            "stdout": log_file,
            "stderr": subprocess.STDOUT,
        }
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen([sys.executable, "-m", module], **popen_kwargs)
        (_PID_DIR / f"{name}.pid").write_text(str(proc.pid), encoding="utf-8")

    for name, _module, port in _SPECIALISTS:
        url = f"http://localhost:{port}/.well-known/agent-card.json"
        for _ in range(50):
            try:
                if httpx.get(url, timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        else:
            print(f"Timed out waiting for {name} on port {port}", file=sys.stderr)
            sys.exit(1)

    print("All 3 A2A specialists ready.")


def stop() -> None:
    """Stop any running A2A specialist servers tracked in .pids/."""
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
    """Launch ADK Web UI on port 8000 for soc_coordinator."""
    sys.argv = ["adk", "web", "--port", "8000", "--reload_agents", ".", *sys.argv[1:]]
    sys.exit(adk_main())
