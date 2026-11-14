"""Self-contained integration and unit tests for the 4-file SOC orchestra."""

from __future__ import annotations

import importlib
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import Agent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
import httpx
import pytest
from starlette.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent

AGENT_MODULES: list[tuple[str, str, int]] = [
    ("agents.deobfuscator", "deobfuscator_agent", 8001),
    ("agents.vt_intel", "vt_intel_agent", 8002),
    ("agents.secops_auditor", "secops_auditor", 8003),
]


def _wait_for_http_200(url: str, timeout: float = 20.0) -> httpx.Response:
    """Polls an HTTP URL until it returns 200 OK or raises TimeoutError."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=1.5)
            if resp.status_code == 200:
                return resp
        except httpx.HTTPError as exc:
            last_err = exc
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for {url}: {last_err}")


def _terminate_procs(procs: list[subprocess.Popen[bytes]]) -> None:
    """Terminates subprocesses cleanly, escalating to kill if needed."""
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    for proc in procs:
        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


@pytest.mark.parametrize("module_name,expected_agent_name,port", AGENT_MODULES)
def test_agent_module_exports_and_a2a_card(
    module_name: str, expected_agent_name: str, port: int
) -> None:
    """Each specialist module exports Agent, Starlette app, and valid A2A card."""
    mod = importlib.import_module(module_name)
    assert isinstance(mod.agent, Agent)
    assert mod.agent.name == expected_agent_name
    assert mod.app is not None

    wrapped_app = to_a2a(mod.agent, host="localhost", port=port)
    with TestClient(wrapped_app) as client:
        resp = client.get("/.well-known/agent-card.json")
        assert resp.status_code == 200
        card: dict[str, Any] = resp.json()
        assert card["name"] == expected_agent_name


def test_coordinator_and_mocked_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """soc_coordinator exports root_agent and discover_a2a_subagents probes cards."""
    import soc_coordinator
    from soc_coordinator import agent as coord_mod

    assert isinstance(soc_coordinator.agent.root_agent, Agent)
    assert coord_mod.root_agent.name == "soc_coordinator"

    def fake_get(url: str, timeout: float = 1.0) -> httpx.Response:
        if "8001" in url:
            return httpx.Response(200, json={"description": "Mock deobf"})
        if "8002" in url:
            return httpx.Response(200, json={"description": "Mock vt"})
        raise httpx.ConnectError("8003 offline")

    monkeypatch.setattr(coord_mod.httpx, "get", fake_get)
    discovered = coord_mod.discover_a2a_subagents(timeout=0.5)
    assert len(discovered) == 2
    assert all(isinstance(sa, RemoteA2aAgent) for sa in discovered)
    assert [sa.name for sa in discovered] == [
        "deobfuscator_agent",
        "vt_intel_agent",
    ]


def test_live_a2a_servers_discovery_and_adk_web() -> None:
    """Starts :8001-:8003 and adk web :8099, verifies discovery & /list-apps."""
    from soc_coordinator.agent import discover_a2a_subagents

    venv_bin = Path(sys.executable).parent
    uvicorn_bin = str(venv_bin / "uvicorn")
    adk_bin = str(venv_bin / "adk")

    procs: list[subprocess.Popen[bytes]] = []
    try:
        for mod_name, _, port in AGENT_MODULES:
            proc = subprocess.Popen(
                [
                    uvicorn_bin,
                    f"{mod_name}:app",
                    "--host",
                    "localhost",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                cwd=str(REPO_ROOT),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            procs.append(proc)

        for _, _, port in AGENT_MODULES:
            _wait_for_http_200(
                f"http://localhost:{port}/.well-known/agent-card.json",
                timeout=20.0,
            )

        discovered = discover_a2a_subagents(timeout=2.0)
        assert len(discovered) == 3
        assert {sa.name for sa in discovered} == {
            "deobfuscator_agent",
            "vt_intel_agent",
            "secops_auditor_agent",
        }

        adk_proc = subprocess.Popen(
            [adk_bin, "web", "--port", "8099", "."],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        procs.append(adk_proc)

        list_resp = _wait_for_http_200(
            "http://localhost:8099/list-apps", timeout=20.0
        )
        apps = list_resp.json()
        assert "soc_coordinator" in apps
    finally:
        _terminate_procs(procs)


def test_python_decoder_and_inline_attachment_decoding() -> None:
    """Verifies plain Python decoder tool and adk web inline attachment decoding."""
    from types import SimpleNamespace
    from google.genai import types
    from agents.deobfuscator import execute_python_sandbox
    from soc_coordinator.agent import decode_inline_attachments

    res = execute_python_sandbox(
        "import base64; print(base64.b64decode(SAMPLE_TEXT).decode())",
        sample_text="aGVsbG8td29ya3Nob3A=",
    )
    assert res["status"] == "ok"
    assert res["stdout"].strip() == "hello-workshop"

    blob = types.Part(
        inline_data=types.Blob(
            mime_type="application/octet-stream",
            data=b"console.log('test');",
        )
    )
    req = SimpleNamespace(contents=[types.Content(role="user", parts=[blob])])
    decode_inline_attachments(None, req)  # type: ignore[arg-type]
    decoded_text = req.contents[0].parts[0].text or ""
    assert "console.log('test');" in decoded_text
    assert "sha256=" in decoded_text


def test_vt_auto_registration_writes_token_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_register_vtai_token stores a validated vtai_ token with 0600 permissions."""
    from agents import vt_intel

    token_path = tmp_path / ".config" / "vt-mcp" / "token"

    def fake_post(url: str, **kwargs: Any) -> httpx.Response:
        assert url == vt_intel.VT_REGISTER_URL
        return httpx.Response(
            200,
            json={"agent_token": "vtai_test_token_12345"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(vt_intel.httpx, "post", fake_post)
    token = vt_intel._register_vtai_token(token_path=token_path)
    assert token == "vtai_test_token_12345"
    assert token_path.read_text(encoding="utf-8").strip() == "vtai_test_token_12345"
    assert (token_path.stat().st_mode & 0o777) == 0o600
    assert vt_intel._register_vtai_token(token_path=token_path) is None
