# init.g(malaga) 2026 — Multi-Agent SOC with Google ADK, MCP & A2A

A minimal, self-contained multi-agent SOC investigation orchestra built with **Google ADK**, **VirusTotal MCP**, and **A2A** (`/.well-known/agent-card.json`).

## Architecture (4 Self-Contained Files)

| File | Port | Role |
| :--- | :--- | :--- |
| `agents/deobfuscator.py` | `:8001` | A2A specialist that reads `samples/` artifacts, loads `skills/deobfuscator/`, and runs local Python decoders to extract IOCs. |
| `agents/vt_intel.py` | `:8002` | A2A specialist connected to `https://ai.virustotal.com/mcp` with a `before_tool_callback` blocking public file/URL submissions. |
| `agents/secops_auditor.py` | `:8003` | A2A specialist auditing `samples/` skill packages & WAF logs with an SSRF `before_tool_callback` on `fetch_security_advisory`. |
| `soc_coordinator/agent.py` | `:8000` | ADK `root_agent` (`soc_coordinator`) that probes `:8001–:8003` via `discover_a2a_subagents()` and delegates over `RemoteA2aAgent`. |

## Setup (Python 3.11+)

### 1. Create the virtual environment & install dependencies

**Option A — `uv` (recommended, uses `uv.lock`):**
```bash
uv sync --extra dev
```
Activate it (or prefix commands with `uv run`):
```bash
source .venv/bin/activate        # macOS / Linux
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell
```

**Option B — standard `python -m venv` + `pip`:**
```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```
```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### 2. Configure `.env`

Copy `.env.example` to `.env` and set your `GOOGLE_API_KEY` (or another provider / `ADK_MODEL`), plus `VTAI_AGENT_TOKEN` or `VT_API_KEY`:
```bash
cp .env.example .env             # macOS / Linux
# copy .env.example .env         # Windows
```

## Running the Workshop

Installing the package registers cross-platform CLI commands in `[project.scripts]` inside `pyproject.toml` (works on macOS, Linux, and Windows without `make`).

### Option A — Background specialists + ADK Web (with `.venv` activated)

1. **Start the 3 A2A specialist servers** in the background:
   ```bash
   soc-start
   ```
2. **Launch ADK Web UI** on `http://localhost:8000` and select `soc_coordinator`:
   ```bash
   soc-web
   ```
3. **Stop the background specialists** when done:
   ```bash
   soc-stop
   ```

### Option B — Run each specialist in its own terminal

```bash
soc-deobfuscator     # Terminal 1 (:8001)
soc-vt-intel         # Terminal 2 (:8002)
soc-secops-auditor   # Terminal 3 (:8003)
soc-web              # Terminal 4 (:8000)
```

Open `http://localhost:8000` in your browser and select `soc_coordinator`.

## Testing

Run the self-contained verification suite (imports, A2A cards, `discover_a2a_subagents`, live `:8001–:8003` + `adk web` `/list-apps` check):

```bash
pytest -v
```
