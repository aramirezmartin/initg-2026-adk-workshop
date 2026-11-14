# init.g(malaga) 2026 — Multi-Agent SOC with Google ADK, MCP & A2A

A minimal, self-contained multi-agent SOC investigation orchestra built with **Google ADK**, **VirusTotal MCP**, and **A2A** (`/.well-known/agent-card.json`).

## Architecture (4 Self-Contained Files)

| File | Port | Role |
| :--- | :--- | :--- |
| `agents/deobfuscator.py` | `:8001` | A2A specialist that reads `samples/` artifacts, loads `skills/deobfuscator/`, and runs local Python decoders to extract IOCs. |
| `agents/vt_intel.py` | `:8002` | A2A specialist connected to `https://ai.virustotal.com/mcp` with a `before_tool_callback` blocking public file/URL submissions. |
| `agents/secops_auditor.py` | `:8003` | A2A specialist auditing `samples/` skill packages & WAF logs with an SSRF `before_tool_callback` on `fetch_security_advisory`. |
| `soc_coordinator/agent.py` | `:8000` | ADK `root_agent` (`soc_coordinator`) that probes `:8001–:8003` via `discover_a2a_subagents()` and delegates over `RemoteA2aAgent`. |

## Quick Start

1. **Configure `.env`** (copy `.env.example` to `.env` and set your API key / `ADK_MODEL`, plus `VTAI_AGENT_TOKEN` or `VT_API_KEY`).
2. **Start the 3 A2A specialist servers** in the background:
   ```bash
   make start
   ```
3. **Launch ADK Web UI** on `http://localhost:8000` and select `soc_coordinator`:
   ```bash
   make web
   ```
4. **Stop the background specialists** when done:
   ```bash
   make stop
   ```

## Testing

Run the self-contained verification suite (imports, A2A cards, `discover_a2a_subagents`, live `:8001–:8003` + `adk web` `/list-apps` check):

```bash
make test
```
