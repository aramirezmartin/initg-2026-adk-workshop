SHELL := /bin/bash
VENV_BIN := ./.venv/bin
PYTHON := $(VENV_BIN)/python
UVICORN := $(VENV_BIN)/uvicorn
PYTEST := $(VENV_BIN)/pytest
ADK := $(VENV_BIN)/adk
PID_DIR := .pids

.PHONY: start stop web test

start:
	@mkdir -p $(PID_DIR)
	@echo "Starting A2A specialist servers (:8001, :8002, :8003)..."
	@nohup $(UVICORN) agents.deobfuscator:app --host localhost --port 8001 --log-level warning > $(PID_DIR)/deobfuscator.log 2>&1 & echo $$! > $(PID_DIR)/deobfuscator.pid
	@nohup $(UVICORN) agents.vt_intel:app --host localhost --port 8002 --log-level warning > $(PID_DIR)/vt_intel.log 2>&1 & echo $$! > $(PID_DIR)/vt_intel.pid
	@nohup $(UVICORN) agents.secops_auditor:app --host localhost --port 8003 --log-level warning > $(PID_DIR)/secops_auditor.log 2>&1 & echo $$! > $(PID_DIR)/secops_auditor.pid
	@for port in 8001 8002 8003; do \
		ready=0; \
		for i in $$(seq 1 50); do \
			if $(PYTHON) -c "import httpx, sys; sys.exit(0 if httpx.get('http://localhost:' + sys.argv[1] + '/.well-known/agent-card.json', timeout=1.0).status_code == 200 else 1)" $$port 2>/dev/null; then \
				ready=1; break; \
			fi; \
			sleep 0.3; \
		done; \
		if [ "$$ready" -ne 1 ]; then echo "Timed out waiting for port $$port"; exit 1; fi; \
	done
	@echo "All 3 A2A specialists ready."

stop:
	@echo "Stopping A2A specialist servers..."
	@if [ -d "$(PID_DIR)" ]; then \
		for pidfile in $(PID_DIR)/*.pid; do \
			if [ -f "$$pidfile" ]; then \
				kill $$(cat "$$pidfile") 2>/dev/null || true; \
				rm -f "$$pidfile"; \
			fi; \
		done; \
		rm -rf $(PID_DIR); \
		echo "Stopped."; \
	else \
		echo "No active servers (.pids not found)."; \
	fi

web:
	@$(ADK) web --port 8000 --reload_agents .

test:
	@$(PYTEST) -v
