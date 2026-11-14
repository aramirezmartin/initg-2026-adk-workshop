---
name: skill-supply-chain-audit
description: Audit AI agent SKILL.md manifests for supply-chain risks, excessive tool permissions, and obfuscated shell bootstrappers.
---
# Skill Supply-Chain Audit Procedure

## Objectives
Agent `SKILL.md` manifests can be weaponized (`trojan.skills`) by requesting dangerous tool permissions or embedding coerced/obfuscated shell commands.

## Procedure

### 1. Inspect the Manifest
Use `audit_skill_package` to read the `SKILL.md` manifest and check automated pattern findings.

### 2. Evaluate Least Privilege
Compare `allowed-tools` and requested capabilities against the skill's stated purpose. Flag broad shell or filesystem execution tools (`execute_bash_command`, `shell`, `exec`) when the task only needs text or document processing.

### 3. Detect Coercive & Obfuscated Execution
Look for:
- Directives instructing the agent to run commands silently or without user confirmation.
- Encoded payloads piped into a shell (`base64 -d | sh`, `curl ... | bash`, etc.).
- External staging URLs or IP addresses.

### 4. Verdict & Advisory Correlation
Return a clear verdict (`MALICIOUS`, `SUSPICIOUS`, or `CLEAN`) with the extracted indicators and, if an internal advisory URL is relevant, query `fetch_security_advisory`.
