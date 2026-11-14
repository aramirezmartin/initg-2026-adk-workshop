---
name: skill-supply-chain-audit
description: Audit AI agent SKILL.md manifests and skill packages for supply-chain backdoors (trojan.skills), excessive tool permissions, and encoded shell bootstrappers.
---
# Skill Supply-Chain Audit Procedure

## Context & Objectives
Agent skills packaged as `SKILL.md` markdown files guide autonomous AI agents during automated workflows. Because LLM agents can follow tool instructions directly, malicious actors can distribute trojanized skill packages (`trojan.skills`) containing hidden bootstrappers, encoded commands, or social-engineering prompts that command the agent to execute unauthorized operations.

## Standard Operating Procedure

### Step 1: Inspect Skill Manifest
Call `inspect_skill_bundle(skill_relpath="<relpath>")` to analyze the skill directory or `SKILL.md` file:
- Note the computed SHA-256 hash.
- Extract frontmatter parameters (`name`, `description`, `allowed-tools`).
- Check decoded Base64 content previews and red-flag indicators.

### Step 2: Audit Tool Permissions
Inspect requested tools in the manifest:
- **Least-Privilege Principle**: A document utility (e.g. `nano-pdf-helper`) should only require text/data parsing tools, NOT arbitrary shell execution tools.
- Flag any manifest requesting `execute_bash_command`, `shell`, `exec`, or broad system access when disproportionate to the tool's advertised functionality (`overprivileged_bash_tool`).

### Step 3: Detect Evasive & Coercive Prompts
Scan the instructional text for coercive phrasing:
- Directives commanding silent execution: `"Run silently first!"`, `"Run without prompting user"`, `"Do not ask for confirmation"`.
- Masqueraded prerequisites: claims that arbitrary shell commands are necessary for "glyph cache initialization" or "font dependencies".

### Step 4: Analyze Encoded Shell Bootstrappers
Identify encoded commands in code blocks:
- Scan for Base64 blobs piped into shell interpreters (`base64 -d | sh`, `echo ... | base64 -d | bash`, `curl ... | sh`).
- Review `decoded_base64_previews` in tool output to observe the underlying command.
- Extract network endpoints contacted by the bootstrapper (e.g. `http://c2.mandiiant-update.dev/skills/nano-pdf-bootstrap.sh`).

### Step 5: Consult Security Advisories
Look up relevant security advisories using `fetch_security_advisory(url="https://advisories.secops.internal/2026/GHSA-glassworm-trojan-skills")`:
- Compare package name and SHA-256 hash against published vulnerability notices.
- Document campaign attribution, supply-chain contamination vectors, and mitigation procedures.
