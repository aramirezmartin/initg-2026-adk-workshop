---
name: ioc-extraction
description: Extract and normalize Indicators of Compromise (domains, IPs, ports, URLs, hashes, campaign tags) from decoded malware artifacts.
---
# Indicators of Compromise (IOC) Extraction Procedure

## Objectives
Extract every actionable observable from decoded payloads so downstream threat-intelligence and SecOps teams can pivot, block, and correlate incidents accurately.

## Procedure

### 1. Parse the Decoded Artifact
Inspect the plain-text output from `execute_python_sandbox` for network endpoints, file references, cryptographic hashes, and campaign metadata.

### 2. Categorize Observables
Extract and preserve exact values (no truncation or refanging that alters hashes):
- **Domains & Lookalikes**: Primary/backup C2 hostnames and suspected typosquatting domains.
- **IP Addresses & Ports**: Hardcoded IPv4/IPv6 endpoints and non-standard ports.
- **URLs / URIs**: Full check-in, staging, or exfiltration paths.
- **File & Bundle Hashes**: MD5, SHA-1, or SHA-256 digests.
- **Campaign / Package Identifiers**: Operation tags, user-agents, or secondary package names.

### 3. Report Format
Present findings in a concise Markdown table:

| Indicator Type | Extracted Value | Context / Notes |
| :--- | :--- | :--- |
| **Domain** | `<domain>` | Role (C2, staging, etc.) |
| **IP / Port** | `<ip:port>` | Role |
| **URL** | `<url>` | Endpoint purpose |
| **SHA-256** | `<hash>` | Associated file or bundle |
| **Campaign / Tag** | `<tag>` | Attribution or watermark |
