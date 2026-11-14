---
name: vt-infrastructure-pivoting
description: Pivot across C2 domains, passive DNS resolutions, IP addresses, and communicating files in VirusTotal MCP to uncover threat actor infrastructure clusters.
---
# VirusTotal Infrastructure Pivoting Procedure

## Context & Objectives
Threat actors operate complex hosting infrastructures, linking registered domains, hosting IPs, and multiple payload stages. Static analysis of a single file in isolation provides limited context. Infrastructure pivoting connects an observed indicator to the broader malicious campaign cluster.

## Standard Operating Procedure

### Step 1: Query Domain Intelligence
Call `get_domain_report(domain="<domain>")`:
- Inspect `last_analysis_stats` (malicious and suspicious counts).
- Examine domain reputation score and registrar information.
- Check for homoglyphs or typosquatting patterns (e.g. `c2.mandiiant-update.dev` targeting `mandiant.com`).
- Check historical DNS resolutions and creation timestamps.

### Step 2: Uncover Passive DNS & Communicating Files
Call `get_passive_dns_and_communicating_files(indicator="<domain_or_ip>")`:
- **Passive DNS**: Identify all historical and current IP addresses resolving to this domain, as well as sibling subdomains resolving to the same IPs.
- **Communicating Files**: Review the list of file hashes observed communicating with this infrastructure. Note both low-detection droppers and high-detection second-stage packages.

### Step 3: Query IP Intelligence
Call `get_ip_report(ip_address="<ip_address>")`:
- Check Autonomous System Number (ASN), AS owner/organization, and hosting provider.
- Evaluate geographical location and reputation metrics.
- Confirm whether the host is bulletproof or proxy hosting.

### Step 4: Retrieve Communicating File Reports
For any critical SHA-256 hashes identified during the pivot, call `get_file_report(sha256="<sha256>")`:
- Compare analysis statistics (e.g. `0/61` undetected dropper vs. `48/65` malicious trojan package).
- Inspect file tags (e.g. `agent-skill`, `trojan-skills`, `curl-pipe-sh`).
- Review threat classification labels and crowdsourced YARA rule hits.

### Step 5: Expand with VTI Search
Execute `search_vt_intelligence(query="<query>")` using campaign tags or infrastructure attributes (e.g. `Operation-GlassWorm-Demo` or `tag:agent-skill`):
- Identify related campaign assets, threat actor naming conventions, or additional staging nodes.
- Compile the multi-stage infrastructure map linking droppers, C2 domains, resolution IPs, and companion backdoors.
