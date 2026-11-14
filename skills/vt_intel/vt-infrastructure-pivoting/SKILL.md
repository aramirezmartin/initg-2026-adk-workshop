---
name: vt-infrastructure-pivoting
description: Pivot across domains, IPs, passive DNS, and communicating files in VirusTotal MCP to map threat infrastructure.
---
# VirusTotal Infrastructure Pivoting Procedure

## Objectives
Connect isolated indicators (domains, IPs, hashes) to broader campaign infrastructure using passive VirusTotal MCP lookups.

## Procedure
1. **Domain & IP Reports**: Query `get_domain_report` and `get_ip_report` to inspect detection ratios, reputation, ASN/hosting, and potential typosquatting.
2. **File Reports**: Query `get_file_report` for observed SHA-256 hashes to review verdicts, tags, and threat labels.
3. **Passive Pivoting**: Correlate shared domains, IPs, and communicating files to map the multi-stage infrastructure without submitting any local files or URLs for public scanning.
