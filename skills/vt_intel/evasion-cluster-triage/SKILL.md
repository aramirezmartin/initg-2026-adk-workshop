---
name: evasion-cluster-triage
description: Correlate zero-detection (0/61 AV) evasive droppers against high-signal companion artifacts and typosquatted domains to prevent false-negative triage.
---
# Evasion Cluster Triage Procedure

## Context & Objectives
Security Operations Centers (SOCs) frequently encounter novel or newly compiled scripts that show `0/61` (zero detection) in static antivirus scans. Treating an undetected file as benign is a critical triage error when the artifact exhibits evasion techniques such as multi-layer XOR encoding, custom packing, or dynamic staging.

This procedure establishes a methodology for correlating evasive droppers with known threat clusters to avoid false negatives.

## Standard Operating Procedure

### Step 1: Detect Evasion Attributes
When evaluating a file report via `get_file_report(sha256="<sha256>")`:
- If `last_analysis_stats.malicious == 0` (e.g. `0/61`), check file tags and sandbox verdicts.
- Note evasion flags: `javascript`, `obfuscated`, `xor-encoded`, `zero-day-candidate`.
- A zero-detection score on an obfuscated loader indicates that static signatures have not yet indexed the fresh wrapper.

### Step 2: Extract Embedded Telemetry Leads
Extract network endpoints embedded in the evasive sample (domains, IPs, companion package names, URLs) using local deobfuscation outputs.

### Step 3: Check Domain & Infrastructure Reputation
Look up the extracted C2 domain via `get_domain_report(domain="<domain>")`:
- A malicious score (e.g. `19/90`), low reputation score (e.g. `-94`), recent registration date, or typosquatting flag strongly indicates malicious intent regardless of the file's individual AV score.

### Step 4: Map Companion Artifacts
Query `get_passive_dns_and_communicating_files(indicator="<domain_or_ip>")`:
- Identify other files communicating with the same infrastructure.
- If a companion file (such as `nano-pdf-helper` / `004c4819...`) has a high malicious score (e.g. `48/65` with label `trojan.skills/glassworm`), the `0/61` sample must be classified as an evasive component of the same malicious cluster.

### Step 5: Assign Cluster Verdict
Formulate a contextual assessment:
- **Verdict**: MALICIOUS (Evasive Dropper / Campaign Cluster).
- **Cluster Rationale**: Although static AV signatures report `0/61`, the artifact is attributed to `Operation-GlassWorm-Demo` based on shared C2 infrastructure (`c2.mandiiant-update.dev`, `185.220.101.42`) and communication with known trojan package `004c4819...`.
- Recommend immediate endpoint quarantine and perimeter block rules.
