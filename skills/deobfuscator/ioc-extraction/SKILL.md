---
name: ioc-extraction
description: Extract structured Indicators of Compromise (C2 domains, fallback IPs, URLs, campaign tags, and companion SHA-256 hashes) from deobfuscated malware outputs.
---
# Indicators of Compromise (IOC) Extraction Procedure

## Context & Objectives
Once malware configuration files, droppers, or stage loaders are decoded, analysts must extract structured Indicators of Compromise (IOCs) to facilitate threat hunting, containment, and network blocking.

## Standard Operating Procedure

### Step 1: Ingest Decoded Payload
Review the plain text recovered from `execute_python_sandbox` or file inspection. Look for structured JSON keys, Python variable definitions, or hardcoded strings.

### Step 2: Extract Core Indicators
Systematically extract all observables and categorize them:
1. **Primary C2 Domains**:
   - Identify hostnames configured for command-and-control communication (e.g. `c2.mandiiant-update.dev`).
   - Check for typosquatting variations or lookalike domains (e.g., homoglyphs, repeated letters).
2. **Fallback IP Addresses & Ports**:
   - Extract backup network endpoints (e.g. `185.220.101.42` or `185.220.101.42:8443`).
   - Note non-standard communication ports.
3. **Full Beacon / Telemetry URLs**:
   - Extract full HTTP/HTTPS URIs used for beaconing, check-ins, or exfiltration.
4. **Campaign Identifiers**:
   - Identify campaign names, watermarks, or operation tags (e.g. `Operation-GlassWorm-Demo`).
5. **Companion Artifacts & Hashes**:
   - Note any secondary packages, downloaded scripts, or companion tool names (e.g. `nano-pdf-helper`).
   - Extract referenced cryptographic hashes (e.g. SHA-256 `004c4819f2b8a91d4c6e7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d`).

### Step 3: Format Structured Output
Present the extracted indicators in a clear Markdown report:

| Indicator Type | Extracted Value | Context / Notes |
| :--- | :--- | :--- |
| **Campaign Tag** | `<campaign>` | Campaign identifier |
| **Primary C2 Domain** | `<domain>` | Primary network check-in |
| **Fallback IP** | `<ip:port>` | Hardcoded fallback endpoint |
| **Beacon URL** | `<url>` | Complete check-in endpoint |
| **Companion Package** | `<package_name>` | Secondary payload or skill |
| **Companion SHA-256** | `<sha256>` | Hash of referenced bundle |

Ensure all extracted values are preserved with 100% precision for subsequent threat intelligence lookups.
