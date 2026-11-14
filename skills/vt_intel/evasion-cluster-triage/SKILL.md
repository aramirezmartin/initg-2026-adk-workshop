---
name: evasion-cluster-triage
description: Correlate low- or zero-detection samples against infrastructure and companion artifacts to prevent false-negative triage.
---
# Evasion Cluster Triage Procedure

## Objectives
Freshly packed or obfuscated payloads often show zero detections in static AV engines. Never classify an obfuscated artifact as benign solely from a `0/N` file score.

## Procedure
1. **Check the File Report**: Inspect `last_analysis_stats`, tags, and sandbox/behavioral signals.
2. **Pivot on Extracted Infrastructure**: Use domains, IPs, and URLs recovered from deobfuscation or logs to query VirusTotal domain/IP reports.
3. **Correlate Companion Artifacts**: Check communicating files or passive DNS resolutions for high-detection companion payloads sharing the same C2 infrastructure.
4. **Assign Cluster Verdict**: Base the final verdict on combined infrastructure, behavioral, and companion-file evidence.
