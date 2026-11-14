---
name: layered-deobfuscation
description: Decode multi-layer obfuscated JavaScript and Python payloads (Hex arrays, repeating-key or single-byte XOR, Base64, and zlib streams) using the isolated local Python sandbox.
---
# Layered Deobfuscation Procedure

## Context & Objectives
Malware authors commonly nest multiple lightweight obfuscation techniques (Hex byte arrays, XOR with static or repeating keys, Base64 encoding, and zlib compression) to evade static signature detection.

Do NOT attempt to mentally calculate XOR, Base64, or zlib math within model token prediction. Mental decoding frequently produces hallucinated or truncated bytes. Always use the isolated Python sandbox tool to decode payloads deterministically.

## Standard Operating Procedure

### Step 1: Read the Artifact
Invoke `read_sample_artifact(sample_filename="<filename>")` to retrieve:
- File metadata (file size, SHA-256 hash).
- Raw source code and structure.

### Step 2: Analyze Obfuscation Envelope
Examine the wrapper syntax, headers, or captured comments to identify the encoding stages:
- **JavaScript Droppers**: Look for hex byte arrays (e.g. `const _0x4f9a = [0x22, 0x2a, ...]`), static XOR keys (e.g. `const _0xkey = "GSEC26"`), and decoding loops that feed into `atob` (Base64 decode).
- **Python Beacons**: Look for Base64 envelopes, single-byte XOR transformations (e.g. XOR with `0x37`), and zlib decompression streams (`zlib.decompress`).

### Step 3: Author a Minimal Sandbox Script
Author a concise Python decoder utilizing standard library modules (`base64`, `binascii`, `json`, `re`, `zlib`).
Take advantage of preloaded sandbox variables:
- `SAMPLE_TEXT`: Contains the file content as a string.
- `SAMPLE_BYTES`: Contains the raw file bytes.

Example patterns:
- For repeating-key XOR + Base64:
  ```python
  import base64
  import json
  import re

  # Extract hex array numbers
  hex_matches = re.findall(r"0x[0-9a-fA-F]+", SAMPLE_TEXT)
  enc_bytes = bytes(int(h, 16) for h in hex_matches)
  key = b"GSEC26"
  xor_decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc_bytes))
  plain_text = base64.b64decode(xor_decoded).decode("utf-8")
  print(plain_text)
  ```
- For Base64 + single-byte XOR + zlib:
  ```python
  import base64
  import re
  import zlib

  match = re.search(r'PAYLOAD_B64\s*=\s*["\']([^"\']+)["\']', SAMPLE_TEXT)
  if match:
    b64_data = match.group(1)
  else:
    b64_data = SAMPLE_TEXT.strip()

  raw_bytes = base64.b64decode(b64_data)
  xor_bytes = bytes(b ^ 0x37 for b in raw_bytes)
  decompressed = zlib.decompress(xor_bytes).decode("utf-8")
  print(decompressed)
  ```

### Step 4: Execute in Isolated Sandbox
Call `execute_python_sandbox(python_code="...", sample_filename="<filename>")`.
Verify:
- `status == "ok"`
- `exit_code == 0`
- Extracted output matches valid JSON, Python, or shell configurations.

### Step 5: Validate & Transition to IOC Extraction
Confirm the deobfuscated payload contains intact telemetry or C2 configuration. Hand off the plain text to the `ioc-extraction` procedure.
