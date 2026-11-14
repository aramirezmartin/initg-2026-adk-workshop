---
name: layered-deobfuscation
description: Methodology for decoding multi-layer obfuscated scripts (hex arrays, XOR, Base64, compression) deterministically with Python execution.
---
# Layered Deobfuscation Procedure

## Objectives
Malicious scripts often chain multiple lightweight encoding or compression layers (hex byte arrays, single-byte or repeating-key XOR, Base64, gzip/zlib) to evade static signatures.

Never guess decoded bytes or perform XOR/Base64/zlib math mentally. Always write and run a deterministic Python script via `execute_python_sandbox`.

## Procedure

### 1. Inspect the Sample
Call `read_sample_artifact(sample_filename="<filename>")` (or inspect inline text if provided) to check file size, SHA-256, and wrapper syntax.

### 2. Identify Encoding Layers
Look for structural clues in the wrapper:
- Byte/hex arrays, character-code loops, or `eval`/`Function`/`atob` sinks.
- Hardcoded XOR keys (strings, hex constants, or single-byte keys).
- Base64/hex payloads or compression headers (`zlib`, `gzip`, `marshal`).

### 3. Decode Deterministically in Python
Write a short standard-library Python script (`base64`, `binascii`, `json`, `re`, `zlib`) and run it with `execute_python_sandbox`.
The variable `SAMPLE_TEXT` is preloaded with the UTF-8 sample text.

### 4. Iterate & Hand Off
If the output reveals another encoded layer, write a follow-up decoder step until plain text (JSON, script, or config) is recovered. Then pass the decoded artifact to `ioc-extraction`.
