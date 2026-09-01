# ComfyUI Attack Surface Analysis (May 2026)

Source code audit of ComfyUI (github.com/comfyanonymous/ComfyUI), 629 Python files, 130M repo.

## Threat Model (from SECURITY.md)

ComfyUI's official stance: **exposed instances are not vulnerabilities.**
- Default bind: `127.0.0.1` (localhost only)
- `--listen 0.0.0.0` is user's responsibility
- No auth by design
- Custom nodes = arbitrary Python code

**Reality:** 204,799 exposed instances on Shodan. Most have no reverse proxy auth.

## Critical Findings

### 1. No Authentication on Any API Endpoint

When bound to `0.0.0.0`, every endpoint is fully accessible without auth:

| Endpoint | Method | Impact |
|---|---|---|
| `/prompt` | POST | Execute arbitrary workflows (code execution) |
| `/queue` | POST | Clear/delete queue items |
| `/interrupt` | POST | Interrupt processing |
| `/free` | POST | Unload models, free memory |
| `/upload/image` | POST | Upload files to input/output/temp dirs |
| `/view` | GET | Read files from disk |
| `/system_stats` | GET | Full system info leak (GPU, RAM, Python, PyTorch, sys.argv) |
| `/object_info` | GET | Dump all node definitions |
| `/models` | GET | List all model files |
| `/history` | GET | View all prompt history |
| `/ws` | WS | WebSocket — no auth |

### 2. Workflow Execution = Code Execution

`POST /prompt` accepts arbitrary JSON workflows. Validation only checks node types exist, does NOT restrict which nodes. Malicious workflows can use `ExecuteScript` nodes for arbitrary Python.

### 3. Custom Node Loading = Arbitrary Code Execution

`nodes.py:2184` uses `importlib.util.module_from_spec()` + `exec_module()` on any Python file in `custom_nodes/`.

### 4. File Upload — Path Traversal Partially Mitigated

`server.py:385` checks `os.path.commonpath()` but no extension validation. User-controlled filename with `overwrite=true`.

### 5. System Info Leakage via `/system_stats`

Returns OS, RAM, GPU details, Python/PyTorch versions, full `sys.argv`, embedded Python status.

### 6. Origin Check Bypassable

`Sec-Fetch-Site` header check is browser-only. Simple `curl` bypasses it.

### 7. No Rate Limiting + No WebSocket Auth

Flood `/prompt` for DoS. WebSocket at `/ws` requires no auth.

## Attack Chains

**RCE via Workflow Upload:**
1. `POST /upload/image` — upload Python file to `input/`
2. `POST /prompt` — execute workflow with `ExecuteScript` node
3. Full RCE

**Data Exfiltration:**
1. `GET /system_stats` → system enum
2. `GET /models` → IP theft
3. `GET `/history` → sensitive prompts
4. `GET /view` → output images

## ComfyUI vs Ollama

| Feature | ComfyUI (204K) | Ollama (210K) |
|---|---|---|
| Code execution | Yes (workflows + custom nodes) | Limited |
| File upload | Yes | No |
| File reading | Yes | No |
| RCE difficulty | Easy | Harder |

## Key Takeaway

SECURITY.md says exposed instances are "not vulnerabilities" — all 204K are out of scope for their bug bounty. The attack surface is real but considered user misconfiguration.
