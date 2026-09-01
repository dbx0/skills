# Ollama Bug Bounty Findings — Validation & Reporting Guide

**For use with `bug-bounty` umbrella skill and sub-skills**

---

## Findings Summary (Ollama v0.24.0–v0.32.0-rc0)

| ID | Vector | Severity | Status | Platform |
|----|--------|----------|--------|----------|
| OLLAMA-01 | Weight hijack text output | HIGH* | v0.24.0 only | H1/Bugcrowd |
| OLLAMA-05 | Integer overflow DoS | MEDIUM | All versions | H1/Bugcrowd |
| OLLAMA-07 | SSRF via /api/pull redirect | MEDIUM | All versions (harder 0.31+) | H1/Bugcrowd |
| OLLAMA-12 | System prompt injection → tool call | HIGH | All versions | H1/Bugcrowd |
| OLLAMA-16 | Weight hijack + tool call RCE | CRITICAL* | v0.24.0 only | H1/Bugcrowd |
| OLLAMA-17 | GGUF chat_template capability injection | HIGH | v0.30.7+ | H1/Bugcrowd |
| OLLAMA-18 | readModelListGGUF integer confusion | LOW | v0.30.7–v0.31.1 | H1 |
| OLLAMA-19 | Dual rendering pipeline | INFO | v0.30.7+ | N/A (arch) |
| OLLAMA-20 | Multi-path capability detection | INFO | v0.30.7+ | N/A (arch) |
| OLLAMA-21 | Agent TUI `--yolo` RCE (client-side) | CRITICAL | v0.32.0-rc0+ | H1/Bugcrowd |
| OLLAMA-22 | GGUF parser integer overflow → OOM (3 parsers) | MEDIUM | v0.31.1+ | H1 |
| OLLAMA-23 | readModelListGGUF parser desync (count*size overflow) | LOW | v0.31.1+ | H1 |

*Broken on v0.30.7+/v0.31.1+ by llama.cpp vocabulary validation (b9840/b9888), NOT Ollama Go code fix.

---

## 7-Question Triage for Each Finding

### OLLAMA-17 (chat_template capability injection) — REPORTABLE

1. **Vulnerability?** YES — GGUF `tokenizer.chat_template` KV containing "tools" grants `CapabilityTools` without Modelfile
2. **Impact?** Model advertised as tool-capable; downstream clients (OpenCode, Agent TUI) send tools; model output parsed as tool calls
3. **Reproducible?** YES — `POST /api/create` with malicious GGUF → `GET /api/tags` shows `tools` capability
4. **In scope?** Ollama is open source; ollama.com registry may have separate program
5. **Reported before?** No public CVE as of 2026-07
6. **CVSS?** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) — supply chain model poisoning
7. **Fix?** Validate chat_template is from known template registry, not arbitrary string

### NOVEL-05 (Agent TUI --yolo RCE) — REPORTABLE

1. **Vulnerability?** YES — `--yolo` flag bypasses all tool approval; `bash` tool executes arbitrary shell
2. **Impact?** Full RCE as user running `ollama agent`
3. **Reproducible?** YES — `ollama agent --yolo --model evil "run command"`
4. **In scope?** New v0.32.0 feature
5. **Reported before?** No
6. **CVSS?** 9.1 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — local execution, but model is supply chain
6. **Fix?** Require explicit tool approval; audit bash tool safety logic

### OLLAMA-05/07/18 — LOWER PRIORITY

- OLLAMA-05 (DoS): Requires malicious GGUF on disk + cache refresh
- OLLAMA-07 (SSRF): Cross-host redirects blocked in v0.31.1+
- OLLAMA-18: Fixed in v0.32.0 rewrite

---

## Evidence Capture (per bug-bounty-evidence skill)

### For OLLAMA-17

```bash
# 1. Create malicious GGUF
python3 exploit_gguf_chat_template.py --output evil.gguf

# 2. Upload via /api/create
curl -X POST http://TARGET:11434/api/create \
  -F "model=evil-model" \
  -F "files[evil.gguf]=@evil.gguf"

# 3. Verify capability injection
curl -X POST http://TARGET:11434/api/show -d '{"model": "evil-model"}'
# Expected: "capabilities": ["completion", "tools"]

# 4. Test downstream client
opencode --model evil-model "list files"
# Observe tool call execution
```

**Screenshots needed:**
- `/api/show` JSON with `tools` capability
- OpenCode/Agent TUI terminal showing tool execution
- Network capture of tool call → client execution

### For NOVEL-05

```bash
# 1. Create model with tool call in weights
python3 exploit_agent_bash.py --output agent_evil.gguf

# 2. Run agent with --yolo
ollama agent --yolo --model agent_evil "run id"
# Observe: command executes without prompt
```

**Screenshots:**
- Terminal showing `ollama agent --yolo` execution
- Command output in agent TUI
- Process tree showing bash child of ollama

---

## Report Template (per bug-bounty-reporting)

### Title
`Supply Chain: Malicious GGUF Model Grants Tool Capability via tokenizer.chat_template KV — Leads to RCE in Downstream Clients`

### Description
Ollama's capability detection reads `tokenizer.chat_template` from GGUF metadata. If the string contains "tools" or "tool_call", `CapabilityTools` is granted **without any Modelfile**. A malicious model uploaded to a shared registry/server will be advertised as tool-capable to all downstream clients (OpenCode, Agent TUI, custom integrations), causing them to send tool definitions and execute model-generated tool calls.

### Steps to Reproduce
1. Create GGUF with `tokenizer.chat_template: "{{ .Tools }}"`
2. Upload via `POST /api/create`
3. Verify `GET /api/tags` shows `capabilities: ["completion", "tools"]`
4. Connect OpenCode/Agent TUI → model receives tool definitions
5. Model outputs tool call JSON → client executes

### Impact
- **Supply chain**: One poisoned model → all downstream clients execute attacker commands
- **RCE**: With `--yolo` Agent TUI, full shell access
- **Data exfil**: Tool calls can HTTP POST to attacker server

### Remediation
- Require chat_template to match known template registry
- Add explicit user consent for tool-capable models from untrusted sources
- Sign/verify models from official registry

---

## Scope Notes

| Target | Program | Notes |
|--------|---------|-------|
| ollama/ollama GitHub | H1 (ollama) | Core server |
| ollama.com registry | H1 (ollama) | Model hosting |
| ollama.ai website | H1 (ollama) | Web interface |
| Desktop app (Tauri) | H1 (ollama) | Agent TUI is in desktop app |

**Check:** H1 program for Ollama may only cover ollama.com services, not self-hosted. Verify scope before reporting self-hosted findings.

---

## Retest Checklist

After Ollama releases fix:
- [ ] `tokenizer.chat_template` with "tools" no longer grants CapabilityTools
- [ ] Only known templates from registry grant capabilities
- [ ] Agent TUI `--yolo` requires explicit per-tool approval
- [ ] Model list cache handles malformed GGUF without OOM
- [ ] `/api/pull` redirects limited to same host or blocked entirely

---

## New Findings Detail (v0.31.2 / v0.32.0-rc0)

### OLLAMA-21: Agent TUI `--yolo` RCE
**Vector:** `ollama agent --yolo --model <malicious>` auto-executes bash/read/edit/web_search/web_fetch tools from model output
**Safety check bypass:** `x/tools/bash.go:rejectUnsafeShellCommand()` is string-based — bypass via:
  - Command substitution: `echo $(cat /etc/shadow)`
  - Variable expansion: `cmd=cat; $cmd /etc/shadow`
  - Base64: `echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash`
  - Shell builtins: `read -r line < /etc/shadow`
**Threat model:** Supply chain — malicious model pulled from registry → user runs `ollama agent --yolo`

### OLLAMA-22: Three GGUF Parsers — Unbounded `make([]byte, uint64)` OOM
All three parsers accept untrusted `uint64` length from GGUF header and allocate without bounds:
1. **New core:** `fs/gguf/gguf.go:195` — `make([]byte, length)` from `readKV`
2. **Legacy:** `fs/ggml/gguf.go:361` — same pattern in old parser
3. **Model list cache:** `server/model_list_cache.go:743` — `make([]byte, length)` during cache refresh
**Impact:** Remote OOM kill via `/api/create` with crafted GGUF → model list cache refresh → server crash

### OLLAMA-23: readModelListGGUF Parser Desync
`server/model_list_cache.go:730` — `int64(count * size)` multiplication overflow on 64-bit count/size → parser skips wrong bytes → desync → subsequent models corrupted

### Weight Hijack Status: BROKEN (llama.cpp, not Ollama)
llama.cpp `b9840` (v0.30.7) / `b9888` (v0.31.1+) added vocabulary 1:1 mapping validation.
Malformed GGUF with 260-token vocab and peaked weights fails: `basic_string::substr: __pos (3) > this->size() (1)`.
This is an **accidental mitigation** in llama.cpp — Ollama Go code has ZERO fixes for weight hijack.

### REPORT-17 Unaffected by `detectChatTemplate` Rewrite
v0.31.1 rewrote `detectChatTemplate` to match against KNOWN template registry (levenshtein < 100).
**But** `chatTemplateHasToolSupport` at `server/images.go:194` reads raw `tokenizer.chat_template` KV independently.
Capability injection still works — only template *selection* changed, not capability *detection*.

---

## Environment

**Environment:** Kali (192.168.0.8), Ubuntu (192.168.0.2), VPS (<vps-ip>)
**Test Ollama:** 192.168.0.15:11434 (v0.24.0), updated to v0.31.1 during testing
**Key files created:** `/home/bx0/ollama_vulns/{v0311_AUDIT.md,v0312_v0320_AUDIT.md,exploit_gguf_chat_template.py}`

**Notable discoveries:**
- `detectChatTemplate` rewritten in v0.31.1 — now matches against KNOWN templates only, but capability detection still reads raw KV
- `PreferChatTemplate` logic chooses between Go template and GGUF chat_template based on tool round-trip support
- 3 separate GGUF parsers with identical OOM vectors
- Agent TUI is a new CLI (`ollama agent`) with built-in bash/file/web tools
- **Zero intentional security fixes** in v0.31.1, v0.31.2, v0.32.0-rc0 Go code — all vuln paths intact
- Weight hijack broken ONLY by llama.cpp vocabulary validation upgrade (b9840→b9888)
- Server-side RCE NOT possible via Ollama Go code — attack surface is llama.cpp C++ (memory corruption, template SSTI)

---