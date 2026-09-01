---
name: js-reverse
description: Use when performing frontend JavaScript reverse engineering with js-reverse-mcp. Suitable for locating signature chains, page observation and evidence collection, runtime sampling, local environment-shim reproduction, and evidence-backed output. Prefer the js-reverse_* tools available in the current environment; when a stronger browser/CDP/Hook surface is needed, work alongside jshookmcp.
---

# MCP Frontend JS Reverse Engineering Operating Guide

## Scope

Prefer this skill when the task falls into the following scenarios:

- Locating API signatures, encryption parameters, and anti-fraud fields
- Observing page request chains and script origins
- Capturing function arguments and return values at runtime
- Tracing the trigger point of an XHR/Fetch/WebSocket call
- Bringing page evidence back to Node for local reproduction and environment shimming

If the target is a binary, APK, PE, ELF, DLL, or SO, use `ida-reverse`, `radare2`, or `reverse-engineering` instead.

## Default Tool Mapping in the Current Environment

This skill does not assume that bare tool names exist; instead it binds by default to the `js-reverse_*` tools available in the current client environment.

If the current task explicitly mentions `jshookmcp`, `JS hook`, `CDP`, browser breakpoints, network interception, SourceMap, or AST deobfuscation, still use this skill; simply switch the underlying MCP surface to `jshookmcp` rather than treating it as a new top-level entry point.

Precondition: `jshookmcp` is not a local bare-command tool but an MCP server that must first be downloaded/registered/enabled. Only after it is connected and enabled in the Claude MCP configuration will its tool surface become truly callable.

Common mappings:

- `list_scripts` -> `js-reverse_list_scripts`
- `get_script_source` -> `js-reverse_get_script_source`
- `search_in_sources` -> `js-reverse_search_in_sources`
- `break_on_xhr` -> `js-reverse_break_on_xhr`
- `evaluate_script` -> `js-reverse_evaluate_script`
- `get_paused_info` -> `js-reverse_get_paused_info`
- `set_breakpoint_on_text` -> `js-reverse_set_breakpoint_on_text`
- `list_network_requests` -> `js-reverse_list_network_requests`
- `get_request_initiator` -> `js-reverse_get_request_initiator`
- `get_websocket_messages` -> `js-reverse_get_websocket_messages`
- `take_screenshot` -> `js-reverse_take_screenshot`
- `new_page` -> `js-reverse_new_page`
- `navigate_page` -> `js-reverse_navigate_page`
- `select_page` -> `js-reverse_select_page`
- `select_frame` -> `js-reverse_select_frame`
- `pause/resume` -> `js-reverse_pause_or_resume`

If the tool name prefix changes in the future, update this section first; do not guess at execution time.

### The Role of jshookmcp

- Role: an enhanced execution surface for `js-reverse`, not a standalone controller
- Good for: browser automation, CDP debugging, JS Hook, network interception, SourceMap reconstruction, AST-assisted understanding
- Call precondition: first download and register `@jshookmcp/jshook` into the MCP client configuration, then ensure the server is enabled
- Recommended entry: still execute according to `Observe -> Capture -> Rebuild`, only preferring jshookmcp's browser and Hook capabilities during the `Observe/Capture` stages
- Relationship with anything-analyzer: both can perform browser/network-side evidence collection; anything-analyzer leans toward packet capture and HTTP analysis, while jshookmcp leans toward the JS runtime, CDP, Hook, and source understanding

## Core Principles

- `Observe-first`
- `Hook-preferred`
- `Breakpoint-last`
- `Rebuild-oriented`
- `Evidence-first`

Observe the page first, then sample minimally, then perform local environment shimming. Do not skip evidence collection and jump straight to guessing the environment.

## Five-Stage Workflow

### 1. Observe

Goal: first confirm the target request, related scripts, and candidate functions; do not guess the environment.

Default actions:

- Use `js-reverse_new_page` or `js-reverse_navigate_page` to open the target page
- Use `js-reverse_list_network_requests` to find the target request
- Use `js-reverse_get_request_initiator` to trace back the call origin
- Use `js-reverse_list_scripts` and `js-reverse_search_in_sources` to narrow down the script scope

Required outputs:

- Target request URL or signature
- Initiator leads
- Suspicious script URLs
- Initial task record

### 2. Capture

Goal: perform minimally invasive sampling on the target request to obtain sample parameters, call ordering, and runtime evidence.

Rules:

- Prefer `js-reverse_break_on_xhr`
- Prefer `js-reverse_evaluate_script` for lightweight runtime observation
- After a hit, first check `js-reverse_get_paused_info`
- Use `js-reverse_set_breakpoint_on_text` only when necessary

### 3. Rebuild

Goal: organize the page evidence into locally iterable Node reproduction material.

Rules:

- Local environment shimming must be based on observed page evidence
- Do not blindly shim `window/document/navigator/crypto/storage` from imagination
- Record only one minimal causal patch decision at a time

### 4. Patch

Goal: drive environment shimming based on errors and the first divergence, until the local script stably produces the target parameters.

Rules:

- First see what is missing, then shim what is missing
- Make only one minimal patch decision at a time
- Retest immediately after each patch
- Write each patch into the task record

### 5. DeepDive

Goal: after the local script works, perform deobfuscation, control-flow recovery, and business-logic distillation.

Rules:

- If the current task is only to produce the signature, this stage can be de-prioritized
- If the algorithm chain needs to be reused long-term, this stage is mandatory

## Execution Requirements

- All important steps must be written into the local task artifact
- If you cannot explain why you are calling a given tool, do not call it
- Prefer collecting evidence directly with the ready-made MCP capabilities of `js-reverse_*` or jshookmcp; do not write scripts to recreate capabilities first
- On failure, fall back per `references/fallbacks.md`
- Output follows `references/output-contract.md`

## Required Reading

- Automation entry: `references/automation-entry.md`
- Parameter defaults: `references/tool-defaults.md`
- Task input template: `references/task-input-template.md`
- MCP-specific task orchestration: `references/mcp-task-template.md`
- Task artifacts: `references/task-artifacts.md`
- Local reproduction: `references/local-rebuild.md`
- Environment shimming: `references/env-patching.md`
- Node reproduction: `references/node-env-rebuild.md`
- Instrumentation: `references/instrumentation.md`
- AST deobfuscation: `references/ast-deobfuscation.md`
- Fallbacks: `references/fallbacks.md`
- Output contract: `references/output-contract.md`

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (controller), `routing.md`
**Upstream alternatives**:
- The browser tools of anything-analyzer MCP (port 23816) can serve as a substitute or supplement
- jshookmcp can serve as a stronger browser/CDP/Hook/Network/SourceMap/AST execution surface
- `reverse-engineering/SKILL.md` (if the target is not frontend JS)

**Downstream exits**:
- Need environment shimming -> `references/env-patching.md`
- Need local reproduction -> `references/local-rebuild.md` / `references/node-env-rebuild.md`
- Need deobfuscation -> `references/ast-deobfuscation.md`
- When stuck, fall back -> `references/fallbacks.md`

**Peer-level related modules**: anything-analyzer MCP (its browser automation and HTTP capture capabilities are complementary)

---

## On-Demand Bootstrap

The MCP capabilities this skill depends on can be automatically registered via the unified bootstrap system.

### Automation Capability Boundaries

| Capability | Auto-registerable | Method | Notes |
|------|-----------|------|------|
| jshookmcp | ✓ | npm-mcp (launched via npx) | Automatically written into the Claude MCP configuration |
| anything-analyzer | ✓ | local-http-mcp | Auto-registered + service can be auto-started |
| Node.js | ✓ | winget install | Runtime dependency |

### Bootstrap Method

```powershell
# Register jshookmcp into the MCP configuration
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('jshookmcp')

# Register and start anything-analyzer
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('anything-analyzer') -StartServices
```

### Notes

- After `jshookmcp` is registered, you still need to **enable** the MCP server in the AI client before it can be called
- `anything-analyzer` requires pnpm and the project source; the bootstrap automatically clones and installs dependencies
- If Node.js is not installed, the bootstrap first installs Node.js 22 via winget
