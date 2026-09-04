# MCP tool integration — jshookmcp

> This document is the tool map for the src-hunter skill to call the local MCP server.

src-hunter is a black-box vulnerability-hunting skill; it assumes by default that you have only a URL, no source code, and no internal information. jshookmcp bundles browser automation, CDP debugging, network interception, JS hooking, deobfuscation, Frida memory forensics, WASM reverse engineering, and source-map reconstruction into a single MCP server, directly serving the five things the hunt phase needs: "read the code / run the payload / intercept data / defeat anti-debug / deobfuscate".

Tool references use the full MCP-protocol name `mcp__jshook__<tool>`. All tool names come from `.omc/tool-manifest.json` (the actual `search_tools` return value in jshookmcp 0.3.0) — **do not invent names**.

## 36-domain index

jshookmcp distributes 134+ tools across 36 capability domains. The table below annotates each domain's core purpose and representative tools (BARE names; add the `mcp__jshook__` prefix when actually calling).

| Domain | When to use | Representative tools |
|---|---|---|
| `adb-bridge` | Android device ADB bridging / APK analysis / WebView remote debug | `adb_apk_analyze` / `adb_webview_attach` / `adb_webview_list` |
| `antidebug` | Bypass debugger / timing / headless fingerprint detection | `antidebug_bypass` |
| `binary-instrument` | Frida script generation / Ghidra decompilation / hook template export | `frida_run_script` / `generate_hooks` / `ghidra_decompile` / `frida_generate_script` |
| `boringssl-inspector` | TLS handshake parsing / SSL pinning bypass / SSLKEYLOGFILE | `tls_cert_pin_bypass_frida` / `tls_keylog_enable` / `tls_probe_endpoint` |
| `browser` | Browser automation / CDP evaluation / anti-detection stealth | `browser_evaluate_cdp_target` / `page_evaluate` / `stealth_inject` |
| `canvas` | Canvas / WebGL engine fingerprinting and object picking | `canvas_engine_fingerprint` / `canvas_pick_object_at_point` |
| `coordination` | Cross-task handoff / page snapshot / session insight | `save_page_snapshot` / `create_task_handoff` / `get_task_context` |
| `core` | Code collection / deobfuscation main pipeline / hook management / crypto detection | `collect_code` / `deobfuscate` / `js_deobfuscate_pipeline` / `detect_crypto` |
| `cross-domain` | Cross-domain evidence-graph aggregation / workflow suggestions | `cross_domain_correlate_all` / `cross_domain_suggest_workflow` |
| `debugger` | JS breakpoints / stepping / expression evaluation / blackbox | `debugger_evaluate` / `debugger_pause` / `debugger_step` / `blackbox_add_common` |
| `encoding` | base64 / protobuf / binary encode-decode | `binary_encode` / `binary_decode` / `protobuf_decode_raw` |
| `evidence` | Reverse evidence-graph query / export / provenance chain | `evidence_query` / `evidence_export` / `evidence_chain` |
| `extension-registry` | Webhook endpoint management (external callbacks) | `webhook` |
| `graphql` | GraphQL introspection / query extraction / replay | `graphql_introspect` / `graphql_extract_queries` / `graphql_replay` |
| `hooks` | JS runtime hook presets (eval/atob/Reflect and 20+ more) | `hook_preset` / `ai_hook` |
| `instrumentation` | Hooks within an instrumented session / network replay / artifacts | `instrumentation_hook_preset` / `instrumentation_network_replay` |
| `macro` | Record / replay tool-call sequences | `run_macro` / `list_macros` |
| `maintenance` | Environment health check / bridge endpoint diagnostics | `doctor_environment` |
| `memory` | In-process memory patch rollback (with Frida) | `memory_patch_undo` |
| `mojo-ipc` | Chromium Mojo IPC monitoring / decoding | `mojo_monitor` / `mojo_messages_get` / `mojo_decode_message` |
| `network` | Request interception / replay / HAR / HTTP2 / performance metrics | `network_intercept` / `network_replay_request` / `http2_probe` / `network_extract_auth` |
| `platform` | Electron / ASAR app analysis / fuse state | `electron_inspect_app` / `electron_ipc_sniff` / `asar_search` |
| `process` | Process-level CDP attach (Electron, etc.) | `electron_attach` |
| `protocol-analysis` | Protocol state-machine inference / ICMP / pattern visualization | `proto_infer_state_machine` / `icmp_echo_build` / `proto_visualize_state` |
| `proxy` | Local proxy start/stop / CA management / Android hookup | `proxy_setup_adb_device` / `proxy_status` / `proxy_stop` |
| `sandbox` | Execute JS inside a QuickJS WASM sandbox | `execute_sandbox_script` |
| `shared-state-board` | Multi-agent shared state board (observe + IO) | `state_board` / `state_board_watch` / `state_board_io` |
| `skia-capture` | Skia scene-tree extraction / renderer detection / node correlation | `skia_extract_scene` / `skia_detect_renderer` |
| `sourcemap` | Source-map fetching / parsing / source-tree reconstruction | `sourcemap_fetch_and_parse` / `sourcemap_reconstruct_tree` / `sourcemap_parse_v4` |
| `streaming` | WebSocket connections and frame capture | `ws_monitor` / `ws_get_connections` |
| `syscall-hook` | Process-level syscall monitoring (ETW / strace / dtrace) | `syscall_start_monitor` / `syscall_get_stats` |
| `trace` | SQLite trace recording / network-flow tracing / Chrome Trace export | `trace_recording` / `trace_get_network_flow` / `export_trace` |
| `transform` | AST rewriting / crypto-function extraction / implementation comparison | `ast_transform_apply` / `crypto_extract_standalone` / `crypto_compare` |
| `v8-inspector` | V8 bytecode extraction / version detection | `v8_bytecode_extract` / `v8_version_detect` |
| `wasm` | WebAssembly disasm / decompile / memory / obfuscation detection | `wasm_disassemble` / `wasm_decompile` / `wasm_dump` / `wasm_detect_obfuscation` |
| `workflow` | Extension workflows / batch API probing / remote bundle search | `js_bundle_search` / `api_probe_batch` / `run_extension_workflow` |

---

## Scenario → tool mapping table

This is the heart of the document. It maps common actions in the SRC hunt phase to jshook tools, annotated with the related src-hunter playbook and the call timing.

| Scenario | Vulnerability type | Recommended tools (`mcp__jshook__*`) | Related playbook | Call timing |
|---|---|---|---|---|
| Intercept outbound requests / observe SSRF | SSRF | `mcp__jshook__network_intercept` + `mcp__jshook__network_get_requests` | ssrf-cache-host.md | passive observation during probing |
| Craft HTTP/2 frames to probe internal | SSRF | `mcp__jshook__http2_probe` + `mcp__jshook__http_request_build` | ssrf-cache-host.md | active filter bypass |
| Replay a modified SSRF request | SSRF | `mcp__jshook__network_replay_request` | ssrf-cache-host.md | verify different protocols / Host headers |
| Run an XSS payload in the browser | XSS | `mcp__jshook__browser_evaluate_cdp_target` + `mcp__jshook__page_evaluate` | xss.md | verify blind / DOM XSS |
| Inject an XSS payload into the page | XSS | `mcp__jshook__page_inject_script` | xss.md | persistent injection |
| Deobfuscate obfuscated JS / AST rewrite | XSS / RCE | `mcp__jshook__ast_transform_apply` + `mcp__jshook__deobfuscate` | xss.md / rce.md | analyze obfuscated business code |
| JSVMP / VM-protected JS deobfuscation | XSS / RCE | `mcp__jshook__js_deobfuscate_jsvmp` + `mcp__jshook__js_deobfuscate_pipeline` | xss.md / rce.md | heavily obfuscated sites |
| Recover original source via source map | Info disclosure / XSS | `mcp__jshook__sourcemap_fetch_and_parse` + `mcp__jshook__sourcemap_reconstruct_tree` | xss.md | find sinks / find interfaces |
| Enumerate Webpack bundle modules | Info disclosure | `mcp__jshook__webpack_enumerate` + `mcp__jshook__js_bundle_search` | xss.md | find frontend secrets / internal APIs |
| Identify / extract crypto algorithms | OAuth / XSS / API | `mcp__jshook__detect_crypto` + `mcp__jshook__crypto_extract_standalone` | oauth-saml-jwt.md / xss.md | recover signing logic |
| eval / atob / Function preset hooks | XSS / RCE | `mcp__jshook__hook_preset` | xss.md / rce.md | find runtime deserialization sinks |
| Set DOM breakpoints / step to the sink | XSS | `mcp__jshook__debugger_pause` + `mcp__jshook__debugger_step` + `mcp__jshook__get_call_stack` | xss.md | DOM XSS dataflow tracing |
| Capture and disassemble a WASM module | RCE | `mcp__jshook__wasm_dump` + `mcp__jshook__wasm_disassemble` + `mcp__jshook__wasm_decompile` | rce.md | reverse WASM business logic |
| WASM obfuscation detection / to C | RCE | `mcp__jshook__wasm_detect_obfuscation` + `mcp__jshook__wasm_to_c` | rce.md | crypto / risk-control core |
| Frida script generation and injection | RCE | `mcp__jshook__generate_hooks` + `mcp__jshook__frida_run_script` | rce.md | verify the RCE landing point |
| Export a runnable Frida hook script | RCE | `mcp__jshook__export_hook_script` | rce.md | offline retest |
| Ghidra function decompilation | RCE | `mcp__jshook__ghidra_decompile` | rce.md | binary deserialization scenarios |
| Bypass anti-debug / debugger detection | XSS / RCE / Mobile | `mcp__jshook__antidebug_bypass` | xss.md / rce.md / mobile.md | target actively anti-debugs |
| Extract Android APK info | Mobile | `mcp__jshook__adb_apk_analyze` | mobile.md | before static analysis |
| Android WebView remote debug | Mobile | `mcp__jshook__adb_webview_attach` + `mcp__jshook__adb_webview_list` | mobile.md | in-app embedded H5 |
| SSL pinning bypass (Frida) | Mobile | `mcp__jshook__tls_cert_pin_bypass_frida` + `mcp__jshook__tls_cert_pin_bypass` | mobile.md | before APK interception |
| Capture keys via SSLKEYLOGFILE | Mobile / API | `mcp__jshook__tls_keylog_enable` + `mcp__jshook__tls_keylog_parse` | mobile.md / oauth-saml-jwt.md | for Wireshark decryption |
| Android proxy hookup | Mobile | `mcp__jshook__proxy_setup_adb_device` + `mcp__jshook__proxy_status` | mobile.md | before traffic observation |
| JWT / token extraction | OAuth/SAML/JWT | `mcp__jshook__network_extract_auth` | oauth-saml-jwt.md | auto-find Authorization / cookie |
| JWT base64 encode-decode | OAuth/SAML/JWT | `mcp__jshook__binary_encode` + `mcp__jshook__binary_decode` | oauth-saml-jwt.md | tamper with header / payload |
| redirect_uri chain debugging | OAuth | `mcp__jshook__debugger_evaluate` + `mcp__jshook__network_replay_request` | oauth-saml-jwt.md | find open redirect |
| GraphQL introspection | API REST | `mcp__jshook__graphql_introspect` | api-rest.md | expand assets |
| GraphQL historical query extraction | API REST | `mcp__jshook__graphql_extract_queries` + `mcp__jshook__graphql_replay` | api-rest.md | replay business requests |
| REST batch endpoint probing | API REST | `mcp__jshook__api_probe_batch` | api-rest.md | batch BOLA / mass-assignment |
| WebSocket frame capture | API REST | `mcp__jshook__ws_monitor` + `mcp__jshook__ws_get_connections` | api-rest.md | real-time business / push |
| File-upload polyglot encoding | File Upload | `mcp__jshook__binary_encode` + `mcp__jshook__binary_decode` | file-upload.md | craft image+script blends |
| File-upload AST rewrite to bypass filters | File Upload | `mcp__jshook__ast_transform_apply` + `mcp__jshook__ast_transform_preview` | file-upload.md | change magic bytes / fix polyglot |
| File-upload multipart boundary change | File Upload | `mcp__jshook__http_plain_request` + `mcp__jshook__network_replay_request` | file-upload.md | bypass MIME checks |
| Protobuf binary blind decode | API REST / info disclosure | `mcp__jshook__protobuf_decode_raw` | api-rest.md | analyze schema-less captures |
| Electron app static structure | RCE / info disclosure | `mcp__jshook__electron_inspect_app` + `mcp__jshook__asar_search` | rce.md | desktop targets |
| Electron IPC monitoring | RCE | `mcp__jshook__electron_ipc_sniff` | rce.md | renderer ↔ main IPC bugs |
| Chromium Mojo IPC monitoring | RCE | `mcp__jshook__mojo_monitor` + `mcp__jshook__mojo_messages_get` | rce.md | browser-kernel vulnerability research |
| Process syscall monitoring | RCE | `mcp__jshook__syscall_start_monitor` + `mcp__jshook__syscall_get_stats` | rce.md | verify post-RCE behavior |
| Protocol state-machine inference | API / info disclosure | `mcp__jshook__proto_infer_state_machine` + `mcp__jshook__proto_visualize_state` | api-rest.md | reverse a custom protocol |
| Full-traffic trace persistence | Investigation / report | `mcp__jshook__trace_recording` + `mcp__jshook__export_trace` | all playbooks | evidence retention / timeline review |
| Anti-detection stealth injection | Long-running tests | `mcp__jshook__stealth_inject` + `mcp__jshook__stealth_verify` | xss.md / api-rest.md | long observation of risk-control sites |
| Cross-domain evidence aggregation | Investigation | `mcp__jshook__cross_domain_correlate_all` + `mcp__jshook__evidence_export` | all playbooks | multi-source alignment / reporting |

---

## Recommended profile

jshookmcp offers three profiles, switched via the environment variable `JSHOOK_BASE_PROFILE` or a tool call. **`search` mode is the default**, in keeping with src-hunter's context-economy principle.

| Profile | Context cost (tokens) | Applies to | How to enable |
|---|---|---|---|
| `search` (**default**) | ~3K | on-demand activation, single-point calls, normal SRC hunt | `JSHOOK_BASE_PROFILE=search` (already the default) |
| `workflow` | medium | continuous orchestration, cross-domain collaboration, reusing the same tool family within one session | call `mcp__jshook__boost_profile workflow` (if available) |
| `full` | 40K+ | when you know you'll use 50%+ of the tools, e.g. a large batch task | call `mcp__jshook__boost_profile full` |

**Default recommended workflow**:

1. `mcp__jshook__search_tools <keyword>` (BM25 retrieval, bucketed by hunt keyword)
2. Take the top-3 results, `mcp__jshook__activate_tools <tool name list>` to activate
3. Call the activated tools
4. For cross-domain collaboration: `mcp__jshook__activate_domain <domain>` to activate a whole domain at once

**Anti-pattern**: do not `boost_profile` for a single tool; it loads 40K+ tokens at once and severely wastes context. Only upgrade when you know you'll heavily reuse a whole tool family next.

---

## Built-in Burp Suite bridge

⚠️ **Local test note**: on the local jshookmcp 0.3.0 build, `mcp__jshook__search_tools burp` **returns** no `burp_*` atomic tools, only:

- `doctor_environment` (maintenance domain; its description mentions a "bridge endpoints" health check)
- generic `proxy_*` tools (proxy domain: start/stop / status / CA management)

The upstream jshookmcp README claims built-in Burp / Ghidra / IDA Pro bridges, but the current 0.3.0 build does not expose the Burp bridge as separate atomic tools.

**Practical alternative path (R8 fallback)**:

1. **Activate the proxy + cross-domain domains**:
   ```
   mcp__jshook__activate_domain proxy
   mcp__jshook__activate_domain cross-domain
   ```
2. **Use `proxy_*` to start a local proxy + CA**, and configure Burp as an upstream proxy chain or reverse hookup.
3. **Use `mcp__jshook__doctor_environment` to check the bridge endpoint status**; if a later jshook version exposes a Burp bridge API, it shows up here.
4. **Use `network_*` + `instrumentation_network_replay` to replace Burp Repeater automation**: `network_replay_request` already handles the batch request-editing of most Repeater scenarios.
5. **Combine `evidence_*` / `cross_domain_correlate_all`**: merge jshook-captured requests with external Burp data manually via the evidence graph (export JSON, then aggregate).

**When you still need a standalone burp-mcp-server**:

- You need Burp Scanner active-scan results fed directly into the LLM
- You need a custom scan check written as a Burp Extender to fire
- Complex Repeater macro / session-handling-rule coordination

If those scenarios apply, register the official Burp MCP separately in `~/.claude.json` (out of scope of this doc), and document it in `references/tools/mcp-burp.md` (future).

---

## Related src-hunter playbooks

The table below shows this MCP's role distribution across src-hunter's 19 playbooks. **This iteration primarily selects 7 highly-related playbooks plus reverse anchors**; the other 12 are untouched this time (see the ADR Follow-ups in `.omc/plans/mcp-tools-integration.md`; sqli / path-traversal / graphql are planned for the next iteration).

| Playbook | Main jshook domains | This MCP's role |
|---|---|---|
| [xss.md](../playbooks/xss.md) | browser / debugger / transform / hooks / sourcemap / core | browser execution + AST deobfuscation + sink breakpoints + source-map recovery |
| [rce.md](../playbooks/rce.md) | wasm / antidebug / binary-instrument / memory / platform / mojo-ipc / syscall-hook | WASM reversing + Frida memory verification + anti-debug + Electron / Chromium IPC |
| [ssrf-cache-host.md](../playbooks/ssrf-cache-host.md) | network / proxy / protocol-analysis | network interception + HTTP/2 crafting + protocol state-machine inference |
| [mobile.md](../playbooks/mobile.md) | adb-bridge / boringssl-inspector / proxy / binary-instrument | SSL pinning bypass + APK info + WebView remote debug + Frida hooks |
| [oauth-saml-jwt.md](../playbooks/oauth-saml-jwt.md) | network / encoding / debugger / core | JWT tampering + redirect_uri debugging + crypto-algorithm identification |
| [api-rest.md](../playbooks/api-rest.md) | graphql / network / workflow / streaming / protocol-analysis | introspection + batch API + WebSocket frames + protocol blind decode |
| [file-upload.md](../playbooks/file-upload.md) | encoding / transform / network | polyglot encoding + AST rewriting + multipart request editing |

**Uncovered playbooks** (to be added next iteration): sqli / path-traversal / graphql / arbitrary-x-authz / logic-flaws / unauth-access / info-disclosure / http-smuggling / race-conditions / dos / llm-prompt-injection / intranet-postexp.

---
