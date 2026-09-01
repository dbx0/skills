---
name: ida-reverse
description: |
  IDA Pro reverse engineering analysis assistance skill. Be sure to use this skill when the user mentions reverse engineering, decompilation, analyzing a binary/PE/ELF/APK/DLL/SO, cracking, finding passwords, vulnerability analysis, malware analysis, firmware analysis, or needs to analyze files such as exe/dll/so/elf/macho/sys.

  Ensure to use this skill when the user wants to analyze any binary file, regardless of whether they explicitly mention "IDA" or "reverse engineering". This includes requests like "look at this exe", "analyze this dll", "help me crack it", "find the password", "how do I register this software", etc.

  Use the bundled scripts (scripts/start.ps1, scripts/open.ps1) for deterministic server management and file opening — do NOT write ad-hoc PowerShell commands for these operations.
---

# IDA Pro Reverse Engineering Skill

## Known Issues and Reflections (Required Reading)

### Pitfalls Encountered

1. **`idalib_open` cannot be called directly via certain code AI clients' MCP**
   - Certain code AI clients' MCP client has a BUG validating the output schema of `idalib_open`
   - Error: `Structured content does not match the tool's output schema`
   - **Solution**: use the `scripts/open.ps1` script to call directly via the HTTP API, bypassing the MCP validation layer
   - After a file is opened, the database is bound to the shared context and all other `idapro_*` tools can be used directly

2. **Files under `C:\Windows\System32\` cannot be opened due to permissions**
   - idalib cannot directly read files under the System32 directory
   - **Solution**: `open.ps1` automatically detects and copies the file to a temp directory before opening

3. **The start-server command blocks the conversation**
   - After `idalib-mcp` starts, it continuously outputs INFO logs to the console
   - **Solution**: use `scripts/start.ps1` (`-WindowStyle Hidden` for silent background startup)
   - The script exits automatically once the service is ready, without blocking the conversation

4. **The MCP server name cannot use hyphens**
   - Previously `ida-pro-mcp` was used as the server name, which could cause tool registration issues
   - **Current config**: server name `idapro`, tool prefix `idapro_*`

5. **Remote HTTP vs Local Stdio**
   - `type:"local"` (stdio) mode: `idalib_open` has the same schema validation problem
   - `type:"remote"` (HTTP) mode: you can open the file with the script first, then use MCP tools
   - **Current approach**: Remote HTTP mode

6. **PR #389 fixed part of the schema problem**
   - Author mrexodia merged a fix via PR #389 after issue #388
   - It fixed the structuredContent schema in HTTP mode, but the certain code AI client side still has validation problems
   - The latest `main` branch version is installed

7. **idalib timeout leaves an orphaned worker process lock file**
   - After the first `open.ps1` times out, idalib's python worker child process becomes an orphan and keeps holding onto `.id0`/`.id1`/`.nam`
   - Any subsequent tool or manually dragging into the IDA GUI will report "insufficient permissions"
   - **Solution**: `start.ps1` now uses `taskkill /F /T` to kill the process tree, leaving no orphans
   - **Fallback**: `open.ps1` adds an automatic downgrade; when it detects the old database is locked, it automatically copies to Temp with a GUID prefix

8. **Opening with auto-analysis looks like a hang**
   - `idalib_open(run_auto_analysis=true)` may not return a response for a long time, but the backend is actually still opening and analyzing
   - Previously the user side saw "PowerShell producing no output", which is easily misjudged as a script hang
   - **Current solution**: `open.ps1` adds `-TimeoutSeconds`, and switches to a background request + foreground polling + periodic progress output
   - When polling detects the session is ready, it returns `OK:filename:session_id` early; on timeout it returns `ERR:open_timeout_xxs`

### Workflow Principles

| Step | What to do | What to use |
|------|--------|--------|
| 1 | Ensure the HTTP server is running | `scripts/start.ps1` (no arguments) |
| 2 | Open the target binary file | `scripts/open.ps1 -Path "xxx.exe"` |
| 3 | Use all 72 MCP tools | Call `idapro_*` tools directly |
| 4 | Analysis complete | Tools are automatically available |

## Script Resources

### start.ps1 — Start the MCP HTTP server

Path: `scripts/start.ps1`

- Kills the old process tree with `taskkill /F /T` (cleaning up worker child processes too) -> starts `idalib-mcp` in the background -> waits for readiness (up to 15 seconds)
- Outputs `OK:72` on success, `ERR:timeout` on failure
- The server runs in the background and does not block the conversation

**Invocation**:
```
powershell -File "<skill-root>\ida-reverse\scripts\start.ps1"
```

### open.ps1 — Open a binary file

Path: `scripts/open.ps1`

- Calls `idalib_open` directly via the HTTP API, bypassing MCP schema validation
- Automatically detects System32 paths and copies to a temp directory
- Automatically cleans up old database files with the same name (`.id0`/`.id1`/`.nam`/`.til`/`.i64`)
- When the old database is locked, automatically downgrades: copies to Temp with a GUID prefix before opening, without erroring
- Runs the open request in the background to avoid long synchronous waits that make the script appear unresponsive
- Supports `-TimeoutSeconds`; returns `ERR:open_timeout_xxs` on timeout instead of hanging indefinitely
- Outputs `INFO:opening:elapsed/timeout-seconds` every 10 seconds, to help judge that analysis is still in progress
- Outputs `OK:filename:session_id` on success, adding a `(temp copy)` marker when downgraded
- On failure, automatically retries via the Temp copy

**Invocation**:
```
powershell -File "<skill-root>\ida-reverse\scripts\open.ps1" -Path "C:\path\to\file.exe"
```

**Optional parameters**:
```
# Specify a SessionId
powershell -File "scripts\open.ps1" -Path "file.exe" -SessionId "my_session"

# Skip auto-analysis (recommended for large files)
powershell -File "scripts\open.ps1" -Path "large.exe" -NoAutoAnalysis

# Set a timeout to avoid long periods with no return during auto-analysis
powershell -File "scripts\open.ps1" -Path "file.exe" -TimeoutSeconds 600
```

**Output conventions**:
```
# Analysis in progress (output every 10 seconds)
INFO:opening:11/600s

# Opened successfully
OK:sample.exe:abcd1234

# Opened successfully, but downgraded to a Temp copy due to a lock file
OK:1234abcd-sample.exe:abcd1234 (temp copy)

# Timeout limit reached
ERR:open_timeout_600s
```

**Measured notes**:
- `Snipaste.exe` with auto-analysis took about `324s` to return success in testing, which is "analyzing for a long time" rather than "script deadlock"
- Therefore, when encountering GUI programs or more complex samples, it is recommended to explicitly set `-TimeoutSeconds 600` first

## Core Tool List

### Overview Analysis (First Step)
- `idapro_survey_binary(detail_level="minimal")` — quick overview: function count, strings, segments, entry point, import classification (crypto/network/file IO)
- `idapro_list_funcs(queries)` — list functions (paginated, filter by name)
- `idapro_list_globals(queries)` — list global variables
- `idapro_entity_query(kind, filter)` — unified query: functions/globals/imports/strings/names

### Decompilation and Disassembly
- `idapro_decompile(addr)` — decompile to pseudocode
- `idapro_disasm(addr, max_instructions=N)` — disassemble
- `idapro_analyze_function(addr, include_asm=false)` — comprehensive analysis (pseudocode + strings + constants + callers + callees + blocks)
- `idapro_func_profile(queries)` — function summary metrics

### Cross-references and Data Flow
- `idapro_xrefs_to(addrs)` — find who references the target address
- `idapro_xref_query(addr, direction)` — advanced xref query (direction/type filter)
- `idapro_callees(addrs)` — callee list
- `idapro_callgraph(roots, max_depth)` — call graph
- `idapro_trace_data_flow(addr, direction, max_depth)` — data flow tracing (forward/backward)

### Search
- `idapro_find_regex(pattern, limit)` — regex search strings
- `idapro_search_text(pattern)` — search text in the disassembly listing
- `idapro_find_bytes(patterns, limit)` — byte pattern search (supports ?? wildcards)
- `idapro_find(type, targets)` — advanced search (immediates/strings/references)

### Memory and Data
- `idapro_get_bytes(addrs)` — read raw bytes
- `idapro_get_string(addrs)` — read strings
- `idapro_get_int(queries)` — read integer values
- `idapro_get_global_value(queries)` — read global variable values
- `idapro_read_struct(queries)` — read struct field values
- `idapro_search_structs(filter)` — search structs

### Modification Operations
- `idapro_set_comments(items)` — add comments (bidirectionally synced between disassembly and decompilation)
- `idapro_append_comments(items)` — append comments
- `idapro_rename(batch)` — batch rename (functions/globals/locals/stack variables)
- `idapro_patch_asm(items)` — patch assembly instructions
- `idapro_patch(patches)` — patch bytes
- `idapro_define_func(items)` — define a function
- `idapro_undefine(items)` — undefine
- `idapro_define_code(items)` — convert bytes to code

### Type System
- `idapro_declare_type(decls)` — declare C structs/enums/unions
- `idapro_set_type(edits)` — apply types to functions/globals/locals
- `idapro_infer_types(addrs)` — infer types
- `idapro_type_query(queries)` — query declared types
- `idapro_type_inspect(queries)` — view type details

### Stack Frames
- `idapro_stack_frame(addrs)` — view stack frame variables
- `idapro_declare_stack(items)` — declare stack variables
- `idapro_delete_stack(items)` — delete stack variables

### Signatures
- `idapro_make_signature(addrs)` — generate a unique byte signature for an address
- `idapro_make_signature_for_function(addrs)` — generate a signature for a function
- `idapro_find_xref_signatures(addrs)` — generate signatures for code that references an address

### Debugger (requires ?ext=dbg)
- `idapro_open_file(file_path)` — open a file in the GUI IDA instance
- Debugger tools are hidden by default and can be enabled via the URL parameter `?ext=dbg`

### Session Management
- `idapro_idalib_open(input_path)` — ⚠️ has a schema validation BUG, use the `open.ps1` script instead
- `idapro_idalib_list()` — list all sessions
- `idapro_idalib_current()` — the session bound to the current context
- `idapro_idalib_switch(session_id)` — switch to another session
- `idapro_idalib_close(session_id)` — close a session
- `idapro_idalib_save(path)` — save the database
- `idapro_idalib_health(session_id)` — check worker health status

### Others
- `idapro_int_convert(inputs)` — base conversion (**must use this, do not compute bases yourself!**)
- `idapro_export_funcs(addrs, format)` — export functions (json/c_header/prototypes)
- `idapro_py_eval(code)` — execute Python in the IDA context
- `idapro_server_health()` — server health check
- `idapro_server_warmup()` — warm up subsystems (string cache, Hex-Rays, etc.)

## Complete Reverse Engineering Workflow

### Step 1: Start the server
Ensure the HTTP service is running in the background.
```
powershell -File "scripts/start.ps1"
```
Output `OK:72` indicates readiness.

### Step 2: Open the file
```
powershell -File "scripts/open.ps1" -Path "C:\target.exe" -TimeoutSeconds 600
```
Output `OK:filename:session_id` indicates success (a trailing `(temp copy)` indicates an automatic downgrade to a temp copy).
If analysis takes a while, it periodically outputs `INFO:opening:...`; if the timeout is reached it outputs `ERR:open_timeout_xxs`.

### Step 3: Global overview
```
idapro_survey_binary(detail_level="minimal")
```
Focus on:
- Architecture (x86/x64/ARM)
- Entry point (main/WinMain/DllMain)
- Interesting strings (URLs, paths, error messages)
- Import classification (crypto functions? network APIs? file operations?)
- Hot functions (functions with high xref counts are usually key logic)

### Step 4: Dive into key functions
```
idapro_analyze_function(addr="key function name")
```
Or:
```
idapro_decompile(addr="function name")
idapro_disasm(addr="function name", max_instructions=50)
```

### Step 5: Data flow and cross-references
```
idapro_xrefs_to(addrs="key address/string")
idapro_callgraph(roots=["key function"], max_depth=3)
idapro_trace_data_flow(addr="key address", direction="backward", max_depth=5)
```

### Step 6: Record and refine
```
idapro_set_comments(items=[{"addr": "0x140001000", "comment": "your understanding"}])
idapro_rename(batch={"func": [{"addr": "function address", "name": "meaningful name"}]})
```

### Step 7: Output report
After analysis is complete, generate `report.md` recording findings and steps.

## Prompt Engineering Guidelines

1. **Do not compute bases manually** — whenever you need to convert a number, use `idapro_int_convert`
2. **Survey first, then dive** — look at the overview before targeted analysis
3. **Continuously add comments and rename** — keep updating function and variable names during analysis to improve the accuracy of later analysis
4. **Track cross-references** — when you find interesting data/strings, use `xrefs_to` to see who references them
5. **When encountering obfuscated code** — first do preprocessing such as string decryption, import-hash removal, and control-flow flattening removal
6. **C++ STL code** — use FLIRT/Lumina to identify library functions, then analyze the business logic
7. **Do not brute-force** — analysis should derive the solution from the disassembly, using simple Python for auxiliary computation
8. **When you hit "No database bound"** — no binary has been opened yet; run `open.ps1` first
9. **When you hit "Failed to open database"** — the old database file may be locked; `open.ps1` will automatically downgrade to a Temp copy (output includes a `(temp copy)` marker)
10. **When opening GUI/complex samples with auto-analysis** — add `-TimeoutSeconds 600` by default, and do not misjudge long `INFO:opening:...` output as a script hang

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (controller), `routing.md`
**Upstream alternative**: `radare2/` (if you don't want to open IDA, you can do quick recon with r2 first)
**Downstream exits**:
- Need Frida dynamic verification -> `reverse-engineering/tools-dynamic.md`
- Need symbolic execution/angr -> `reverse-engineering/tools-dynamic.md`
- Need general reverse-engineering methodology -> `reverse-engineering/SKILL.md`

**Peer-level related modules**: `radare2/` (fallback when IDA is unavailable)

---

## On-Demand Bootstrap

This skill's entry scripts are integrated with the unified bootstrap system.

### Automation Capability Boundaries

| Tool | Auto-installable | Install method | Notes |
|------|-----------|---------|------|
| idalib-mcp | ✓ | pip install (from GitHub) | Auto-installed when `start.ps1` is missing it |
| IDA Pro itself | ✗ | Commercial software, must install manually | Set the `IDADIR` environment variable to point to the install directory |

### Installation Steps (verified)

```cmd
# 1. Set the IDA path (replace with your actual IDA install directory)
setx IDADIR "<your IDA install directory>"

# 2. Install ida-pro-mcp from GitHub (the ida-mcp on PyPI is a different project, don't install the wrong one!)
pip install git+https://github.com/mrexodia/ida-pro-mcp.git

# 3. Install the IDA plugin (choose Streamable HTTP + Global + select all clients)
ida-pro-mcp --install

# 4. Restart IDA Pro and open the target file
# The plugin automatically listens on 127.0.0.1:13337

# 5. Verify
ida-pro-mcp --config
```

> ⚠️ **Note**: the `ida-mcp` package on PyPI (author jtsylve) is a different project, not the one we need.
> You must install `mrexodia/ida-pro-mcp` from GitHub.

### Bootstrap Trigger Points

- `scripts/start.ps1`: automatically calls `bootstrap-reverse.ps1` when `idalib-mcp` is missing
- MCP registration: the bootstrap automatically writes `idapro` into the Claude MCP configuration

### Preconditions

- IDA Pro is installed and the `IDADIR` environment variable is set (or the script's default path is correct)
- Python is installed (idalib-mcp depends on Python)
