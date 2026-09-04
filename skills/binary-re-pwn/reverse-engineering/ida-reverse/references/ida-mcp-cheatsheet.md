# IDA Pro MCP Tool Quick Reference

> 72 MCP tools grouped by function, with common parameters and typical usage.
> Server name: `idapro`, tool prefix: `idapro_*`, runs in HTTP mode.

---

## Startup and Session Management

### Starting the Server

```powershell
# Start the MCP HTTP server (silent, in the background)
powershell -File "scripts/start.ps1"
# Output OK:72 means it is ready

# Open the target file (bypasses schema validation)
powershell -File "scripts/open.ps1" -Path "C:\target.exe"
# Output OK:filename:session_id

# For large files/GUI programs, add a timeout
powershell -File "scripts/open.ps1" -Path "C:\big.exe" -TimeoutSeconds 600

# Skip auto analysis (fast open)
powershell -File "scripts/open.ps1" -Path "C:\huge.sys" -NoAutoAnalysis
```

### Session Tools

| Tool | Purpose | Example |
|------|------|------|
| `idapro_idalib_list()` | List every session | — |
| `idapro_idalib_current()` | The currently bound session | — |
| `idapro_idalib_switch(session_id)` | Switch sessions | When comparing multiple files |
| `idapro_idalib_close(session_id)` | Close a session | Free resources |
| `idapro_idalib_save(path)` | Save the database | Save analysis progress |
| `idapro_idalib_health(session_id)` | Check worker status | Troubleshoot a hang |
| `idapro_server_health()` | Server health check | — |
| `idapro_server_warmup()` | Warm up subsystems | Before first use |

---

## Step One: Global Overview

### survey_binary, a quick overview

```
idapro_survey_binary(detail_level="minimal")
```

Returns:
- Architecture (x86/x64/ARM/MIPS)
- Entry point
- Total function count
- String statistics
- Segment information
- Import classification (crypto/network/file IO/registry)
- Hot functions with high xref counts

**detail_level options**:
- `"minimal"`, a quick overview (recommended first choice)
- `"standard"`, includes more detail
- `"full"`, complete information

### Function Listing

```
# List all functions (paginated)
idapro_list_funcs(queries=[{"offset": 0, "limit": 50}])

# Filter by name
idapro_list_funcs(queries=[{"filter": "crypt", "offset": 0, "limit": 20}])
idapro_list_funcs(queries=[{"filter": "main", "offset": 0, "limit": 10}])
```

### Unified Query

```
# Query imported functions
idapro_entity_query(kind="imports", filter="Create")

# Query strings
idapro_entity_query(kind="strings", filter="http")

# Query all named symbols
idapro_entity_query(kind="names", filter="")
```

---

## Decompilation and Disassembly

### Decompilation (pseudocode)

```
# By function name
idapro_decompile(addr="main")
idapro_decompile(addr="sub_140001000")

# By address
idapro_decompile(addr="0x140001000")
```

### Disassembly

```
# Default instruction count
idapro_disasm(addr="main")

# Specify the instruction count
idapro_disasm(addr="0x401000", max_instructions=100)
```

### Combined Analysis (recommended)

```
# Get it all at once: pseudocode + strings + constants + callers + callees + basic blocks
idapro_analyze_function(addr="main", include_asm=false)

# Include the assembly
idapro_analyze_function(addr="sub_401000", include_asm=true)
```

### Function Summary

```
# Get function metrics in bulk (size, block count, xref count)
idapro_func_profile(queries=["main", "sub_401000", "sub_402000"])
```

---

## Cross References and Call Graphs

### Who References the Target

```
# See who calls a function
idapro_xrefs_to(addrs=["sub_401000"])

# See who references a string/data item
idapro_xrefs_to(addrs=["0x404000"])

# Batch query
idapro_xrefs_to(addrs=["CreateFileW", "ReadFile", "WriteFile"])
```

### Advanced xref Queries

```
# Specify the direction and type
idapro_xref_query(addr="0x401000", direction="to")    # who references me
idapro_xref_query(addr="0x401000", direction="from")  # who I reference
```

### Callee Listing

```
idapro_callees(addrs=["main"])
```

### Call Graph

```
# Start at main, depth 3
idapro_callgraph(roots=["main"], max_depth=3)

# Multiple roots
idapro_callgraph(roots=["sub_401000", "sub_402000"], max_depth=2)
```

### Data Flow Tracing

```
# Trace backward: where does this value come from
idapro_trace_data_flow(addr="0x401050", direction="backward", max_depth=5)

# Trace forward: where does this value go
idapro_trace_data_flow(addr="0x401050", direction="forward", max_depth=5)
```

---

## Searching

### String Search (regex)

```
# Search for URLs
idapro_find_regex(pattern="https?://", limit=20)

# Search for file paths
idapro_find_regex(pattern="C:\\\\", limit=20)

# Search for error messages
idapro_find_regex(pattern="error|fail|invalid", limit=30)

# Search for key/password related strings
idapro_find_regex(pattern="key|password|secret|token", limit=20)
```

### Disassembly Text Search

```
# Search within the disassembly listing
idapro_search_text(pattern="call    sub_")
idapro_search_text(pattern="xor     eax, eax")
```

### Byte Pattern Search

```
# Exact bytes
idapro_find_bytes(patterns=["48 8B 05"], limit=10)

# With wildcards
idapro_find_bytes(patterns=["48 89 ?? 24 ??"], limit=10)

# Multiple patterns
idapro_find_bytes(patterns=["CC CC CC CC", "90 90 90 90"], limit=5)
```

### Advanced Search

```
# Search for an immediate value
idapro_find(type="immediate", targets=["0xDEADBEEF"])

# Search for string references
idapro_find(type="string", targets=["password"])
```

---

## Reading Memory and Data

### Read Raw Bytes

```
idapro_get_bytes(addrs=[{"addr": "0x401000", "size": 64}])
```

### Read a String

```
idapro_get_string(addrs=["0x404000", "0x404100"])
```

### Read an Integer

```
idapro_get_int(queries=[{"addr": "0x405000", "size": 4}])
```

### Read a Global Variable

```
idapro_get_global_value(queries=["g_flag", "g_key_size"])
```

### Read a Structure

```
idapro_read_struct(queries=[{"addr": "0x405000", "type": "HEADER"}])
```

### Search Structures

```
idapro_search_structs(filter="FILE")
```

---

## Modification Operations

### Adding Comments

```
# A single comment
idapro_set_comments(items=[{"addr": "0x401000", "comment": "decryption function entry"}])

# Batch comments
idapro_set_comments(items=[
    {"addr": "0x401000", "comment": "XOR decryption loop"},
    {"addr": "0x401050", "comment": "key initialization"},
    {"addr": "0x4010A0", "comment": "result validation"}
])

# Append a comment (does not overwrite the existing one)
idapro_append_comments(items=[{"addr": "0x401000", "comment": "note: key length is 16"}])
```

### Renaming

```
# Rename a function
idapro_rename(batch={"func": [
    {"addr": "sub_401000", "name": "decrypt_payload"},
    {"addr": "sub_402000", "name": "verify_license"}
]})

# Rename a global variable
idapro_rename(batch={"global": [
    {"addr": "0x405000", "name": "g_encryption_key"}
]})

# Rename a local variable
idapro_rename(batch={"local": [
    {"func": "decrypt_payload", "old": "v1", "name": "plaintext_buf"}
]})
```

### Patching Assembly

```
# NOP out the detection code
idapro_patch_asm(items=[{"addr": "0x401050", "asm": "nop"}])

# Change a jump
idapro_patch_asm(items=[{"addr": "0x401060", "asm": "jmp 0x401080"}])

# Force a true return
idapro_patch_asm(items=[
    {"addr": "0x401000", "asm": "mov eax, 1"},
    {"addr": "0x401005", "asm": "ret"}
])
```

### Patching Bytes

```
# Write bytes directly
idapro_patch(patches=[{"addr": "0x401050", "bytes": "9090909090"}])
```

---

## Type System

### Declaring a Structure

```
idapro_declare_type(decls=[{
    "name": "PacketHeader",
    "decl": "struct PacketHeader { uint32_t magic; uint16_t type; uint16_t length; uint8_t data[0]; };"
}])
```

### Applying a Type

```
# Set a function prototype
idapro_set_type(edits=[{
    "addr": "sub_401000",
    "type": "int __fastcall decrypt(void *buf, int size, const char *key)"
}])

# Set the type of a global variable
idapro_set_type(edits=[{
    "addr": "0x405000",
    "type": "PacketHeader"
}])
```

### Inferring Types

```
idapro_infer_types(addrs=["sub_401000", "sub_402000"])
```

### Querying/Inspecting Types

```
idapro_type_query(queries=["Packet"])
idapro_type_inspect(queries=["PacketHeader"])
```

---

## Stack Frame Analysis

```
# Inspect a function's stack frame
idapro_stack_frame(addrs=["main", "sub_401000"])

# Declare a stack variable
idapro_declare_stack(items=[{
    "func": "sub_401000",
    "offset": -0x20,
    "name": "local_buf",
    "type": "char [32]"
}])
```

---

## Signature Generation

```
# Generate a unique byte signature for an address
idapro_make_signature(addrs=["0x401000"])

# Generate a signature for an entire function
idapro_make_signature_for_function(addrs=["decrypt_payload"])

# Generate signatures for code that references an address
idapro_find_xref_signatures(addrs=["0x405000"])
```

---

## Base Conversion

```
# Hexadecimal → decimal
idapro_int_convert(inputs=["0x401000"])

# Decimal → hexadecimal
idapro_int_convert(inputs=["4198400"])

# Batch conversion
idapro_int_convert(inputs=["0xDEAD", "0xBEEF", "12345"])
```

> ⚠️ **Always use this tool for base conversion, never do the math yourself!**

---

## Export and Scripting

### Exporting Functions

```
# JSON format
idapro_export_funcs(addrs=["main", "sub_401000"], format="json")

# C header file
idapro_export_funcs(addrs=["main", "sub_401000"], format="c_header")

# Function prototypes
idapro_export_funcs(addrs=["main", "sub_401000"], format="prototypes")
```

### Executing Python Scripts

```
# Run Python inside the IDA context
idapro_py_eval(code="import idautils; print(list(idautils.Functions())[:10])")

# Get segment information
idapro_py_eval(code="import idc; print(idc.get_segm_name(0x401000))")

# Bulk operations
idapro_py_eval(code="import ida_funcs; f=ida_funcs.get_func(0x401000); print(f.size())")
```

---

## Typical Analysis Workflows

### Malware Analysis

```text
1. survey_binary → look at the imports (network API? crypto? registry?)
2. find_regex("http|socket|connect") → find network related strings
3. xrefs_to(address of the network string) → find the referencing functions
4. decompile(the referencing function) → study the communication logic
5. trace_data_flow(the crypto argument, "backward") → trace where the key comes from
6. set_comments + rename → annotate the findings
```

### Cracking Registration Checks

```text
1. find_regex("serial|license|register|valid") → find validation related strings
2. xrefs_to(the validation string) → locate the validation function
3. analyze_function(the validation function) → understand the logic
4. callgraph(the validation function, 2) → look at the call chain
5. patch_asm(the conditional jump address, "jmp always_pass") → patch it
```

### CTF Reversing

```text
1. survey_binary → confirm the architecture and entry point
2. decompile("main") → read the main logic
3. find_regex("flag|correct|wrong") → find the check
4. trace_data_flow(the check, "backward") → trace the input transformation
5. Use Python to help with the math/decryption → get the flag
```

### Vulnerability Analysis

```text
1. entity_query(kind="imports", filter="strcpy|sprintf|gets") → find dangerous functions
2. xrefs_to(the dangerous function) → find the call sites
3. analyze_function(the function containing the call site) → look at the context
4. stack_frame(the function) → confirm the buffer size
5. trace_data_flow(the dangerous argument, "backward") → confirm it is user controlled
```

---

## Common Errors and Fixes

| Error | Cause | Fix |
|------|------|------|
| "No database bound" | No file has been opened | Run `open.ps1` |
| "Failed to open database" | The old database is locked | `open.ps1` automatically falls back to Temp |
| Schema validation failure | An MCP client bug | Use `open.ps1` instead of `idalib_open` |
| Tool timeout | A large file is still being analyzed | Add `-TimeoutSeconds 600` |
| "ERR:timeout" (start.ps1) | The server failed to start | Check the Python/idalib-mcp installation |
| Base conversion error | Manual math went wrong | Use `idapro_int_convert` |
| Function name not found | The name is not exact | Search first with `list_funcs` + filter |
