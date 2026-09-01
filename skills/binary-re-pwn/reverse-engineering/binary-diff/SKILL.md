---
name: binary-diff
description: |
  Cross-version symbol migration and binary diffing. Use when you have symbols/reverse-engineering results for an old version and need to quickly migrate them to a new version.
  Applicable scenarios: deriving new-version symbols for a kernel that lacks a PDB from old-version symbols, batch-migrating function names after a program update, quickly locating new offsets after an application update.
  Core method: use an LLM for structured diff comparison, with programmatic input/output, at extremely low cost (~1 RMB for 200 functions).
  Trigger keywords: symbol migration, bindiff, cross-version, PDB missing, function offset migration, symbol migration, binary diff, version comparison.
---

# Cross-Version Symbol Migration (Binary Diff)

## Scope

Use this skill when the task falls into the following scenarios:

1. **Kernel/driver missing PDB** — you have symbols for an old ntoskrnl.exe, the new-version PDB has been pulled by Microsoft, and you need to use the old-version symbols to derive the addresses of new-version non-exported functions
2. **Symbol migration after a program update** — you previously reverse-engineered a program, the program has been updated, and you don't want to reverse it all over again, so you batch-migrate using the old-version results
3. **Protection mechanism update** — the old version has complete reverse-engineering results, and the new version requires quickly locating the new offset of the same function
4. **Any "have old-version symbols + new version has no symbols" binary comparison scenario**

### Division of Labor with Other Skills

| Scenario | What to use |
|------|--------|
| Reverse-engineering a binary from scratch | `ida-reverse/` or `radare2/` |
| Have old-version results, migrating to a new version | **this skill** |
| Comparing two completely different binaries | BinDiff / Diaphora (traditional tools) |

### Core Advantages

Compared to traditional approaches:

| Approach | Cost for 200 functions | Time | Accuracy |
|------|--------------|------|--------|
| Manually comparing two IDA windows | Free but exhausting | Several hours | High |
| BinDiff automatic matching | Free | Fast | Medium (fails when structural changes are large) |
| Fully handing off to an Agent (CC/Codex) | 50-100 RMB | Slow | High |
| **this skill (LLM batch comparison)** | **~1 RMB** | **~10 sec/function** | **High** |

## Core Principle

```text
Old-version function (has symbols)          New-version same function (no symbols)
    ↓                              ↓
Export disassembly + pseudocode          Export disassembly + pseudocode
    ↓                              ↓
    └──────── LLM structured comparison ────────┘
                    ↓
         Output YAML (symbol mapping table)
                    ↓
         Programmatic parsing → batch-apply to the new-version IDB
```

Key points:
- The prompt is a fixed template, filled programmatically
- The input/output formats are fixed, parsed programmatically
- The LLM only handles the single step of "looking at two pieces of code and finding the correspondence"
- The time cost and token cost are extremely low

## Prompt Template

### Standard Comparison Prompt

```text
I have disassembly outputs and procedure code of the same function.

This is the function for reference:

**Disassembly for Reference**
```c
{disasm_for_reference}
```

**Procedure code for Reference**
```c
{procedure_for_reference}
```

This is the function you need to reverse-engineering:

**Disassembly to reverse-engineering**
```c
{disasm_code}
```

**Procedure code to reverse-engineering**
```c
{procedure}
```

What you need to do is to collect all references to "{symbol_name_list}" in the function you need to reverse-engineering and output those references as YAML.

Example:
```yaml
found_vcall: # This is for indirect call to virtual function or virtual function pointer fetching.
  - insn_va: '0x180777700' # Always be the instruction with displacement offset
    insn_disasm: call [rax+68h] # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate
  - insn_va: '0x180777778' # Always be the instruction with displacement offset
    insn_disasm: mov rax, [rax+80h] # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount

found_call: # This is for direct call to non-virtual regular function.
  - insn_va: '0x180888800'
    insn_disasm: call sub_180999900
    func_name: CLoopMode_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: call sub_180555500
    func_name: CLoopMode_SetSystemState

found_funcptr: # This is for non-virtual regular function pointer.
  - insn_va: '0x180666600' # Must load/reference the function pointer target address
    insn_disasm: lea rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopMode_OnClientPollNetworking

found_gv: # This is for reference to global variable.
  - insn_va: '0x180444400'
    insn_disasm: mov rcx, cs:qword_180666600 # Must load/reference the global variable
    gv_name: g_pNetworkMessages
  - insn_va: '0x180333300'
    insn_disasm: lea rax, unk_180222200 # Must load/reference the global variable
    gv_name: s_EventManager

found_struct_offset: # This is for reference to struct offset. NOTE THAT virtual function pointer should not be here! virtual function pointer should ALWAYS be in found_vcall !
  - insn_va: '0x1801BA12A' # Always be the instruction with displacement offset
    insn_disasm: mov rcx, [r14+58h] # Always be the instruction with displacement offset
    offset: '0x58'
    size: 8
    struct_name: CResourceService
    member_name: m_pEntitySystem
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.
```

### Variable Reference

| Variable | Source | Description |
|------|------|------|
| `{disasm_for_reference}` | Old-version IDA export | Disassembly with symbols |
| `{procedure_for_reference}` | Old-version IDA export | Pseudocode with symbols |
| `{disasm_code}` | New-version IDA export | Disassembly without symbols |
| `{procedure}` | New-version IDA export | Pseudocode without symbols |
| `{symbol_name_list}` | Extracted from old version | List of symbols to locate in the new version |

## Workflow

### Full Process

```text
Step 1: Prepare data
  - Load the old-version binary into IDA (has PDB/symbols)
  - Load the new-version binary into IDA (no symbols)
  - Find anchor functions that are the same across both versions (exported functions, string references, etc.)

Step 2: Batch export
  - Export from old version: anchor function disassembly + pseudocode (with symbol names)
  - Export from new version: the same anchor function's disassembly + pseudocode (without symbol names)

Step 3: LLM comparison
  - Fill the prompt template with the data
  - Call the LLM API (recommended: deepseek for volume and low cost, switch to gpt for very large functions)
  - Parse the returned YAML

Step 4: Apply results
  - Batch-apply the symbol mappings from the YAML to the new-version IDB
  - Batch-rename using idapro_rename or an IDAPython script

Step 5: Iterate
  - The functions migrated in the first round become new anchors
  - Enter these functions and continue comparing their internal calls
  - Repeat until all target functions are covered
```

### Anchor Selection Strategy

| Anchor type | Reliability | Notes |
|---------|--------|------|
| Exported function | Highest | Name is stable, address may change |
| String reference | High | String content is stable, reference location may change |
| Constant/magic number | Medium | Signature value is stable |
| Code pattern | Medium | Function structure is similar but the address fully changes |

### Batch Processing Recommendations

- Compare 1 function at a time (avoid context explosion)
- Use deepseek for medium functions (<200 lines)
- Switch to gpt-4o or claude for very large functions (>500 lines)
- Concurrent calls to improve speed (10-20 concurrent)
- Cache results to avoid duplicate calls

## Output Format

### The 5 Symbol Types in YAML Output

| Type | Meaning | Key fields |
|------|------|---------|
| `found_vcall` | Virtual function call (indirect call) | `vfunc_offset`, `func_name` |
| `found_call` | Direct function call | `insn_va`, `func_name` |
| `found_funcptr` | Function pointer reference | `insn_va`, `funcptr_name` |
| `found_gv` | Global variable reference | `insn_va`, `gv_name` |
| `found_struct_offset` | Struct offset reference | `offset`, `struct_name`, `member_name` |

### Application Actions After Parsing

```text
found_call → idapro_rename(addr=call_target, name=func_name)
found_vcall → idapro_set_comments(addr=insn_va, comment="vcall: {func_name} @ +{offset}")
found_funcptr → idapro_rename(addr=funcptr_target, name=funcptr_name)
found_gv → idapro_rename(addr=gv_addr, name=gv_name)
found_struct_offset → idapro_set_comments(addr=insn_va, comment="{struct_name}.{member_name}")
```

## Typical Scenario Examples

### Scenario 1: ntoskrnl.exe missing PDB

```text
Have: ntoskrnl.exe 10.0.26100.2000 + complete PDB
Target: ntoskrnl.exe 10.0.26100.2605 (PDB pulled)
Need: locate the new address of PspSetCreateProcessNotifyRoutine

Steps:
1. Load both versions into IDA
2. Find the exported function PsSetCreateProcessNotifyRoutine (present in both versions)
3. In the old version it calls PspSetCreateProcessNotifyRoutine (has symbol)
4. In the new version it calls sub_140822108 (no symbol)
5. The LLM immediately sees: sub_140822108 = PspSetCreateProcessNotifyRoutine
6. Batch-apply
```

### Scenario 2: Migration after an application update

```text
Have: complete reverse-engineering results for target.exe v1.0 (200+ functions already named)
Target: target.exe v1.1 (all symbols lost)
Need: batch-migrate 200 function names

Steps:
1. Export disassembly + pseudocode of all named functions from the old version
2. Find the corresponding anchors in the new version via exported functions/strings
3. Batch-call the LLM to compare
4. Parse the YAML and batch-rename
5. Iterate deeper
```

## LLM Selection Recommendations

| Model | Suitable scenario | Cost | Speed |
|------|---------|------|------|
| DeepSeek V3 | Small-to-medium functions (<200 lines), batch processing | Very low | Fast |
| GPT-4o | Very large functions, complex control flow | Medium | Fast |
| Claude Sonnet | Medium-to-large functions requiring reasoning | Medium | Fast |
| Claude Opus | Extremely complex functions requiring deep understanding | High | Slow |

Recommended strategy: default to DeepSeek, automatically upgrade when hitting context limits or when results are inaccurate.

## Notes

- **Do not dump the entire binary into the LLM** — compare only one function at a time
- **Anchors must be reliable** — if the anchor itself is matched wrong, everything downstream is wasted
- **Results need manual spot-checking** — the LLM is not 100% accurate; key symbols must be verified
- **Cache intermediate results** — avoid wasting tokens on duplicate calls
- **Mind the context limit** — very large functions (>1000 lines of disassembly) need to be split or use a large-context model

---

## On-Demand Bootstrap

### Tool Dependencies

| Tool | Purpose | Auto-installable |
|------|------|-----------|
| IDA Pro | Export disassembly/pseudocode | ✗ (commercial software) |
| Python | Script execution, API calls | ✓ |
| PyYAML | Parse the YAML returned by the LLM | ✓ (pip install pyyaml) |
| LLM API | Perform the comparison | Requires an API key |

### Notes

The core of this skill does not depend on heavyweight tool installation; it mainly depends on:
- IDA Pro already available (managed via the `ida-reverse/` skill)
- Python + requests/httpx (to call the API)
- An LLM API endpoint

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (controller), `routing.md`
**Trigger condition**: have old-version symbols/reverse-engineering results and need to migrate to a new version
**Downstream exits**:
- Need to open the binary first -> `ida-reverse/`
- Need quick recon to confirm version differences -> `radare2/`

**Peer-level related modules**: `ida-reverse/` (data export and symbol application both go through IDA)
