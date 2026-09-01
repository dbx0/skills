---
name: radare2
description: |
  Use this skill whenever the user wants to analyze binaries with radare2/r2 from the command line, including reverse engineering, disassembly, function analysis, strings/import inspection, patching, binary diffing, hex inspection, or r2 scripting. Also use it when the user mentions PE/ELF/Mach-O/DEX/WASM files together with CLI analysis, `rabin2`, `rasm2`, `radiff2`, `r2pipe`, or asks for radare2 command help on Windows/Linux/macOS.
---

# radare2

A binary analysis skill oriented around the `radare2` CLI. The focus is completing recon, analysis, locating, exporting, and lightweight modification directly from the command line, without relying on a GUI.

## Scope

Prefer this skill when the user has these intents:

- Wants to analyze `exe`, `dll`, `so`, `elf`, `apk`, `dex`, `wasm`, etc. with `r2` / `radare2`
- Asks how to use `rabin2`, `rasm2`, `radiff2`, `rahash2`, `rax2`
- Needs command-line disassembly, viewing functions, viewing strings, viewing imports/exports, checking cross-references, or patching
- Needs to write `radare2` batch commands, `-c` automation commands, or `r2pipe` scripts

If the user explicitly wants GUI reverse engineering, Hex-Rays-style pseudocode, or an IDA workflow, prefer `ida-reverse`. For web JS reverse engineering, prefer `reverse-engineering`.

## Confirm the Environment First

Do not assume `r2` is available. Check first:

```powershell
r2 -v
rabin2 -v
```

If not installed, check common install locations or suggest installing.

Common Windows executables:

- `radare2.exe`
- `rabin2.exe`
- `rasm2.exe`
- `radiff2.exe`
- `rahash2.exe`
- `rax2.exe`
- `r2pm.exe`

## Built-in Resources

This skill bundles two resources; reuse them first rather than assembling a duplicate set of commands each time.

### `scripts/recon.ps1`

A standard recon script, good for a first round of overview analysis. It outputs:

- Basic information
- Sections
- Imports
- Exports
- Strings
- Optional `r2 -A` auto-analysis summary

Invocation:

```powershell
powershell -File "<skill-root>\radare2\scripts\recon.ps1" -TargetPath "C:\path\to\sample.exe"
```

If you need to include `r2` auto-analysis:

```powershell
powershell -File "<skill-root>\radare2\scripts\recon.ps1" -TargetPath "C:\path\to\sample.exe" -RunAnalysis
```

### `references/cheatsheet.md`

When you need more command detail, common-scenario templates, or want to quickly recall syntax, read this cheatsheet rather than guessing from memory.

## Known Phenomena

### Occasional `.sdb` missing warning on Windows

Some PE files may produce a warning like the following during `rabin2` recon:

```text
ERROR: Cannot find ...\share\format\dll\*.sdb
```

If the main output still returns normally, it usually does not affect the basic recon conclusions; continue analysis. Do not conclude that analysis failed just because of this kind of incidental warning.

## Basic Principles

### 1. Recon first, then dig deep

Do not start with a full auto-analysis. First use lightweight commands to confirm file type, architecture, entry point, strings, and import table, then decide whether to run `aaa`, `aaaa`, or targeted analysis.

### 2. Prefer the minimal sufficient command

`radare2` has a huge number of commands; the user usually only needs the shortest path:

- View file info: `rabin2 -I`
- View strings: `rabin2 -z`
- View imports/exports: `rabin2 -i` / `rabin2 -E`
- Interactive analysis: `r2 <file>` then run local commands

### 3. Stay cautious before modifying

If the user wants to patch a binary:

- Open read-only by default: `r2 <file>`
- Only use write mode when modification is clearly needed: `r2 -w <file>` or `oo+` in the session
- Warn about risk before modifying, to avoid unintentionally overwriting the original file

## Common Workflows

## Workflow 1: Quick Recon

Good for when you just received a binary file.

Prefer running the built-in script directly:

```powershell
powershell -File "<skill-root>\radare2\scripts\recon.ps1" -TargetPath "sample.exe"
```

If you only need the minimal manual commands, use:

```powershell
rabin2 -I sample.exe
rabin2 -z sample.exe
rabin2 -i sample.exe
rabin2 -E sample.exe
```

Focus points:

- File format, bitness, architecture, platform
- Entry point address
- Suspicious strings: URLs, paths, errors, registry, command-line arguments
- Import functions: network, file, crypto, process injection, registry operations

## Workflow 2: Interactively Analyze Functions

```powershell
r2 sample.exe
```

Common commands after entering:

```text
aaa          # Standard auto-analysis
afl          # List functions
iz           # List strings
iS           # List sections
is           # List symbols
s entry0     # Jump to entry point
pdf          # Disassemble the current function
VV           # Enter visual mode (if the terminal is suitable)
q            # Quit
```

Notes:

- Prefer `aaa` by default; do not start with the heavier `aaaa`
- If the sample is very large or analysis is slow, you can analyze only near the entry point, then manually expand

## Workflow 3: Locate main / Key Logic

```text
afl~main
afl~sym.
iz~http
iz~error
axt <addr>
```

Approach:

- Start from `main`, the entry point, and string references
- Use `axt` to find who references a string or address
- After finding a reference point, use `s <addr>`, `pdf`

## Workflow 4: Hex and Memory Inspection

```text
px 64        # 64 bytes of hex from the current address
pd 20        # Disassemble 20 instructions
psz          # Read the string at the current address
pxa          # A friendlier hex view
```

## Workflow 5: Binary Patch

Use only when the user explicitly requests file modification:

```powershell
r2 -w sample.exe
```

For example, after entering:

```text
s 0x401000
wa nop
wa jmp 0x401050
wq
```

Common write operations:

- `wa <asm>`: write assembly
- `wx <hex>`: write raw bytes
- `wq`: write and quit

It is best to back up the original file before modifying. If the user did not mention a backup, at least remind them once.

## Workflow 6: Non-interactive Automation

Good for one-shot output:

```powershell
r2 -A -q -c "afl;iz;ii;q" sample.exe
```

Common parameters:

- `-A`: auto-analyze on startup
- `-q`: quiet mode
- `-c`: run a command string

If there are many commands, organize them into a readable order rather than cramming them into a hard-to-maintain giant string.

It is more advisable to first lay a foundation with the built-in recon script, then decide whether to add custom commands.

## Common Sub-tools

### `rabin2`

Good for static information extraction:

```powershell
rabin2 -I sample.exe   # Basic info
rabin2 -S sample.exe   # Sections
rabin2 -s sample.exe   # Symbols
rabin2 -i sample.exe   # Imports
rabin2 -E sample.exe   # Exports
rabin2 -z sample.exe   # Strings
rabin2 -zz sample.exe  # More detailed strings
```

### `rasm2`

Good for quick assembly/disassembly:

```powershell
rasm2 -d "9090"
rasm2 -a x86 -b 64 "xor eax, eax"
```

### `radiff2`

Good for comparing two binaries:

```powershell
radiff2 old.exe new.exe
radiff2 -C old.exe new.exe
```

### `rahash2`

Good for computing hashes:

```powershell
rahash2 -a md5 sample.exe
rahash2 -a sha256 sample.exe
```

### `rax2`

Good for base and encoding conversion:

```powershell
rax2 0x401000
rax2 4198400
rax2 -s hello
```

## Recommended Analysis Order

When encountering an unknown sample, follow this order:

1. `rabin2 -I` to see format, architecture, entry point
2. `rabin2 -z` to see strings
3. `rabin2 -i` to see import functions
4. If interactive analysis is needed, enter `r2`
5. First `aaa`, then `afl` / `iz` / `pdf`
6. Progressively locate key functions via string references, import calls, and the entry flow

The benefit of this order is low noise and building a sense of direction as quickly as possible.

## Windows Notes

- When paths contain spaces, commands must be quoted correctly
- If the current terminal cannot find `r2`, the `PATH` may have just been updated; open a new terminal and try again
- Some samples require administrator privileges to read, but do not proactively elevate privileges by default unless the user clearly needs it
- Before dynamically debugging a suspicious sample, first confirm the user's intent to avoid mistakes

## Output Style

When the user wants you to actually analyze the file, not just give commands:

- Give a summary of the recon results first
- Then list the key evidence: strings, imports, functions, addresses
- Finally give next-step suggestions or continue deeper analysis

Do not just list commands without explaining why you do it this way.

## Typical Request Examples

### Example 1: Analyze an exe

User: `help me see what this exe does, radare2 is fine`

Handling:

1. First use `rabin2 -I/-z/-i`
2. Decide whether entering `r2` is needed
3. Use `aaa`, `afl`, `pdf` to dig into the entry and key string references

### Example 2: Find where a string is called

User: `which function triggers this error string`

Handling:

1. Use `iz~keyword` to find the string address
2. Use `axt <addr>` to find references
3. Jump to the reference point `s <addr>` then `pdf`

### Example 3: Change a jump

User: `change this jne to je`

Handling:

1. First confirm the target address
2. Clearly state that write mode will be entered
3. Use `wa je <target>` or `wx` directly
4. Disassemble again after modifying to verify

## Practices to Avoid

- Do not treat `radare2` as a tool with only the single command `aaa`
- Do not open the user's file in write mode without explaining the risk
- Do not draw conclusions before doing basic recon
- Do not misroute web JS reverse engineering to this skill; that is the scope of `reverse-engineering`

## References

- Command cheatsheet: `references/cheatsheet.md`
- Standard recon script: `scripts/recon.ps1`

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (controller), `routing.md`
**Upstream alternative**: `ida-reverse/` (upgrade to IDA when decompilation/pseudocode is needed)
**Downstream exits**:
- Need dynamic analysis -> `reverse-engineering/tools-dynamic.md` (Frida/GDB)
- Need deep decompilation -> `ida-reverse/`
- After finding interesting strings via PAT, need cross-references -> `ida-reverse/` (IDA's xref is more powerful)

**Peer-level related modules**: `ida-reverse/` (complementary: r2 recon is fast, IDA decompilation is deep)

---

## On-Demand Bootstrap

This skill's entry scripts are integrated with the unified bootstrap system. When radare2 is missing, it does not error directly but automatically attempts installation.

### Automation Capability Boundaries

| Tool | Auto-installable | Install method | Notes |
|------|-----------|---------|------|
| r2 | ✓ | GitHub Release ZIP (w64) | Automatically downloaded and extracted to `%USERPROFILE%\Tools\radare2\` |
| rabin2 | ✓ | Same as above (included in the radare2 distribution) | — |
| rasm2 | ✓ | Same as above | — |
| radiff2 | ✓ | Same as above | — |
| rahash2 | ✓ | Same as above | — |
| rax2 | ✓ | Same as above | — |

### Bootstrap Trigger Points

- `scripts/recon.ps1`: automatically calls `bootstrap-reverse.ps1` when `rabin2` or `r2` is missing

### When Bootstrap Fails

If automatic installation fails (no network, GitHub API rate-limiting, etc.), the script throws a clear error with a manual install link.

Manual install: download `radare2-*-w64.zip` from https://github.com/radareorg/radare2/releases, extract to `%USERPROFILE%\Tools\radare2\`, and ensure the `bin\` directory is in PATH.
