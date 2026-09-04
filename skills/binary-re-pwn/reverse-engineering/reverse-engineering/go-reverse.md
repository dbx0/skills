# Go Binary Reverse Engineering Guide

> Go compiled binaries bring their own challenges: static linking makes them huge, function counts run into the tens of thousands, string layout is unusual, and recovery is hard once symbols are stripped.
> This document covers the toolchain, recovery techniques, and practical workflows.

---

## Identifying a Go Binary

Quick ways to tell whether a binary was compiled with Go:

```bash
# String signatures
strings binary | grep -E "runtime\.|go\.buildid|GOROOT"

# rabin2 recon
rabin2 -z binary | grep -i "runtime"

# Unusually large file size (statically linked runtime)
# Typical Hello World: C ~20KB, Go ~2MB
```

Common indicators:
- A large number of functions prefixed with `runtime.`
- A `go.buildid` section
- `GOROOT` and `GOPATH` path strings
- 5000-50000+ functions (the whole runtime and standard library are included)

---

## Core Toolchain

### Symbol Recovery

| Tool | Purpose | Link |
|------|------|------|
| **GoReSym** | By Mandiant, parses Go symbol information (pclntab/moduledata) | https://github.com/mandiant/GoReSym |
| **GoResolver** | By Volexity, automatically deobfuscates Garble binaries using CFG similarity | https://github.com/volexity/GoResolver |
| **redress** | Analyzes stripped Go binaries, recovers types/interfaces/package structure | https://github.com/goretk/redress |
| **GoStringUngarbler** | By Google, dedicated to recovering Garble obfuscated strings | https://github.com/mandiant/GoStringUngarbler |

### IDA Plugins

| Tool | Purpose | Link |
|------|------|------|
| **go_parser** | IDA plugin, parses moduledata/pclntab/type information | https://github.com/0xjiayu/go_parser |
| **IDAGolangHelper** | IDA script collection, parses Go type information | https://github.com/sibears/IDAGolangHelper |
| **AlphaGolang** | SentinelLabs IDAPython script collection | https://github.com/SentineLabs/AlphaGolang |
| **Native support in IDA 9.2+** | Official Hex-Rays Go decompilation improvements | https://hex-rays.com/blog/stop-guessing-and-start-going |

### Ghidra Plugins

| Tool | Purpose | Link |
|------|------|------|
| **Ghidra + GoReSym output** | Export symbols with GoReSym, then import them into Ghidra | Used together |
| **golang_loader_assist** | Ghidra Go loading helper | Community script |

### Standalone Analysis Tools

| Tool | Purpose | Link |
|------|------|------|
| **gore** | Go reverse engineering library (the layer underneath redress) | https://github.com/goretk/gore |
| **garble** | Go obfuscation tool (understand it to beat it) | https://github.com/burrowers/garble |

---

## Key Structures in a Go Binary

### pclntab (PC Line Table)

The single most important structure in a Go binary. It contains:
- The mapping of every function name to its address
- Source file paths
- Line number information
- Stack frame sizes

Even after symbols are stripped, the pclntab is usually still present (the Go runtime depends on it).

```text
How to locate it:
1. Search for the magic bytes: 0xFFFFFFF0 (Go 1.16+) or 0xFFFFFFFB (Go 1.18+)
2. Locate it automatically with GoReSym
3. Parse it automatically with the go_parser IDA plugin
```

### moduledata

Contains:
- The pclntab pointer
- The type information table
- itab (the interface table)
- Global variable information

### String Layout

Go strings are not C style null terminated; they are a `(pointer, length)` structure:

```text
C string:   "hello\0"
Go string:  struct { ptr *byte; len int } → ptr points at "hello" (no \0)
```

As a result, the default string detection in IDA/Ghidra misses a large number of Go strings.

**Solutions**:
- Use `go_parser` to identify Go strings automatically
- Export the string list with GoReSym
- Manually: find `runtime.stringtable` or locate strings through cross references

---

## Practical Workflows

### Scenario 1: an unstripped Go binary

```text
1. GoReSym -t -d -p binary > symbols.json
   → exports every function name, type, and source file path
2. Load it into IDA/Ghidra
3. Import the GoReSym symbol information
4. Filter out runtime.* and standard library functions, focus on user code
5. Start the analysis at main.main
```

### Scenario 2: a stripped Go binary

```text
1. GoReSym -t -d -p binary > symbols.json
   → even after stripping, the pclntab is usually still there
2. If GoReSym fails → use redress
   redress -src binary    # recover source file paths
   redress -pkg binary    # recover package structure
   redress -type binary   # recover type information
3. Load into IDA with the go_parser plugin
4. Run go_parser for automatic recovery
5. Start from the recovered main.main
```

### Scenario 3: a Garble obfuscated Go binary

```text
Garble will:
- Randomize function names (main.main → main.a3f2b1c)
- Encrypt strings
- Strip file path information
- Obfuscate package names

Countermeasures:
1. GoResolver (CFG signature matching)
   → recovers standard library function names through control flow graph similarity
2. GoStringUngarbler (string decryption)
   → automatically recognizes Garble's string encryption patterns and decrypts them
3. Dynamic analysis (Frida/dlv)
   → hook runtime functions and observe the actual behavior
4. Differential analysis
   → compile a Hello World with the same Go version and use binary-diff on the runtime portion
```

### Scenario 4: mixed CGo builds

```text
1. Identify the CGo boundary (_cgo_* functions)
2. Recover the Go side with go_parser
3. Analyze the C side with normal IDA workflow
4. Pay attention to bridge functions such as _cgo_topofstack and crosscall2
```

---

## Command Quick Reference

```bash
# GoReSym: export symbols
GoReSym -t -d -p binary > symbols.json
GoReSym -t -d -p binary -o ida_script.py  # generate an IDA script

# redress: analyze a stripped binary
redress -src binary          # source file paths
redress -pkg binary          # package structure
redress -type binary         # type information
redress -interface binary    # interface information
redress -filepath binary     # full file paths

# GoResolver: deobfuscate Garble
GoResolver -binary binary -output resolved.json

# GoStringUngarbler: decrypt Garble strings
GoStringUngarbler -i binary -o deobfuscated_binary

# Quickly determine the Go version
strings binary | grep "go1\."
GoReSym -p binary | grep "Version"
```

---

## Go Analysis Workflow in IDA

```text
1. Load the binary (pick the correct architecture)
2. Wait for auto analysis to finish
3. Run the go_parser plugin:
   - File → Script File → go_parser.py
   - Or Edit → Plugins → Go Parser
4. The plugin automatically:
   - Parses the pclntab
   - Recovers function names
   - Marks Go strings
   - Parses type information
5. Filter the view:
   - Hide runtime.* functions
   - Focus on main.* and third party packages
6. Start reversing at main.main
```

---

## Common Pitfalls

| Pitfall | Description | Fix |
|------|------|------|
| Too many functions to work through | Static linking in Go yields 5000-50000 functions | Filter by package name, only look at main.* and business packages |
| Incomplete string detection | Go strings are not null terminated | Recover them with go_parser or GoReSym |
| Hard to read decompilation | Go's defer/goroutine/interface make the pseudocode complex | IDA 9.2+ improves this, or lean on dynamic analysis |
| Garble obfuscation | Function names and strings are all randomized | GoResolver + GoStringUngarbler |
| Version differences | The pclntab format differs across Go versions | GoReSym supports Go 1.2-1.23+ |
| CGo boundary | Go and C code mixed together | Use the _cgo_* functions as the dividing line |

---

## Pairing With Other Skills

| Need | What to Use |
|------|--------|
| Deep IDA analysis of a Go binary | `ida-reverse/` + the go_parser plugin |
| Ghidra analysis (free) | Ghidra + GoReSym symbol import |
| Fast recon | `radare2/`, `rabin2 -z` to look at strings |
| Dynamic hooking | Frida (hook runtime functions) or dlv (the native Go debugger) |
| Cross version comparison | `binary-diff/`, migrate symbols from an old build to a new one |
| Garble deobfuscation | GoResolver + GoStringUngarbler |
