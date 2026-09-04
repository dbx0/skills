---
name: lumine-reverse-2026-05-15
description: Full reverse-engineering recovery of lumine v0.9.1, a Go 1.24.5 TLS fragmentation proxy, including source reconstruction of 7 packages
metadata:
  type: project
---

# lumine v0.9.1 — reversing a Go TLS fragmentation proxy

**Date**: 2026-05-15
**Target**: `lumine_v0.9.1_windows_amd64.exe` (PE32+, Go 1.24.5, 11.6 MB)
**Source report**: `REVERSE_REPORT.md`

## Background

The request was to recover readable Go source from the binary. The target is a TLS anti-DPI proxy whose technique derives from the Python project [TlsFragment](https://github.com/maoist2009/TlsFragment).

## Process

1. **Toolchain setup**: Python + capstone for disassembly, GoReSym to recover the symbol table (1,944 Go functions, 269 of them from the project itself)
2. **Package structure identification**: inferred 12 packages from GoReSym's `package.function` naming
3. **Type recovery**: derived the JSON deserialization types from `config.json`, recovering fields by cross-referencing function usage
4. **Source reconstruction**: wrote readable Go package by package, preserving the logic rather than restoring it line by line
5. **Sub-package completion**: dial (outbound binding), errors (error types), format (string helpers)

## Key findings

- Core anti-DPI mechanism: TLS record fragmentation + noise injection + waiting for ACK + OOB + fake TTL
- Policy engine: domain trie + IP trie → policy match
- Depends on `go-freelru` (an LRU cache) for DNS/TTL caching
- The source repository `github.com/moi-si/lumine` returns 404, so recovery had to come entirely from the binary

## Tools

| Tool | Purpose | Version |
|---|---|---|
| GoReSym | Go symbol recovery | v1.7.1 (Mandiant) |
| Capstone | Disassembly engine | latest |
| pefile | PE structure parsing | latest |

## Pitfalls encountered

1. **Python3 path problem**: the WindowsApps stub python3 cannot `pip install capstone`; use a full CPython install path instead
2. **GoReSym subprocess paths**: `~` is not expanded automatically, so call `os.path.expanduser()`
3. **Mixed tabs and spaces**: the generated Python decompilation scripts mixed tabs and spaces, corrupting the Go source formatting; v3 fixed it by using spaces throughout
4. **vendor-less GoReSym**: when a Go 1.24.5 binary carries no vendor symbols, GoReSym still extracts function names, but parameters and locals are unrecoverable
5. **String noise**: Go standard library string constants flood the output and must be filtered carefully at package level

## Artifacts

- `REVERSE_REPORT.md` — the full reverse-engineering report
- `reconstructed_src_v3/` — 7 Go source files: the core engine plus 3 sub-packages
