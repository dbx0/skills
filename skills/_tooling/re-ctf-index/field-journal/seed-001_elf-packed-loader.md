# [seed] Reversing a self-extracting ELF loader

## Scenario category
Binary analysis

## Target overview
Analyze an ARM64 ELF self-extracting loader disguised as a .sh script, and recover its decompression algorithm and payload-injection flow.

## Full execution chain

1. `file` confirms the real type (ELF, not a shell script)
2. `readelf -l` views the program headers → finds the 3rd PHDR deliberately corrupted (0x0a padding)
3. `rabin2 -I` gets the architecture (AArch64), entry point, compiler info
4. Load in IDA/Ghidra → start analysis from the entry point
5. Identify the LZSS decompression loop (bit-stream operations + sliding-window back-copy)
6. Identify the mmap → decompress → mprotect → jump injection flow
7. Rewrite the decompressor in Python, dump out the payload
8. Analyze the payload contents (contains a /proc/self/exe reference, indicating a process injector)

## Pitfalls encountered

| Problem | Cause | Fix | Time lost |
|------|------|---------|------|
| readelf errors, cannot parse | The 3rd PHDR is deliberately padded with 0x0a | Ignore the corrupted PHDR, look only at the first 2 LOAD segments | 10min |
| IDA decompilation is unreadable | ARM64 bit-operation heavy, Hex-Rays optimizes it poorly | Switch to the disassembly view and analyze manually | 30min |
| The Python decompressor outputs wrong data | The pop_bit refill path had the wrong return value (adcs vs adds) | Compare carefully against the assembly; on refill the return is bit31 of the newly loaded word | 2h |
| Unsure of the payload entry offset | The entry_offset field in the data table is of unclear meaning | Trace the loader function's `br mmap_base + 0x14`, confirming the entry is at +0x14 | 20min |

## Toolchain findings

- `file` is step one; never trust the file suffix
- `rabin2 -I` is more fault-tolerant than `readelf` (it handles a corrupted PHDR)
- For ARM64 bit-operation-heavy code, the decompiler is worse than reading the assembly directly
- Python's struct module + a hand-written decompressor is the standard method for analyzing custom compression

## Key code and commands

```bash
# Confirm the file type
file LinYuDriverLoader4.9.sh
# ELF 64-bit LSB executable, ARM aarch64

# View the program headers
readelf -l binary 2>/dev/null | head -20

# Extract the compressed data
dd if=binary bs=1 skip=$((0xa6a24)) count=1981 of=compressed.bin

# Compute the file offset
# vaddr 0x3d66bc → file_offset = 0x3d66bc - 0x330000 = 0xa66bc
```

```python
# LZSS decompressor core (simplified)
def decompress(data):
    shift_reg = 0x80000000
    # ... bit-stream read + literal/match branch
```

## Suggested improvements to this pack

- `elf-analysis.md` should add more traits for "identifying custom compression algorithms"
- The ARM64 syscall table should include notes on cache-maintenance instructions (dc cvau / ic ivau)
- Consider adding a general methodology for "how to rewrite an assembly algorithm in Python"

## Reusable patterns and script fragments

**Standard pattern for identifying a self-extracting ELF**:
```text
entry point → minimal init → call the decompress function → mmap(RW) → decompress into the mmap region → mprotect(RX) → jump
```

**General pattern for ARM64 bit-stream reading**:
```text
lsl w4, w4, #1    # left shift (extract the top bit into carry)
cbz w4, refill    # if shifted empty, load a new 32 bits from input
```

## Follow-up actions
- [x] Updated the sub-skill documentation (elf-analysis.md added)
- [ ] No routing-matrix update needed
- [ ] No bootstrap-manifest update needed

## Environment
- OS: Linux/Android ARM64 target
- Tool versions: IDA Pro / Ghidra + radare2
- Target platform: Android ARM64 (AArch64)

## Anonymization note
This entry is seed data written from publicly known technique patterns; no real target is involved.

---
<!-- [evolution stats] cumulative completed projects: 1 | new patterns this time: 2 | toolchain issues fixed this time: 0 -->
<!-- [community contribution] seed data, no PR needed -->
