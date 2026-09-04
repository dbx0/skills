# radare2 cheat sheet

## Basic recon

```powershell
rabin2 -I sample.exe
rabin2 -S sample.exe
rabin2 -i sample.exe
rabin2 -E sample.exe
rabin2 -zz sample.exe
```

## Entering interactive mode

```powershell
r2 sample.exe
```

```text
aaa
afl
iz
iS
is
s entry0
pdf
q
```

## Strings and references

```text
iz~http
iz~error
axt <addr>
s <addr>
pdf
```

## Common views

```text
px 64
pd 20
psz
pxa
```

## patch

```powershell
r2 -w sample.exe
```

```text
s 0x401000
wa nop
wx 9090
wq
```

## Non-interactive mode

```powershell
r2 -A -q -c "afl;iz;ii;q" sample.exe
```

## Other tools

### rasm2

```powershell
rasm2 -d "9090"
rasm2 -a x86 -b 64 "xor eax, eax"
```

### radiff2

```powershell
radiff2 old.exe new.exe
radiff2 -C old.exe new.exe
```

### rahash2

```powershell
rahash2 -a md5 sample.exe
rahash2 -a sha256 sample.exe
```

### rax2

```powershell
rax2 0x401000
rax2 4198400
rax2 -s hello
```
