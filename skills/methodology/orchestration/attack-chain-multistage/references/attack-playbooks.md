# Attack Chain Playbook Quick Reference

> Select the corresponding playbook by target type. Each playbook defines the standard path from initial access to objective completion.

---

## Playbook 1: External Web Application → Domain Controller

```
1. Subdomain enumeration + port scanning
2. Web fingerprinting → find components with known vulnerabilities
3. Exploit to obtain a Webshell / RCE
4. Internal reconnaissance (ipconfig/ifconfig, arp, net user)
5. Set up a tunnel (frp/chisel/ssh)
6. Internal scanning (live hosts, open ports)
7. Credential harvesting (mimikatz/hashdump/config files)
8. Lateral movement (PTH/WMI/PsExec)
9. Domain reconnaissance (BloodHound)
10. Domain privilege escalation (Kerberoasting/DCSync/constrained delegation)
11. Obtain domain controller privileges
```

**Key tool chain**: subfinder → httpx → nuclei → sqlmap/sstimap → frp → nmap → mimikatz → crackmapexec → bloodhound → certipy

---

## Playbook 2: Phishing → Internal-Network Penetration

```
1. Collect target-employee information (LinkedIn/Maimai)
2. Craft a phishing email (spoofed sender/legitimate subject)
3. Build a payload (macro doc/LNK/ISO/HTML smuggling)
4. Send the phishing email
5. Wait for check-in (C2 beacon)
6. Local reconnaissance + privilege escalation
7. Credential extraction
8. Lateral movement
9. Persistence
10. Objective complete
```

**Key tool chain**: theHarvester → gophish → msfvenom/cobalt-strike → mimikatz → bloodhound

---

## Playbook 3: Near-Source Penetration → Internal Network

```
1. Physical reconnaissance (WiFi signals, access-control type, USB ports)
2. WiFi attack (Fluxion fake hotspot / WPA cracking)
   or BadUSB implant (Rubber Ducky keystroke injection)
   or network implant (Raspberry Pi / LAN Turtle)
3. Obtain an internal-network access point
4. Internal scanning
5. Continue with steps 5-11 of Playbook 1
```

**Key tool chain**: fluxion/aircrack-ng → rubber-ducky → frp → nmap → crackmapexec

---

## Playbook 4: Cloud Environment Penetration

```
1. Cloud asset discovery (subdomain → CNAME → cloud provider)
2. Storage bucket enumeration (S3/OSS/Blob public access)
3. SSRF → cloud metadata (169.254.169.254)
4. Obtain temporary credentials (AK/SK/Token)
5. Cloud API enumeration (IAM/EC2/Lambda/RDS)
6. Privilege escalation (PassRole/AssumeRole)
7. Lateral movement (cross-account/cross-region)
8. Data acquisition
```

**Key tool chain**: subfinder → nuclei(ssrf) → aws-cli → pacu → ScoutSuite

---

## Playbook 5: Bug Bounty / SRC Rapid Triage

```
1. Asset collection (subdomains + ports + JS files)
2. Fingerprinting → rapid validation of known vulnerabilities (nuclei)
3. Parameter discovery (arjun/paramspider)
4. Test category by category:
   - IDOR/authorization bypass (change ID/change role)
   - SSRF (internal probing/cloud metadata)
   - SQL injection (sqlmap)
   - XSS (xsstrike)
   - File upload (bypass detection)
   - Business-logic flaws (payment/CAPTCHA/password reset)
5. Write PoC + submit report
```

**Key tool chain**: subfinder → httpx → nuclei → arjun → sqlmap → xsstrike → burpsuite

---

## Playbook 6: AD CS Certificate Attack

```
1. Discover the AD CS service (certipy find)
2. Identify vulnerable templates (ESC1-ESC8)
3. Request a malicious certificate
4. Authenticate as the target user using the certificate
5. Obtain an NTLM hash or TGT
6. DCSync to export all credentials
```

**Key tool chain**: certipy → rubeus → mimikatz → secretsdump

---

## General Decision Matrix

| Current state | Next-step priority |
|---------|-------------|
| Only the target domain | Subdomain enumeration → port scanning → Web fingerprinting |
| Have a Web vulnerability | Obtain a shell → internal reconnaissance |
| Have a low-privilege shell | Privilege escalation → credential extraction |
| Have one internal-network machine | Set up a tunnel → internal scanning → lateral movement |
| Have domain-user credentials | BloodHound → find attack paths |
| Have a domain-admin hash | DCSync → Golden Ticket |
| Have cloud AK/SK | Enumerate privileges → escalate → acquire data |
| Phishing check-in | Local privilege escalation → credentials → lateral movement |
| Near-source access | Internal scanning → same as above |
