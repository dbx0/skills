# Information Gathering

_20 tool commands_

### Nmap  `nmap`
_Network scanning and security auditing tool_

**Step 0**
> Perform port scanning using the TCP connect method
```
nmap -sT target_ip
```
**Syntax breakdown:**
- `nmap` — Nmap scanning tool _command_
- `-sT` — TCP connect scan mode _parameter_
- `target_ip` — Target IP address _value_

**Step 0**
> Use SYN packets for stealth scanning, requires root privileges
_platform: linux_
```
nmap -sS target_ip
```
**Syntax breakdown:**
- `-sS` — SYN scan (half-open scan), stealthier _parameter_

**Step 0**
> Scan UDP ports
```
nmap -sU target_ip
```
**Syntax breakdown:**
- `-sU` — UDP scan mode _parameter_

**Step 0**
> Detect service version information on open ports
```
nmap -sV target_ip
```
**Syntax breakdown:**
- `-sV` — Service version detection _parameter_

**Step 0**
> Attempt to identify the target's operating system
```
nmap -O target_ip
```
**Syntax breakdown:**
- `-O` — Operating system detection _parameter_

**Step 0**
> Enable advanced features for a comprehensive scan
```
nmap -A target_ip
```
**Syntax breakdown:**
- `-A` — Enable OS detection, version detection, script scanning, and traceroute _parameter_

**Step 0**
> Scan only the specified ports
```
nmap -p 22,80,443 target_ip
```
**Syntax breakdown:**
- `-p` — Specify ports _parameter_
- `22,80,443` — List of port numbers _value_

**Step 0**
> Scan a specified range of ports
```
nmap -p 1-1000 target_ip
```
**Syntax breakdown:**
- `1-1000` — Port range _value_

**Step 0**
> Use the Nmap Scripting Engine for vulnerability scanning
```
nmap --script=vuln target_ip
```
**Syntax breakdown:**
- `--script=` — Specify an Nmap script _parameter_
- `vuln` — Vulnerability detection script category _value_

**Step 0**
> Scan SMB shares and user information
```
nmap --script=smb-enum-shares,smb-enum-users target_ip
```

**Step 0**
> HTTP service vulnerability scan
```
nmap --script=http-enum,http-vuln* -p 80,443 target_ip
```

**Step 0**
> Fast scan, only scan common ports
```
nmap -F target_ip
```
**Syntax breakdown:**
- `-F` — Fast mode, scans the 100 most common ports _parameter_

**Step 0**
> Scan an entire subnet
```
nmap 192.168.1.0/24
```
**Syntax breakdown:**
- `192.168.1.0/24` — Subnet in CIDR format _value_

**Step 0**
> Save scan results to a file
```
nmap -oN output.txt target_ip
```
**Syntax breakdown:**
- `-oN` — Normal format output _parameter_
- `-oX` — XML format output _parameter_
- `-oG` — Grepable format output _parameter_

---

### Gobuster  `gobuster`
_Directory and subdomain brute-forcing tool_

**Step 0**
> Brute-force website directories
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt
```
**Syntax breakdown:**
- `gobuster` — Gobuster tool _command_
- `dir` — Directory brute-force mode _value_
- `-u` — Target URL _parameter_
- `-w` — Wordlist file _parameter_

**Step 0**
> Specify file extensions
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt
```
**Syntax breakdown:**
- `-x` — File extensions _parameter_

**Step 0**
> Brute-force subdomains
_platform: linux_
```
gobuster dns -d target.com -w subdomains.txt
```
**Syntax breakdown:**
- `dns` — DNS brute-force mode _value_
- `-d` — Target domain _parameter_

**Step 0**
> Authenticate using a cookie
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt -c "PHPSESSID=xxx"
```
**Syntax breakdown:**
- `-c` — Set cookie _parameter_

**Step 0**
> Add a custom header
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt -H "Authorization: Bearer token"
```
**Syntax breakdown:**
- `-H` — Add a header _parameter_

**Step 0**
> Set the number of threads
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt -t 50
```
**Syntax breakdown:**
- `-t` — Number of threads _parameter_

**Step 0**
> Ignore specific status codes
_platform: linux_
```
gobuster dir -u http://target.com -w wordlist.txt -b 404,403
```
**Syntax breakdown:**
- `-b` — Blacklisted status codes _parameter_

---

### Nuclei  `nuclei`
_Fast vulnerability scanning tool_

**Step 0**
> Scan using all templates
_platform: linux_
```
nuclei -u http://target.com
```

**Step 0**
> Use CVE templates
_platform: linux_
```
nuclei -u http://target.com -t cves/
```

**Step 0**
> Specify vulnerability severity levels
_platform: linux_
```
nuclei -u http://target.com -severity critical,high
```

**Step 0**
> Read targets from a file
_platform: linux_
```
nuclei -l urls.txt
```

**Step 0**
> Update the template library
_platform: linux_
```
nuclei -update-templates
```

**Step 0**
> Save scan results
_platform: linux_
```
nuclei -u http://target.com -o results.txt
```

**Step 0**
> JSON format output
_platform: linux_
```
nuclei -u http://target.com -json -o results.json
```

---

### Seatbelt  `seatbelt-tool`
_Windows security information gathering tool_

**Step 0**
> Collect all information
_platform: windows_
```
Seatbelt.exe -group=all
```

**Step 0**
> Collect system information
_platform: windows_
```
Seatbelt.exe -group=system
```

**Step 0**
> Collect user information
_platform: windows_
```
Seatbelt.exe -group=user
```

**Step 0**
> Collect security configuration
_platform: windows_
```
Seatbelt.exe -group=security
```

**Step 0**
> Collect network information
_platform: windows_
```
Seatbelt.exe -group=network
```

**Step 0**
> Remote information gathering
_platform: windows_
```
Seatbelt.exe -group=all -computername=TARGET -username=DOMAIN\user -password=password
```

---

### SearchSploit  `searchsploit-tool`
_Exploit search tool_

**Step 0**
> Search for Apache vulnerabilities
_platform: linux_
```
searchsploit apache 2.4
```

**Step 0**
> Exact-match search
_platform: linux_
```
searchsploit -e "Apache 2.4"
```

**Step 0**
> Exclude a specific type
_platform: linux_
```
searchsploit apache --exclude="DoS"
```

**Step 0**
> View exploit code
_platform: linux_
```
searchsploit -x exploits/xxx.py
```

**Step 0**
> Copy to the current directory
_platform: linux_
```
searchsploit -m exploits/xxx.py
```

**Step 0**
> Update the exploit database
_platform: linux_
```
searchsploit -u
```

---

### Amass  `amass-tool`
_Subdomain enumeration tool_

**Step 0**
> Enumerate subdomains
_platform: linux_
```
amass enum -d target.com
```

**Step 0**
> Passive information gathering
_platform: linux_
```
amass enum -passive -d target.com
```

**Step 0**
> Active information gathering
_platform: linux_
```
amass enum -active -d target.com
```

**Step 0**
> Brute-force subdomains
_platform: linux_
```
amass enum -brute -d target.com -w wordlist.txt
```

**Step 0**
> Save enumeration results
_platform: linux_
```
amass enum -d target.com -o output.txt
```

---

### Subfinder  `subfinder-tool`
_Subdomain discovery tool_

**Step 0**
> Enumerate subdomains
_platform: linux_
```
subfinder -d target.com
```

**Step 0**
> Recursive enumeration
_platform: linux_
```
subfinder -d target.com -recursive
```

**Step 0**
> Save results
_platform: linux_
```
subfinder -d target.com -o output.txt
```

**Step 0**
> JSON format output
_platform: linux_
```
subfinder -d target.com -json -o output.json
```

**Step 0**
> Batch-process domains
_platform: linux_
```
subfinder -dL domains.txt
```

---

### HTTPX  `httpx-tool`
_HTTP probing tool_

**Step 0**
> Probe HTTP services
_platform: linux_
```
cat urls.txt | httpx
```

**Step 0**
> Get page titles and status codes
_platform: linux_
```
cat urls.txt | httpx -title -status-code
```

**Step 0**
> Web page screenshots
_platform: linux_
```
cat urls.txt | httpx -screenshot
```

**Step 0**
> Technology stack detection
_platform: linux_
```
cat urls.txt | httpx -tech-detect
```

**Step 0**
> Save results
_platform: linux_
```
cat urls.txt | httpx -o output.txt
```

---

### Masscan  `masscan`
_The fastest Internet port scanner, capable of scanning the entire Internet in 5 minutes_

**Step 0**
> Scan all ports of a target at a rate of 1000 packets per second
```
masscan -p1-65535 target_ip --rate=1000
```
**Syntax breakdown:**
- `masscan` — High-speed port scanner _command_
- `-p1-65535` — Scan all 65535 ports _parameter_
- `--rate=1000` — Send 1000 packets per second _parameter_

**Step 0**
> Scan common web and database ports
```
masscan -p80,443,8080,8443,3306,6379,27017 target_ip/24 --rate=500
```

**Step 0**
> Supports JSON/XML/Grepable format output
```
masscan -p1-65535 target_ip --rate=1000 -oJ result.json
masscan -p1-65535 target_ip --rate=1000 -oX result.xml
masscan -p1-65535 target_ip --rate=1000 -oG result.grep
```

**Step 0**
> Specify the network interface and exclude a specific IP range
_platform: linux_
```
masscan -p1-65535 10.0.0.0/8 --rate=10000 -e eth0 --excludefile exclude.txt
```

**Step 0**
> Grab service banner information
```
masscan -p80,443 target_ip/24 --banners --rate=500
```

---

### Dirsearch  `dirsearch`
_Advanced web directory and file brute-forcing tool_

**Step 0**
> Scan directories and files with specified extensions
```
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js
```
**Syntax breakdown:**
- `-u` — Target URL _parameter_
- `-e` — Specify the file extensions to scan _parameter_

**Step 0**
> Use a custom wordlist and set a request delay
```
dirsearch -u https://target.com -w /usr/share/wordlists/dirb/big.txt --delay=0.5
```

**Step 0**
> Recursively scan to a depth of 3, excluding 403/404
```
dirsearch -u https://target.com -e php -r -R 3 --exclude-status=403,404
```

**Step 0**
> 20 concurrent threads, carrying authentication information
```
dirsearch -u https://target.com -t 20 --cookie="session=abc123" -H "Authorization: Bearer token"
```

**Step 0**
> Output results in JSON format
```
dirsearch -u https://target.com -o result.json --format=json
```

---

### FeroxBuster  `feroxbuster`
_High-performance recursive directory discovery tool written in Rust_

**Step 0**
> Scan directories using a SecLists wordlist
```
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
**Syntax breakdown:**
- `feroxbuster` — High-speed directory enumeration tool written in Rust _command_
- `-u` — Target URL _parameter_
- `-w` — Wordlist file path _parameter_

**Step 0**
> Recurse 3 levels, filter status codes, limit rate
```
feroxbuster -u https://target.com -d 3 -C 403,404,500 -x php,asp,html --rate-limit 50
```

**Step 0**
> Carry authentication headers, 30 concurrent threads
```
feroxbuster -u https://target.com -H "Cookie: session=abc" -H "Authorization: Bearer xxx" -t 30
```

**Step 0**
> Automatically adjust request rate and filtering conditions
```
feroxbuster -u https://target.com --auto-tune --smart
```

---

### MassDNS  `massdns`
_High-performance DNS resolver used for subdomain brute-force enumeration_

**Step 0**
> Resolve subdomains using a wordlist file
_platform: linux_
```
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt
```
**Syntax breakdown:**
- `-r resolvers.txt` — List of DNS resolvers _parameter_
- `-t A` — Query A records _parameter_
- `-o S` — Concise output mode _parameter_

**Step 0**
> Batch-generate subdomains and output in JSON format
_platform: linux_
```
cat subdomains.txt | sed "s/$/.target.com/" > full_subs.txt
massdns -r resolvers.txt -t A -o J full_subs.txt > results.json
```

**Step 0**
> Set concurrency and hash table size to improve performance
_platform: linux_
```
massdns -r resolvers.txt -t A -o S -w output.txt --hashmap-size 10000 -s 10000 subs.txt
```

---

### Amass  `amass`
_OWASP's deep attack surface mapping and asset discovery tool_

**Step 0**
> Enumerate subdomains using passive data sources only
```
amass enum -passive -d target.com -o results.txt
```
**Syntax breakdown:**
- `enum` — Enumeration mode _command_
- `-passive` — Passive collection only (does not send requests) _parameter_
- `-d` — Target domain _parameter_

**Step 0**
> Active DNS enumeration + wordlist brute-forcing
```
amass enum -active -d target.com -brute -w /usr/share/amass/wordlists/subdomains-top1mil.txt
```

**Step 0**
> Collect WHOIS and organization-related domain intelligence
```
amass intel -d target.com -whois
amass intel -org "Target Corp" -max-dns-queries 2500
```

**Step 0**
> Generate a D3.js visualization chart and view historical data
```
amass viz -d3 -d target.com
amass db -show -d target.com
```

---

### Subfinder  `subfinder`
_Passive subdomain discovery tool supporting multiple online data sources_

**Step 0**
> Enumerate subdomains and output to a file
```
subfinder -d target.com -o subs.txt
```
**Syntax breakdown:**
- `subfinder` — Passive subdomain enumeration tool _command_
- `-d` — Target domain _parameter_

**Step 0**
> Recursively enumerate using all data sources
```
subfinder -d target.com -recursive -all -o subs.txt
```

**Step 0**
> Combine with httpx to probe for live subdomains
```
subfinder -d target.com -silent | httpx -silent -status-code -title
```

**Step 0**
> Read multiple domains from a file for batch enumeration
```
subfinder -dL domains.txt -o all_subs.txt -t 30
```

---

### HTTPX  `httpx`
_Fast, multi-purpose HTTP probe tool for batch-probing web services_

**Step 0**
> Batch-probe URL liveness, titles, and technology stacks
```
httpx -l urls.txt -status-code -title -tech-detect -o alive.txt
```
**Syntax breakdown:**
- `-status-code` — Display HTTP status codes _parameter_
- `-title` — Extract page titles _parameter_
- `-tech-detect` — Identify web technology stacks _parameter_

**Step 0**
> Screenshots, extract favicon hashes and JARM fingerprints
```
httpx -l urls.txt -screenshot -favicon -hash md5 -jarm
```

**Step 0**
> Filter specific status codes and display server information
```
cat subs.txt | httpx -silent -mc 200,301,302 -content-length -web-server
```

**Step 0**
> Batch-probe specified paths
```
httpx -l urls.txt -path "/api/v1/health,/admin,/.env,/robots.txt" -mc 200
```

---

### WhatWeb  `whatweb`
_Web fingerprinting tool that identifies the technology stack a website uses_

**Step 0**
> Identify the target website's technology stack
```
whatweb https://target.com
```
**Syntax breakdown:**
- `whatweb` — Web technology fingerprinting tool _command_

**Step 0**
> Verbose output, aggression level 3 (deeper probing)
```
whatweb -v https://target.com -a 3
```

**Step 0**
> Read URLs from a file for batch scanning
```
whatweb --input-file=urls.txt --log-json=results.json
```

**Step 0**
> List or specify the use of particular plugins
```
whatweb --info-plugins
whatweb -p WordPress,Joomla,Drupal https://target.com
```

---

### WAFW00F  `wafw00f`
_Web Application Firewall (WAF) detection and fingerprinting tool_

**Step 0**
> Detect whether the target has a WAF deployed and its WAF type
```
wafw00f https://target.com
```
**Syntax breakdown:**
- `wafw00f` — WAF fingerprinting tool _command_

**Step 0**
> Verbose mode, test all WAF signatures
```
wafw00f https://target.com -v -a
```

**Step 0**
> Batch-detect multiple URLs
```
wafw00f -i urls.txt -o results.csv
```

**Step 0**
> List all identifiable WAF products
```
wafw00f -l
```

---

### DNSRecon  `dnsrecon`
_DNS enumeration and information gathering tool_

**Step 0**
> Standard DNS record enumeration (SOA/NS/A/MX/TXT, etc.)
```
dnsrecon -d target.com -t std
```
**Syntax breakdown:**
- `-d` — Target domain _parameter_
- `-t std` — Standard record enumeration type _parameter_

**Step 0**
> Attempt a DNS zone transfer
```
dnsrecon -d target.com -t axfr
```

**Step 0**
> Brute-force enumerate subdomains using a wordlist
```
dnsrecon -d target.com -t brt -D /usr/share/wordlists/subdomains.txt
```

**Step 0**
> Perform reverse DNS lookups on an IP range
```
dnsrecon -r 192.168.1.0/24 -t rvl
```

---

### DNSEnum  `dnsenum`
_DNS information gathering tool supporting zone transfers and subdomain enumeration_

**Step 0**
> Enumerate DNS information (NS/MX/A/zone transfer, etc.)
```
dnsenum target.com
```

**Step 0**
> Brute-force enumerate subdomains using a wordlist
```
dnsenum --enum -f /usr/share/dnsenum/dns.txt --threads 10 target.com
```

**Step 0**
> Specify a DNS server for enumeration
```
dnsenum --dnsserver 8.8.8.8 target.com
```

---

### theHarvester  `theharvester`
_OSINT information gathering tool for emails, subdomains, IPs, etc._

**Step 0**
> Gather information using all data sources
```
theHarvester -d target.com -b all -l 500
```
**Syntax breakdown:**
- `-d` — Target domain _parameter_
- `-b all` — Use all available data sources _parameter_
- `-l 500` — Maximum number of results _parameter_

**Step 0**
> Gather using specified data sources
```
theHarvester -d target.com -b google,bing,linkedin,shodan
```

**Step 0**
> Generate an HTML format report
```
theHarvester -d target.com -b all -f report.html
```

---
