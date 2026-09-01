# Playbooks Master Index

> Every playbook takes a black-box perspective: assume only the URL and parameters are known, with no source code

---

## Reading Recommendations

Read in "SRC value / ease of shipping" order:

| Priority | Playbook | One-line value |
|-------|---------|-----------|
| 🔴 P0 | `unauth-access.md` | Default credentials / Redis-Mongo-ES / Actuator / Swagger / .git — the P0s handed to you at the start |
| 🔴 P0 | `rce.md` | Log4Shell / Spring4Shell / Fastjson / Struts2 / command injection fingerprint library |
| 🔴 P0 | `file-upload.md` | Parser vulnerabilities + editor vulnerabilities + truncation bypass |
| 🔴 P0 | `path-traversal.md` | `../etc/passwd` plus 6 encodings + WEB-INF / web.config |
| 🟠 P1 | `info-disclosure.md` | .git / .svn / backup files / phpinfo / logs / OSS bucket |
| 🟠 P1 | `logic-flaws.md` | Password reset 4 patterns / IDOR / privilege escalation / CAPTCHA / payment |
| 🟠 P1 | `arbitrary-x-authz.md` | Arbitrary X sub-authorization (arbitrary account 86.4% / arbitrary operation 72.5%) |
| 🟠 P1 | `oauth-saml-jwt.md` | redirect_uri / state / JWT alg / kid / SAML wrapping |
| 🟠 P1 | `sqli.md` | Distilled from 27,732 real cases, includes high-frequency parameter frequency table |
| 🟠 P1 | `ssrf-cache-host.md` | Internal network probing + cloud metadata + Host header / cache poisoning |
| 🟡 P1/P2 | `api-rest.md` | BOLA / Mass Assignment / rate limiting / CORS |
| 🟡 P1/P2 | `graphql.md` | Introspection / nested IDOR / DoS |
| 🟡 P2 | `race-conditions.md` | Coupon double-spend / balance over-deduction / limit bypass |
| 🟡 P2 | `xss.md` | 7,532 real cases, context bypass table |
| 🟡 P2 | `http-smuggling.md` | CL.TE / TE.CL / H2→H1 |
| 🟡 P2 | `mobile.md` | Android exported components / Intent / WebView / Pinning |
| 🟡 P2 | `llm-prompt-injection.md` | Prompt injection / RAG poisoning / Agent tools |

---

## Unified Structure of Each Playbook

```
1. State clearly what it is in one line + why SRC cares
2. High-frequency entry points (parameter names / paths / headers), citing statistics
3. Probing techniques (Probe) — payload + response signature + out-of-band/time-delay/differential
4. Bypass matrix (encoding, obfuscation, WAF, filter bypass)
5. Exploitation / privilege escalation / lateral movement (from trigger to value escalation)
6. Real-case fingerprints (CVE/wooyun ID + 1-line version signature + detection payload)
7. Reproduction/evidence essentials (HTTP packets, key CVSS vector, impact section wording)
8. What not to do (compliance boundaries / data protection)
```

---

## Relationship to the Methodology

```
methodology/01-attack-priority   →  decides which playbook to hit first
methodology/04-control-gap        →  endpoint classification → flip to the corresponding playbook
methodology/02-bypass-toolkit     →  general bypass when a payload is blocked
methodology/03-evidence            →  evidence discipline before writing the report
playbooks/<type>.md                →  probing/exploitation details for the specific type
templates/report-submission.md     →  H1/Bugcrowd three-part submission template
```
