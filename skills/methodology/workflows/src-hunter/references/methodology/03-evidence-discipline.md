# Black-box evidence discipline

> Perspective: before reporting a bug, make sure every claim you make holds up and that a platform reviewer can reproduce it.

---

## 1. The one-line principle

**Every vulnerability conclusion = one reproducible piece of HTTP traffic + one observable side-effect as evidence.**

Without both of those, it is not a bug, it is a guess. Do not put it in the report.

---

## 2. How black-box "hallucinations" arise

| Hallucination type | Typical symptom | The reality |
|---------|---------|---------|
| **Response-signature hallucination** | Seeing a 500 + "syntax error" and calling it SQLi | It may just be a parameter type mismatch, not necessarily injectable |
| **Delay hallucination** | The response slows after `sleep(5)`, so you call it time-based blind SQLi | It may be network jitter, rate limiting, or an occasional slow response |
| **Reflection hallucination** | You see your own payload reflected and call it XSS | It may sit in a `<textarea>`, be escaped, or have Content-Type=text/plain |
| **Error-message hallucination** | The error page mentions `/var/www/html/...` and you call it a path disclosure | It may be public documentation to begin with |
| **Version-guess hallucination** | Seeing `Server: nginx/1.x` and reporting a CVE | With no PoC to verify it |
| **Internal-IP hallucination** | One DNSLog record arrives and you call it SSRF | It may be browser prefetch or a third-party scan |
| **Platform-data hallucination** | "I assumed it was that company's asset" | The asset is out of scope, and submitting it is a violation |

> SRC platform reviewers see hundreds of reports a day; an "I assumed" bug gets instantly rejected and lowers your reputation score.

---

## 3. The three principles of black-box evidence

### Principle 1: traffic verbatim

The PoC in the report **must** be copy-pasteable into curl / Repeater and reproduce directly.

Do not write:
```
"Submit ' or 1=1-- at the search endpoint to trigger SQL injection"
```

Write:
```http
POST /api/search HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGc... (redacted to the first 10 characters)
Content-Type: application/json
Content-Length: 45

{"keyword":"a' UNION SELECT version()-- -"}
```

Plus:
- The full URL (including the scheme)
- The full method + headers (sensitive headers redacted)
- The body, verbatim
- The key part of the response (screenshot + text)

### Principle 2: differential proof

A vulnerability is behavior that deviates from what's expected. Proving the deviation needs a "control group".

| Test | At least these 3 requests |
|------|--------------|
| **SQLi (blind)** | true-condition request (5s delay) + false-condition request (immediate return) + clean baseline request |
| **IDOR** | your own resource 200 + another user's resource 200 (containing their data) + a nonexistent resource 404 |
| **Broken access control** | ordinary user denied 403 + admin allowed 200 + ordinary user bypassing to 200 (the key evidence) |
| **Logic** | the response for the normal flow + the response for the tampered flow + the real side effect of tampering (the order appears) |
| **SSRF** | internal IP denied (reference) + internal IP allowed (the bug) + external callback (DNSLog) |

### Principle 3: observable side effect

For code-execution-class bugs, you must have evidence that "something happened on the target":

| Vulnerability type | Side-effect evidence |
|---------|----------|
| **RCE** | DNSLog / HTTP out-of-band echo / a file created and read back / a screenshot of command output |
| **SSRF** | the internal response body received / a metadata token / logs on an external callback server |
| **Arbitrary file read** | the actual contents of the target file (`/etc/passwd` with a root: line, config with a real database address) |
| **File upload** | access the file after upload and get a non-404 response |
| **SQLi** | real data: `version()`, `current_database()`, an admin hash prefix |
| **XSS** | an alert screenshot + the URL bar, or a callback received via the SRC's own XSS Hunter platform |

**Strictly forbidden:** dumping databases, deleting data, changing passwords, leaving a shell. Take just enough evidence to prove the capability, then stop.

---

## 4. Reproduction-rate requirements

| Severity | Minimum reproduction rate | Number of reproductions |
|---------|----------|---------|
| P0 RCE / auth bypass | 100% | at least 3 times, 1h+ apart |
| P1 SQLi / IDOR | 95%+ | at least 3 times |
| P1 logic / broken access | 90%+ | at least 5 times (different accounts / different times) |
| P2 / time-based blind | 80%+ | at least 5 times, with the measured delay difference attached |
| Race condition | "hits reliably in N attempts" | 5+ times, with the script |

If you cannot hit the rate, **proactively** state so in the report ("succeeded in 4 of 5 tests"); do not pretend it is 100%.

---

## 5. DNSLog / out-of-band platform choice

| Purpose | Recommended platform |
|------|---------|
| DNS exfil | `dnslog.cn`, `ceye.io`, Burp Collaborator, `interactsh` (free, self-hostable) |
| HTTP exfil | Burp Collaborator, `requestbin.com`, a self-built webhook |
| LDAP (JNDI/Log4Shell) | self-hosted `JNDI-Injection-Exploit` / `marshalsec` |
| General callback | `webhook.site` (friendly UI, easy to screenshot) |

**Strongly recommended: run your own OOB server**:
- You keep a complete evidence log
- You won't collide with another researcher's token
- You can place it in a different IP range to verify SSRF "external reachability"

In the report, write:
```
Out-of-band echo domain: xx.attacker.com (attacker-controlled)
DNS resolution record: 2025-05-09 10:23:45 UTC, source IP a.b.c.d queried xx.attacker.com
Full log in the attached dns_log.txt
```

---

## 6. Screenshot conventions

Every screenshot should include at least:

- The full URL bar (proving the domain + path + parameters)
- The browser / Burp timestamp
- The response content (with the field most relevant to the bug highlighted)
- If there is data: **mask/redact it**, but keep the length and format (phone number `138****1234`, ID `12*****345`)

The report's cover page usually needs one "vulnerability overview" image (the result at a glance).

---

## 7. Screen-recording conventions (recommended for high-value bugs)

For P0/P1 bugs, a 30s-2min recording greatly speeds up the review.

Recording essentials:
- Show the URL + current user identity at the start
- Demonstrate the request + response in real time
- Mask key pages/data
- Keep the timestamp visible
- Do not edit the recording (editing invites suspicion of forgery)

Tools: OBS, ScreenToGif, Burp's built-in Logger recording, ffmpeg `ffmpeg -f x11grab ...`.

---

## 8. Scope / compliance boundaries

Self-check before reporting:

- [ ] The domain / IP is within the program scope (check the H1/Bugcrowd policy)
- [ ] You did not access anyone else's PII (if you did, stop immediately, note it in the report, and do not include the raw data)
- [ ] You did not trigger a DDoS / high request volume (rate-limit fuzzing to 1-5 rps, take at most 10 sample records when walking IDOR)
- [ ] You did not delete or modify any data
- [ ] You did not upload content others can access (a webshell / phishing page)
- [ ] You did not access other users' accounts (OAuth testing uses only two accounts you control)

Non-compliant "evidence" invalidates the bug and gets your account banned.

---

## 9. Anti-patterns (these get instantly rejected by reviewers)

```
❌ "SQL injection may exist; further verification is recommended."
❌ "The backend is presumed to use MySQL, hence a time-based blind."
❌ "Because the header carries X-Powered-By: PHP, it may be a deserialization bug."
❌ "By black-box guessing, admin/admin may log in." (must be tested for real, and only 1-3 times, to avoid brute force)
❌ "I have no PoC, but in theory it could..."
❌ "Webshell uploaded, at /uploads/x.php" (a violation)
❌ "I have already downloaded 1000 user records locally" (a violation)
```

Correct:

```
✓ "By the stable 5-second delay difference between sleep(5) and sleep(0) on the same parameter,
   time-based blind injection is confirmed. Full traffic in attachment 1; reproduced 5/5 times."
✓ "With two test accounts A and B, A can read B's order details;
   attached are the HTTP request + a screenshot + a single sample (redacted).
   No enumeration or export was attempted."
```

---

## 10. Self-check list (run through before submitting)

- [ ] The title follows the `[severity][precondition][type] endpoint - one line` format
- [ ] The asset is in scope
- [ ] The reproduction steps are numbered one by one, with full HTTP requests
- [ ] At least 1 response screenshot + 1 screenshot with the URL visible
- [ ] Side-effect evidence (out-of-band / data / file)
- [ ] At least 3 successful reproductions
- [ ] A CVSS 3.1 / 4.0 vector + the impacted segment
- [ ] Remediation advice (specific + actionable)
- [ ] No irreversible impact on production data
- [ ] Personal PII / third-party data is redacted

Run through all 10 before clicking Submit.
