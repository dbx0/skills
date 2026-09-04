---
name: bug-bounty
description: "Bug bounty methodology: evidence capture, triage, reporting. Covers the full bug bounty lifecycle from finding validation to report writing for H1/Bugcrowd/Intigriti."
version: 2.0.0
author: Hermes Agent (consolidated)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bug-bounty, evidence, triage, reporting, h1, bugcrowd, intigriti]
    related_skills: [bug-bounty-evidence, bug-bounty-triage, bug-bounty-reporting, bug-bounty-methodology, bugbounty-report-format]
---

# Bug Bounty Methodology

This is the **umbrella skill** for bug bounty hunting. It covers the full lifecycle from evidence capture to triage to report writing.

**Sub-skills (loaded automatically when needed):**
- `bug-bounty-evidence` — Evidence-capture and PoC-redaction discipline
- `bug-bounty-triage` — Finding validation before writing any report (7-Question framework)
- `bug-bounty-reporting` — Bug bounty report writing for H1/Bugcrowd/Intigriti/Immunefi
- `bug-bounty-methodology` — Use at the START of any bug bounty hunting session
- `bugbounty-report-format` — The submission structure and prose rules: section order, attack path, `V1..Vn` validation blocks, proven-only discipline

## Quick Decision Guide

| Phase | Go to |
|-------|-------|
| Starting a new bug bounty session | `bug-bounty-methodology` |
| Capturing evidence / PoC | `bug-bounty-evidence` |
| Validating before reporting | `bug-bounty-triage` |
| Writing the report | `bugbounty-report-format` |
| Restructuring a draft that is too long or unreadable | `bugbounty-report-format` |
| Choosing the VRT / severity to submit under | `vrt-classifier` |

## Skill Routing — Call the Right Skill for Every Situation

**This is the biggest source of missed coverage: skills exist in the arsenal but don't get invoked.** Do not rely on memory of what a skill does — invoke it. Re-check this table every time the hunt pivots to a new target type, asset class, or finding type, not just at session start.

**Rule:** before acting on a new lead, target type, or asset class, scan the table below. If a row matches, invoke that skill via the `Skill` tool BEFORE doing the work manually. If two rows match, invoke both — narrowest first.

| Situation / target type | Skill to invoke |
|---|---|
| Starting a new bug bounty session, no plan yet | `bug-bounty-methodology`, `bugbounty-hunt` |
| Need a general offensive posture / mindset check | `offensive-security`, `redteam-mindset` |
| Subdomain enum, asset discovery, live-host sweep | `web2-recon` |
| Homepage looks thin, need second-order pivots | `artifact-pivot-intelligence` |
| JS bundles, source maps, client-side routes/secrets | `client-runtime-intelligence` |
| Secret/key/token found via variable-name grep in a JS bundle | `build-env-secret-triage` |
| Recovered credential needs proof it's live before reporting | `credential-verification` |
| Host is dead/replaced, or a fixed endpoint might still leak via archived responses | `archive-credential-recovery` |
| First-party JS has `addEventListener("message", …)` / `onmessage` (widgets, iframes, SSO) | `postmessage-security` |
| REST / GraphQL / WebSocket / SOAP endpoint testing | `api-security` |
| GraphQL introspection blocked but schema recovery still needed | `graphql-schema-reconstruction` |
| A sensitive path returns a WAF/edge 403 while siblings respond normally | `waf-path-bypass` |
| General web app vuln hunting (XSS, SQLi, logic flaws) | `vulnerability-hunting` |
| Deep manual attack on ONE business workflow | `deep-hunt` |
| JS obfuscation / signature chains / request signing in frontend | `js-reverse` |
| Request smuggling suspected (front/back desync) | `request-smuggling-specialist` |
| Flask/Werkzeug fingerprinted on target | `flask-werkzeug-attack` |
| Target has a Play Store / App Store listing or APK URL | `apk-redteam-pipeline` |
| Already have an APK/IPA to reverse | `apk-reverse`, `mobile-reverse` |
| Cloud storage bucket, hosted identity platform, backend service exposed | `cloud-exposure-triage` |
| AWS key / Azure secret / GCP SA JSON / K8s SA token found | `cloud-iam-deep` |
| Okta tenant in scope | `okta-attack` |
| M365 / Entra ID in scope | `m365-entra-attack` |
| VMware vCenter/ESXi in scope | `vmware-vcenter-attack` |
| Enterprise VPN appliance in scope | `enterprise-vpn-attack` |
| Source code repo, package registry, CI/CD, dependency chain | `supply-chain-attack-recon`, `supply-chain-security`, `src-hunter` |
| Binary, firmware, or compiled artifact needs reversing | `reverse-engineering`, `radare2`, `ida-reverse`, `firmware-pentest`, `binary-diff` |
| Malware sample or C2 panel found | `malware-analysis`, `c2-panel-analysis`, `edr-bypass-re` |
| Need to identify a person/handle across platforms (OSINT) | `sherlock` |
| Have a primitive, need to prove real-world impact | `attack-chain` |
| Multiple findings need chaining into one A-to-B path | `attack-chain-multistage` |
| Several independent leads that don't share state | `subagent-hunt-orchestration` |
| Target needs ongoing/recurring surface monitoring | `continuous-surface-monitoring` |
| Mid-engagement, suspect defensive detection/response kicking in | `mid-engagement-ir-detection` |
| Capturing evidence / building a PoC | `bug-bounty-evidence` |
| About to validate a finding before reporting it | `bug-bounty-triage` |
| Writing the actual report | `bugbounty-report-format` |
| Draft report is too long, or evidence is tangled up with the narrative | `bugbounty-report-format` |
| Need an attack path or an "as an attacker I could" statement for a finding | `bugbounty-report-format`, `attack-chain` |
| Picking the VRT entry, CWE or CVSS baseline | `vrt-classifier` |
| A finding risks being misclassified by delivery mechanism rather than context | `vrt-classifier`, `bugbounty-report-format` |
| Full pentest engagement (not pure bug bounty) | `pentest-playbook`, `pentest-tools` |

### Red Flags — You're About to Skip a Relevant Skill

| Thought | Reality |
|---|---|
| "I already know how to do this" | Skills encode methodology beyond what you'd freewheel. Invoke it anyway. |
| "This is a quick check, not a full workflow" | Quick checks are exactly where coverage gets missed. Check the table. |
| "I'll invoke it if I get stuck" | The skill tells you what to try before you'd know you're stuck. Front-load it. |
| "The target doesn't perfectly match a row" | Match on asset class, not exact wording. Mobile app in scope → mobile row, even if you're "just poking at it." |
| "I already loaded a skill this session" | A new target type or asset class mid-hunt means re-checking the table, not reusing the last skill loaded. |

## The 7-Question Triage Framework

Before writing any report or presenting a finding to the user, validate:
1. **Is this actually a vulnerability, or just an observation?**
   — An endpoint existing ≠ a vulnerability. An API returning 401 ≠ a vulnerability. A user seeing their own data ≠ a vulnerability.
   — Distinguish between "attack surface" (an endpoint exists) and "actual vulnerability" (the endpoint leaks/corrupts data or bypasses auth).
   — Presenting features as vulnerabilities will frustrate clients. Validate what makes it a vulnerability before speaking.
2. **What is the impact — and has it been DEMONSTRATED, not asserted?**
   — See the Impact Demonstration Gate below. This is the question that gets reports closed as Not Applicable. A described impact is not an impact.
3. **Can it be reproduced reliably?**
   — Show exact steps with request/response evidence.
4. **Is it in scope?**
5. **Has it been reported before?**
6. **What is the CVSS score?**
7. **What is the recommended fix?**

## The Impact Demonstration Gate (READ BEFORE CALLING ANYTHING A VULNERABILITY)

**This is the single most common reason reports get closed as Not Applicable.** The typical rejection reads:

> After reviewing your report, we were unable to identify any security impact. [...] In order to be a triaged issue a submission must demonstrate an impact that can have an effect on the customer, the application/website, or its users. Submissions should always answer the question, **"as an attacker I could"**, with a suitable demonstration of such. Findings that reveal points of information or security best practices without an impact are not eligible for a reward.

**The rule:** a finding is not a vulnerability until you have *executed* the attack and *captured the result*. Impact must be proven with evidence, never inferred from configuration, code reading, or plausibility.

### The "as an attacker I could" test

Write the sentence literally, then check it against evidence:

> "As an attacker I could **[concrete action]**, resulting in **[concrete harm to the customer/app/users]**, demonstrated by **[captured request/response, decrypted data, screenshot, callback hit]**."

If any of the three brackets can only be filled with speculation, **it is not a reportable vulnerability yet** — it is a lead. Keep testing or drop it.

| Not demonstrated (assertion) | Demonstrated (evidence) |
|---|---|
| "This could allow an attacker to steal card data" | Captured POST to attacker collector + decrypted PAN/CVV in plaintext |
| "An attacker could access other users' records" | Two-account test: account A retrieves account B's freshly-created record, both responses shown |
| "This field is not sanitized, enabling XSS" | Payload rendering and executing in a real browser, screenshot/console proof of execution context |
| "Missing header X exposes users to attack Y" | Attack Y actually carried out against a real session, with the outcome captured |
| "Exposed key could allow unauthorized API access" | Key used to make an authenticated call, response showing data/privilege obtained |
| "Enumerable IDs allow mass data harvesting" | Actual retrieval across N IDs with counts and sample (redacted) records |

### Hard requirements before writing any report

1. **Execute the attack.** Do not report a theoretical chain. If the exploit requires a browser, drive a real browser. If it requires two accounts, use two accounts. If it requires decryption, decrypt it.
2. **Capture the outcome, not the setup.** A request that *reaches* a sink proves reachability, not impact. Show what the attacker *ends up holding*.
3. **Name a real victim class.** "The customer", "the application", or "its users" — if the only party affected is the tester's own account or a fixture/test record, there is no impact. (A record identical across two unrelated accounts is a shared fixture, not a leaked user record.)
4. **Confirm the security boundary was actually crossed.** Reading your own data, hitting a properly-401'd endpoint, or triggering a documented feature is not a crossing.
5. **Rule out the benign explanation first.** Before claiming a bypass, verify the control exists and is enforced elsewhere. Before claiming a leak, verify the data is not intentionally public.
6. **State the ceiling honestly.** Explicitly note what the finding does *not* achieve. Overclaiming gets the whole report discounted; a stated ceiling makes the demonstrated part credible.

### Categories that are Not Applicable without a demonstrated exploit

These are "security best practices" findings — informational only unless attached to a working, captured exploit:

- Missing/weak security headers (CSP, HSTS, X-Frame-Options) with no demonstrated attack
- Cookie flags (`HttpOnly`, `Secure`, `SameSite`) with no session compromise shown
- Version disclosure, banner grabbing, verbose errors with no exploited consequence
- Source maps / bundle disclosure with no secret or vulnerability extracted *from* them
- Exposed keys/tokens never tested against a live endpoint (test them, or don't report them)
- CORS wildcard without credentials, with no cross-origin data retrieval shown
- Rate limiting absent, with no abuse outcome demonstrated
- Self-XSS, or "unsanitized storage" with no confirmed render/execution context
- Enumerable identifiers with no data actually retrieved
- Scanner canaries found in stored data — proves a prior scan, not a working exploit
- Clickjacking on pages with no state-changing action
- Any finding whose impact statement contains "could", "may", "potentially", or "an attacker might" and nothing captured

**If the finding is genuinely informational, say so plainly** and file it as an observation rather than dressing it up as a vulnerability. A short honest note preserves credibility; an overclaimed report burns it and risks the program's trust in the rest of your submissions.

## Pitfalls — Findings That Are NOT Vulnerabilities

Common traps where observations look like findings but aren't:

| What you found | Why it's NOT a vuln |
|---|---|
| Phone numbers on marketplace ad pages | Expected — buyers need to contact sellers. HOWEVER: correlating phone numbers from ads with names from a separate public feed IS a data leak (see Data Exposure Correlation below) |
| User sees their own notifications | Expected — that's the feature |
| API endpoint returns 401 | Expected — it's properly protected |
| Supabase URL in client JS | Expected — it's how SPAs connect to backend |
| Cookie set on login | Expected — that's session management |
| User profile with own data | Expected — that's the profile page |
| Admin login page exists | Expected — admins need a login form |
| WHM/cPanel accessible on port 2087/2083 | Expected — those are the standard management ports. Not a vulnerability unless there are default creds or unpatched CVEs. |
| 525 SSL error on Cloudflare-proxied subdomain | Infrastructure misconfiguration, not a vulnerability. The origin server is down or misconfigured. Document as an observation, not a finding. |
| 502/503/526 error pages | Server health issues, not security vulnerabilities. Document separately if relevant. |

### Key Distinction: Feature vs. Data Leak

A single data point exposed is often a feature. **Correlation across multiple public endpoints** that creates a PII profile of a user is a vulnerability. A phone number in an ad is a feature. A phone number + full name + vehicle + event timestamp + Instagram handle obtained by chaining two public APIs is a data leak.

See `references/marketplace-pii-correlation.md` for the full extraction methodology, shell escaping patterns, and scaling strategy.

## Data Exposure Correlation (Marketplace/Classifieds PII Leak)

A common pattern in marketplace/classifieds platforms: individually non-sensitive data points become PII when correlated across separate public endpoints.

### The Pattern

```
Feed/Activity API (public, no auth)
  ├─ actor: "Leonardo Tomaz Pereira"     (full name)
  ├─ url: "/ads/jetta-variant-2-5-5-cilindros"  (ad slug)
  └─ type: "ad_sold"                     (transaction info)
        │
        ▼
Ad Detail Page (public, no auth)
  ├─ Phone: (47) 98858-8969              (seller phone)
  ├─ WhatsApp: wa.me/554788588969        (WhatsApp link)
  └─ Instagram: @lucapagliosa            (social media)
        │
        ▼
Correlated Profile
  ├─ Name: Fabricio Kreusch
  ├─ Phone: (47) 98858-8969
  ├─ Vehicle: BMW 320 - 2017
  ├─ Instagram: @lucapagliosa (if applicable)
  └─ Event: Anunciou em 2026-07-01 23:47
```

### Detection Methodology

1. **Find the activity/notification feed** — Look for `/api/notifications_feed.php`, `/api/feed`, `/api/activity`, etc. Check if it returns names + URLs without auth.

2. **Check ad/page detail endpoints** — Visit the URLs from the feed. Check what PII is exposed on the detail page (phone, WhatsApp, email, Instagram).

3. **Crawl all listings** — Use search/browse endpoints to enumerate ALL active listings, not just recent ones. Look for pagination parameters (`page`, `per_page`, `offset`, `limit`).

4. **Check for search API** — Look for POST-based search endpoints with multipart form data. These often have pagination with `has_more`, `total` fields in JSON responses. Try parameters: `q`, `page`, `per_page`, `sort`, `tab`, `brand_id`, `model_id`.

5. **Scale extraction** — Crawl all paginated pages to collect every listing URL, then visit each listing page to extract PII. Batch processing with rate-limiting (~100-200ms delay).

6. **Correlate** — Match names from feed with phone/Instagram data from ad pages. The same user posting multiple items can be identified across listings by matching phone numbers.

### Common Endpoint Patterns

| Endpoint | What it leaks | Auth |
|---|---|---|
| `/api/notifications_feed.php` | Names, ad URLs, event types, timestamps | None |
| `/api/user_notifications.php` | User-specific notifications | Session cookie |
| `/api/activity`, `/api/feed` | Activity stream data | Varies |
| Search API (POST) | All active listing URLs | Varies (may accept session cookie) |
| `/ads/{slug}` | Phone, WhatsApp, Instagram per seller | None |
| `/pecas/{slug}` | Same as /ads/ but for parts | None |

### Script Template for Bulk Extraction

```python
# Phase 1: Crawl search/browse pages to get ALL listing URLs
all_urls = set()
for page in range(1, 50):
    # POST to search API with multipart form data
    body = multipart_form_data(page=page, per_page=36)
    r = requests.post("https://target.com/index.php?action=search", 
                      data=body, cookies=session)
    data = r.json()
    urls = extract_ad_urls(data['results_html'])
    all_urls.update(urls)
    if not data.get('has_more'): break

# Phase 2: Visit each listing to extract PII
for url in all_urls:
    r = requests.get(f"https://target.com{url}")
    phones = extract_phones(r.text)
    whatsapp = extract_whatsapp(r.text)
    instagram = extract_instagram(r.text)
    save(url, phones, whatsapp, instagram)
```

### Severity Assessment

- **HIGH**: Public feed + ad pages expose name, phone, WhatsApp, Instagram for ALL users. Enables mass PII database construction, spam, social engineering, SIM-swap, stalking.
- **MEDIUM**: Only names + ad URLs exposed (phones not on ad pages).
- **LOW**: Only ad details exposed without correlation to real names.

File upload is a high-value attack surface. When testing upload functionality:

## CORS Assessment Rules

When evaluating CORS headers:

| Header combination | Severity |
|---|---|
| `Access-Control-Allow-Origin: *` alone | MEDIUM — enables cross-origin scraping of non-sensitive content |
| `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` | HIGH — enables session-bearing cross-origin requests |
| `Access-Control-Allow-Origin: https://attacker.com` (reflecting Origin) + credentials | CRITICAL — full account takeover via CSRF |
| No CORS headers | Not a finding — default secure behavior |

**Always check both headers.** CORS wildcard without credentials is a common finding but is limited in impact — document it as defense-in-depth, not as a critical vulnerability.

## IDOR (Insecure Direct Object Reference) Testing

Systematic approach to discover IDOR vulnerabilities:

### 1. Map ID-Based Endpoints
- Find all URLs/parameters that accept numeric or UUID identifiers
- Check authenticated areas (profile, messages, orders, notifications)
- Document: `user_id`, `id`, `uid`, `ad_id`, `order_id`, `msg_id`, `part_id`, etc.

### 2. Parameter Fuzzing
Try multiple parameter names for the same function:
```
?user_id=1  ?user=1  ?uid=1  ?u=1  ?id=1  ?profile_id=1  ?view=1  ?userid=1
```

### 3. Verify False Positives
- If `?user_id=1` and `?user_id=999` both return the same page, it's NOT IDOR — the parameter is being ignored
- If `?user_id=1` returns User A's data and `?user_id=2` returns User B's data, it IS IDOR
- Always check if the response actually changes between different IDs
- **Common pitfall:** All IDs return the logged-in user's profile — the parameter is ignored, not vulnerable

### 4. Endpoint-Specific IDOR Checks

| Endpoint Type | What to test |
|---|---|
| User profiles | `profile.php?user_id=N`, `/api/users/N`, `/api/v1/user/N` |
| Ads/listings | `/ads/ID`, `/ads?id=N`, `/api/ads/N`, `/api/v1/ads/N` |
| Messages | `/messages/ID`, `/api/messages/N`, `?thread_id=N` |
| Orders/transactions | `/orders/ID`, `/api/orders/N`, `?order_id=N` |
| Files/uploads | `/uploads/ID`, `/api/files/N`, `?file_id=N` |
| Notifications | `/api/notifications/N`, `?notification_id=N` |
| Comments/reviews | `/comments/ID`, `?review_id=N`, `?comment_id=N` |

### 5. API IDOR — Check Auth Mechanism
- If the API returns "Autenticação ausente" (401) — it's properly protected, not a finding
- If the API returns data for a different user's ID — it's IDOR
- Differentiate between:
  - "Endpoint não encontrado" (404) — endpoint doesn't exist
  - "Autenticação ausente" (401) — endpoint exists, properly protected
  - Actual data returned for another user's ID — IDOR confirmed

### 6. Sequential ID Enumeration
- Try IDs around known values: if you know ad 4193 exists, try 4192, 4194, 4190, 4200
- Try edge cases: 0, 1, -1, 999999, string values ("admin", "test")
- Check if draft/pending/unpublished items have predictable IDs

### 7. Verify IDOR
- Use TWO different authenticated sessions (or one logged-in + one logged-out)
- Confirm the IDOR by accessing another user's data from an incognito/browser session
- Take screenshots showing both sessions for evidence

## Open Redirect XSS Assessment

When testing open redirects for XSS exploitation:

### Step 1: Protocol Testing
Test all URI schemes in the redirect parameter:
```
?url=http://evil.com          — standard redirect
?url=javascript:alert(1)      — JS protocol
?url=data:text/html,<script>alert(1)</script>  — data URI
?url=vbscript:msgbox(1)       — VBScript (IE)
?url=file:///etc/passwd       — file protocol
?url=//evil.com               — protocol-relative
```

### Step 2: Check Browser Protection
Modern browsers (Chrome 88+, Firefox 101+, Edge 100+) **block `javascript:` in 302 redirects**. This means:
- `Location: javascript:alert(1)` in a 302 response will NOT execute in modern browsers
- The redirect is still valid for phishing (open redirect to any HTTP/HTTPS URL)
- The `javascript:` redirect may work in:
  - Older browsers (IE 6-9, Safari < 10)
  - WebViews / embedded browsers in mobile apps
  - Some OAuth libraries that follow redirects programmatically
  - If the response has `Content-Type: text/html` AND contains a `<meta>` refresh or JS redirect

### Step 3: Check Content-Type Manipulation
- Does the `fmt` or `format` parameter allow changing Content-Type?
- Can you make the response render as HTML instead of redirecting?
- Check for `Content-Type: text/html` vs `image/*` or `application/json`

### Step 4: Check Cache Control
- `Cache-Control: no-store, no-cache, must-revalidate` — prevents cache poisoning
- `Cache-Control: public, max-age=31536000` — cacheable → potential cache poisoning XSS
- Check `Vary` header — missing `Vary: Origin` can enable cache poisoning

### Step 5: Check for Server-Side Fetch (SSRF)
If the server processes the URL before redirecting:
- Response time differs between fast and slow URLs
- Error response differs between reachable and unreachable URLs
- Server returns the content of the target URL (not just a redirect)

### Reporting
- `javascript:` protocol redirect without browser bypass → report as **Open Redirect** (MEDIUM), not XSS
- If the redirect points to HTTP/HTTPS URLs freely → report as **Open Redirect** (MEDIUM-HIGH)
- Only report as **XSS** if you have a confirmed browser execution vector (e.g., stored XSS, DOM-based XSS, or a confirmed browser that executes the `javascript:` redirect)

## Deep Recon Methodology

When the user says "go deeper" or "find real vulnerabilities":

### What "go deeper" means:
- NOT: re-scanning the same endpoints with the same tools
- NOT: listing every observation as a "finding"
- NOT: describing features as vulnerabilities
- YES: testing for actual security flaws (IDOR, XSS, SQLi, SSRF, auth bypass, etc.)
- YES: using authenticated access to explore protected areas
- YES: chaining multiple observations into an exploit path

### Deep Recon Checklist
1. **Authenticated access** — if credentials are provided, use them to explore the platform
2. **IDOR** — test all ID-based endpoints with different values
3. **XSS** — test reflected, stored, DOM, and blind XSS vectors
4. **API fuzzing** — discover hidden endpoints, test auth requirements
5. **Business logic** — test workflows, state transitions, edge cases
6. **Admin panels** — test default creds, parameter injection, CSRF on admin forms
7. **Subdomain depth** — test takeover, hidden services, dev/staging instances
8. **File handling** — path traversal, upload abuse, directory listing

### When You Hit Technical Issues
- **Don't make excuses** — the user doesn't care about shell escaping, Python errors, or tool limitations
- **Fix the problem** — use heredoc, write scripts to the target machine, or use execute_code
- **Speed > perfection** — pre-stage commands, fire immediately when user provides time-sensitive data (TOTP, tokens). Don't take >30s from user providing a code to executing it.
- **Finish what you start** — tasks must be FULLY completed, not left at 80%. Be proactive.
- **If genuinely stuck** — say "I can't do X because of Y constraint" and offer the next best alternative
- **False positives** — verify before reporting. If you're not sure, test again or ask

## Shell Escaping When Testing Authenticated Endpoints

Passwords with special characters (`&`, `@`, `$`, `#`, `!`, etc.) will break inline shell commands:

```bash
# BROKEN — & and @ confuse the shell:
curl -X POST -d 'password=pentest@123&email=test@test.com' 'https://target.com/login'

# FIXED — write POST data to a file first:
echo 'password=pentest@123&email=test@test.com' > /tmp/post_data.txt
curl -X POST -d @/tmp/post_data.txt 'https://target.com/login'

# Or use Python to avoid shell escaping entirely:
python3 -c "
import subprocess
subprocess.run(['curl', '-X', 'POST', '-d', 'password=pentest@123&email=test@test.com', 'https://target.com/login'])
"
```

Always use `-d @file` or a Python wrapper when authenticating with user-provided credentials that may contain special characters.

## F — Upload Testing

File upload is a high-value attack surface. When testing upload functionality:

1. **Presigned URL pattern** (common in modern SPAs): Request URL → upload to S3/R2 → CDN serving. Test filename validation, Content-Type validation, and response headers of uploaded files.
2. **SVG XSS**: Upload SVG with embedded JavaScript. Check if served with correct MIME type and without `nosniff` header.
3. **File listing**: Check for endpoints that enumerate uploaded files (`/api/me/uploads`, `/api/me/files`).

See `references/file-upload-testing.md` in the offensive-security skill for full methodology.

**Do NOT create accounts on targets unless explicitly authorized.** Use unauthenticated attack vectors first. If the user says "don't create accounts" — respect it strictly. This applies to:
- Registration endpoints
- Login with fabricated credentials
- Any state-changing operation that creates user data

**Authorized red-team engagements:** When the scope explicitly includes authenticated testing (e.g., "test the API with valid credentials" or "assess post-auth vulnerabilities"), creating test accounts is appropriate. Always:
1. Use clearly identifiable test emails (e.g., `pentest@yourdomain.com`)
2. Clean up test data after testing (delete accounts, remove uploaded content)
3. Document all test accounts created in the report

**No Traces on Third-Party Content:**
- NEVER post comments, likes, messages, or any user-visible content on other users' assets (videos, posts, profiles, etc.)
- NEVER modify other users' data (view counts, profiles, settings) — even if the API allows it
- Test all state-changing operations (comments, likes, follows, messages) ONLY on content you own or have explicit authorization to modify
- If you accidentally leave a trace on third-party content, disclose it immediately to the client — do NOT try to cover it up
- View count inflation, profile picture changes, or any other modification to other users' assets is an OPSEC violation, not just a "test"

**XSS Validation Requirement:**
- NEVER flag stored XSS as a finding without verifying actual browser rendering
- React/Vue/Angular escape JSX text by default — stored HTML in comments/bio is NOT automatically exploitable
- Check for `dangerouslySetInnerHTML`, `v-html`, or equivalent raw HTML rendering before confirming XSS
- If the frontend properly escapes content, downgrade to INFO (missing server-side sanitization — defense-in-depth gap)

**Scope Discipline:**
- When the user asks you to do X, do X — do NOT drift to other vectors "while you're at it"
- If you can't accomplish what the user asked (e.g., no delete endpoint exists), say so directly — don't go on a tangent looking for unrelated functionality
- The user directs the scope. If they say "validate finding X," don't drift to "let me check everything while I'm at it"

Focus on: unauthenticated enumeration, information disclosure, auth bypass, injection, business logic flaws available without valid credentials.
