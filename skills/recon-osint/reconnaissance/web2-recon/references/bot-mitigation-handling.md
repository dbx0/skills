# Handling Bot Mitigation Services in Web Reconnaissance

## Overview
Modern web applications frequently employ bot mitigation services that intercept and challenge automated requests. These services return JavaScript challenges, CAPTCHAs, or other bot-detection mechanisms instead of the expected API responses, making standard reconnaissance tools ineffective.

Common bot mitigation services include:
- Vercel Security Checkpoint
- Cloudflare Bot Management / Bot Fight Mode
- Akamai Bot Manager
- PerimeterX
- DataDome
- Imperva Bot Protection
- Shape Security (now part of F5)
- Amazon ATC (Advanced Threat Protection)
- Google reCAPTCHA Enterprise
- hCaptcha Enterprise
- Kasada
- Netacea

## Detection Signatures

### HTTP Response Characteristics
1. **Status Code**: Often 200 (not 403/429) with challenge content
2. **Content-Type**: `text/html` instead of `application/json`
3. **Response Body**: Contains JavaScript, HTML challenge elements
4. **Specific Headers**:
   - `x-vercel-id` (Vercel)
   - `cf-ray`, `cf-chl-bypass` (Cloudflare)
   - `akamai-botman` (Akamai)
   - `pxvid` (PerimeterX)
   - `dd-cookie` (DataDome)

### Visual Indicators in Response
- Titles: "Verifying your browser", "Just a moment...", "Checking your browser"
- References to security services in HTML/JS
- Invisible form fields or JavaScript challenges
- References to `/cdn-cgi/` (Cloudflare)
- References to `_vercel` or `.vercel` (Vercel)

## Detection Commands

### Quick Check for Challenge Response
```bash
# Check if response looks like HTML challenge vs expected API response
curl -s "https://target.com/api/endpoint" | head -10 | grep -qiE "<!doctype|<html|verifying|checking|just a moment|challenge" && echo "LIKELY CHALLENGE RESPONSE"

# Check content type
curl -s -I "https://target.com/api/endpoint" | grep -i content-type

# Look for known bot mitigation headers
curl -s -I "https://target.com/api/endpoint" | grep -i -E "vercel|cloudflare|akamai|perimeterx|datadome|shape"
```

### Detailed Analysis
```bash
# Save response for inspection
curl -s "https://target.com/api/endpoint" -o response.html

# Check if it's HTML
file response.html

# Look for challenge indicators
grep -i "verifying\|challenge\|javascript\|cookie\|session" response.html
grep -i "vercel\|cloudflare\|akamai\|perimeterx\|datadome" response.html
```

## Handling Strategies

### 1. Documentation-First Approach (Recommended for Initial Recon)
When encountering a bot challenge:
- Document that the endpoint exists but is protected
- Note the specific service identified (if detectable)
- Move on to other endpoints/subdomains
- Return for detailed testing when browser automation is available

**Example finding:**
> "Endpoint `https://api.target.com/v1/users` appears to exist (returns challenge page instead of 404) but is protected by Vercel Security Checkpoint. Requires browser automation for direct testing. Similar endpoints on `dev.api.target.com` and `staging.api.target.com` should be checked for reduced protection levels."

### 2. Browser Automation for Active Testing
When deeper testing is required and in scope:

#### Akamai Bot Manager: headless is detected, headful is not

Against Akamai Bot Manager, `chromium.launch()` (headless by default) **is fingerprinted and
blocked**. The Playwright recipe below works on simpler challenges but fails here. What worked in
the field:

- headful Chromium under `xvfb-run` (no visible display needed, but a real browser build)
- driven over **raw CDP websockets**, not a automation framework
- `Network.setExtraHTTPHeaders` to inject a research/identification header on every request
- **warm on a same-origin static asset**, not the site root

That last point is the one that costs hours. Warming on `https://target.com/` can fail because a
SPA client-side-redirects to a per-brand or per-locale waypoint on a *different* origin before the
sensor validates. The `_abck` cookie then belongs to the wrong origin and same-origin `fetch()`
still 403s. Warm on something static and unambiguous instead:

```
https://target.com/polyfills.<hash>.js
```

Then export cookies and replay with curl, or keep issuing `fetch()` from inside the page.

```python
proc = subprocess.Popen(["chromium", "--no-sandbox", "--disable-gpu",
                         "--remote-debugging-port=9333",
                         "--user-data-dir=/tmp/prof", "about:blank"])
# discover ws url from http://127.0.0.1:9333/json, then over the websocket:
#   Network.enable / Page.enable / Runtime.enable
#   Network.setExtraHTTPHeaders {"X-Research": "<handle>"}
#   Page.navigate  -> a STATIC same-origin asset
#   sleep ~10s so the sensor JS runs and validates _abck
#   Runtime.evaluate: fetch(target, {credentials:'include'})
```

Run under `xvfb-run -a python3 script.py`.

Note: Playwright itself may be unusable on a given box for unrelated reasons (a node 24 / babel
incompatibility broke it during this engagement), which is another reason to know the raw-CDP path.

#### Distinguish bot detection from geo-blocking before you fight it

A 403 from Akamai is not always bot mitigation. Check the response for a geolocation cookie:

```
set-cookie: GMWP_location=country_code=DE,region_code=HE,city=FRANKFURT
```

If the edge has geolocated your egress and the property is region-specific, a browser will **also**
get 403 and no amount of sensor work will help. Confirm by testing the same channel against a
sibling host that is not region-locked: if the browser channel works there and fails here, it is
geo, and the fix is an egress IP in the right country, not better automation.

#### Using Playwright
```javascript
// Basic POST request with JSON body
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  
  // Navigate to let cookies/session establish if needed
  await page.goto('https://target.com/', { waitUntil: 'networkidle' });
  
  // Make the actual API request
  const response = await page.request.post('https://target.com/api/endpoint', {
    data: JSON.stringify({ 
      // your payload here
    }),
    headers: {
      'Content-Type': 'application/json',
      // Add any headers observed from legitimate requests
    }
  });
  
  console.log('Status:', response.status());
  console.log('Headers:', await response.headers());
  console.log('Body:', await response.text());
  
  await browser.close();
})();
```

#### Using curl with cookies from browser session
For simpler challenges that just set a cookie:
```bash
# Step 1: Visit main page to get cookies (do this in browser or with curl if simple)
curl -c cookies.txt "https://target.com/"

# Step 2: Use those cookies for API request
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"param":"value"}' \
  "https://target.com/api/endpoint"
```

### 3. Finding Alternate Access Points
Often the same backend API is available through less-protected routes:

```bash
# Check subdomains
for sub in dev staging test internal api admin internal-api; do
  echo "Testing $sub.target.com:"
  curl -s "$sub.target.com/api/endpoint" | head -5
done

# Check different paths
for path in /api/v2 /internal /backend /service /ws; do
  echo "Testing target.com$path:"
  curl -s "target.com$path/endpoint" | head -5
done

# Check if mobile API differs
curl -s -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)" \
  "https://target.com/api/endpoint"
```

### 4. Bypass Techniques (When Authorized)
Only attempt these with explicit permission:

#### User-Agent Rotation
```bash
# Try various browser user agents
for ua in \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"; do
  echo "Testing with UA: $ua"
  curl -s -A "$ua" "https://target.com/api/endpoint" | head -2
done
```

#### Header Manipulation
Some services look for specific headers:
```bash
# Try common headers that might indicate legitimate traffic
curl -s -H "Accept: application/json" \
     -H "X-Requested-With: XMLHttpRequest" \
     -H "Referer: https://target.com/" \
     "https://target.com/api/endpoint"
```

## Reporting Findings

When documenting bot-protected endpoints in reports:

### For Executive Summary
- "Multiple API endpoints identified but protected by bot mitigation services requiring browser-based testing for full assessment"
- "Recommend implementing rate-based protections alongside bot management to defend against low-and-slow attacks"

### For Technical Details
```
Endpoint: https://api.example.com/v1/payment-methods
Method: POST
Expected Parameters: {"token": "string", "amount": "number"}
Protection: Vercel Security Checkpoint (detected via response headers and challenge page)
Evidence: 
  - Returns HTTP 200 with HTML challenge page titled "Verifying your browser"
  - Contains Vercel-specific JavaScript and sets __vc cookie
  - After challenge resolution (via browser), returns expected JSON structure
Impact: Payment token enumeration possible if protection bypassed
Recommendation: 
  1. Consider adjusting bot sensitivity to reduce false positives on legitimate API traffic
  2. Implement rate limiting per authenticated user alongside bot prevention
  3. Regularly test bot rules against legitimate client applications
```

### For Remediation Suggestions
- "Ensure bot management rules don't block legitimate API clients (mobile apps, SPIs, integrations)"
- "Consider challenge-free allowlists for known good internal/service-to-service traffic"
- "Implement progressive challenges: start with JavaScript invocation before presenting CAPTCHAs"
- "Monitor challenge solve rates to detect tuning needs"

## Special Cases

### Rate-Limited Challenges
Some services combine rate limiting with challenges:
- First few requests: normal response
- After threshold: JavaScript challenge
- After more failures: CAPTCHA or block

**Detection:** Make same request multiple times and observe when response changes

### Session-Bound Challenges
Some challenges bind to session cookies:
- Solving challenge on one endpoint doesn't grant access to others
- Each endpoint may require its own challenge solution

**Approach:** Handle challenges per-endpoint or maintain session throughout testing

### Progressive Challenges
Increasingly difficult challenges based on perceived threat:
1. JavaScript execution check
2. DOM property verification  
3. Timing-based checks
4. CAPTCHA

**Strategy:** Solve in order - don't skip to harder challenges prematurely

## Tools for Automated Handling

### Headless Browser Frameworks
- **Playwright** (recommended) - Excellent API, auto-waiting, multiple browser support
- **Puppeteer** - Chrome-specific, mature ecosystem
- **Selenium** - Broadest browser support, more complex setup
- **Cypress** - Great for testing, less flexible for arbitrary navigation

### Specialized Tools
- **cups** (https://github.com/cmuench/cups) - CLI utility for solving common challenges
- **cloudscraper** (Python) - Handles Cloudflare challenges
- **flaresolverr** (Python) - HTTP server to bypass Cloudflare and similar
- **rekaptcha** - Audio CAPTCHA solver (when applicable)

### HTTP Libraries with Challenge Support
- **axios-retry** + custom interceptors (Node.js)
- **requests** + adapters (Python)
- **OkHttp** + interceptors (Java)

## Verification That Challenge Was Solved
After attempting to bypass a challenge, verify success by:
1. Checking for expected response format (JSON, XML, etc.)
2. Looking for absence of challenge indicators in response
3. Checking for session cookies that weren't present before
4. Validating response contains expected data structure
5. Ensuring status code matches expectation (200 for success, not challenge page)

## Legal and Ethical Considerations
- Only bypass protections with explicit written authorization
- Some jurisdictions consider bypassing technological protection measures illegal without permission
- Document all bypass techniques used in engagement reports
- Consider whether the insight gained justifies the technique employed
- When in doubt, consult with engagement manager or legal counsel

## References
- OWASP Automated Threat Handbook (OWASP AT001-020)
- Various vendor blogs on bot management techniques
- PortSwigger Web Security Academy: "Authentication" section (for logic flaws post-bypass)
- BLACKhat/DEF CON talks on bypassing bot mitigation services