# [Seed] JS Signature Reversing (Webpack + AES + Timestamp)

## Scenario Category
JS signature

## Target Overview
Recover the generation algorithm for a web application API's `sign` parameter and reproduce it locally.

## Full Execution Chain

1. Captured browser traffic → found a POST request carrying `sign` and `timestamp` parameters
2. Searched the JS source for "sign" → traced it to a webpack-bundled chunk file
3. Set a breakpoint where sign is assigned → hit it, inspected the call stack
4. Walked back up the call stack → found the signing function (inside one of the webpack modules)
5. Analyzed the signing logic: `sign = HmacSHA256(sorted_params + timestamp, secret_key)`
6. Key source: hardcoded in another webpack module
7. Reproduced it locally in Node.js → the generated sign matched the browser's
8. Validation: sent an API request using the reproduced sign → normal data came back

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| Too many results when searching for "sign" | Variable names were minified by the webpack build | Search for `sign=` instead, or find the request in the Network panel and walk back via the initiator | 15min |
| Breakpoint hit but the code was unreadable | webpack minification + variable name obfuscation | Format it with Chrome's Pretty Print, combined with the SourceMap if one exists | 10min |
| Local reproduction produced a different result | The parameter sort order was wrong | Read the sort logic in the source carefully (alphabetical by key + special character handling) | 30min |
| Wrong timestamp precision | The server used seconds, I used milliseconds | `Math.floor(Date.now() / 1000)` | 5min |
| Could not find the key | The key lived in another chunk file and was pulled in via require | console.log the key variable at the breakpoint | 10min |

## Toolchain Findings

- Chrome DevTools' initiator column locates the signing function faster than searching the source
- For webpack-bundled code, Pretty Print + breakpoints is more efficient than reading it raw
- If a SourceMap (.map file) is available, recover the original source directly
- Node.js's `crypto` module can reproduce most signing algorithms directly

## Key Code / Commands

```javascript
// Node.js reproduction
const crypto = require('crypto');

function generateSign(params, timestamp, secretKey) {
    // 1. Sort parameters alphabetically by key
    const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
    // 2. Append the timestamp
    const message = sorted + '&timestamp=' + timestamp;
    // 3. HMAC-SHA256
    return crypto.createHmac('sha256', secretKey).update(message).digest('hex');
}

const params = { user_id: '123', action: 'query' };
const timestamp = Math.floor(Date.now() / 1000);
const secretKey = 'hardcoded_key_from_webpack';
console.log(generateSign(params, timestamp, secretKey));
```

## Improvement Suggestions for This Package

- js-reverse's env-patching.md should add "how to handle dependencies across webpack chunks"
- Suggest adding a "common signing algorithm identification" quick reference (HMAC-SHA256 vs MD5 vs custom)

## Reusable Patterns / Script Snippets

**Standard JS signature reversing workflow**:
```text
1. Capture traffic and find the signed request
2. Locate the signing function via the initiator / call stack
3. Analyze the signing logic (parameter sorting + concatenation + encryption)
4. Find the key source (hardcoded / returned by an API / time-derived)
5. Reproduce in Node.js
6. Compare and validate
```

**Common signing patterns**:
```text
- HmacSHA256(sorted_params, key) → most common
- MD5(params + salt + timestamp) → older systems
- AES(JSON.stringify(params), key) → encryption rather than signing
- RSA sign → rare, usually financial systems
```

## Evolution Actions
- [ ] No routing matrix update needed
- [ ] No bootstrap-manifest update needed
- [ ] No sub-skill documentation update needed

## Environment Information
- OS: Windows
- Tool versions: Chrome DevTools, Node.js 20+
- Target platform: Web (Webpack-bundled SPA)

## Redaction Requirements
This entry is seed data, written from publicly known technical patterns, and does not involve any real target.

---
<!-- [Evolution stats] Cumulative projects completed by this package: 4 | New patterns added this round: 2 | Toolchain issues fixed this round: 0 -->
<!-- [Community contribution] Seed data, no PR needed -->
