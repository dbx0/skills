# Hermes Bytecode & Cloud Function Testing (Expo SDK 52+)

## Hermes Bytecode Analysis

### HBC Version Incompatibility
`hbctool` only supports Hermes bytecode versions 59-76. Expo SDK 52+ uses HBC v85-v96+. The bundle header magic `c61fbc03` with version 96 will fail to parse with `hbctool`. Check version:
```python
with open('assets/index.android.bundle', 'rb') as f:
    version = int.from_bytes(f.read(8)[8:12], 'little')
print(f"HBC version: {version}")
```

### hermes_dec Disassembler Traps
The `hermes_dec` package provides `do_disassemble(path)` but it **prints to stdout and returns None**. To capture output, redirect stdout:
```python
import sys, io
from hermes_dec.disassembly.hbc_disassembler import do_disassemble

old_stdout = sys.stdout
sys.stdout = buffer = io.StringIO()
do_disassemble('assets/index.android.bundle')
sys.stdout = old_stdout
output = buffer.getvalue()
with open('/tmp/disasm.txt', 'w') as f:
    f.write(output)
```

### Firebase API Key Extraction
The full Firebase API key is NEVER stored as a plain string in Expo SDK 52+ bundles. The `app.config` stores a truncated/obfuscated version. The `/__/firebase/init.json` endpoint REDACTS the key. To get a valid idToken:
1. Ask user for `firebase.auth().currentUser.getIdToken()` from browser DevTools console
2. Or use web SDK login flow with known credentials
3. Do NOT waste time on XOR/brute-force — key is constructed at runtime from native code

### String Interning
Hermes concatenates and interns strings at compile time. You may see `FIREBASE_API_KEY_TO_IDESKTOP_MIN_DELAY...` as a single merged string. This is normal compiler behavior, not a finding.

---

## Cloud Function Auth Testing

### Auth Testing Matrix (for each function)
1. **No auth** → 400 = needs auth, 200/404 = no auth needed
2. **Fake token** → 401 = auth works, 400 = no auth check
3. **Empty body** → reveals required params via error messages

### Input Validation Payloads (systematic)
```python
{
    "nosql":     [{"email": {"$gt": ""}}, {"code": {"$regex": ".*"}}],
    "injection": [{"code": "' OR '1'='1"}, {"email": "$(whoami)@test.com"}],
    "xss":       [{"code": "<script>alert(1)</script>"}, {"username": "{{7*7}}"}],
    "overflow":  [{"code": "a" * 10000}, {"count": 99999999999999}],
    "proto":     [{"__proto__": {"isAdmin": True}, "code": "TEST"}],
    "redos":     [{"username": "(a+)+" + "a" * 30 + "!"}],
}
```

### Key Pattern
Only `storeInstallFingerprint` was unauthenticated; all 20+ other functions required auth. Focus on no-auth functions.

---

## Algolia Stored XSS Detection

### Search for XSS Payloads
```python
xss_terms = ["<script", "javascript:", "onerror", "onload", "<img", "<iframe", "<svg", "eval(", "alert(", "document.cookie"]
for term in xss_terms:
    payload = {"query": term, "hitsPerPage": 3, "attributesToRetrieve": ["content", "userName", "objectID"]}
    # POST to https://{APP_ID}-dsn.algolia.net/1/indexes/{INDEX}/query
```

### False Positive Warning
Many "XSS matches" in fitness apps are Portuguese: "alerta gatilho" = "trigger alert", "eval" as username. Verify actual HTML/JS before reporting.

### Key Permission Check
`settings` permission on search-only keys is excessive (defense-in-depth issue).

---

## Firebase Storage Security

### Download Token Permanence
Firebase Storage download tokens (`?alt=media&token=...`) are **permanent by default**. Extracted URLs remain valid indefinitely even after Firestore vulns are patched.

### CORS Testing
```bash
curl -s -I -X OPTIONS "https://firebasestorage.googleapis.com/v0/b/{bucket}/o/test" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET"
```

### Security Checklist
- [ ] Download tokens permanent? → MEDIUM
- [ ] CORS allows all origins? → MEDIUM
- [ ] Directory listing blocked? → Should be 403
 - [ ] Upload requires auth? → Should be 403

### StoreInstallFingerprint Validation Gaps (real-world example)
Tested on pumpgym-93f15.cloudfunctions.net (fitness app, June 2026). The ONLY unauthenticated cloud function found.

| Payload | Result | Note |
|---------|--------|------|
| `{"code": "MAT"}` | 200 OK | Valid affiliate code (Matheus Gobbi) |
| `{"code": "TEST"}` | 404 | `affiliate_not_found` |
| `{"code": "a"*1000}` | 400 | Length limit enforced (~100 chars max) |
| `{"code": "<script>"}` | 400 | XSS payload rejected |
| `{"code": "' OR '1'='1"}` | 400 | SQLi payload rejected |
| `{"code": "{{7*7}}"}` | 400 | SSTI payload rejected |
| `{"code": "MAT", "extra": "val"}` | 200 OK | Extra params silently accepted (no mass assignment check) |
| `{"code": "MAT", "count": -1}` | 200 OK | Negative integer accepted (no range validation) |
| `{"code": "MAT", "count": 99999999999999}` | 200 OK | Huge integer accepted |
| `{"code": "MAT", "__proto__": {"isAdmin": true}}` | 200 OK | Proto pollution accepted but no effect on response |

Key takeaway: even when auth is bypassed, input validation may still reject injection payloads. Always test BOTH auth bypass AND input validation independently. The `code` field has a length limit (~100 chars max) but no format restriction beyond alphanumeric.

### HBCReader String Table Access (HBC v96+)
For HBC versions unsupported by hbctool (v85+), `HBCReader` can still parse string tables from the raw file:
```python
import io
reader = HBCReader()
reader.file_buffer = io.BytesIO(data)
reader.read_small_string_table()   # stores in reader.small_string_table
reader.read_overflow_string_table()  # stores in reader.overflow_string_table
# Each entry is a named tuple with offset, length fields
for entry in reader.small_string_table:
    s = data[entry.offset:entry.offset+entry.length].decode('utf-8', errors='ignore')
    if 'AIza' in s:
        print(f"FOUND: {s}")
```
This DOES contain regular app config strings but NOT the Firebase API key (key is constructed at runtime from native code, never stored contiguously).
