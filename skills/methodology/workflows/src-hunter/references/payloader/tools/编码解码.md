# Encoding/Decoding

_6 tool commands_

### Base64 Encoding  `base64-encode`
_Collection of Base64 encode/decode commands_

**Step 0**
> Base64 encoding methods across platforms
```
# Linux:
echo -n "payload" | base64
base64 file.txt > encoded.txt

# Windows PowerShell:
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("payload"))

# Python:
python3 -c "import base64; print(base64.b64encode(b'payload').decode())"
```

**Step 0**
> Base64 decoding methods across platforms
```
# Linux:
echo "cGF5bG9hZA==" | base64 -d
base64 -d encoded.txt > decoded.txt

# Windows PowerShell:
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("cGF5bG9hZA=="))

# Python:
python3 -c "import base64; print(base64.b64decode('cGF5bG9hZA==').decode())"
```

**Step 0**
> URL-safe Base64 encoding (+/ replaced with -_)
```
# Python:
import base64
base64.urlsafe_b64encode(b"payload").decode()
base64.urlsafe_b64decode("cGF5bG9hZA==").decode()
```

---

### URL Encoding  `url-encode`
_Collection of URL encode/decode commands_

**Step 0**
> URL encoding methods (single/double)
```
# Python:
python3 -c "from urllib.parse import quote; print(quote('<script>alert(1)</script>'))"

# Double encoding:
python3 -c "from urllib.parse import quote; print(quote(quote('<script>alert(1)</script>')))"

# CyberChef online: https://gchq.github.io/CyberChef/
```

**Step 0**
> URL decoding method
```
# Python:
python3 -c "from urllib.parse import unquote; print(unquote('%3Cscript%3Ealert(1)%3C%2Fscript%3E'))"

# Linux:
printf '%b' "\x3Cscript\x3E"
```

---

### Hex Encoding  `hex-encode`
_Collection of hexadecimal encode/decode commands_

**Step 0**
> Hexadecimal encoding methods
```
# Linux:
echo -n "payload" | xxd -p
echo -n "payload" | od -A n -t x1 | tr -d " \n"

# Python:
python3 -c "print('payload'.encode().hex())"
python3 -c "print('\\x'.join([hex(ord(c))[2:] for c in 'payload']))"
```

**Step 0**
> Hexadecimal decoding methods
```
# Linux:
echo "7061796c6f6164" | xxd -r -p

# Python:
python3 -c "print(bytes.fromhex('7061796c6f6164').decode())"
```

**Step 0**
> Using hex encoding in SQL injection and XSS
```
# Used in SQL injection:
SELECT 0x61646D696E  -- "admin"

# Used in XSS:
<img src=x onerror=\x61\x6c\x65\x72\x74(1)>
```

---

### HTML Encoding  `html-encode`
_Collection of HTML entity encode/decode commands_

**Step 0**
> HTML entity encoding (named/decimal/hexadecimal)
```
# Python:
python3 -c "import html; print(html.escape('<script>alert(1)</script>'))"

# Numeric encoding:
python3 -c "print(''.join(['&#'+str(ord(c))+';' for c in '<script>alert(1)</script>']))"

# Hexadecimal HTML encoding:
python3 -c "print(''.join(['&#x'+hex(ord(c))[2:]+';' for c in 'alert']))"
```

**Step 0**
> HTML entity decoding
```
# Python:
python3 -c "import html; print(html.unescape('&lt;script&gt;alert(1)&lt;/script&gt;'))"
```

**Step 0**
> HTML entity reference commonly used for XSS bypass
```
# Common HTML entities:
# < => &lt; or &#60; or &#x3c;
# > => &gt; or &#62; or &#x3e;
# " => &quot; or &#34; or &#x22;
# ' => &apos; or &#39; or &#x27;
# & => &amp; or &#38; or &#x26;
```

---

### Unicode Encoding  `unicode-encode`
_Collection of Unicode encode/decode commands_

**Step 0**
> Various Unicode encoding forms
```
# Python Unicode escape:
python3 -c "print(''.join(['\\u'+hex(ord(c))[2:].zfill(4) for c in 'alert']))"
# Output: \u0061\u006c\u0065\u0072\u0074

# UTF-8 bytes:
python3 -c "print('alert'.encode('utf-8'))"
```

**Step 0**
> Unicode decoding methods
```
# Python:
python3 -c "print('\\u0061\\u006c\\u0065\\u0072\\u0074'.encode().decode('unicode_escape'))"

# JavaScript:
console.log("\u0061\u006c\u0065\u0072\u0074")
```

**Step 0**
> Using Unicode encoding to bypass WAF/filters
```
# JavaScript Unicode bypass:
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

# Overlong UTF-8 encoding:
# / => %c0%af (can bypass path filters)
# . => %c0%ae
```

---

### JWT Decode  `jwt-decode`
_JWT (JSON Web Token) decoding and analysis tools_

**Step 0**
> Decode a JWT using online tools
```
# Online tools:
# https://jwt.io
# https://token.dev
# Paste the JWT to view the Header and Payload
```

**Step 0**
> Decode a JWT using the Python command line
```
# Python:
python3 -c "
import base64, json, sys
token = sys.argv[1]
parts = token.split('.')
for i, part in enumerate(parts[:2]):
    padded = part + '=' * (4 - len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    print(json.dumps(json.loads(decoded), indent=2))
" YOUR_JWT_HERE
```

**Step 0**
> JWT structure analysis and key security-check points
```
# JWT structure: Header.Payload.Signature
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"1234","name":"user","iat":1516239022}
# Signature: HMACSHA256(base64url(header)+"."+base64url(payload), secret)

# Check points:
# 1. Whether alg can be changed to none
# 2. Whether the key is a weak password
# 3. Whether RS256 can be changed to HS256
# 4. Whether exp has expired
```

---
