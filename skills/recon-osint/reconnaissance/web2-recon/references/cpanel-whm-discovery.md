# cPanel / WHM Discovery on Non-Standard Ports

## Port Mapping

cPanel & WHM use specific non-standard ports:

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| WHM (root admin) | 2087 | HTTPS | WebHost Manager — server-level admin |
| cPanel (user) | 2083 | HTTPS | Per-account hosting management |
| Webmail | 443 | HTTPS | Roundcube / Horde / SnappyMail |
| cPanel API | 2083 | HTTPS | JSON/XML API at `/json-api/` and `/xml-api/` |
| WebDisk | 2077/2078 | HTTP/HTTPS | WebDAV access |

## Detection via DNS Brute-Force

cPanel auto-generates these subdomains for every account:

```bash
# Brute force these subdomains
for sub in cpanel whm webmail cpcalendars cpcontacts webdisk autodiscover; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "https://${sub}.target.com/")
  echo "${sub}.target.com → ${code}"
done
```

Common response patterns:
- `cpanel.target.com` → 525/526 (SSL behind Cloudflare)
- `whm.target.com` → 526 (different cert issue)
- `cpcalendars.target.com` → 503 (Service Unavailable)
- `cpcontacts.target.com` → 503
- `webdisk.target.com` → 401 (Authorization Required)
- `autodiscover.target.com` → 400 (email autodiscovery)

## Direct Port Access Behind Cloudflare Spectrum

When cPanel/WHM is behind Cloudflare Spectrum (proxied non-standard ports):

```bash
# Connect directly to Cloudflare IP on cPanel/WHM ports
curl -sL --connect-to 'whm.target.com:2087:CLOUDFLARE_IP' 'https://whm.target.com:2087/'
# Returns WHM login page: <title>Login no WHM</title>

curl -sL --connect-to 'whm.target.com:2083:CLOUDFLARE_IP' 'https://whm.target.com:2083/'
# Returns cPanel login page: <title>Login do cPanel</title>
```

**Cloudflare Spectrum indicators:**
- `server: cloudflare` in response headers on non-standard ports
- `alt-svc: h3=":2087"` — HTTP/3 support on that port
- Direct IP access WITHOUT Host header fails (SSL handshake failure)

## cPanel Version Fingerprinting

Try the JSON API (usually requires auth but returns version info):

```bash
curl -s 'https://target.com:2083/json-api/version'
# {"cpanelresult":{"apiversion":"2","error":"Access denied", ...}}
# If "Access denied" = cPanel exists and is working
```

**CSS/Known asset paths:**
```bash
# cPanel_magic_revision paths in CSS reveal cPanel version
curl -sL 'https://target.com:2083/' | grep -oP 'cPanel_magic_revision_[0-9]+'
# Example: cPanel_magic_revision_1648610195
```

## Shared Server Detection

When webmail, WHM, and cPanel share the same server, cookies cross-pollinate:

```
set-cookie: roundcube_sessid=expired;  ← same Roundcube session cookie
set-cookie: PPA_ID=expired;            ← same PPA cookie
set-cookie: whostmgrsession=...        ← WHM session
```

All three services setting `roundcube_sessid` = same underlying server.

## Real-world Example (insurance-group engagement (phase 2))

**Target:** gosorcio.com.br

```
whm.gosorcio.com.br:2087 → WHM login page (200)
whm.gosorcio.com.br:2083 → cPanel login page (200)
webmail.gosorcio.com.br  → Roundcube on port 443
```

All behind Cloudflare Spectrum:
- `server: cloudflare`
- `alt-svc: h3=":2087"`
- Roundcube, WHM, cPanel all share same server (cross-contaminated cookies)

**cPanel_magic_revision paths found:**
- `cPanel_magic_revision_1648610195/unprotected/cpanel/fonts/open_sans/open_sans.min.css`
- `cPanel_magic_revision_1762392869/unprotected/cpanel/style_v2_optimized.css`
- `cPanel_magic_revision_1739247148/unprotected/cpanel/images/notice-error.png`