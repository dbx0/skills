# Roundcube / WebMail Recon

## Detection

Roundcube webmail is identifiable by its cookies:
- `roundcube_sessid` — Session ID
- `roundcube_sessauth` — Session auth token
- `PPA_ID` — Post-Post-Auth cookie
- `roundcube_cookies` — Cookie acceptance check

## Common Exposed Paths — False Positive Warning

Roundcube uses catch-all routing that returns the login page for ANY path:
```
/installer        → 200 (but returns login page, not installer)
/installer/index.php → 200 (same — login page)
/bin/             → 200 (login page)
/SQL/             → 200 (login page)
/README           → 200 (login page)
/CHANGELOG        → 200 (login page)
/UPGRADING        → 200 (login page)
/config/          → 200 (login page)
/temp/            → 200 (login page)
/logs/            → 200 (login page)
/vendor/          → 200 (login page)
/composer.json    → 200 (login page)
```

**All of these are 200 → login page,** NOT actual directory listing or file exposure. The catch-all router returns the Roundcube login page for any unrecognized path. Don't report these as directory listing vulnerabilities.

To verify: check `Content-Type` header — if it's `text/html` with Roundcube cPanel CSS, it's the login page, not the actual file.

## Determining Roundcube Version

Roundcube version is rarely visible in response headers or HTML. Look for:
- `composer.json` content if catch-all is bypassed (unlikely)
- CHANGELOG/UPGRADING content if accessible
- CSS/JS file patterns in page source
- `?_task=login` GET parameter reveals it's Roundcube

## Login Form

Standard Roundcube login:
```
POST /?_task=login&_action=login
Parameters: _user, _pass, _action=login
```
The login form submits to a JavaScript handler (`javascript:void(0)`) with fields `user` and `pass`.

## cPanel / WHM Co-Location

When webmail runs on the same server as cPanel/WHM, cookies cross-contaminate:

```
webmail.gosorcio.com.br    → roundcube_sessid, PPA_ID, roundcube_cookies
whm.gosorcio.com.br:2087   → whostmgrsession, roundcube_sessid, PPA_ID
cpcalendars.gosorcio.com.br → same server (503 error)
```

All three setting `roundcube_sessid` = same underlying cPanel server.

The HTML also references cPanel assets:
```html
<link href="/cPanel_magic_revision_1648610195/unprotected/cpanel/fonts/..."/>
<link href="/cPanel_magic_revision_1762392869/unprotected/cpanel/style_v2_optimized.css"/>
```

This means the webmail is hosted INSIDE the cPanel installation, not on a separate server. The `cPanel_magic_revision_*` paths in the Roundcube login page confirm shared hosting.

## Real-world Example (insurance-group engagement (phase 2))

**Target:** webmail.gosorcio.com.br
- Login page serves cPanel CSS assets
- 200 on all paths (catch-all router — false positive for directory listing)
- Shares server with WHM (:2087) and cPanel (:2083)
- cPanel_magic_revision paths confirm co-location