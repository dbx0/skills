# WordPress XML-RPC Attack Surface

## Overview
WordPress XML-RPC (`/xmlrpc.php`) exposes up to 80 methods. Large attack surface including file upload, post manipulation, user enumeration.

## Key Methods
- `wp.getUsers` — user enumeration (auth required)
- `wp.uploadFile` — file upload/webshell (auth required)
- `wp.newPost`/`wp.editPost`/`wp.deletePost` — content manipulation
- `system.multicall` — amplification/DDoS vector
- `pingback.ping` — SSRF potential

## Detection
```bash
curl -s -X POST "https://target.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

## Pitfall: False Positive .git Exposure
When subdomain returns 200 for `/.git/HEAD`, verify it's real git not SPA catch-all:
- Real git: `ref: refs/heads/master`
- SPA catch-all: `<!doctype html>...` (SPA shell)

## Real Example (membership-org engagement)
- example-org.tld/xmlrpc.php: 80 methods, all require valid credentials
- Pingback returns empty (blocked)
- adm.example-org.tld/.git/HEAD returns Angular SPA shell (false positive)
