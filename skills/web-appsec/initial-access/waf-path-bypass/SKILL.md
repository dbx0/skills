---
name: waf-path-bypass
description: Use when a path returns a WAF/edge block (403, challenge page) but the underlying origin may still serve it under a normalized path variant — covers trailing-slash and path-normalization bypass testing. Trigger on "WAF bypass", "403 bypass", "path normalization", "edge block", or when a sensitive path is blocked at the edge but you suspect the origin still serves it.
version: 1.0.0
author: field-derived (iFood engagement, Keycloak realm WAF bypass)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [waf, bypass, path-normalization, misconfiguration]
    related_skills: [api-security, bug-bounty]
---

# WAF / Path-Normalization Bypass

Reverse proxies, WAFs, and edge rules often normalize paths differently than the origin server does.
A rule blocking `/admin/realms/master` may not match `/admin/realms/master/` — the WAF treats them
as different strings while the origin's router treats them as the same route.

## When to Use

- A specific path returns a block (`403`, a WAF challenge page, a generic edge-level denial) while
  sibling paths on the same host respond normally
- You suspect a rule was written to match one exact path shape rather than the route it's meant to
  protect
- Fingerprinting (`keycloak-openid-config` style hits, admin-panel signatures) suggests something
  sensitive sits behind the blocked path

## Method

1. **Confirm the block is edge-level, not origin-level.** Check response headers/body for WAF/edge
   fingerprints (vendor error page, missing origin-specific headers) versus what a genuine
   application-level 403 looks like on that same target.
2. **Try path variants** that a WAF string-match rule commonly fails to normalize but the origin's
   router accepts identically:

```
/admin/realms/master        → 403 (blocked)
/admin/realms/master/       → trailing slash
//admin/realms/master       → doubled leading slash
/admin/./realms/master      → dot-segment
/admin/realms/master%2F     → encoded trailing slash
/admin/realms/master#       → fragment (rarely reaches origin differently, but cheap to try)
/ADMIN/realms/master        → case variation, if the WAF rule is case-sensitive and origin isn't
```

3. **Confirm the origin actually serves the sensitive response**, not just a different-looking error
   page. Compare full response body/headers against what the blocked path would return if genuinely
   accessible (e.g. a realm's public key, a config payload, an admin page's real markup) — don't
   report a bypass based on status code alone.
4. **Check what the bypass actually reaches.** A bypassed path that still requires valid
   authentication downstream is a lower-severity misconfiguration (WAF gap, but no direct impact) than
   one that reaches genuinely sensitive functionality (an admin realm's JWKS/token endpoint, an
   internal API, exposed config).

## Severity Guidance

| What the bypass reaches | Severity |
|---|---|
| Same generic error/login page as the non-blocked route | Low — WAF hygiene gap only |
| Configuration/metadata disclosure (realm public key, JWKS, version info) | Low–Medium |
| Functional endpoint that still requires its own auth | Medium — defense-in-depth loss |
| Functional endpoint with weak/no downstream auth reachable only via the bypass | High |

## Common Mistakes

- Reporting a bypass based on status code change alone (`403` → `200`) without confirming the body
  actually contains the sensitive content, not just a different block/error page
- Not checking whether the "protected" route was reachable through some other path all along,
  making the WAF rule cosmetic rather than the sole protection
- Stopping at one variant — if the trailing slash doesn't work, the other normalization variants
  above are cheap to try before concluding the WAF is correctly configured

## Cross-References

- `api-security` for the broader endpoint-discovery and authz-testing methodology this plugs into
- If the bypassed path exposes an IAM/SSO admin surface, treat what's reachable there as its own
  finding using standard IDOR/authz testing from `bug-bounty`
