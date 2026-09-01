# Better Auth Framework — Security Testing Notes

## Identification

Better Auth is a TypeScript authentication framework. Detection signals:

- JS bundle imports from `better-auth` or `@better-auth/*`
- Cookie name: `__Secure-better-auth.session_token`
- Two-part dot-separated session token (NOT standard JWT with 3 parts): `payload.signature`
- API base URL configured as `baseURL: "https://api.example.com"`
- Plugin system: `plugins: [{ id: "infer-server-plugin", ... }]`

## Session Token Format

Better Auth tokens are **not JWTs**. Two-part format: `base64payload.base64signature`

The payload is a random token ID — user data is stored server-side.

## CSRF Protection

Requires `Origin` header on state-changing requests. Without it:
`{"message": "Missing or null Origin", "code": "MISSING_OR_NULL_ORIGIN"}`

## Cookie Characteristics

- Cookie name: `__Secure-better-auth.session_token`
- **Domain-specific**: cookie for `api.example.com` NOT sent to `admin.example.com`
- `__Secure-` prefix requires HTTPS

## Endpoint Discovery

Search JS bundle for `pluginPathMethods` object — reveals all auth endpoints and HTTP methods. Standard endpoints: `/sign-out`, `/revoke-sessions`, `/delete-user`, `/update-user`, `/change-email`, `/change-password`, `/sign-in/social`, `/sign-in/email`, `/sign-up/email`, `/callback/google`, `/get-session`.

## Test Vectors

### Mass Assignment on update-user
`{"name":"test","role":"ADMIN","isAdmin": true}` → expect `FIELD_NOT_ALLOWED`

### OAuth redirect_uri / state manipulation
Custom values in `redirectUri` or `state` fields should be ignored; server generates its own.

### Cookie without Origin → 403
### Cookie on wrong domain → not sent

## Rate Limiting

Check for asymmetry: POST endpoints may have rate limiting (`429 RATE_LIMIT_EXCEEDED`) while GET endpoints don't.
