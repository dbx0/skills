# OAuth/OIDC Client-Side Configuration Exposure

## Pattern

Single-page applications and traditional web apps that embed OAuth/OIDC providers (Okta, Auth0, Azure AD, Keycloak) via client-side JavaScript widgets often expose their entire authentication configuration in the HTML source or loaded JS files.

## What to Look For

Search page source for these patterns:

### Okta Sign-In Widget
```javascript
OktaSignIn({
  clientId: '0oamaek00tqkisZbS4x6',
  issuer: 'https://tenant.okta.com/oauth2/default',
  redirectUri: 'https://app.com/callback',
  scopes: ['openid', 'email', 'profile'],
});
```
Also look for variable assignments like:
```javascript
var cID = '0oamaek00tqkisZbS4x6';
var authority = 'https://tenant.okta.com/oauth2/default';
var rUrl = 'https://app.com/callback';
```

### Auth0 Auth0Lock/NewAuth0Lock
```javascript
new Auth0Lock(
  'CLIENT_ID',
  'tenant.auth0.com',
  { /* config */ }
);
```

### Azure AD MSAL
```javascript
new msal.PublicClientApplication({
  auth: {
    clientId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    authority: 'https://login.microsoftonline.com/tenant-id',
    redirectUri: 'https://app.com'
  }
});
```

## Red Flags

| Finding | Severity | Notes |
|---------|----------|-------|
| Client ID exposed | Low-Medium | Expected in OAuth — but combined with other findings it enables targeted attacks |
| Dev tenant in production | High | `dev-` prefix Okta tenants or `localhost` redirect URIs suggest dev config deployed to prod |
| Outdated widget version | Medium | Okta widget < 5.x, Auth0 lock < 11.x may have known CVEs |
| Localhost redirect URI in production | High | Dev configuration leak; may indicate weak redirect URI validation |
| `none` in token_endpoint_auth_methods | Medium | Allows public client auth — check if client secret is also exposed |
| `registration_endpoint` enabled | Medium | Anyone with a session can register OAuth clients |

## Post-Discovery Steps

1. **Check OpenID configuration:** `GET /.well-known/openid-configuration` on the issuer
   - Look for `registration_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported`
   - Check if `password` grant type is enabled (resource owner password credentials)
   - Check if `implicit` grant type is enabled (deprecated, less secure)

2. **Test redirect URI manipulation:** Try changing the `redirect_uri` parameter in the authorization request to an attacker-controlled domain

3. **Test for open redirect on callback:** If the redirect URI validation is weak, chain with XSS or token theft

4. **Check client registration:** If `registration_endpoint` is enabled, test whether unauthenticated registration is possible: `POST /oauth2/v1/clients` with a new client config

## financial institution Example (May 2026)

On `iccweb.example-bank.tld/SignOn.aspx`, the Okta Sign-In Widget 3.2.1 config was fully exposed:

```javascript
cID = '0oamaek00tqkisZbS4x6';
rUrl = 'http://localhost:8080/SignOn.aspx';
authority = 'https://dev-653002.okta.com/oauth2/default';
base = 'https://dev-653002.okta.com';
```

Key findings:
- Client ID `0oamaek00tqkisZbS4x6` visible in page source
- Dev tenant `dev-653002.okta.com` referenced in production
- Localhost redirect URI `http://localhost:8080/SignOn.aspx` in production
- Widget version 3.2.1 (current is 7.x — 4+ years outdated)
- `registration_endpoint` enabled on both dev and prod tenants (requires auth session)

The `secure.digital.example-bank.tld` production portal uses Okta widget 7.45.2 with a proper Okta custom domain (`examplebank.okta.com`) — significantly better config.

## Reporting

When reporting OAuth config exposure, lead with the concrete impact:
- **High:** Dev tenant in production + localhost redirect + outdated widget → session hijacking potential
- **Medium:** Client ID + issuer + open registration endpoint → unauthorized client registration
- **Low:** Client ID alone → expected in OAuth, but document as part of a larger finding
