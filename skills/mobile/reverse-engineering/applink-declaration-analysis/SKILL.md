---
name: applink-declaration-analysis
description: Mine .well-known/assetlinks.json and apple-app-site-association for app identifiers, staging/internal builds, and the exact URL paths a mobile app claims — then decide exploitability with the cert-fingerprint binding check. Use during mobile recon, when a target has iOS/Android apps in scope, when you need iOS surface without an IPA, or before reporting any "staging app can hijack production links" claim.
sources: field_recon (fintech engagement — recovered macOS/iOS staging bundle ids and claimed payment/account-linking paths from public declarations)
report_count: 0
---

# App Link Declaration Analysis

Two public JSON files declare which apps may handle a domain's URLs. They are unauthenticated,
never require the binary, and routinely leak build identifiers that appear nowhere else.

This is the cheapest iOS surface available when you cannot obtain an IPA.

## Fetch both, on every candidate host

```bash
for h in target.com www.target.com app.target.com m.target.com; do
  for f in apple-app-site-association assetlinks.json; do
    printf '%-28s %-32s ' "$h" "$f"
    curl -s -o /tmp/al -w '%{http_code} %{size_download}b\n' "https://$h/.well-known/$f"
  done
done
```

Also try `/apple-app-site-association` (no `.well-known/`) — the legacy location, still served
by some stacks and sometimes stale relative to the modern one.

## What you get

**Non-production bundle identifiers.** Staging, internal and desktop builds are frequently
declared alongside production:

```
A1B2C3D4E5.com.example.iphone           ← production
A1B2C3D4E5.com.example.iphone.staging   ← staging, declared on the PRODUCTION domain
A1B2C3D4E5.com.example.macos.staging    ← a macOS app not otherwise known to exist
A1B2C3D4E5.com.example.<codename>       ← internal codename build
com.example.staging_alpha               ← Android staging, in production assetlinks.json
```

Codename builds and unexpected platforms are the real prize — they name products and teams that
no other public source mentions, and they correlate with intent-filters inside the production APK
(a `com.<pkg>.staging_alpha.action.*` filter shipping in production is the same signal).

**The exact paths the app claims.** This is a curated list of the sensitive flows, written by the
target:

```json
"paths": ["/payment/*", "/account-linking/*", "/email-verification/*",
          "/verify-email/*", "/sim/*"]
```

`/account-linking/*` and `/payment/*` are far better test candidates than anything you would have
guessed. A host claiming `["*"]` hands every path to the app.

**`webcredentials`.** Lists apps sharing password autofill for the domain. Staging apps appearing
here means credential autofill is shared with a non-production build.

## The decisive check: is any of it exploitable?

The obvious write-up — *"a staging app is authorized to handle all production URLs"* — is almost
always **wrong**, and filing it burns credibility. Both platforms bind declarations to a signing
identity.

**Android — compare cert fingerprints:**

```bash
python3 - <<'PY'
import json
d = json.load(open('assetlinks.json'))
m = {}
for e in d:
    t = e.get('target', {})
    m[t.get('package_name')] = set(t.get('sha256_cert_fingerprints', []))
for pkg, fps in m.items():
    print(pkg, len(fps), 'fingerprint(s)')
ks = list(m)
if len(ks) > 1:
    print('shared between prod and staging:', len(m[ks[0]] & m[ks[1]]))
PY
```

- **Distinct fingerprints, zero shared** → Android verifies the signing cert. An attacker cannot
  publish an app with that package name and inherit the links. **Not exploitable.** Hygiene note only.
- **Fingerprint array empty or missing** → verification is weakened. Now worth investigating.

**iOS** — appIDs are `TEAMID.bundleid` and Apple validates the team ID at install. A staging appID
under the same team is not claimable by an outsider.

**The genuinely reportable variants** are narrower: a declaration referencing a bundle id or
package that is *no longer registered* (claimable in the store), a fingerprint list that is empty,
or an AASA served over a host you can already control.

## Testing the claimed paths

The paths are a target list for the *web* surface too. Fetch them with placeholder values — they
usually 404 without a valid token, which itself confirms they are token-bearing flows worth
attention once you have credentials.

## Cross-platform inference when you cannot get the IPA

If the app is Flutter/React Native, iOS and Android share the business logic. Grep every harvested
web asset and the Android binary for custom schemes:

```bash
grep -rhoE '\b[a-z][a-z0-9+.-]{2,20}://[a-zA-Z0-9._/~-]*' <assets> | sort -u
```

Finding **only** the same scheme as Android is a meaningful negative: it means the API surface is
shared and the untested iOS-specific remainder is native-layer only (`Info.plist`, Keychain, ATS)
— not endpoints. State that inference explicitly rather than logging iOS as wholly untested.
