---
name: credential-verification
description: Use when a credential (API key, app secret, token) has been recovered from a bundle, config, or leak and needs to be proven live without abusing it or causing damage — covers the three-state verification method and cloud API key restriction false positives. Trigger on "is this key live", "verify credential", "prove key works", "API key restriction", or before writing up any recovered secret as a finding.
version: 1.0.0
author: field-derived (iFood engagement, Faster secrets / Nx token / Google key)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [credentials, verification, api-keys, evidence, false-positive]
    related_skills: [build-env-secret-triage, bug-bounty-evidence, bug-bounty]
---

# Three-State Credential Verification

Before reporting a recovered credential as a live finding, prove it is real and active without
using it to do anything destructive, telemetry-polluting, or privileged. Programs distrust
unverified "found a secret" reports, and using a found credential to actually exercise a privileged
action (forge a signature, write data, alter production config) is usually out of scope for
unauthenticated discovery.

## When to Use

- Any time a bundle sweep, config leak, or archive recovery yields something that looks like an API
  key, app secret, service token, or credential pair
- Before writing a report claiming a credential is "live" or "valid"
- When deciding whether a cloud API key is meaningfully "unrestricted"

## The Three-State Method

Test the same endpoint/check three ways and confirm three **distinguishable** responses:

1. **No credential** → baseline rejection (e.g. `403 Gatekeeper`, `401 Unauthorized`, a generic
   auth-required error)
2. **Bogus credential of the right shape** (a random UUID, a garbage string matching the expected
   format) → a *different* rejection than state 1 (e.g. `401 invalid credential` vs the no-credential
   `403`) — this proves the endpoint actually validates the credential rather than ignoring it
3. **The recovered credential** → `200`, or a response distinguishably different from both rejection
   states

Three distinct states is proof the credential is real and live. It does not require exercising any
privileged action the credential grants — stop there unless the program has explicitly authorized
post-auth testing (see `bug-bounty-evidence` / `bug-bounty`'s scope-discipline rules). Note in the
report what the credential *could* be used for and let the program authorize that next phase.

If states 1 and 2 return the same response, the endpoint may not be validating the credential at
all — verify you're not looking at a parameter that's silently ignored before concluding anything is
"live."

## Gateway-Fronted Credentials — "real but not externally exploitable"

A credential can be genuinely live yet **unusable by an external attacker** because the endpoint it
targets sits behind a gateway that authenticates the *client application* by a mechanism the
attacker can't present (usually **mutual TLS**). Check this before writing an exposed credential up
as exploitable, or you file an N/A:

- Fingerprint the stack from headers/cookies: `X-Backside-Transport: FAIL FAIL` = **IBM DataPower**;
  `BIGipServer*` = F5; `visid_incap_*` = Imperva. See [[egress-waf-evasion]].
- Symptom: sending the recovered credential (any header/format) returns the SAME "anonymous / from
  client / access blocked" response as sending **no** credential — i.e. it never reaches the
  credential-validating layer.
- Confirm no mTLS is what's expected: `openssl s_client` shows the origin is *behind* the gateway;
  the gateway, not your request, holds the client cert. The credential authenticates the frontend
  app to the gateway from *inside* the trusted network.
- Verdict: report it as a **hardcoded-secret hygiene issue**, not an exploitable auth bypass, and
  state plainly that the gateway's mTLS/client-auth makes it non-exploitable externally. This is a
  more credible report than an "exploitable credential" claim that dies on re-validation.

## Firebase / GCP Key Reach — quick recipes

Firebase web/Android keys are **non-secret by design**; the finding is what the *backend* allows.
Test each backend, unauthenticated, and record the three states:

```
# Realtime DB open read (shallow = keys only, avoids pulling PII):
curl "https://<project>.firebaseio.com/.json?shallow=true"
#   200 + JSON => OPEN (critical);  401 "Permission denied" => rules enforced (active, secured);
#   423 "deactivated" => dead DB (no finding)
# Firestore:   https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents?key=<K>
#   (404 => no Firestore provisioned)
# Storage:     https://firebasestorage.googleapis.com/v0/b/<project>.appspot.com/o
# Self-signup (account creation on their project):
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<K>" -d '{"returnSecureToken":true}'
#   idToken => OPEN signup;  400 ADMIN_ONLY_OPERATION => disabled (secured)
# Maps billing abuse (per the referrer-vs-service rule above):
#   StaticMap / StreetView often ignore referrer restriction even when Geocoding/Directions/Places
#   enforce it -> a 200 real image on StaticMap is billable-abuse even on an otherwise-"restricted" key.
```
An Android-restricted key answers `Requests from this Android client application <empty> are blocked`
for signUp — that is a *secured* key, not a finding.

## Cloud API Key Restriction — False Positive to Check For

Before reporting a cloud API key (Google, AWS, etc.) as "unrestricted," distinguish **referrer/IP
restriction** from **API/service-level restriction** — a key can lack one while still being blocked
by the other:

- Test the key against the specific API/service it appears intended for, from a context with no
  referrer header (server-side call, not a browser).
- A response like `API_KEY_SERVICE_BLOCKED` (Google Cloud) or an equivalent service-level denial
  means that specific API is blocked at the key level even though no referrer restriction exists.
- Only claim "no restriction at all" if the key succeeds against the real target API with no
  referrer set. If some APIs are blocked and others aren't, report precisely which restriction is
  missing and which APIs remain callable — that's the actual exploitable surface, and it's a more
  defensible, accurate claim than a blanket "unrestricted key."

## Common Mistakes

- Reporting a credential as "live" from a single successful-looking response without the bogus-value
  control to rule out the endpoint simply not checking anything
- Going further than proof-of-liveness — forging signatures, writing data, or otherwise exercising a
  privileged action without explicit program authorization
- Claiming a cloud API key is fully unrestricted without checking service-level blocks, producing a
  report that gets partially disproven on re-validation
- Not documenting the exact three responses (status codes, distinguishing body/headers) as evidence
  — the report needs to show the differential, not just assert it

## Cross-References

- `build-env-secret-triage` for confirming a matched variable name actually carries a real secret
  before you get to verification
- `bug-bounty-evidence` for PoC capture and redaction discipline once a credential is confirmed live
- `cloud-iam-deep` if the verified credential is a cloud IAM key/token and you're authorized to
  explore what it grants
