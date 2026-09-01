---
name: client-runtime-intelligence
description: Client-runtime and bundle analysis methodology for converting front-end assets into route maps, auth assumptions, object graphs, and manual test queues. Use when JavaScript, source maps, or mobile-facing assets are available.
sources: local_tooling_corpus, field_recon
report_count: 0
---

# Client Runtime Intelligence

Use this skill whenever the target exposes meaningful client code.

## Why it matters

The runtime tells you what the product believes about itself:
- which APIs exist
- which objects matter
- which roles the UI expects
- which states the client thinks are valid
- which surfaces the frontend tries to hide

## What to extract

Prioritize these categories:
- route templates and API base paths
- GraphQL queries, mutations, fragments, and object identifiers
- feature flags and rollout guards
- role names and permission checks
- import, upload, export, clone, restore, preview, and support actions
- hidden form fields and query parameters
- environment markers and region hints
- error handlers and fallback paths
- admin, staff, or internal-only route references
- auth-provider configuration and token-handling logic

## Reading strategy

Work from coarse to fine:

1. Product map
- identify app modules
- separate marketing code from authenticated product code
- identify admin/support bundles versus user bundles

2. Data-flow map
- which views create objects
- which views mutate objects
- which views export or share objects
- which views trigger background work

3. Trust map
- where the client performs role checks
- where object ownership is assumed rather than enforced
- where a helper action uses a lighter payload than the main action
- where a hidden parameter appears to select tenant, workspace, actor, or role

## Manual test queue generation

Transform client findings into hypotheses, not just notes.

High-value hypotheses usually come from:
- role checks present only in UI logic
- helper mutations or helper endpoints with weaker context
- object identifiers reused across modules
- preview/export paths that use different endpoints than edit/view paths
- imports and uploads that trigger processors after the initial request
- support or admin actions referenced in shared components
- alternate flows for onboarding, invitations, recovery, or collaboration

## Transport-difference analysis

For each important object or workflow, compare:
- UI request shape
- direct API request shape
- background-job or webhook side effects
- batch or helper endpoints
- mobile or legacy routes if visible

The useful question is not "is the route there" but "which transport enforces the weakest assumptions."

## Hidden-parameter discipline

Treat parameter discovery as a first-class outcome.

Track:
- query names
- body keys
- feature toggles
- state flags
- pagination and filter fields
- actor or tenant selectors
- secondary object IDs

Then cluster them by workflow so you can ask:
- which ones are trusted too much
- which ones switch object context
- which ones select a helper path

## Runtime anti-patterns to watch

High-signal patterns:
- role checks in client code with no obvious server pairing
- disabled buttons guarding dangerous actions
- comments or dead code referencing internal endpoints
- dual object references in one mutation or form
- environment switches exposing staging or region-specific logic
- error handlers disclosing backend route names or validation rules

## Source map recovery

A `.map` with `sourcesContent` returns the original source: real filenames, comments, dead code,
config objects, and route tables the minifier flattened. This is the highest-yield step in the
skill and is worth doing before any manual reading of minified output.

### Finding maps

Two paths, and you need both:
- **declared** — `//# sourceMappingURL=` at the tail of each bundle. Resolve it relative to the
  bundle URL. The declared name often differs from `<bundle>.js.map`.
- **conventional** — probe `<bundle>.js.map` directly. Some builds strip the comment but still
  ship the file.

Harvest bundle URLs from `<script src>` on every live host, then from a crawler for
sub-page-only chunks.

### Validating a map — the trap

Validate by searching the **whole file** for `"sources"`. Never a fixed prefix.

`"mappings"` is emitted before `"sources"` and is frequently megabytes of VLQ data. Measured case:
`"sources"` at byte **1,423,388** of a 6.4 MB map. A `head -c 3000 | grep '"sources"'` check
therefore rejects every large map and keeps only trivial ones — silently inverting the sweep so it
discards exactly the application bundles worth reading.

```bash
head -c 200 "$f" | grep -q '"version"' || exit 0     # cheap shape check
grep -qF '"sources"' "$f"        || exit 0           # WHOLE file
grep -qF '"sourcesContent"' "$f" && has_content=1
```

Symptom that you have this bug: a host you know serves a large map never appears in your recovery
output.

### Recovering source

Parse `sources[]` against `sourcesContent[]` and write each entry to disk. Then filter vendor noise:
- `node_modules`, `webpack/bootstrap`, `webpack/runtime`, core-js, regenerator
- **libraries vendored by URL** — some builds inline deps fetched from
  `raw.githubusercontent.com/...`, which pass a `node_modules` filter. Excluding only
  `node_modules` leaves hundreds of third-party files in your "first-party" set.

A 1,284-source map may yield only ~150 genuinely first-party files. Filter before reading.

### What to read first

- `constants.ts`, `environment.js`, `config.js`, `env.js` — base URLs and auth config per environment
- `axiosInstance.js`, `api.ts`, `*BackendCalls*` — the full endpoint surface and how auth is attached
- `AppRoutes`, route tables — **including routes gated by a hostname allowlist**; check whether the
  public host matches the allowlist (a `musea2.azure.ext.gm.com` entry matched the public host and
  exposed a debug harness in production)
- `*Interceptor*`, `*Guard*` — client-side-only authorization

## Secret detection in recovered source

### Regex banks miss returned secrets

Pattern banks match assignment. They cannot match this:

```js
const getGameClientSecret = () => {
  return "6yHPi11xK2LNGtgboMXhsJozojyg9cZh64vMoTj6Qrc="
}
```

There is no `secret = "..."`, no `secret: "..."`, no key-value pair at all. A 67-rule bank scored
zero on this file; the credential was found by reading it.

Run a second pass that does not depend on assignment syntax:

1. **Secret-named identifier proximity** — flag any line matching
   `client_secret|api_key|password|credential|token|private_key|...` in a *function or variable
   name*, then report every string literal within the following few lines.
2. **Entropy sweep** — report quoted literals independent of surrounding syntax, filtered by
   length, Shannon entropy, and mixed character classes. Exclude camelCase, kebab-case, file paths,
   MIME types, and framework suffixes (`*Component`, `*Module`, `*Service`).

Both passes are noisy on their own and precise together. On a 5,013-file corpus this reduced to
48 named hits and 2,082 entropy hits, of which exactly two were real credentials — and it caught
the one the regex bank missed.

See `references/sourcemap-recovery.md` for working implementations.

### Validate every recovered credential before reporting

A credential in a bundle is not a finding until you know it is live. Test it against its own issuer
and read the error precisely:
- Azure AD `AADSTS700016` = app registration does not exist
- Azure AD `AADSTS7000215` = app exists, secret rotated
Both mean dead. Reporting a dead secret as "compromised, rotate immediately" burns credibility.

Public-by-design values are not secrets: MSAL/OIDC public client IDs, Adyen **client** keys
(`live_`/`test_` prefix, origin-restricted), Firebase web config, Sentry DSNs. Adyen **API** keys
(`AQE...`) are server-side and do matter.

## Good work product

End with:
- an endpoint and object graph
- a parameter dictionary grouped by workflow
- a trust-mismatch list
- a manual test queue focused on actor, state, and helper-object differences
