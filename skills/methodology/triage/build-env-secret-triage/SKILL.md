---
name: build-env-secret-triage
description: Use when grepping frontend JS bundles for secrets/keys/tokens by variable name — triages whether a matched environment-variable assignment actually ships to the browser based on bundler prefix rules (NEXT_PUBLIC_, VITE_, REACT_APP_), and how to spot a systemic root cause across many hosts. Trigger on "env var leak", "hardcoded secret in bundle", "process.env", "build-time secret", or after a source-map/JS sweep surfaces credential-like assignments.
version: 1.0.0
author: field-derived (iFood engagement, Faster secret pattern)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [secrets, javascript, env-vars, bundler, source-map, triage]
    related_skills: [client-runtime-intelligence, credential-verification, bug-bounty]
---

# Build-Time Environment Variable / Secret Triage

Frontend build tools only inline environment variables into the shipped client bundle if the
variable name matches a bundler-specific prefix. A variable-name grep match on a secret-looking
assignment is not proof of exposure — it depends entirely on whether that bundler would have
inlined it. Getting this wrong produces false positives (claiming a leak that evaluates to an
empty string in the browser) and false negatives (missing that a whole SDK forces real secrets
into dozens of apps).

## When to Use

- After a JS/source-map sweep surfaces `secret`, `key`, `token`, `password`, `apiKey` style
  variable names or `process.env.X` references
- Before reporting any credential found via bundle grep — this is a mandatory check, not optional
- When one finding (a leaked secret) looks like it might repeat across other apps sharing a
  build pipeline or shared internal SDK

## The Prefix Rule

| Bundler | Client-exposed prefix | Everything else |
|---|---|---|
| Next.js | `NEXT_PUBLIC_*` | Stays server-side; `process.env.X` evaluates to `undefined` in the browser bundle |
| Vite | `VITE_*` | Same — dead in the client bundle |
| Create React App | `REACT_APP_*` | Same |
| Nx (workspace-level) | Whatever the build config explicitly declares for that app | Varies per app — check the actual build config, don't assume |
| Webpack (`DefinePlugin`/`EnvironmentPlugin`) | Whatever keys are explicitly listed | No default prefix convention — must check config |

## Method

1. **Find the variable name and the bundler.** Identify which build tool produced the bundle
   (look for `__NEXT_DATA__`, `import.meta.env`, Vite's dev-server signature, CRA's `manifest.json`,
   Nx's build output structure).
2. **Check the prefix.** If the variable name does not carry the exposure prefix for that bundler,
   it very likely compiles to `process.env.X || ""` and ships as an empty string or `undefined`.
3. **Confirm by literal value, not declaration.** Search the *built* bundle for the actual literal
   string value assigned to that variable (`grep` for a plausible secret pattern near the variable
   name, or beautify and locate the assignment). A declaration alone (`const x = process.env.SECRET`)
   proves nothing about what shipped — only a non-empty literal in the compiled output does.
4. **If it's a real leak, check for a systemic cause before filing N reports.** Search whether a
   shared internal SDK/plugin *mandates* the config key (e.g. throws an error without it — grep for
   `MANDATORY_*_KEYS`, required-field validation in a shared plugin's source). If so, every app using
   that SDK is independently forced to supply a real value. File **one** report describing the
   platform-level root cause and list every affected host, rather than duplicate single-host reports.
5. **Recognize correct behavior as a contrast, not silence.** A placeholder value
   (`THIS_IS_NOT_USED`, `MISSING_ENV_VAR`, an unresolved template token) shipped in place of a real
   secret means that app's owners configured it correctly — worth naming explicitly in the report as
   proof the platform *can* be used safely, which strengthens the case that the leaking apps are a
   defect, not an accepted risk.

## Common Mistakes

- Reporting a `secret`/`token` variable name match without checking the bundler's prefix rule — the
  single most common false positive in this class of finding
- Treating `const x = process.env.SECRET_KEY` as proof of a leak instead of checking what literal
  value, if any, actually ended up in the compiled bundle
- Filing separate reports per host when the root cause is one shared SDK requirement — undersells
  the finding's severity (looks like N minor bugs instead of one platform defect) and wastes report
  slots
- Missing that a *correctly configured* sibling app (placeholder value) is useful evidence that the
  platform supports safe configuration, making the leaking apps clearly a defect rather than expected
  behavior

## Cross-References

- Use `client-runtime-intelligence` for the broader bundle-reading methodology this triage plugs
  into
- Once a credential is confirmed to have a real literal value, use `credential-verification` (the
  three-state test) to prove it's live before reporting
