---
name: postmessage-security
description: Use when a target serves first-party JavaScript and you need to test window.postMessage listeners for missing/weak origin checks — covers listener sweeps, sink classification, origin-check bypass patterns, and end-to-end proof via CDP/window.open. Trigger on "postMessage", "cross-origin messaging", "iframe communication", "onmessage", or when auditing an embedded widget/iframe checkout/SDK.
version: 1.0.0
author: field-derived (iFood engagement, Critical PAN/CVV exfil finding)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [postmessage, xss, origin-check, iframe, client-side, dom]
    related_skills: [client-runtime-intelligence, bug-bounty]
---

# postMessage Origin-Check Testing

`window.postMessage` listeners are a recurring source of critical findings. A missing or weak
origin check on a listener that feeds a sensitive sink — a tokenization URL, an encryption key, a
`localStorage` write, a navigation — can turn an embedded widget into a data-exfiltration primitive
controlled entirely by whoever can get a victim to load an attacker page. This exact pattern
produced a Critical PAN/CVV exfiltration finding: a payment iframe's origin check accepted any
origin matching `/\.(com|net)\.br$/`, and both the tokenization URL and the RSA encryption key came
from the untrusted message.

## When to Use

- Target serves first-party JS (SPA, embedded widget, iframe-based checkout/SSO/chat)
- You're auditing anything that gets embedded cross-origin (payment widgets, SSO iframes, support
  chat widgets, partner integrations)
- `client-runtime-intelligence` recon surfaced `addEventListener` or `onmessage` in recovered source

## Method

### 1. Sweep the JS corpus

Grep the full first-party bundle set for `addEventListener("message", …)` / `onmessage =`. Exclude
on sight (these dominate raw match counts but are not exploitable):
- Library-internal `MessageChannel`/`setImmediate` scheduler polyfills
- Web Worker `onmessage` handlers (same-origin by construction — origin checks don't apply)

### 2. Classify every remaining listener by sink

Does `event.data` (or a field of it) flow into:
- a URL used for a subsequent network request (tokenization endpoint, API base URL)
- a decryption/encryption key or credential
- a `localStorage`/`sessionStorage` write
- `location.href` / `location.replace()` / `location.assign()`
- `innerHTML` / `dangerouslySetInnerHTML` / `v-html`

Any of these is a candidate. A listener that only updates a UI-local state variable with no
downstream sensitive effect is low value — note it and move on.

### 3. Read the origin check literally, don't skim it

| Pattern seen | Reality |
|---|---|
| No check at all | Any origin — including `null` from a `file://` PoC page, or a `window.open()` popup from an attacker page — can post messages |
| Regex suffix/substring check, e.g. `/\.(com\|net)\.br$/` | Accepts `evil.com.br`, not just the intended domain — a suffix match is not a domain match |
| `event.origin === trustedOrigin` against a hardcoded string | Safe, but verify it's actually `===` and not `==` against something coercible |
| `event.origin.includes(trustedDomain)` | Bypassed by `trustedDomain.attacker.com` or `attacker.com/trustedDomain` in some URL shapes — treat `.includes()` origin checks as broken by default |
| Check only on `postMessage` used to *send*, not to *receive* | Irrelevant — the receiving side's check is what matters |

### 4. Prove it end to end

Don't stop at citing the source line — demonstrate the sink actually fires:
- Drive a real browser via CDP or Playwright from a `file://` page (origin reports as `null`) or a
  `window.open()` popup hosted on an attacker-controlled domain
- Post the crafted message with the payload that exercises the sink you identified
- Capture proof the sink fired: the exfil request left with attacker-controlled data, the
  decryption key changed to the attacker's key, the storage value landed, the navigation occurred

### 5. Storage-partitioning caveat

An `<iframe>` embedded from a third-party origin writing to `localStorage` is neutralized by modern
browser storage partitioning — the write lands in an isolated partition invisible to the real
origin's own scripts. `window.open()` popups are **not** partitioned this way. If both an iframe and
a popup vector are available on the same listener, demonstrate impact with `window.open()`, and note
the iframe variant as reduced/no impact rather than claiming both.

## Severity Guidance

| Sink | Typical severity |
|---|---|
| Tokenization URL / encryption key controlled by message → credential/PAN exfil | Critical |
| Arbitrary `localStorage`/`sessionStorage` write with attacker-chosen keys read by other app logic | Medium–High, depends what reads those keys |
| `location.replace()`/`location.href` with unvalidated message data | Open Redirect, or Stored/DOM XSS if the reflected value later renders unsanitized |
| UI-local state only, no sensitive downstream effect | Not a finding — note and move on |

## Common Mistakes

- Reporting the listener's *existence* as the finding instead of the missing/weak origin check plus
  a proven sink
- Skipping the regex/string-check nuance and assuming any origin check present is sufficient
- Testing only with an iframe when a `window.open()` vector exists and would bypass partitioning
- Not checking whether `X-Frame-Options`/CSP `frame-ancestors` at least limits framing even if the
  message-origin check is broken — report both gaps if both are missing, since either alone reduces
  exploitability
