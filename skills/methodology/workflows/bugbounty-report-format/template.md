# <Title: lead with the vulnerability class and where it sits, not the delivery mechanism>

**Asset:** `<host>` — <scope tier>. Also confirmed on `<other host>`.
**Endpoints:** `<METHOD /path>`, `<METHOD /path>`
**Weakness:** CWE-<n> (<name>) + CWE-<n> (<name>)
**VRT:** <Category > Subcategory > Variant> (priority: <P_ or Varies>). Escalates to <entry> (<P_>) once <gate> is confirmed. Secondary: <entry> (<P_>), for <which validation>.
**CVSS v3.1:** <score> `<vector>` proven; <score> (`<changed metrics>`) once <gate> is confirmed.
**Discovered:** <YYYY-MM-DD>
**Testing:** `<compliance header>` on every request. Unauthenticated and read-only: no account, no OTP/SMS, no customer data, no takeover. <Any attacker-controlled infrastructure used.>

## Summary

<One paragraph. What is broken, what it hands out, what it fails to check. Name the evidence class that proves it is the live code path, not a dead route.>

## The vulnerability

**What it is.** <The defect in one or two sentences, against the standard or control it violates. Cite the RFC section or expected control.>

**What an attacker achieves.** <Concrete gain, in attacker terms. What do they end up holding? Name the scope or data class.>

**Where it sits.** <The role of this host or route in the system. Why this location makes the defect matter.>

## Attack path

> **As an attacker I could** <concrete action>, <resulting in concrete harm to the customer, app, or users>.

<One or two sentences on what the victim experiences, especially anything that defeats the usual user-side defence: real domain, real certificate, no phishing page, no interaction beyond X.>

## Steps to reproduce the attack path

**Step 1 — <what the attacker does>.**

```
<the crafted request, link, or payload>
```

<One line on why it survives inspection, pointing at the validation that proves it: (validation **V3**).>

**Step 2 — <what the victim does>.** <Plain description.>

**Step 3 — <a step you could not observe>.**
*<Why: server-side, needs an authenticated session, needs a provisioned device. See "Open item" below.>*

**Step 4 — <what the system does>.** From <evidence source> (**V8**):

```
<the decisive excerpt>
```

**Step 5 — <the delivery>.** Proven in **V1**-**V4**.

**Step 6 — <what the attacker does with it>.** <Why no control blocks it, pointing at its validation.>

**Step 7 — Attacker holds <the end state>.**

### Open item

Steps <list> are proven in the validation section below. Step <n> is <where it is decided>, which requires <the constraint>. <State the constraint as a fact, not an apology.>

**One <request/test> confirms it:** <the exact check>. If <outcome>, <what that means for the chain>. I am glad to support that reproduction.

## Validation

Responses verbatim; <bot-management cookies and unrelated headers> trimmed for length. `<compliance header>` was sent on every request.

### V1 — <what this proves, in a few words>

```bash
<runnable command>
```

```
<verbatim response: status line, meaningful headers, transaction IDs, body if it identifies the framework>
```

<At most one line of interpretation.>

### V2 — <...>

<Repeat. Number them V1..Vn in the order the steps reference them.>

### V<n> — The response is app behaviour, not a <CDN/WAF> edge artifact

<Only when the target is edge-fronted. Contrast the app's own error shape against the edge's.>

## Remediation

1. **<The single fix that closes the whole class>**, <specifics>. <Which standard requires it.>
2. <Next most decisive.>
3. <Defence in depth.>

## Notes

**Client under test:** <parameters, identifiers, scopes used>. <How the surface was found.>

**No customer data accessed.** All requests <auth state>; <what attacker-controlled infrastructure was used>. No real user affected, no OTP/SMS sent, no PII viewed. <Rate limiting observed.>

**Related, reported separately.** <Adjacent finding, explicitly scoped out of this report.>
