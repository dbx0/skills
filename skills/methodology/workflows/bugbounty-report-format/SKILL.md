---
name: bugbounty-report-format
description: Use when writing or restructuring a bug bounty submission for Bugcrowd, HackerOne, Intigriti or a VDP, when a draft report has evidence tangled up with narrative, when a finding needs an attack path an attacker's-eye impact statement, or when a report is too long and a triager will not read it. Triggers on "write the report", "triage this report", "add an attack path", "this report is too long", "format this finding", "what is the VRT".
---

# Bug Bounty Report Format

A submission is read by a triager under time pressure who must answer one question: **what can an attacker do, and did you prove it?** This format separates the narrative that answers that question from the evidence that backs it, so a triager can decide in the first screen and verify on demand.

**REQUIRED BACKGROUND:** the Impact Demonstration Gate in `bug-bounty` — a finding is not a vulnerability until you have executed the attack and captured the result. This skill formats a finding that already passes that gate.

## Section order

Use `template.md` in this directory as the skeleton. Never reorder these:

| Section | Job |
|---|---|
| Header block | Asset, endpoints, CWE, **VRT**, CVSS, testing conditions. One `**Field:**` per line. |
| Summary | One paragraph. What is broken, in plain terms. |
| The vulnerability | Three labelled paragraphs: **What it is** / **What an attacker achieves** / **Where it sits**. |
| Attack path | One blockquoted sentence starting `> **As an attacker I could**`. |
| Steps to reproduce the attack path | The attack narrated as steps 1..n. Each step points at the validation proving it. |
| Validation | `V1`..`Vn`. Each is a runnable command plus its verbatim response. |
| Remediation | Numbered, most decisive fix first. |
| Notes | Client under test, no-customer-data statement, related-but-separate findings. |

## The two rules that matter most

**1. Steps narrate the attack; Validation holds the evidence.** A triager reads steps 1..n and understands the attack without touching a single HTTP response, then verifies any individual claim by jumping to its `V` number. Never interleave curl output into the narrative — that is what makes reports unreadable.

**2. Only what is proven and works.** Never include a disproved hypothesis, a withdrawn claim, a "correction to my earlier reading", or a self-critical narrative. Never include reliability caveats ("returned 503 once", "intermittent", "worked on retry") — if it worked once, show the capture from the time it worked. Every one of these invites a triager to doubt the finding, and none of them adds evidence.

## Handling a step you could not prove

Do not delete it, and do not assert it. Mark it inline and name the single check that settles it:

```
**Step 3 — The server mints an authorization code for that `redirect_uri`.**
*Server-side; requires an authenticated session to observe. See "Open item" below.*
```

Then an `### Open item` block directly under the steps: which steps are proven, why this one is not (a constraint, not an apology), and the one request that confirms it. A named gate with a named test reads as rigor. A vague "this may be exploitable" reads as padding.

## Validation entries

Each `V` is a heading, a runnable command, its verbatim response, and at most one line of interpretation.

Trim from responses: bot-manager cookies (`_abck`, `bm_sz`), `akamai-grn`, `server-timing`, and any header that carries no meaning. Keep: status line, `location`, transaction/correlation IDs (they prove the app answered and let the vendor find the request in their own logs), CORS headers, and the response body when it identifies the framework.

Strip shell artifacts before pasting — a trailing `%` from zsh reads as a truncated URL.

When the target sits behind a CDN or WAF, include a **layer attribution** validation proving the behaviour is app-authored and not an edge artifact: contrast the app's own error shape (framework 404, JSON error naming its own contract) against the edge's (`Access Denied` HTML). Without it a triager can dismiss the whole report as a CDN quirk.

## State the VRT in the header

**REQUIRED SUB-SKILL:** use `vrt-classifier` to choose the entry. It carries the taxonomy, CWE and CVSS baselines locally with a search script, so never hand-pick an entry from memory or re-fetch the JSON yourself.

This skill covers only what the *report* does with that entry: put it in the header block, alongside the escalation target if a gate opens and any secondary entry a separate validation supports. A triager who sees the intended classification before the reproduction steps is far less likely to file it somewhere else.

**Check for a mechanism-vs-context trap before submitting.** The taxonomy rates some findings by how they are *delivered* rather than what they *carry*, and a triager skimming for the mechanism will land on the wrong entry. `Open Redirect > POST-Based` is **P5** while `GET-Based` is **P4** — so an OAuth code-delivery flaw on a POST-only route hits the floor of the taxonomy if it is read as a redirect bug. When such a trap exists: name the correct entry in the header, and make the **title lead with the context, not the mechanism**. A title beginning "Open Redirect" names the P5 category before the triager reaches your argument.

## Prose style

Single-line paragraphs — no hard wrapping mid-paragraph. Submission fields render markdown and reflow to the browser width; hard-wrapped text reads as ragged there. No `---` horizontal rules; headings carry the section breaks.

## Red flags

| In the draft | Fix |
|---|---|
| Curl output inside the reproduction narrative | Move to a `V` entry, reference it by number |
| "DISPROVED", "correction", "I was wrong", "an earlier version claimed" | Delete. The report states current findings only |
| "returned 503 once", "intermittent", "reproduces on retry" | Delete the caveat, keep the successful capture |
| Impact stated with "could", "may", "potentially" and nothing captured | Not ready — return to the Impact Demonstration Gate |
| Title leads with the mechanism ("Open Redirect") | Lead with the context ("Insecure Redirect URI on the OAuth code-delivery leg") |
| Paragraphs hard-wrapped at 80-100 chars | Unwrap to single lines |
| `%` at the end of a pasted response line | zsh artifact, strip it |
