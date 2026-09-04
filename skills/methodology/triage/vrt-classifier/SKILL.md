---
name: vrt-classifier
description: "Use when a finding needs a Bugcrowd VRT classification, priority (P1-P5), CWE or CVSS baseline before writing a report, or when triaging/disputing a submission's assigned severity."
sources: bugcrowd_vrt
vrt_release: 2026-07-08
---

# Bugcrowd VRT Classifier

Map a finding to exactly one Bugcrowd Vulnerability Rating Taxonomy entry and carry that entry's baseline priority, CWE, and CVSS v3 vector into the report.

**Core principle:** the VRT entry is chosen from the *demonstrated* impact, never from the theoretical ceiling of the bug class. Bugcrowd triage downgrades on proof, not on plausibility.

## When to Use

- Writing a Bugcrowd (or VRT-aligned) submission and the severity field needs a defensible value
- A submission was rated lower than expected and you need the taxonomy text to argue the reclassification
- Sorting a batch of findings by what is actually worth reporting
- You need the CWE or the CVSS v3 baseline vector that Bugcrowd itself publishes for a bug class

**Not for:** programs that publish their own severity table that overrides VRT (read the brief first, it wins), or scoring bugs with no VRT analogue (fall back to CVSS and say so).

## Data

`references/` mirrors the official `bugcrowd/vulnerability-rating-taxonomy` repo (release **2026-07-08**): `vrt.json`, `cvss_v3.json`, `cwe.json`, `remediation_advice.json`. 437 leaf entries across 26 categories.

Query it with `scripts/vrt.py` rather than guessing at ids:

```
scripts/vrt.py search <keywords...>    ranked candidates with priority, CWE, CVSS
scripts/vrt.py show <id-path>          full record + children + remediation advice
scripts/vrt.py list [category-id]      categories, or children of one
scripts/vrt.py flat [--priority N]     every leaf as TSV
```

`references/high-priority.md` is a scan list of every P1 and P2 entry.

VRT names are formal and often diverge from hunter shorthand: "s3 bucket" returns nothing, "misconfigured cloud storage" does. When a search misses, retry with the taxonomy's vocabulary (`list` the plausible category, then `list <category-id>`) before concluding the finding has no entry.

## Workflow

1. **State the demonstrated impact in one sentence** before touching the taxonomy. What did the PoC actually do, as what actor, to whose data? If that sentence contains "could" or "an attacker might", the finding is not yet at the priority you want to claim.
2. **Search for candidates.** `scripts/vrt.py search idor tenant` beats scrolling the JSON. Search on the mechanism *and* the impact.
3. **Descend to a leaf.** A category or subcategory id is not an answer when it has children. `show` prints the children; pick the variant that matches the proof. Reporting `broken_access_control` instead of the specific variant is what gets a submission bounced back for clarification.
4. **Check the priority modifiers below** and adjust off the baseline, stating the reason.
5. **Record the tuple**: `id-path | Pn | CWE | CVSS v3 vector`. `show` gives all four plus Bugcrowd's own remediation text, which belongs in the report's remediation section.

## Choosing Between Close Entries

| Situation | Rule |
|---|---|
| Two entries both fit | Pick the one whose *name* describes the impact you proved, not the one with the higher priority |
| The bug chains into something worse | Classify the chain's endpoint, and only if the full chain is demonstrated end to end; otherwise classify the primitive |
| Impact depends on the target's data | Use the entry's `Varies` priority and justify a concrete Pn from the affected asset |
| Nothing fits | Use the category's `other` variant if one exists, else the nearest leaf, and say in the report why the taxonomy is off |
| Self-only / requires victim to paste a payload | Almost always P5, regardless of the underlying class |

## Priority Modifiers

Baselines assume an unauthenticated attacker, a realistic user interaction level, and production impact. Move off the baseline when:

**Downgrade**

- Requires an unrealistic precondition (attacker-controlled MITM, physical access, a victim performing multiple deliberate steps)
- Affects only the reporter's own account or data
- Target is a non-production, sandbox, or already-public asset
- Impact is unauthenticated-to-unauthenticated with no state change or data exposure

**Upgrade**

- Crosses a tenant, org, or trust boundary that the baseline entry assumes stays intact
- Reaches secrets, session material, or internal-only services
- Affects an asset the brief names as critical
- Pre-auth where the entry assumes authenticated access

Every deviation from the baseline goes in the report with its reason. An unexplained upgrade reads as inflation and costs credibility on the next submission.

## Common Mistakes

- **Classifying the bug class, not the finding.** "SQL injection" is P1; an error-based leak of a public catalogue table on a staging host is not.
- **Stopping at a subcategory.** If `show` lists children, you have not finished.
- **Copying the CVSS vector unchanged.** It is Bugcrowd's baseline for the class; adjust AV/PR/UI to what your PoC actually required and keep both values visible.
- **Assuming `Varies` means "pick the highest".** It means the taxonomy is deferring to you: justify the number from the asset.
- **Ignoring the program brief.** A brief's out-of-scope list or custom severity table overrides everything here.
- **Treating stale data as current.** Bugcrowd revises the VRT; `references/` is pinned at 2026-07-08. Re-pull from `bugcrowd/vulnerability-rating-taxonomy` when a classification hinges on a recently added category.

## Output Contract

```text
VRT entry:    <id-path>
VRT name:     <Category > Subcategory > Variant>
Priority:     P<n>  (baseline P<n>, adjusted because ...)
CWE:          CWE-<id>
CVSS v3:      <baseline vector>  ->  <as-demonstrated vector> (<score>)
Demonstrated: <one sentence, past tense, no "could">
Preconditions:<auth level, user interaction, scope of affected users>
```
