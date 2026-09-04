# [date] [short project name]

## Scenario Category
<!-- APK reversing / JS signing / binary analysis / penetration testing / CTF / traffic capture analysis / other -->

## Target Overview
<!-- One sentence on what is being done -->

## Full Execution Chain
<!-- The complete steps from receiving the target to producing the result, including the dead ends you went down -->

1. ...
2. ...
3. ...

## Pitfalls Log

| Issue | Cause | Fix | Time spent |
|------|------|---------|------|
| ... | ... | ... | ... |

## Toolchain Findings
<!-- Which tools were used, which worked well, which have gotchas, version compatibility issues -->

## Key Code/Commands

```
<!-- Paste the key commands, hook scripts and decryption logic actually used -->
```

## Improvement Suggestions for This Package
<!-- Is the routing accurate? Is anything missing from bootstrap? Do the docs need additions? Do new tools need to be added to the manifest? -->

## Reusable Patterns/Script Snippets
<!-- If you produced a reusable hook script, decryption logic or bypass technique, paste it here -->

## Evolution Actions
<!-- Which updates were actually performed during this write-back -->
- [ ] Updated the routing matrix
- [ ] Updated tool-index
- [ ] Updated bootstrap-manifest
- [ ] Updated the sub-skill documentation
- [ ] Added a pitfalls entry
- [ ] No update needed

## Environment Details
<!-- Record the key environment details at the time -->
- OS:
- Tool versions:
- Target platform/version:

## Anonymization Requirements

> **This file may be synced to a remote repository, so it must be anonymized. The full specification is in [`anonymization.md`](anonymization.md) (master placeholder table + automated detection script).**

- Target domain/IP: replace with `{target_domain}` / `{target_ip}` (see `anonymization.md` for details)
- Real URL paths: keep the structure, replace the domain
- Token/cookie/password/JWT/API key: use the `{token}` / `{password}` / `{api_key}` placeholders
- Username/phone number/email: use the `{username}` / `{phone}` / `{user_email}` placeholders
- Internal IPs/ports: keep only the first two octets of internal ranges (`10.0.x.x`)
- Vulnerability payloads: technical content can stay, but replace target-identifying parameters (e.g. `?id={user_id}`)

Before submitting, run a regex scan against the **field-journal mandatory checklist** at the end of `anonymization.md`.

If the repository is private and confirmed never to go public, these rules can be relaxed, but anonymization is still recommended.

## Index Sync (the last step before submitting)

After writing this journal, you must update `_index.md` in step:

1. Add a row under the matching subsection of "By Scenario Category" (including the date and keywords)
2. Append this filename under the matching technique in "High-Frequency Successful Patterns (by technique)"
3. Append this filename under the matching entity in "Entity Inverted Index (by target characteristic)"
4. Update the totals and the "last updated" date in "Cumulative Statistics"

---
<!-- [Evolution stats] Cumulative projects completed in this package: N | New patterns this round: X | Toolchain issues fixed this round: Y -->
<!-- [Community contribution] When done, ask the user whether to PR to the main repository. See CONTRIBUTE-BACK.md for the workflow. -->
