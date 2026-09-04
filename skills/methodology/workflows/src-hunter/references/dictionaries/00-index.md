# Wordlists, credentials and fingerprints

> Unlike the international HackerOne-style wordlists, this directory targets the **Chinese SRC arena** specifically: default credentials for CN vendors, fingerprints and paths for CN middleware / OA / CMS, and high-frequency CN parameters.
> How this relates to `playbooks/` and `industry/`: playbooks teach method, industry teaches targeting, and dictionaries/ supplies ready-to-use ammunition.

---

## Files

| File | Purpose | Applies to |
|------|------|---------|
| `default-credentials-cn.md` | Default credentials and paths for CN services, OA, CMS and network devices | Weak-password and default-configuration probing |
| `chinese-srcfingerprints.md` | CN component fingerprints, default paths and a high-frequency parameter wordlist | Asset identification, fuzzing, IDOR parameter enumeration |

---

## Mapping to the methodology and playbooks

```
playbooks/unauth-access.md   §2  →  this directory adds the CN middleware / OA / network-management dimension
playbooks/info-disclosure.md      →  this directory adds CN backup and log paths
playbooks/sqli.md                 →  this directory adds high-frequency CN injection parameters
playbooks/file-upload.md          →  this directory adds CN editor and OA upload paths
industry/banking-finance.md       →  the finance component fingerprints here (Seeyon / Yonyou / Kingdee)
industry/telecom-isp.md           →  the telecom component fingerprints here (U2000 / OTNM2000 / SP platforms)
```

---

## Usage limits

1. **Rate limits**: when using default-credentials for brute forcing, stay at ≤ 4 concurrent requests and ≤ 50 attempts per hour per target. Most SRC platforms have zero tolerance for high-frequency brute forcing.
2. **Evidence**: once default credentials work, stop at **a screenshot of the logged-in view showing the core feature names**. Do not proceed into business operations.
3. **Data**: finding a fingerprint is not finding a vulnerability. A fingerprint is only an entry point; you still need the playbook to fully demonstrate exploitation and business impact.
4. **Currency**: these fingerprints come from real cases between 2010 and 2016. Some components (ActiveX, IE controls, Flash editors) are retired and no longer a primary battleground, surviving only in government/enterprise, older state-owned firms and legacy OA systems.

---

## Principles for extending these wordlists

- **Do not copy international wordlists**: HackerOne and SecLists already cover those. This directory only fills CN-specific gaps.
- **Statistics-driven**: where possible, every entry should carry a case count or an occurrence frequency.
- **Actionable**: every entry is either a path, a credential or a parameter, usable as-is.
- **Not verbose**: no explanations, no stories, just lists.
