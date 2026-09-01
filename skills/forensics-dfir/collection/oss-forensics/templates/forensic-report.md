# Forensic Investigation Report

**Target Repository**: `{{OWNER}}/{{REPO}}`
**Investigation ID**: `INV-{{YYYYMMDD}}-{{SEQ}}`
**Date Started**: `{{START_DATE}}`
**Date Completed**: `{{END_DATE}}`
**Investigator**: `{{INVESTIGATOR}}`
**Classification**: `{{PUBLIC|PRIVATE|CONFIDENTIAL}}`

---

## Executive Summary

**Verdict**: `{{COMPROMISED|CLEAN|INCONCLUSIVE}}`
**Confidence**: `{{HIGH|MEDIUM|LOW}}`

**One-paragraph summary**: {{SUMMARY}}

**Key Findings**:
- {{FINDING_1}}
- {{FINDING_2}}
- {{FINDING_3}}

---

## Timeline of Significant Events

| Date/Time (UTC) | Event | Evidence ID(s) | Source |
|-----------------|-------|----------------|--------|
| {{TIMESTAMP}} | {{EVENT_DESCRIPTION}} | EV-XXXX, EV-YYYY | {{SOURCE}} |
| {{TIMESTAMP}} | {{EVENT_DESCRIPTION}} | EV-XXXX | {{SOURCE}} |

---

## Validated Hypotheses

### HYP-001: {{HYPOTHESIS_TITLE}}

**Status**: `{{VALIDATED|INCONCLUSIVE|REJECTED}}`

**Claim**: {{DETAILED_CLAIM}}

**Supporting Evidence**:
- EV-XXXX: {{DESCRIPTION}}
- EV-YYYY: {{DESCRIPTION}}

**Disproof Evidence Checked**: {{LIST}}

**Confidence**: {{HIGH|MEDIUM|LOW}}

---

## Evidence Registry

| Evidence ID | Timestamp | Source | Type | Observation | Verification | Content SHA256 |
|-------------|-----------|--------|------|-------------|--------------|----------------|
| EV-0001 | {{TS}} | {{SRC}} | {{TYPE}} | {{OBS}} | {{VER}} | {{SHA}} |
| EV-0002 | {{TS}} | {{SRC}} | {{TYPE}} | {{OBS}} | {{VER}} | {{SHA}} |

---

## Indicators of Compromise (IOCs)

| IOC ID | Type | Value | Context | Enrichment |
|--------|------|-------|---------|------------|
| IOC-001 | COMMIT_SHA | `a1b2c3d4...` | Force-pushed commit | Recovered via Method 1 |
| IOC-002 | DOMAIN | `evil.com` | Exfiltration target | Passive DNS: 2024-01-15 |
| IOC-003 | PACKAGE_NAME | `internal-lib-v2` | Dependency confusion | NPM: published 2024-01-10 |

---

## Chain of Custody

| Evidence ID | Collected At | Collected By | Method | Stored At |
|-------------|--------------|--------------|--------|-----------|
| EV-0001 | {{TS}} | {{INVESTIGATOR}} | BigQuery | evidence.json |
| EV-0002 | {{TS}} | {{INVESTIGATOR}} | GitHub API | evidence.json |

---

## Recommendations

### Immediate (if COMPROMISED)
- [ ] Rotate all credentials exposed in repository
- [ ] Pin dependency hashes in lockfiles
- [ ] Notify affected users/downstream consumers
- [ ] Coordinate with package registry (npm/PyPI) if published package affected

### Short-term
- [ ] Enable required PR reviews and status checks
- [ ] Require GPG signing for all commits
- [ ] Enable Dependabot/security alerts
- [ ] Audit all workflow files for external calls

### Long-term
- [ ] Implement SLSA/Supply-chain Levels for Software Artifacts
- [ ] Regular automated supply chain scans
- [ ] Maintainer account security training (MFA, hardware keys)

---

## Appendix: Investigation Metadata

- **Total Evidence Items**: {{COUNT}}
- **Verified Evidence**: {{VERIFIED_COUNT}}
- **Hypotheses Tested**: {{HYP_COUNT}}
- **Hypotheses Validated**: {{VALID_COUNT}}
- **Investigation Duration**: {{DURATION}}
- **Tools Used**: git, gh, bq, curl, wayback, evidence-store.py

---

**Report Prepared By**: {{INVESTIGATOR}}
**Reviewed By**: {{REVIEWER}}
**Distribution**: {{DISTRIBUTION_LIST}}