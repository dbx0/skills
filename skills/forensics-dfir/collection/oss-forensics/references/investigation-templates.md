---
name: investigation-templates
description: Pre-built hypothesis templates for common OSS attack patterns
---

# Investigation Hypothesis Templates

Use these as starting points for Phase 4 hypothesis formation. Each template includes the key evidence types to look for.

---

## Template 1: Maintainer Account Compromise

**Claim**: Legitimate maintainer account was compromised and used to inject malicious code.

**Supporting Evidence Needed**:
- [ ] PushEvents from maintainer after prolonged inactivity (`gh-archive`)
- [ ] New IP/location for maintainer (if detectable via BigQuery) (`gh-archive`)
- [ ] Commits bypassing normal review (direct to main, no PR) (`github-api`)
- [ ] Malicious payload in workflow/config files (`git`, `github-api`)
- [ ] MFA disabled or weak auth (check account settings if public) (`github-api`)

**Disproof Evidence**:
- [ ] Maintainer confirms they made the changes
- [ ] Changes follow normal review process
- [ ] No anomalous timing/location patterns

---

## Template 2: Dependency Confusion / Package Squatting

**Claim**: Malicious package uploaded to public registry with name matching internal dependency.

**Supporting Evidence Needed**:
- [ ] Package name in target's package.json/lockfile not on public registry before date X (`ioc-enrichment`)
- [ ] Package published by unknown maintainer (`ioc-enrichment`)
- [ ] Target repo updated to vulnerable version after package publication (`git`, `github-api`)
- [ ] Package contains obfuscated/executable code (`ioc-enrichment`)

**Disproof Evidence**:
- [ ] Package existed before internal usage
- [ ] Package is legitimate fork/mirror
- [ ] No version bump in target repo

---

## Template 3: CI/CD Workflow Injection

**Claim**: Malicious modification to GitHub Actions/workflow files to exfiltrate secrets or run arbitrary code.

**Supporting Evidence Needed**:
- [ ] Workflow file modified to add `run:` steps with curl/wget to external domains (`git`, `wayback`)
- [ ] Secrets referenced in workflow that shouldn't be accessible (`git`, `github-api`)
- [ ] Self-hosted runner registration added (`git`)
- [ ] Workflow triggers changed to `workflow_dispatch` or `pull_request_target` for privileged access (`git`)

**Disproof Evidence**:
- [ ] Changes reviewed and approved by maintainers
- [ ] External domains are known trusted CDNs
- [ ] Secrets are properly scoped/limited

---

## Template 4: Force-Push to Hide Credential Leak

**Claim**: Developer accidentally committed secret, then force-pushed to erase it.

**Supporting Evidence Needed**:
- [ ] Force-push detected (reflog/BigQuery `distinct_size=0`) (`git`, `gh-archive`)
- [ ] Secret pattern in commit before force-push (if recoverable) (`git`, `gh-archive`)
- [ ] Commit message suggests "fix" or "cleanup" (`git`, `github-api`)
- [ ] Short time between commit and force-push (< 1 hour) (`gh-archive`)

**Disproof Evidence**:
- [ ] No secrets found in recovered commits
- [ ] Force-push was for legitimate rebase/squash
- [ ] Multiple commits force-pushed (not single commit erase)

---

## Template 5: Malicious Binary/Artifact Upload

**Claim**: Compiled binary or artifact with backdoor uploaded to releases or artifacts.

**Supporting Evidence Needed**:
- [ ] Binary file added in commit (`git` - check `diff-filter=A -- "*.so" "*.dll" "*.exe"`)
- [ ] Binary not present in source, only in release artifacts (`github-api` releases)
- [ ] Binary analysis shows suspicious behavior (network, shell) (`ioc-enrichment` - static analysis)
- [ ] Release created by unexpected actor (`github-api`)

**Disproof Evidence**:
- [ ] Binary is legitimate build artifact
- [ ] Source matches binary (reproducible build)
- [ ] Actor is authorized release manager

---

## Template 6: Typosquatting / Lookalike Package

**Claim**: Attacker uploaded package with name similar to legitimate dependency.

**Supporting Evidence Needed**:
- [ ] Similar package name in registry (levenshtein distance 1-2) (`ioc-enrichment`)
- [ ] Target repo recently added dependency with typo (`git`, `github-api`)
- [ ] Typosquat package has malicious code (`ioc-enrichment`)

**Disproof Evidence**:
- [ ] No typo in target's dependency files
- [ ] Similar package is legitimate alternative

---

## Template 7: Contributor Impersonation

**Claim**: Attacker impersonates known contributor via similar username/email.

**Supporting Evidence Needed**:
- [ ] Commits from lookalike username (`github-api`, `gh-archive`)
- [ ] Email domain mismatch (e.g., `@users.noreply.github.com` vs corporate) (`git`, `github-api`)
- [ ] No GPG verification on commits (`git`)

**Disproof Evidence**:
- [ ] Contributor confirms identity
- [ ] Commits are GPG signed with known key