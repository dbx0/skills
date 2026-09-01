---
name: evidence-types
description: IOC taxonomy and evidence source types for OSS forensics
---

# Evidence Types & IOC Taxonomy

## IOC Types

| Type | Description | Examples |
|------|-------------|----------|
| `COMMIT_SHA` | Git commit hash (40-char SHA-1) | `a1b2c3d4e5f6...` |
| `FILE_PATH` | Repository file path | `.github/workflows/deploy.yml`, `package.json` |
| `API_KEY` | API key/token pattern | `ghp_***`, `sk-***`, `AKIA***` |
| `SECRET` | Generic secret/credential | Passwords, private keys, connection strings |
| `IP_ADDRESS` | IPv4/IPv6 address | `192.168.1.1`, `2001:db8::1` |
| `DOMAIN` | Domain name | `evil.com`, `cdn.malicious.io` |
| `PACKAGE_NAME` | NPM/PyPI/crates.io package name | `internal-lib`, `lodash-es` |
| `ACTOR_USERNAME` | GitHub username/handle | `octocat`, `malicious-actor` |
| `MALICIOUS_URL` | URLs hosting payloads/phishing | `https://evil.com/payload.sh` |
| `OTHER` | Anything not fitting above | Custom IOC types |

---

## Evidence Source Types

| Source | Code | Description |
|--------|------|-------------|
| Local Git | `git` | Local clone analysis (fsck, reflog, log) |
| GitHub API | `github-api` | REST API queries (commits, PRs, issues, events) |
| Wayback Machine | `wayback` | Archived snapshots from web.archive.org |
| GH Archive | `gh-archive` | BigQuery GitHub Archive (PushEvents, DeleteEvents, etc.) |
| IOC Enrichment | `ioc-enrichment` | Passive DNS, WHOIS, package registries, profiles |

---

## Observation Types (per evidence entry)

| Type | Description |
|------|-------------|
| `force_push` | Force-push detected (reflog/BigQuery) |
| `deleted_content` | Content present in archive but missing from current state |
| `suspicious_commit` | Commit with anomalies (binary, unsigned, large) |
| `credential_leak` | Secret/API key found in commit |
| `malicious_code` | Code pattern matching known malware/backdoor |
| `dependency_confusion` | Package name squatting detected |
| `workflow_injection` | CI/CD workflow modified maliciously |
| `maintainer_anomaly` | Contributor behavior deviation |
| `branch_deletion` | Branch/tag deleted (DeleteEvent) |
| `other` | Custom observation |

---

## Verification Status

| Status | Meaning | Requirements |
|--------|---------|--------------|
| `UNVERIFIED` | Single source only | — |
| `VERIFIED` | Confirmed from 2+ independent sources | Cross-referenced |
| `DISPUTED` | Conflicting evidence exists | Flagged for review |

---

## Evidence Record Schema (evidence.json)

```json
{
  "id": "EV-0001",
  "timestamp": "2024-01-15T14:32:00Z",
  "source": "gh-archive",
  "type": "force_push",
  "ioc_ref": "IOC-0042",
  "content_sha256": "sha256:...",
  "content": "{...raw API response...}",
  "verification": "VERIFIED",
  "notes": "Cross-referenced with GitHub API investigator"
}
```