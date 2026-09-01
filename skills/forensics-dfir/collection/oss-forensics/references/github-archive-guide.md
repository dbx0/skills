# GitHub Archive Guide

## BigQuery Table Structure

GitHub Archive data is available in BigQuery under the `githubarchive` project:
- `githubarchive.month.YYYYMM` — Monthly tables (e.g., `202401`, `202402`)
- `githubarchive.day.YYYYMMDD` — Daily tables for recent months

## Event Types (12 Total)

| Event Type | Description | Key Payload Fields |
|------------|-------------|-------------------|
| `PushEvent` | Commits pushed to repo | `commits[]`, `before`, `head`, `size`, `distinct_size`, `ref` |
| `CreateEvent` | Branch/tag created | `ref`, `ref_type` (branch/tag/repository) |
| `DeleteEvent` | Branch/tag deleted | `ref`, `ref_type` |
| `PullRequestEvent` | PR opened/closed/merged | `action`, `pull_request.*`, `number` |
| `PullRequestReviewEvent` | PR review submitted | `action`, `review.*` |
| `IssuesEvent` | Issue opened/closed/reopened | `action`, `issue.*` |
| `IssueCommentEvent` | Comment on issue/PR | `action`, `comment.*` |
| `WatchEvent` | Repository starred | `action` (started) |
| `ForkEvent` | Repository forked | `forkee.*` |
| `ReleaseEvent` | Release published | `action`, `release.*` |
| `WorkflowRunEvent` | GitHub Actions workflow | `workflow_run.*`, `workflow_job.*` |
| `MemberEvent` | Collaborator added/removed | `action`, `member.*` |

## Common Query Patterns

### Force-Push Detection
```sql
-- Force pushes show size > 0 but distinct_size = 0 (commits force-erased)
SELECT created_at, actor.login, repo.name, payload.ref,
       payload.size, payload.distinct_size, payload.before, payload.head
FROM `githubarchive.month.YYYYMM`
WHERE type = 'PushEvent'
  AND repo.name = 'OWNER/REPO'
  AND payload.size > 0
  AND payload.distinct_size = 0
ORDER BY created_at DESC
```

### Deleted Branch/Tag Detection
```sql
SELECT created_at, actor.login, repo.name, payload.ref, payload.ref_type
FROM `githubarchive.month.YYYYMM`
WHERE type = 'DeleteEvent'
  AND repo.name = 'OWNER/REPO'
ORDER BY created_at DESC
```

### Maintainer Account Takeover Signals
```sql
-- New PushEvent after long inactivity
SELECT created_at, actor.login, repo.name, payload.ref, payload.commits
FROM `githubarchive.month.YYYYMM`
WHERE type = 'PushEvent'
  AND repo.name = 'OWNER/REPO'
  AND actor.login = 'SUSPICIOUS_USER'
  AND created_at > '2024-01-01'
ORDER BY created_at DESC
```

### CI/CD Injection Detection
```sql
-- Workflow file changes in PushEvents
SELECT created_at, actor.login, repo.name, payload.commits
FROM `githubarchive.month.YYYYMM`, UNNEST(payload.commits) AS commit
WHERE type = 'PushEvent'
  AND repo.name = 'OWNER/REPO'
  AND EXISTS (
    SELECT 1 FROM UNNEST(commit.added) AS file
    WHERE file.path LIKE '%.github/workflows/%'
  )
```

## CDX API Parameters (Wayback Machine)

| Parameter | Description | Example |
|-----------|-------------|---------|
| `url` | Target URL pattern | `github.com/OWNER/REPO` |
| `output` | Output format | `json` |
| `limit` | Max results | `100` |
| `from` | Start date (YYYYMMDD) | `20240101` |
| `to` | End date (YYYYMMDD) | `20241231` |
| `filter` | HTTP status filter | `statuscode:200` |
| `collapse` | Deduplication key | `digest` or `urlkey` |

## Cost Optimization

```bash
# ALWAYS dry-run first
bq query --use_legacy_sql=false --dry_run "SELECT ... LIMIT 1000"

# Check bytes processed before running
# Free tier: 10 TiB/month (as of 2024)
# Estimate: ~1 GB per month table for moderate repo
```

## Authentication

```bash
# BigQuery
gcloud auth application-default login
# Or set GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json

# GitHub API
export GITHUB_TOKEN=ghp_...
# Or: gh auth login (uses keychain/credential helper)
```