---
name: recovery-techniques
description: Methods for recovering deleted/force-pushed commits and content
---

# Git Recovery Techniques

Three methods to recover force-pushed or deleted commits from GitHub repositories.

---

## Method 1: Direct GitHub Patch URL (Fastest)

Works for commits that still exist in GitHub's internal storage but are not on any branch.

```bash
# Try direct commit URL (may 404 if fully GC'd)
curl -s "https://github.com/OWNER/REPO/commit/SHA.patch" > commit.patch

# Check if valid patch
head -20 commit.patch
```

**Success indicators**: Returns valid git patch format with diff content.
**Failure indicators**: Returns HTML (404 page) or "Not Found" text.

---

## Method 2: GitHub Archive / BigQuery (Most Reliable)

Query GH Archive for the PushEvent containing the commit, then use the commit SHA from the payload.

```sql
-- Find PushEvents with the commit SHA in payload
SELECT created_at, actor.login, payload.commits, payload.head
FROM `githubarchive.month.YYYYMM`
WHERE repo.name = 'OWNER/REPO'
  AND type = 'PushEvent'
  AND JSON_EXTRACT_SCALAR(payload.head, '$.sha') = 'COMMIT_SHA'
LIMIT 10
```

Then use Method 1 with the SHA from `payload.head.sha`.

---

## Method 3: Local Git fsck (If You Have Clone)

```bash
# In a fresh clone of the repo
git clone https://github.com/OWNER/REPO.git && cd REPO

# Find all unreachable (dangling) commits
git fsck --lost-found --unreachable 2>&1 | grep "dangling commit" | awk '{print $3}' > dangling.txt

# Inspect each dangling commit
while read sha; do
  echo "=== $sha ==="
  git show --stat --format="%H|%ai|%an|%ae|%s" -s "$sha"
done < dangling.txt
```

**Note**: This only works if the dangling commits haven't been garbage collected. GitHub's server-side GC runs periodically.

---

## Recovery Workflow

1. **Start with Method 1** — fastest, ~60% success for recent force-pushes (< 30 days)
2. **Use Method 2** — if Method 1 fails, query GH Archive for the PushEvent
3. **Use Method 3** — if you have a local clone that predates the force-push

---

## Force-Push Detection

```bash
# GH Archive query for force-push indicators
SELECT created_at, actor.login, payload.size, payload.distinct_size, payload.head
FROM `githubarchive.month.YYYYMM`
WHERE repo.name = 'OWNER/REPO'
  AND type = 'PushEvent'
  AND payload.size > 0
  AND payload.distinct_size = 0  -- Force push: commits removed from history
ORDER BY created_at DESC
LIMIT 50
```

**Interpretation**: `size > 0 AND distinct_size = 0` = force push that erased commits. The `payload.head` SHA is the new head after the force push.