# Resilient API Data Export Pattern

## Problem

When exporting large datasets via API (e.g., querying 2,863 users against RevenueCat), scripts can crash due to:
- Rate limiting (HTTP 429)
- Connection timeouts
- CSV fieldname mismatches
- Memory issues
- Process termination

If the script crashes after 30 minutes of work with no intermediate saves, all data is lost.

## Solution Pattern

```python
#!/usr/bin/env python3
"""Resilient API dump with resume support."""

import json, urllib.request, urllib.error, os, time, csv

OUTPUT_JSON = "/tmp/dump.json"
OUTPUT_CSV = "/tmp/dump.csv"

# 1. RESUME: Load existing results
existing = {}
if os.path.exists(OUTPUT_JSON):
    with open(OUTPUT_JSON) as f:
        for u in json.load(f):
            if isinstance(u, dict):
                existing[u["uid"]] = u

# 2. SKIP already-queried users
pending = [u for u in users if u["uid"] not in existing]
results = list(existing.values())

# 3. RETRY with exponential backoff
def query_user(uid, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={...})
            resp = urllib.request.urlopen(req, timeout=15)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 5 * (attempt + 1)
                time.sleep(wait)
                continue
            elif e.code == 404:
                return None
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return None

# 4. SAVE every N records (not just at the end)
for i, user in enumerate(pending):
    # ... query and append ...
    
    if (i+1) % 50 == 0:
        with open(OUTPUT_JSON, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(results)} records...")

# 5. SEPARATE JSON (all data) from CSV (filtered subset)
with open(OUTPUT_JSON, "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

# CSV: only include records that match criteria
premium = [u for u in results if u.get("active_subscriptions")]
csv_rows = []
for u in premium:
    for s in u.get("active_subscriptions", [{}]):
        csv_rows.append({"uid": u["uid"], "sub_id": s.get("id", "")})

if csv_rows:
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
        writer.writeheader()
        writer.writerows(csv_rows)
```

## Key Principles

1. **Save early, save every 50-100 records** — not just at the end
2. **Resume from checkpoint** — skip already-queried IDs on restart
3. **Retry with backoff** — handle 429 rate limits gracefully
4. **Separate JSON from CSV** — JSON saves all data, CSV saves filtered subset
5. **Match fieldnames exactly** — ensure CSV DictWriter fieldnames match dict keys
6. **Save errors too** — include failed queries with error field for debugging

## Real-World Example

From a fitness-app engagement — RevenueCat dump of ~2,900 users:
- First run: crashed at CSV writing (fieldname mismatch), lost all in-memory data
- Second run: crashed at 1,400 entries (no intermediate save)
- Third run: used this pattern, completed all 2,863 users with 0 data loss
