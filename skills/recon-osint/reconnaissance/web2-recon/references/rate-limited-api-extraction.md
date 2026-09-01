# Rate-Limited Paginated API Data Extraction

Technique for extracting large datasets (10k+ records) from paginated APIs that enforce rate limiting (HTTP 429).

## The Problem

Vercel-hosted APIs (and others) enforce rate limiting after ~50 requests in a short window. With `pageSize=20` and 13k records, that's 662 requests — impossible without hitting 429.

## Solution: Adaptive Extraction

### 1. Reduce Request Count

| pageSize | Requests needed for 13,236 records | Status |
|----------|-----------------------------------|--------|
| 20 | 662 | Blocked by 429 after ~50 |
| 100 | 133 | Completed with adaptive delay |

**Always test the maximum pageSize the API accepts.** Many APIs silently accept `pageSize=100` even if the default UI uses 20.

### 2. Adaptive Backoff Strategy

```python
import json, urllib.request, time

base = "https://target.com/api/clients"
all_data = []
page = 1
page_size = 100
total = 13236
delay = 2.5  # start delay

while len(all_data) < total:
    url = f"{base}?page={page}&pageSize={page_size}"
    try:
        time.sleep(delay)
        req = urllib.request.Request(url, 
            headers={'User-Agent': 'Mozilla/5.0 (compatible; PentestBot)'})
        resp = urllib.request.urlopen(req, timeout=20)
        items = json.loads(resp.read()).get("data", [])
        if not items:
            break
        all_data.extend(items)
        delay = max(0.5, delay - 0.1)  # gradually reduce on success
        page += 1
        
        # Checkpoint: save every 500 records
        if len(all_data) % 500 == 0:
            with open("/tmp/checkpoint.json", "w") as f:
                json.dump(all_data, f)
        
    except urllib.error.HTTPError as e:
        if e.code == 429:
            delay = min(8, delay + 1.5)  # back off significantly
            print(f"429 on page {page}, backing off ({delay:.0f}s)")
            time.sleep(5)  # extra wait on top of delay
        else:
            print(f"HTTP {e.code} on page {page}")
            break
    except Exception as e:
        print(f"Error on page {page}: {e}")
        time.sleep(5)

# Final save
with open("/tmp/extracted_data.json", "w") as f:
    json.dump(all_data, f, indent=2, ensure_ascii=False)
```

### 3. Background Execution

For long-running extractions (10+ minutes), use terminal background mode:

```bash
# Run in background with completion notification
terminal(command="python3 extract.py", background=True, notify_on_complete=True, timeout=900)
```

This lets you continue working while the extraction runs.

### 4. Resume from Checkpoint

If the extraction stops mid-way (timeout, crash), resume from last checkpoint:

```python
try:
    with open("/tmp/extracted_data.json") as f:
        all_data = json.load(f)
except FileNotFoundError:
    all_data = []

# Resume from the next page
page = (len(all_data) // page_size) + 1
```

## Real-World Results

| Target | Endpoint | Records | File Size | Time | 
|--------|----------|---------|-----------|------|
| app.example-insurance.tld | /api/clients | 13,200 | 3.2 MB | ~8 min (rate limited) |
| app.example-insurance.tld | /api/policies | 753 | 507 KB | ~30s (no rate limit) |

## Pitfalls

- **429 too aggressive:** If delay reaches 8s+ and still getting 429, the rate limit window may be longer (e.g., 1-hour sliding window). Try pausing for 60s then resuming.
- **Timeout:** If the script times out (default 180s terminal), use `timeout=900` or run in background.
- **Memory:** 10k+ records in a Python list is fine (< 50MB). For 100k+ records, consider streaming/batch writes.
- **Concurrent connections:** Some APIs accept multiple concurrent connections but rate-limit per-IP. Single-threaded sequential requests are safer than parallel.