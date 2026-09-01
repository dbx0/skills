# Marketplace PII Correlation — Reference

## Technique Overview

Correlating data across multiple public endpoints on marketplace/classifieds platforms to build comprehensive PII profiles.

## Key Discovery Pattern

1. **Public Activity Feed** — Often at `/api/notifications_feed.php`. Returns JSON with:
   - `actor`: Full name of seller
   - `url`: URL slug to ad detail page
   - `title`: Vehicle/item title
   - `type`: Event type (ad_sold, ad_created, part_created, ad_boosted)
   - `created_at`: Timestamp

2. **Search/Browse API** — POST with multipart form data:
   - URL: `POST /index.php?action=search`
   - Fields: `q`, `page`, `per_page`, `sort`, `tab`, `brand_id`, `model_id`
   - Response: JSON with `ok`, `page`, `per_page`, `total`, `has_more`, `results_html`

3. **Ad Detail Pages** — `/ads/{slug}` or `/pecas/{slug}`:
   - Phone: Brazilian format `(DD) XXXXX-XXXX`
   - WhatsApp: `wa.me/55XXXXXXXXX`
   - Instagram: `instagram.com/{handle}`

## PII Extraction Regex

```python
import re
phones_br = re.findall(r'\((\d{2})\)\s*(\d{4,5})-?(\d{4})', html)
phones_int = re.findall(r'\+55(\d{2})(\d{4,5})(\d{4})', html)
whatsapp = re.findall(r'wa\.me/(\d+)', html)
instagram = re.findall(r'instagram\.com/([a-zA-Z0-9._]+)', html, re.I)
```

## Pagination via Search API

```python
for page in range(1, 50):
    body = multipart_form_data(page=page, per_page=36)
    r = requests.post(url, data=body, headers=headers)
    data = r.json()
    urls = re.findall(r'href="(/ads/[^"]+)"', data['results_html'])
    if not data.get('has_more'): break
```

## Shell Escaping for Auth

When passwords have `&`, `@`, `$` characters:
- Write POST data to file: `echo 'data' > /tmp/post.txt; curl -d @/tmp/post.txt`
- Use Python subprocess instead of shell commands

## Scaling
- Phase 1: Collect URLs via search API (fast)
- Phase 2: Visit each ad page (slow, 200-300ms each)
- Use background nohup + JSON progress tracking for resume support