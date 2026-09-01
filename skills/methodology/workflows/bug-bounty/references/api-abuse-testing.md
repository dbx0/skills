# API Abuse Testing

## View Count Forgery

### Pattern
Many web applications expose a view counting endpoint that increments on each request. Common issues:
- No authentication required
- No rate limiting
- No deduplication (IP, session, cookie)
- No cooldown period

### Testing
```bash
# Test without auth
curl -X POST "https://target.com/api/views/{id}" \
  -H "Content-Type: application/json" -d '{}'

# Rapid fire test (100 requests)
for i in $(seq 1 100); do
  curl -s -X POST "https://target.com/api/views/{id}" \
    -H "Content-Type: application/json" -d '{}' -o /dev/null
done

# Check if count increased
curl -s "https://target.com/api/videos/{id}" | jq '.viewCount'
```

### example-auto.tld 2026-06 Finding
- `POST /api/videos/{videoId}/view` — no auth, no rate limit, no deduplication
- 1000 requests = ~981 views forged
- Works on ANY video including other users'
- Verified: inflated a video from 0 to 10,423 views via ~10,000 unauthenticated requests
- Endpoint is NOT `/api/views/{id}` — correct path is `/api/videos/{id}/view`
- Severity: HIGH

### User Enumeration via Search
- `GET /api/creators/search?q={prefix}` — unauthenticated, no rate limit
- Returns up to 8 users per query (handle, displayName, avatarUrl)
- Two-letter brute force (676 combinations) enumerates ~1,700+ users
- Single-letter queries return ~69 users
- Severity: MEDIUM — exposes all registered users without authentication

---

## Streaming (RTMPS) Abuse

### Pattern
Live streaming platforms using Cloudflare Stream or similar services may have:
- Stream key exposure in API responses
- No rate limiting on stream start
- Ability to stop other users' streams
- Unsanitized stream titles (stored XSS)

### Testing
```bash
# Start a stream
curl -X POST "https://target.com/api/live/start" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test"}'

# Test RTMPS ingest with FFmpeg
ffmpeg -f lavfi -i "testsrc=duration=10:size=640x360:rate=30" \
  -f lavfi -i "sine=frequency=440:duration=10" \
  -c:v libx264 -preset ultrafast -tune zerolatency \
  -c:a aac -b:a 128k \
  -f flv "rtmps://live.cloudflare.com:443/live/<stream_key>"

# Test title XSS
curl -X POST "https://target.com/api/live/start" \
  -H "Content-Type: application/json" \
  -d '{"title":"<script>alert(1)</script>"}'
```

### example-auto.tld 2026-06 Finding
- Stream start requires auth (good)
- No rate limiting on stream start
- Stream titles not sanitized (stored but escaped by React)
- Stream keys not exposed in API responses (good)

---

## General API Abuse Checklist

1. **View counting** — test without auth, rapid fire, different IPs
2. **Like/reaction counting** — same patterns as views
3. **Follower counting** — can we follow/unfollow rapidly?
4. **Search rate limiting** — can we enumerate data via search?
5. **Upload rate limiting** — can we upload many files rapidly?
6. **Stream start rate limiting** — can we start many streams?
7. **Comment spam** — can we post comments without rate limiting?
8. **Notification spam** — can we trigger many notifications?
