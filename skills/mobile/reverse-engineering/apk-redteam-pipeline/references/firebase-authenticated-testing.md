# Firebase Callable Functions — Authenticated Testing (fitness app, June 2026)

## Callable Function Protocol

Firebase callable functions (used via `functions.httpsCallable()` in the JS SDK) require a specific `{"data": {...}}` wrapper. Direct parameter passing returns `INVALID_ARGUMENT`:

```python
# WRONG — returns INVALID_ARGUMENT
requests.post(f"{CF_BASE}/checkUsernameAvailability",
    json={"username": "test"}, headers=auth)

# CORRECT — wrap params in {"data": {...}}
requests.post(f"{CF_BASE}/checkUsernameAvailability",
    json={"data": {"username": "test"}}, headers=auth)
# Returns: {"result": {"available": true}}
```

All callable functions use this format: checkUsernameAvailability, sendEmailOTP, verifyEmailOTP, openaiProxy, checkAffiliateCode, createUserReferral, checkUserReferralCode, submitAffiliateApplication, finalizeExpiredChallenges, assignValentineGiftCode, validateGiftOfferRedemption, markGiftOfferRedeemed, markValentineGiftShared, recordAffiliateInstall, garminRequestToken, stravaRequestToken.

## openaiProxy — Full OpenAI API Access (Cost Abuse)

The openaiProxy callable proxies to OpenAI with no model restrictions and no per-user rate limits. Format: `{"data": {"model": "...", "messages": [...]}}`. All models confirmed working: gpt-3.5-turbo, gpt-4, gpt-4-turbo, gpt-4o, gpt-4o-mini. No server-side max_tokens cap. Prompt injection possible via messages array (system role override). Impact: any authenticated user (open signup, no email verification) can burn OpenAI credits.

## sendEmailOTP — Unrestricted Email Sending

Sends OTP to ANY email address, not just the authenticated user's. Rate limited to 1 req/min. verifyEmailOTP confirms with error message for wrong codes.

## checkUsernameAvailability — Username Enumeration

Works with callable format. Returns `{"result": {"available": true/false}}`.

## Firebase Auth Email Duplication

Firebase Auth allows multiple accounts with the same email when "One account per email address" is disabled. Both accounts get valid idTokens and full API access. Impact: username sniping, account confusion, potential takeover if email verification is later enabled. Fix: enable "One account per email address" in Firebase Auth settings.

## Firestore PATCH Creates Documents

When POST/create returns 403, PATCH may still create the document successfully.

## Firebase API Key Handling

Tool output (read_file, terminal) may truncate or redact long strings. Read as raw bytes: `open("/tmp/fkey.txt", "rb").read().strip().decode("ascii")`. The key with literal ellipsis IS the actual key.

## Social Actions — Push Notification Triggers

- Follow user: works (200) — may trigger push
- Like post: protected (403)
- Comment: works (200) — may trigger push
- Create post: works (200)
- Mention in post: works (200)
- Direct message: protected (403)
- Create notification: protected (403)
- Report content: works (200)

## XSS in Post Content

All 27 XSS payload variants accepted and stored (script, img, svg, iframe, body, details, marquee, video, audio, object, embed, math, template, link, meta, form, button, long_payload, unicode, null_bytes, encoding, double_encoding, mixed_case, spaces, newlines, tabs). No content length limit. Indexed in Algolia within seconds. React Native renders as plain text by default — exploitable only in WebView/email contexts.
