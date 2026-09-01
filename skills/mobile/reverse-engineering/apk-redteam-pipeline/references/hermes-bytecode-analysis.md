# Hermes Bytecode Deep Analysis — fitness app Case Study

## System Prompt Extraction

System prompts and AI instructions are stored as plain strings in the Hermes bundle. Search for them directly in the raw bytes:

```python
import re
with open('index.android.bundle', 'rb') as f:
    text = f.read().decode('latin-1')

# Find "You are..." prompts (English)
for m in re.finditer(r'You are (?:a|an|the)[^.]{50,500}', text, re.IGNORECASE):
    print(m.group())

# Find Portuguese prompts
for m in re.finditer(r'Voce e[oa]?[^.]{50,500}', text, re.IGNORECASE):
    if 'responsavel' in m.group().lower() or 'assistente' in m.group().lower():
        print(m.group())
```

### fitness app System Prompts Found

1. **Personal Trainer AI**: "You are a concise, knowledgeable personal trainer AI assistant embedded in a workout session app called fitness app..."

2. **Nutritional Assistant**: "You are a specialized nutritional assistant. Return ONLY CSV format..."

3. **Medical Disclaimer (PT)**: "Você é o único responsável por decidir se as recomendações..."

4. **Liability Waiver (PT)**: "Você é responsável por escolher cargas, equipamentos e ambiente seguros..."

These prompts are sent to OpenAI's API and can be overridden by any authenticated user via the `openaiProxy` function's `system` role messages.

## Disassembly Approach

For Expo/React Native apps where `strings` extraction isn't enough, use the Hermes bytecode disassembler:

```bash
# hbc-dissembler is pre-installed in the hermes venv
/home/bx0/.hermes/hermes-agent/venv/bin/hbc-disassembler \
  extracted_apk/assets/index.android.bundle /tmp/hbc_disasm.txt
```

Produces ~3M lines for a 18MB bundle. Search for:

```bash
# Cloud function names (httpsCallable calls)
grep -n 'httpsCallable' /tmp/hbc_disasm.txt | grep 'String:' | head -30

# Auth patterns
grep -n 'typedAuth\|currentUser\|getIdToken\|checkAdminAccess' /tmp/hbc_disasm.txt | head -20

# XSS surfaces
grep -n 'dangerouslySetInnerHTML\|innerHTML\|renderHTML' /tmp/hbc_disasm.txt | head -20

# Content validation
grep -n 'sanitize\|escape\|validate\|filterText\|profanity' /tmp/hbc_disasm.txt | head -20

# WebView bridge security
grep -n 'postMessage\|origin' /tmp/hbc_disasm.txt | grep 'String:' | head -30

# Full function dump with string references
grep -n -A 200 'Function #XXXX "functionName"' /tmp/hbc_disasm.txt | grep 'String:'
```

## fitness app Findings

### Cloud Functions Discovered (19+)
`checkUsernameAvailability`, `openaiProxy`, `sendEmailOTP`, `verifyEmailOTP`, `checkAffiliateCode`, `createUserReferral`, `checkUserReferralCode`, `submitAffiliateApplication`, `finalizeExpiredChallenges`, `assignValentineGiftCode`, `validateGiftOfferRedemption`, `markGiftOfferRedeemed`, `markValentineGiftShared`, `recordAffiliateInstall`, `stravaRequestToken`, `stravaToken`, `stravaDisconnect`, `stravaCreateActivity`, `garminRequestToken`, `garminAccessToken`, `garminDisconnect`, `garminActivities`, `getRevenueCatMetrics`

### createPost Flow
1. Validates auth: `typedAuth`, `currentUser`, `getIdToken`
2. Reads: `userName`, `userUsername`, `content`, `postType`, `visibility`
3. Validates username: `trim()` → `normalizeUsername()` (toLowerCase, replace spaces/substring) → `isValid()` (regex test with `USERNAME.ALLOWED_CHARS`)
4. Extracts hashtags via `matchAll` regex on content
5. Creates Firestore doc with: `content`, `postType`, `visibility`, `likes`, `likedBy`, `comments`, `views`, `hashtags`, `mentions`, `searchNormalizedText`, `searchTerms`, `searchPrefixes`
6. Calls `updateUserStreak`, `notifyStreakUpdate`
7. **NO HTML/JS sanitization on post content** — only username is validated

### XSS Surface Analysis
- `dangerouslySetInnerHTML`: 5 occurrences in 3 internal components:
  1. dialog/formTitle (branding HTML)
  2. successMessageText (success notifications)
  3. editor (text editor with styleNonce)
- NOT used for post content rendering
- React Native `Text` renders as plain text by default
- WebView only used for 3D globe (club visualization), NOT post content
- **postMessage with origin `'*'`** in WebView bridge — any origin can communicate with the WebView

### Auth Checks in deletePost
- Verifies authentication: `Usuário não autenticado` error
- Verifies ownership: `postOwnerId === uid` OR `checkAdminAccess(uid)`
- Error message: `Você não tem permissão para deletar este comentário`

### Key Security Concerns (Require Auth Bypass)
1. `openaiProxy` — potential OpenAI credit drain
2. `sendEmailOTP` — email flooding
3. `checkUsernameAvailability` — username enumeration
4. `checkAffiliateCode` — affiliate code enumeration
5. `finalizeExpiredChallenges` — challenge manipulation
6. Gift code functions — potential unauthorized redemption
7. Strava/Garmin OAuth — token theft via manipulated OAuth flow
8. Content injection — posts stored without sanitization
9. WebView postMessage origin wildcard — cross-origin communication
