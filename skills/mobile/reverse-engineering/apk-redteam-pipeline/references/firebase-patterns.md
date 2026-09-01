# Firebase Patterns — fitness app Case Study

## Cloud Function Calling Convention

fitness app uses Firebase Callable Functions. Wrap all params in `{"data": {...}}`. Direct params without `data` wrapper return 400 INVALID_ARGUMENT.

## Discovered Cloud Functions

| Function | Auth | Key Params | Notes |
|----------|:---:|---|---|
| checkUsernameAvailability | Yes | username | Returns available: bool |
| openaiProxy | Yes | model, messages | All OpenAI models accessible |
| sendEmailOTP | Yes | email | 1/min rate limit |
| verifyEmailOTP | Yes | email, code | "Codigo invalido" on wrong code |
| assignValentineGiftCode | Yes | (none) | Returns static iOS gift code |
| markValentineGiftShared | Yes | code | Returns ok: true |
| storeInstallFingerprint | **No** | code | Unauthenticated |

## openaiProxy Details

Working models: gpt-3.5-turbo, gpt-4, gpt-4-turbo, gpt-4o. Rate limit: ~10 rapid requests then 429. No per-user daily cap observed. System prompt injection possible via messages array with role: "system".

## Firestore PATCH Creates Documents

PATCH on a non-existent document creates it. Useful for profile creation when app's normal flow hasn't created the user document yet.

## Firebase Auth Delete — No Cascade

`POST /v1/accounts:delete` removes the Auth record but ALL Firestore data persists: users/{uid}, posts, comments, likes, followers, Algolia indices. GDPR Article 17 / LGPD violation. Requires fresh token (CREDENTIAL_TOO_OLD_LOGIN_AGAIN if stale).

## System Prompts in Bundle

Personal Trainer AI: "You are a concise, knowledgeable personal trainer AI assistant..."
Nutritional Assistant: "You are a specialized nutritional assistant. Return ONLY CSV format..."
Medical Disclaimer (PT): "Voc e o unico responsavel por decidir se as recomendacoes..."
Liability Waiver (PT): "Voc e responsavel por escolher cargas, equipamentos e ambiente seguros..."

## Key Attack Vectors

1. OpenAI Cost Abuse: gpt-4 + 4000 tokens = ~$0.30/request, no rate limits
2. Email Spam: sendEmailOTP to any address, 1/min per user
3. Email Duplication: multiple auth accounts per email, no uniqueness enforcement
4. Incomplete Deletion: Firestore data persists after auth deletion
