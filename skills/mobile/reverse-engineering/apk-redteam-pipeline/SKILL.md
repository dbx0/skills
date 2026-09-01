---
name: apk-redteam-pipeline
description: End-to-end Android APK red-team pipeline — automated APK acquisition (Play Store + apkpure + apkmirror fallback), jadx decompilation, secret/URL/JWT/Firebase grep, pinned-cert extraction, exported-component enumeration, Frida runtime instrumentation templates, intent-injection probes. Built from an authorized external red-team engagement where 7 APKs were pulled manually, 4 download download attempts truncated, and a hardcoded JWT + 30 internal API endpoints were recovered from one of the apps. Use when target has a mobile app catalogue (Play Store developer page), when you find an APK URL hosted on a web server, or when post-recon mentions "mobile app" in scope.
---

# APK Red-Team Pipeline

## Overview

End-to-end pipeline for Android APK security testing: acquisition → decompilation → secret extraction → runtime analysis.

## Phase 1: Acquisition

```bash
# Primary: apktool dump
apktool d target.apk -o /tmp/apk_out --no-res

# Fallback sources: apkpure, APKMirror, Play Store (via gplaycli)
```

### Reliable acquisition without a device — use `apkeep` (not raw apkpure URLs)

The apkpure *direct-download* endpoint (`d.apkpure.com/b/APK/<pkg>`) returns an **XAPK bundle whose
zip central directory is malformed** — `unzip`/python `zipfile` reject it ("File is not a zip
file"), and the inner base APK 7z-extracts corrupt. Do not fight it. Use **apkeep** (EFF), a single
static binary that yields clean APKs:

```bash
# one-time: grab the release binary
curl -L https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-unknown-linux-gnu -o apkeep && chmod +x apkeep
# download from apkpure (no Google auth needed):
./apkeep -a com.example.app -d apk-pure .
#   -> com.example.app.apk  (valid zip; verify: python3 -c "import zipfile;zipfile.ZipFile('...').namelist()")
```
For split APKs (`split_config.*.apk`) apkeep fetches the set; merge or analyze each. Play-Store
source (`-d google-play`) needs an AAS token; apkpure needs nothing and is enough for static analysis.

<!-- xapk-note-end -->
```

## Phase 2: Static Analysis

### Secret Extraction
```bash
# Firebase config
grep -r "AIzaSy" /tmp/apk_out/ 2>/dev/null
grep -r "google_api_key|firebase" /tmp/apk_out/res/ 2>/dev/null
grep -r "Algolia|revenuecat|sentry" /tmp/apk_out/ 2>/dev/null

# Check app.config (Expo apps)
cat /tmp/apk_out/assets/app.config 2>/dev/null

# Network security config
cat /tmp/apk_out/res/xml/network_security_config.xml 2>/dev/null
```

### Framework Detection (BEFORE secret extraction)

Determine the framework first — the analysis approach differs significantly:

**React Native (Expo):**
- Look for `assets/index.android.bundle` (Hermes bytecode)
- Check HBC version: `python3 -c "import struct; f=open('bundle','rb'); print(struct.unpack('<I',f.read(12),8)[0])"`
- Firebase keys are split/obfuscated in HBC v96+ (Expo SDK 52+)
- Use `hbctool` for HBC ≤ v76; use runtime Frida for v85+

**Flutter:**
- No Hermes bundle — Dart compiles to native ARM
- Main logic is in `lib/arm64-v8a/libapp.so` (large, 5-15MB)
- **String extraction:** `strings libapp.so | grep -iE "firebase|api_key|AIzaSy"`
- **Firebase keys are NOT in `libapp.so` as plaintext** — they're stored in `resources.arsc` as truncated values (e.g., `AIzaSy...V8b8`)
- Use `aapt dump --values resources base.apk` to extract resource strings
- Split APKs (`split_config.*.apk`) contain the native libs and resources — check them too
- Flutter apps use standard Android networking (OkHttp) — no certificate pinning unless explicitly implemented
- Look for `libflutter.so`, `libapp.so`, `libdartjni.so` as confirmation

**Native (Kotlin/Java):**
- Standard DEX bytecode — use jadx for full decompilation
- Firebase keys may be in `res/values/strings.xml` or `google-services.json`
- Check for ProGuard/R8 obfuscation

### Flutter-Specific API Endpoint Extraction

```bash
# Extract all API endpoints from Flutter native library
strings lib/arm64-v8a/libapp.so | grep -E "^/api/|^/v[0-9]/" | sort -u

# Extract URLs/domains
strings lib/arm64-v8a/libapp.so | grep -E "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u

# Extract Firebase config from split APK resources
aapt dump --values resources split_config.arm64_v8a.apk 2>/dev/null | grep -A2 "google_app_id\|google_api_key\|firebase_database\|project_id\|gcm_defaultSender\|google_storage"
```

**Critical:** Expo SDK 52+ fully obfuscates Firebase API keys. The key is NOT stored as a contiguous string in the Hermes bytecode (HBC v96). Extraction methods:

1. **Check `app.config`** — truncated key shown as `AIzaSy...sMBc`
2. **Check `resources.arsc`** — `aapt dump strings` shows shortened key
3. **Hermes bytecode (HBC v96)** — NOT supported by hbctool (max v76). The key is split/obfuscated at compile time.
4. **Runtime extraction** (requires Frida):
   ```javascript
   Java.perform(function() {
     var FirebaseOptions = Java.use("com.google.firebase.FirebaseOptions");
   });
   ```
5. **Network interception** — mitmproxy with custom CA cert to capture signup request URL containing the key
6. **`/tmp/fkey.txt`** — check if key was previously extracted and stored locally. Read as raw bytes: `open("/tmp/fkey.txt", "rb").read().strip().decode("ascii")`. A key with literal `...` IS the actual key — do NOT assume it is truncated.

**If key is obtained:** Save to `/tmp/fkey.txt` for future sessions.

### Hermes Bytecode Analysis
```bash
# Check HBC version
python3 -c "
import struct
with open('/tmp/apk_out/assets/index.android.bundle', 'rb') as f:
    print('Version:', struct.unpack_from('<I', f.read(12), 8)[0])
"

# String extraction (HBC v59-76 only)
hbctool disasm /tmp/apk_out/assets/index.android.bundle /tmp/hbc_disasm.txt
grep -i "firebase|api_key|algolia|revenuecat" /tmp/hbc_disasm.txt

# For HBC v85+ (Expo SDK 50+): use hermes_dec
python3 -c "
import sys; sys.path.insert(0, '/home/bx0/.hermes/hermes-agent/venv/lib/python3.11/site-packages')
from hermes_dec.decompilation.hbc_disassembler import do_disassemble
do_disassemble('/tmp/apk_out/assets/index.android.bundle')
" 2>&1 | grep -i "firebase|api_key"
```

## Phase 3: Cloud Function Discovery

From disassembly, look for function names in string tables. Common patterns: `checkUsernameAvailability`, `openaiProxy`, `sendEmailOTP`, `verifyEmailOTP`, `assignValentineGiftCode`, `storeInstallFingerprint`, etc.

**Firebase callable function format:** `{"data": {"param": "value"}}`

Probe the same surface for gift-code abuse, incomplete account deletion, and report spam.

## Phase 4: Authentication

```python
import json, urllib.request, urllib.error

FIREBASE_KEY = open("/tmp/fkey.txt").read().strip()

result = urllib.request.urlopen(
    urllib.request.Request(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_KEY}",
        data=json.dumps({"email": "user@test.com", "password": "Pass123!", "returnSecureToken": True}).encode(),
        headers={"Content-Type": "application/json"}
    )
)
token = json.loads(result.read())["idToken"]
```

## Phase 5: Runtime Testing (Frida)

See `references/frida-templates.md` for instrumentation scripts.

## Exported-Component Authz Sinks (beyond intent-injection)

Enumerating exported components is not enough — read what the exported activity *does* with
attacker-controlled extras. The highest-value Android authz bug is the **confused deputy**:

- An `activity`/`service` with `android:exported="true"`, **no `android:permission`**, and often
  **no intent-filter** (a blanket export just to satisfy Android 12's explicit-export rule).
- It reads an attacker-controlled extra — especially a **nested `Intent`** (`getParcelableExtra`) or
  a `content://` URI — and acts on it under the victim app's own permissions.
- **Look for the wrong permission-check API**: `context.checkCallingOrSelfUriPermission(uri, ...)`
  (or `checkCallingOrSelfPermission`) evaluates the *victim app's own* uid when there is no active
  Binder transaction (e.g. from a `LiveData` observer on the main thread). It answers "can I read
  this?" not "could the caller?" — so a zero-permission app can hand the victim a `content://` URI
  it cannot itself read and have the victim read it under its permissions and act on it (send it,
  upload it). The correct API is `checkCallingUriPermission` / validating `getCallingPackage()`.

Grep the decompiled sources:
```bash
grep -rn "checkCallingOrSelf\|getParcelableExtra\|getCallingActivity\|FLAG_GRANT_READ_URI" sources/
```
PoC discipline: `adb shell am start` is NOT a valid impact proof — the shell uid holds permissions a
real malicious app would not. Demonstrate from a **zero-permission** PoC app whose manifest declares
no permissions (include an on-screen negative control proving the PoC itself cannot read the URI).

## Pitfalls

- **Expo SDK 52+ (HBC v96):** Firebase keys are NOT extractable from bytecode alone. Use runtime hooking or network interception.
- **Callable functions:** Use `{"data": {...}}` wrapper, not flat params.
- **Rate limits:** Most cloud functions rate-limit after ~10-20 requests/min.
- **Firestore rules:** Read access is open for authenticated users (common misconfiguration).
- **PATCH creates documents:** When POST/create returns 403, PATCH may still create the document successfully.
- **Key with `...` is real:** A Firebase API key containing literal ellipsis characters IS the actual key. Don't assume it's truncated.
- **Email duplication:** Firebase Auth allows multiple accounts with the same email when "One account per email" is disabled. Both get valid idTokens and full API access.
- **Account deletion is incomplete:** `accounts:delete` removes the auth record but NOT Firestore data (posts, comments, likes, followers, etc.). This is a GDPR/LGPD violation.
- **React Native Text is safe:** XSS in post content does NOT render in the app's `<Text>` components. Only exploitable in WebView/email/notification contexts.
- **Flutter Firebase keys:** In Flutter apps, the Firebase API key is stored in `resources.arsc` as a truncated value (e.g., `AIzaSy...V8b8`). The full key is NOT in `libapp.so` as a plaintext string. Runtime extraction (Frida) or network interception is required to obtain the full key. Do NOT assume the key is missing — it's obfuscated at the resource level.
- **Flutter string extraction:** Use `strings` on `libapp.so` for API endpoints and URLs. jadx decompilation of Flutter apps produces mostly framework code — the interesting strings are in the native binary, not the DEX.
