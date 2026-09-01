# Flutter APK Analysis — example-auto.tld Case Study

## App Details
- **Package:** `media.car.app` v1.0.2 (versionCode 8)
- **Framework:** Flutter (Dart → native ARM)
- **Target SDK:** 36 (Android 16)
- **Min SDK:** 24 (Android 7.0)

## Architecture

### APK Structure
- `base.apk` (8.7MB) — Main code + resources
- `split_config.arm64_v8a.apk` (36MB) — Native libraries (libflutter.so, libapp.so, libssl.so, etc.)
- `split_config.pt.apk` (33KB) — Portuguese resources
- `split_config.es.apk` (33KB) — Spanish resources
- `split_config.xxhdpi.apk` (198KB) — xxhdpi assets

### Key Files
- `lib/arm64-v8a/libapp.so` (7.9MB) — Main Dart compiled binary
- `lib/arm64-v8a/libflutter.so` (11.6MB) — Flutter engine
- `lib/arm64-v8a/libssl.so` / `libcrypto.so` — OpenSSL
- `lib/arm64-v8a/libjingle_peerconnection_so.so` — WebRTC
- `res/values/strings.xml` — Resource strings (Firebase config truncated)

## What Worked

### API Endpoint Extraction
```bash
# This was the most effective technique — extracted 34+ endpoints
strings /tmp/apk_libs/lib/arm64-v8a/libapp.so | grep -E "^/api/|^/v[0-9]/" | sort -u
```

### Firebase Config Extraction
```bash
# From split APK resources (truncated key)
aapt dump --values resources split_config.arm64_v8a.apk 2>/dev/null | grep -A2 "google_app_id\|google_api_key\|project_id"
# Result: project_id=carmedia-etnrlz, app_id=1:171888063838:android:97ecb68a212c5a448fcbcf
```

### Exported Components
```bash
aapt dump xmltree base.apk AndroidManifest.xml 2>/dev/null | grep -B5 -A5 "exported.*0xffffffff"
# Found: MainActivity, FlutterFirebaseMessagingReceiver, FirebaseInstanceIdReceiver, ProfileInstallReceiver
```

## What Didn't Work

### Firebase Key Extraction
- `strings libapp.so | grep AIzaSy` — No match (key not in native library)
- `grep -r "AIzaSy" split_*.apk` — No match in any split APK
- `aapt dump strings base.apk | grep AIzaSy` — Only truncated `AIzaSy...V8b8`
- The full key is obfuscated at the resource level — requires runtime extraction

### jadx Decompilation
- jadx produced mostly Flutter framework code — not useful for finding app-specific logic
- The interesting data (API endpoints, config) was in `libapp.so` strings, not DEX

## Findings Summary

| Finding | Severity | Technique |
|---------|----------|-----------|
| No certificate pinning | LOW | Smali grep for CertificatePinner/TrustManager |
| Firebase key truncated in resources | INFO | aapt dump --values resources |
| 34+ API endpoints in native lib | INFO | strings libapp.so |
| Email exposure via block API | MEDIUM | Authenticated API testing |
| No rate limiting on auth | LOW | Repeated login attempts |
| No email verification | LOW | Signup response analysis |
| Mass assignment protection | POSITIVE | PUT profile with extra fields |

## Tools Used
- `apktool d` — Resource extraction
- `jadx` — DEX decompilation (limited value for Flutter)
- `aapt dump` — Resource string extraction
- `strings` — Native binary string extraction
- `zipinfo` / `unzip -l` — APK structure analysis
