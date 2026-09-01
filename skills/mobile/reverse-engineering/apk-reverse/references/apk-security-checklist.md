# APK Security Testing Quick Reference

> Compiled based on the OWASP MASTG (Mobile Application Security Testing Guide).
> Covers six dimensions: static analysis, dynamic analysis, network communication, data storage, authentication/authorization, and code protection.

---

## Static Analysis Checklist

### Manifest Audit

```text
□ android:debuggable="true" → debuggable (should not appear in production)
□ android:allowBackup="true" → data can be backed up and extracted
□ Components with android:exported="true" → exposed Activity/Service/Receiver/Provider
□ Custom permission protectionLevel → is it normal (should be signature)
□ scheme in intent-filter → can the custom deeplink be hijacked
□ android:usesCleartextTraffic="true" → allows cleartext HTTP
□ minSdkVersion too low → may lack security features
```

### Key Points for Code Audit

```text
□ Hardcoded keys/tokens (search "key", "secret", "password", "api_key")
□ Insecure random numbers (java.util.Random instead of SecureRandom)
□ Insecure cryptography (ECB mode, DES, MD5 for passwords)
□ WebView configuration (setJavaScriptEnabled + addJavascriptInterface = RCE risk)
□ SQL injection (rawQuery concatenating user input)
□ Path traversal (ContentProvider's openFile not validating the path)
□ Log leakage (Log.d/Log.i outputting sensitive information)
□ Clipboard leakage (ClipboardManager storing sensitive data)
□ Implicit Intent leakage (sendBroadcast without specifying a package name)
```

### Third-Party Library Audit

```text
□ Outdated OkHttp/Retrofit versions (known vulnerabilities)
□ Outdated WebView core
□ SDKs with known vulnerabilities (check CVEs)
□ Ad SDK data collection scope
□ Push SDK configuration (whether it leaks tokens)
```

---

## Dynamic Analysis Checklist

### Priority Targets for Frida Hooking

| Target | Hook Point | Purpose |
|------|---------|------|
| Login authentication | `LoginActivity.login()` | Observe credential handling |
| Signature generation | `*Sign*`, `*sign*`, `*encrypt*` | Reconstruct the signing algorithm |
| SSL Pinning | `CertificatePinner.check` | Bypass to capture traffic |
| Root detection | `*root*`, `*su*`, `*magisk*` | Bypass detection |
| Encryption operations | `javax.crypto.Cipher` | Extract keys/IV |
| Token storage | `SharedPreferences.getString` | Observe token read/write |
| Network requests | `OkHttpClient.newCall` | Observe request construction |

### Common Frida One-Line Commands

```bash
# Trace all encryption operations
frida-trace -U -f com.target.app -j '*Cipher*!*'

# Trace all HTTP requests
frida-trace -U -f com.target.app -j '*OkHttp*!*'

# Trace SharedPreferences read/write
frida-trace -U -f com.target.app -j '*SharedPreferences*!*'

# Trace all native function calls
frida-trace -U -f com.target.app -i 'Java_*'
```

### Objection Quick Commands

```bash
# Connect
objection -g com.target.app explore

# Common commands
android hooking list activities
android hooking list services
android sslpinning disable
android root disable
android clipboard monitor
env                              # View the app directory
sqlite connect <db_path>         # Connect to the database
```

---

## Network Communication Security

### Traffic Capture Configuration

```text
Method 1: System proxy + Burp/mitmproxy
- Set the WiFi proxy → Burp listening address
- Install the CA certificate on the device
- Android 7+ requires network_security_config or a Frida bypass

Method 2: VPN mode (recommended)
- Use HttpCanary / Packet Capture
- No root needed, no proxy configuration needed
- But cannot decrypt SSL Pinning traffic

Method 3: Frida + r2frida
- Intercept network calls directly inside the process
- Not subject to proxy/VPN limitations
```

### Check Items

```text
□ Whether HTTPS is used (all API calls)
□ Whether SSL Pinning is present (certificate pinning)
□ Whether certificate validation is correct (does not accept self-signed)
□ Whether there is Certificate Transparency (CT) checking
□ Whether API keys are transmitted in cleartext in requests
□ Whether tokens have an expiration mechanism
□ Whether there is request signing for tamper protection
□ Whether there is replay attack protection (nonce/timestamp)
□ Whether WebSocket is encrypted
□ Whether sensitive data is in URL parameters (will be logged)
```

---

## Data Storage Security

### Locations to Check

| Location | Risk | Check Command |
|------|------|---------|
| SharedPreferences | Cleartext storage of token/password | `adb shell cat /data/data/pkg/shared_prefs/*.xml` |
| SQLite database | Unencrypted sensitive data | `adb pull /data/data/pkg/databases/` |
| External storage | Readable by any app | `adb shell ls /sdcard/Android/data/pkg/` |
| App logs | Leaked debug information | `adb logcat \| grep pkg` |
| Backup files | allowBackup=true | `adb backup -f backup.ab pkg` |
| Keyboard cache | Input history | Check whether `inputType` is `textPassword` |
| Screenshot protection | Sensitive pages can be screenshotted | Check `FLAG_SECURE` |

### Encrypted Storage Solution Comparison

| Solution | Security | Notes |
|------|--------|------|
| SharedPreferences cleartext | ❌ | Directly readable after root |
| EncryptedSharedPreferences | ✓ | AndroidX Security library |
| SQLCipher | ✓ | Encrypted SQLite |
| Android Keystore | ✓✓ | Hardware-level key protection |
| Custom AES encryption | ⚠️ | Depends on key management |

---

## Authentication and Authorization

### Common Vulnerabilities

| Vulnerability | Test Method |
|------|---------|
| Weak password policy | Try 123456, password, etc. |
| No lockout mechanism | Brute-force the login endpoint |
| Token does not expire | Replay the old token after logout |
| Broken access control | Modify the user_id in the request |
| SMS verification code brute-forceable | 4/6-digit numbers with no rate limit |
| OAuth misconfiguration | redirect_uri can be tampered with |
| Biometric authentication bypass | Hook BiometricPrompt |
| Device binding bypass | Modify device_id |

### Test Payloads

```bash
# Broken access control test
curl -H "Authorization: Bearer USER_A_TOKEN" \
     "https://api.target.com/users/USER_B_ID/profile"

# Token replay
# 1. Log in normally to obtain a token
# 2. Log out
# 3. Request with the old token → should return 401

# SMS verification code brute-force
for code in $(seq 0000 9999); do
    curl -X POST "https://api.target.com/verify" \
         -d "phone=13800138000&code=$code"
done
```

---

## Code Protection Assessment

| Protection Measure | Detection Method | Bypass Difficulty |
|---------|---------|---------|
| ProGuard obfuscation | Check in jadx whether class names are a/b/c | Low (just renaming) |
| String encryption | Find the decryption function, hook to get cleartext | Medium |
| Anti-debugging | Try to attach a debugger | Medium (Frida can bypass) |
| Root detection | Run on a rooted device | Medium (generic script bypass) |
| Emulator detection | Run on an emulator | Low-Medium |
| Integrity checks | Install after modifying the APK | Medium (patch the check function) |
| Packer/shell | Check the entry class and .so | Medium-High (requires unpacking) |
| Native protection | Core logic in .so | High (requires IDA analysis) |
| VMP virtualization | Code is executed virtualized | Extremely high |

---

## Quick Test Workflow (30 minutes)

```text
1. [5min] Unpack + Manifest audit
   apktool d app.apk
   Check debuggable/allowBackup/exported/cleartext

2. [10min] Quick code audit
   jadx -d out app.apk
   Search: password, key, secret, token, http://

3. [5min] Network test
   Configure the proxy → operate the app → check for cleartext/weak encryption

4. [5min] Storage check
   adb shell → check shared_prefs and databases

5. [5min] Dynamic verification
   Frida hook key functions → confirm findings
```
</content>
