# [seed] Bypassing OkHttp SSL pinning in an APK with Frida

## Scenario category
APK reverse engineering / mobile security testing

## Target overview
For an Android app using OkHttp plus a custom CertificatePinner, bypass certificate validation dynamically with Frida so Burp can see cleartext traffic.

## Full execution chain

1. Install Frida and frida-server, launch the target app, confirm the process name
   ```bash
   adb shell "ps -A | grep com.target.app"
   frida-ps -U | grep target
   ```
2. Try intercepting with Burp → a certificate error confirms pinning is enabled
3. Decompile the APK in jadx → search for `CertificatePinner` or `checkServerTrusted`
4. Determine whether it is OkHttp's built-in `CertificatePinner` or a custom `X509TrustManager`
5. Write a Frida script hooking the key validation points
6. Inject with Frida: `frida -U -f com.target.app -l bypass.js --no-pause`
7. Intercept again → Burp now sees cleartext HTTPS

## Pitfalls encountered

| Problem | Cause | Fix | Time lost |
|------|------|---------|------|
| Frida fails with `unable to connect to remote frida-server` | Server not running, or the port is taken | `adb forward tcp:27042 tcp:27042`, then start the server | 10min |
| Hooks do not take effect | The app starts too fast and Frida injects too late | Use spawn mode via `-f` together with `--no-pause` | 15min |
| Some requests still fail with SSL errors after hooking | The app uses both OkHttp and the native HttpsURLConnection | Also hook `X509TrustManager.checkServerTrusted` and `HostnameVerifier.verify` | 20min |
| Anti-analysis: the app exits once it detects Frida | The app checks the frida-server port and `/data/local/tmp/re.frida.server` | Switch to frida-gadget (inject the .so into the APK) or magisk + zygisk-frida | 30min+ |
| Class names cannot be found after ProGuard obfuscation | Class names are shortened to forms like `a.b.c` | Use `Find Usages` in jadx to trace back who instantiates OkHttpClient.Builder | 25min |

## Toolchain findings

- **objection** has a built-in `android sslpinning disable` that covers 80% of cases in one command, with no Frida script to write
- **frida-multiple-unpinning** (GitHub: WithSecureLabs) is a catch-all script covering OkHttp 3/4, Retrofit, HttpsURLConnection, Conscrypt and Cordova
- The **MEDUSA** framework ships assorted Android bypass modules and is quicker to pick up than raw Frida

## Key code and commands

Minimal working OkHttp pin bypass script:

```javascript
Java.perform(function () {
    // 1. OkHttp 3/4 built-in CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peers) {
            console.log('[+] OkHttp CertificatePinner.check bypassed: ' + host);
            return;
        };
    } catch (e) {}

    // 2. Custom X509TrustManager.checkServerTrusted
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrusted, holdHost, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed: ' + host);
            return untrusted;
        };
    } catch (e) {}

    // 3. Make HostnameVerifier always pass
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    // Fill in the rest from objection's own template...
});
```

One-shot command (recommended):

```bash
objection --gadget com.target.app explore -s "android sslpinning disable"
```

## Suggested improvements to this pack

- `apk-reverse/references/` should have a dedicated `ssl-pinning-bypass.md` consolidating the four mainstream cases (OkHttp 3/4, Conscrypt, custom TrustManager, Flutter/boringssl) into one quick reference
- Add `objection` (a pip package) to the bootstrap manifest

## Reusable patterns and script fragments

**General bypass workflow:**

```text
1. Intercept traffic → identify the error class (CertPin / Hostname / TrustManager)
2. Search jadx for the key classes (CertificatePinner / X509TrustManager / HostnameVerifier)
3. Try objection's one-liner first → then frida-multiple-unpinning → then hand-write a script
4. If anti-Frida detection is present → switch to frida-gadget or zygisk
5. Handle Flutter apps separately (hook `ssl_verify_peer_cert` in libflutter.so)
```

## Follow-up actions
- [x] Covered by the routing matrix (apk-reverse + Frida)
- [x] frida status checked in the tool index
- [ ] Suggest adding an ssl-pinning-bypass.md quick reference

## Environment
- Kali / Windows + adb + frida-tools 16.x
- Target Android: 8-14 (the TrustManagerImpl path differs by version)
- Injection method: USB debugging + frida-server, or hidden via zygisk-frida

## Anonymization note
This entry is seed data written from publicly known technique patterns; no real target is involved. The package name `com.target.app` is a placeholder.
