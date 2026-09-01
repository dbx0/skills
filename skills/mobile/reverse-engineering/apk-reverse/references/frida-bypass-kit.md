# Frida Bypass Kit — Android General-Purpose Security Bypass Framework

> Source: [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) (2025)
> Applicable scenario: bypassing root detection, SSL pinning, emulator detection, and anti-debugging during APK dynamic analysis

## Overview

FridaBypassKit is a Frida script that integrates four major bypass capabilities. It requires no app-specific customization and works out of the box.

## Four Major Bypass Capabilities

### 1. Root Detection Bypass

- Hook `File.exists()` to hide the su binary
- Intercept root-check calls to `Runtime.exec()`
- Hide root-related packages (Magisk, SuperSU, etc.) from PackageManager
- Modify system properties to make the device appear unrooted

### 2. SSL Pinning Bypass

- Hook `TrustManagerImpl.verifyChain()`
- Hook `TrustManagerImpl.checkTrustedRecursive()`
- Bypass certificate chain validation
- Return an empty certificate chain to avoid verification
- Compatible with OkHttp, Retrofit, and custom implementations

### 3. Emulator Detection Bypass

- Spoof TelephonyManager return values
- Return fake phone numbers and carrier names
- Modify Build properties

### 4. Anti-Debugging Bypass

- Hook `Debug.isDebuggerConnected()`
- Prevent debugger detection
- Bypass anti-debugging checks

## Usage

```bash
# Prerequisites
pip install frida-tools
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c /data/local/tmp/frida-server &

# Inject the target app
frida -U -f com.example.app -l FridaBypassKit.js
```

## Other Recommended Frida Bypass Scripts

| Project | Features | Link |
|------|------|------|
| httptoolkit/frida-interception-and-unpinning | Directly MitM all HTTPS traffic | [GitHub](https://github.com/httptoolkit/frida-interception-and-unpinning) |
| 0xCD4/SSL-bypass | General non-custom SSL bypass | [GitHub](https://github.com/0xCD4/SSL-bypass) |
| incogbyte/ssl-bypass gist | Bypass common SSL pinning methods | [Gist](https://gist.github.com/incogbyte/1e0e2f38b5602e72b1380f21ba04b15e) |
| Zero3141/Frida-OkHttp-Bypass | Specifically targets OkHttp CertificatePinner | [GitHub](https://github.com/Zero3141/Frida-OkHttp-Bypass) |

## Integration With This Package

In the `apk-reverse` workflow, use this when encountering the following situations:

1. The app detects root and refuses to run → enable Root Detection Bypass
2. HTTPS requests show no cleartext during capture → enable SSL Pinning Bypass
3. The app detects an emulator and refuses to run → enable Emulator Detection Bypass
4. The app crashes after attaching Frida → enable Debug Detection Bypass

Recommended combined usage: run the full FridaBypassKit first, then adjust as needed.
</content>
