---
name: apk-reverse
description: Use when reverse engineering Android APKs in a CLI environment. Applies to APK unpacking, Java decompilation, smali modification, repackaging, Frida dynamic hooking, and switching to so/native analysis as needed. Prefer the locally installed jadx, apktool, frida, adb, ida-reverse, radare2.
---

# APK Reverse Engineering CLI Working Guide

## Scope

Prefer this skill when the task falls into the following scenarios:

- Analyzing the Java business logic of an APK
- Locating login, signing, risk control, certificate validation, root detection
- Viewing and modifying `AndroidManifest.xml`
- Viewing and modifying smali
- Repackaging an APK
- Java/native dynamic hooking with Frida
- Switching to native analysis when the APK contains `.so`

## CLI Tools Verified Available on the Current Machine

- `jadx` `1.5.5`
- `apktool` `3.0.2`
- `frida-ps` `17.9.6`
- `adb`
- `java`

## Scenarios Where Scripts Are Preferred

The following workflows are high-frequency and error-prone in their parameters, so prefer the scripts bundled with this skill:

- Run `jadx + apktool` end to end and produce a summary in one shot: `scripts/decode.ps1`
- Frida device check, process enumeration, spawn/attach injection: `scripts/frida-run.ps1`
- Rebuild, align, sign, install APK: `scripts/rebuild-sign-install.ps1`
- Quickly extract key Manifest components and permissions: `scripts/manifest-summary.ps1`

The following one-line commands stay as direct calls and are not wrapped separately:

- `adb devices`
- `adb logcat`
- `frida-ps -U`
- `jadx --version`
- `apktool --version`

## Bundled Scripts

### `scripts/decode.ps1`

Purpose:

- Run `jadx` and `apktool` uniformly
- Create a task output directory in the same directory as the original APK by default
- Output a summary of `package`, `java_files`, `smali_dirs`, `so_files`, etc.
- Handle cases where `jadx` has partial decompilation errors but still produces usable artifacts

Examples:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Name demo -SkipJadx
```

### `scripts/frida-run.ps1`

Purpose:

- Unify Frida device, process, and spawn/attach entry points
- Avoid confusing `-f`, `-n`, `-U` when writing parameters by hand

Examples:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -ListDevices
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -ListProcesses
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -Spawn -Package com.example.app -ScriptPath "D:\hooks\test.js"
```

### `scripts/rebuild-sign-install.ps1`

Purpose:

- `apktool b` to rebuild the APK
- `zipalign` for alignment
- `apksigner` for signing and signature verification
- Optionally `adb install` directly

Examples:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Install -Reinstall -DeviceSerial "127.0.0.1:7555"
```

Notes:

- Generates and reuses a debug keystore by default
- Outputs to the same directory as `ProjectDir` by default, making it convenient to keep alongside the original package and the unpacked directory

### `scripts/manifest-summary.ps1`

Purpose:

- Extract the package name
- List permissions
- List activity/service/receiver/provider
- Flag the main launcher activity

Example:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\manifest-summary.ps1" -ManifestPath "C:\work\apktool_out\AndroidManifest.xml"
```

If you need to analyze `.so`, `lib/arm64-v8a/*.so`, `lib/armeabi-v7a/*.so`, then combine with:

- `ida-reverse`
- `radare2`

## Tool Roles

### `jadx`

Used for:

- Reading Java decompilation
- Searching package names, class names, method names
- Understanding the APK from high-level logic first

Common commands:

```bash
jadx -d jadx_out app.apk
jadx --single-class com.example.LoginActivity -d jadx_out app.apk
jadx --deobf -d jadx_out app.apk
```

### `apktool`

Used for:

- Unpacking the APK
- Viewing and modifying `AndroidManifest.xml`
- Viewing and modifying smali
- Rebuilding the APK

Common commands:

```bash
apktool d app.apk -o apktool_out
apktool b apktool_out -o rebuilt.apk
```

### `frida`

Used for:

- Dynamically observing Java method calls
- Hooking native exported functions
- Bypassing root detection, certificate validation, debugger detection

Common commands:

```bash
frida-ps -U
frida -U -f com.example.app -l hook.js
frida-trace -U -f com.example.app -j '*!*certificate*'
```

### `adb`

Used for:

- Device connection
- Installing APKs
- Viewing logs
- Pulling files

Common commands:

```bash
adb devices
adb install -r app.apk
adb shell pm list packages
adb logcat
adb pull /data/local/tmp/file .
```

## Recommended Workflow

### 1. Triage

Determine the rough composition of the APK first, without rushing to modify the package or hook.

Suggested actions:

1. Export Java code with `jadx -d jadx_out app.apk`
2. Export smali and resources with `apktool d app.apk -o apktool_out`
3. Look first at:
   - `AndroidManifest.xml`
   - The main `package`
   - `application`, `activity`, `service`, `receiver`
   - Whether there is `.so` in the `lib/` directory

### 2. Java Logic Observation

Read from `jadx_out` first:

- `MainActivity`
- `Application`
- Classes related to login, network, encryption, risk control
- Third-party SDK initialization classes

Common keywords:

- `login`
- `sign`
- `encrypt`
- `cipher`
- `token`
- `root`
- `certificate`
- `trust`
- `okhttp`
- `retrofit`
- `webview`

If the Java code is readable, locate the business logic here first.

### 3. Smali and Resource Layer Confirmation

When the `jadx` result is incomplete, heavily obfuscated, or an actual patch is needed, switch to `apktool_out`:

- Look at `smali*/`
- Look at `res/values/strings.xml`
- Look at `AndroidManifest.xml`

Priority patch targets:

- `android:exported`
- Debug flags
- Root detection return values
- Login validation logic
- Certificate validation branches

### 4. Rebuild and Install

After modification:

```bash
apktool b apktool_out -o rebuilt.apk
```

Or close the loop directly with the script:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "apktool_out" -Install -Reinstall -DeviceSerial "127.0.0.1:7555"
```

Notes:

- This skill only guarantees the `apktool` rebuild chain
- If you later need to formally install to a device, a signing flow is usually also required
- If the task moves into signing/alignment, add `apksigner` / `zipalign`

### 5. Dynamic Hooking

When static analysis is insufficient, use Frida:

- Hook the login function
- Hook key points of `OkHttp` / `Retrofit` / `WebView`
- Hook `javax.crypto`, `MessageDigest`
- Hook root detection functions
- Hook SSL pinning logic

Principles:

- Hook the Java layer first, then see whether native hooking is needed
- Print parameters and return values first, then decide whether to actively modify the return value

Suggestions:

- Use `frida-*` directly for simple one-off commands
- Prefer `scripts/frida-run.ps1` for injection flows that need stable reuse

### 6. Native `.so` Triage

If the APK contains critical `.so`:

- Use `apktool` or `jadx` to find `lib/**/*.so`
- For just exporting symbols, strings, or quick triage, use `radare2`
- For long-term deep analysis, decompilation, renaming, or type recovery, use `ida-reverse`

Switch to native as soon as you hit these signals:

- The Java layer is just a JNI wrapper
- The core signing logic is not in Java
- Key logic disappears after `System.loadLibrary()`
- Certificate validation/risk control is in the `.so`

## Output Requirements

At minimum, state the following in the end:

- Entry components and key classes
- Whether the key logic is in Java, smali, or `.so`
- Confirmed sensitive points: login, signing, root, SSL, WebView, JNI
- If a patch was made, describe what was changed
- If a hook was made, describe which class/method/exported function was hooked

## Prohibitions

- Do not blindly modify smali at the very start
- Do not write hooks before looking at the manifest and main entry point
- Do not equate incomplete Java decompilation directly with "the logic cannot be analyzed"
- Do not keep grinding on the Java layer when the `.so` clearly carries the core logic

## Quick Command Cheat Sheet

```bash
# Decompile Java
jadx -d jadx_out app.apk

# Unpack APK
apktool d app.apk -o apktool_out

# Rebuild APK
apktool b apktool_out -o rebuilt.apk

# Devices and processes
adb devices
frida-ps -U

# Spawn and inject
frida -U -f com.example.app -l hook.js
```

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (master control), `routing.md`
**Downstream exits**:
- Core logic in `.so` → `ida-reverse/` or `radare2/`
- Need dynamic hooking/validation → `reverse-engineering/tools-dynamic.md` (Frida section)
- General reverse engineering methodology → `reverse-engineering/SKILL.md`

**Peer-level related modules**: `reverse-engineering/` (.so analysis and advanced Frida usage)

---

## On-Demand Bootstrap

This skill's entry scripts are wired into the unified bootstrap system. When a tool is missing, it does not error out directly but automatically attempts installation.

### Automation Capability Boundaries

| Tool | Auto-installable | Installation Method | Notes |
|------|-----------|---------|------|
| jadx | ✓ | GitHub Release ZIP | Auto-download and extract to `%USERPROFILE%\Tools\jadx\` |
| apktool | ✓ | GitHub Release JAR + wrapper | Auto-download jar and generate bat to `%USERPROFILE%\Tools\apktool\` |
| frida / frida-ps | ✓ | pip install frida-tools | Requires Python already installed |
| adb | ✓ | winget / fallback path | Auto-install Android Platform-Tools |
| zipalign | ✗ | Requires manual install of Android Build-Tools | `sdkmanager "build-tools;35.0.0"` |
| apksigner | ✗ | Requires manual install of Android Build-Tools | Same as above |

### Bootstrap Trigger Points

- `scripts/decode.ps1`: automatically calls `bootstrap-reverse.ps1` when jadx or apktool is missing
- `scripts/rebuild-sign-install.ps1`: automatically calls bootstrap when adb or apktool is missing
- `scripts/frida-run.ps1`: still a manual check for now (frida is usually already installed via pip)

### When Bootstrap Fails

If auto-installation fails, the script throws a clear error with a manual installation link. Common causes:
- No network connectivity (GitHub API / PyPI unreachable)
- winget unavailable (Windows version too old)
- Java not installed (apktool depends on the JDK)
</content>
</invoke>

---

## Addendum — defeating repeating-XOR string obfuscation

*(field_recon: fintech Android app — recovered intent extras, deeplink templates and API paths that appear nowhere in plaintext)*

Commercial obfuscators replace string literals with `pNNN.C$.$("<garbage>")`. `strings` and
plaintext grep find nothing, so the app's real intent actions, extras and URL templates look absent.

Recover them statically — no device, no Frida.

### The shape

```java
// pNNN.C$  — the decoder
public static String $(String s) {
    byte[] k = pMMM.C$.$();            // key provider
    char[] c = s.toCharArray();
    for (int i = 0; i < c.length; i++)
        c[i] = (char)(c[i] ^ (k[i % k.length] & 255));
    return new String(c);
}

// pMMM.C$  — key built by XOR-ing TWO byte arrays from separate classes
public static final byte[] $ = { (byte)51, (byte)73, ... };
public static byte[] $() {  /* XOR of $ with pXXX.C$.$ */  }
```

Each decoder package has its **own** key, so resolve the chain per package.

### Two gotchas that will silently corrupt output

**1. Don't scrape byte values from the whole class file.** The key-builder loop contains
`(byte) 0` literals in its ternaries. Regexing every `(byte) N` in the file appends spurious
zeros, inflating a 16-byte key to 18 — decoding is then correct for exactly the first 16
characters and garbage after. Parse **only the array initializer**:

```python
m = re.search(r"byte\[\]\s+\$?\w*\s*=\s*\{(.*?)\}", src, re.S)
vals = re.findall(r"\(byte\)\s*\(?\s*(-?\d+)\s*\)?", m.group(1))
```

The symptom is distinctive: `nuapp://samsung-` then noise. Sixteen good characters means a
length bug, not a wrong key.

**2. Parse Java string literals properly.** jadx emits real UTF-8 characters *and* `\uXXXX`
escapes in the same literal. Python's `unicode_escape` decodes via latin-1 and mangles the
non-ASCII half. Expand escapes manually and leave everything else alone.

Sanity-check against a known value — decoding `"UTF-8"` correctly proves key and parser together.

### Targeting

Decompile one class at a time rather than the whole APK:

```bash
jadx -j 4 --single-class 'br.com.app.SomeActivity' -d /tmp/out app.apk
```

Then decode every `pNNN.C$.$("...")` in that file. Working script:
`deobf_xor_strings.py` (alongside this skill) — resolves decoder→key chains, caches keys, and
decodes a whole decompiled file.

### What it yields

From one exported activity, previously invisible:

```
action    : android.intent.action.Pix
extra key : PIX_DATA                       (String, capped at 8192)
deeplink  : nuapp://bdc/moises/expr/transfer-out.qrcode?qrcode=<INPUT>
            &initiation-type=samsung-camera&initial-route=parse
alt path  : nuapp://samsung-pix?qrcode=<URLEncoded INPUT>
```

That is the entire attack surface of an exported, permission-less activity — the extra name to
fuzz, the template the input lands in, and whether encoding is applied (there, behind a **remote
feature flag**, so the safe behaviour was a runtime setting rather than a code guarantee).
