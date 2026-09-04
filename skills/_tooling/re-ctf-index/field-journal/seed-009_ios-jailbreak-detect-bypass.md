# [Seed] iOS Jailbreak Detection Bypass + Traffic Capture

## Scenario Category
iOS reversing / mobile security testing

## Target Overview
An iOS app crashes on launch or displays "abnormal environment" on a jailbroken device. Jailbreak detection has to be bypassed before its HTTP requests can be analyzed further.

## Full Execution Chain

1. Prepare a jailbroken device (Dopamine / palera1n / unc0ver) → install frida-server (Cydia repo `build.frida.re`)
2. Copy the IPA onto the device, sign it with AppSync Unified → launch it and confirm `frida-ps -U` works
3. Launch the app → it crashes or pops "abnormal environment"
4. Run `frida-trace -U -i 'open' -i 'stat' -i 'access' -i 'fork' com.target.app` to observe the detection calls
5. Common hits: probing `/Applications/Cydia.app`, `/private/var/lib/apt`, `/usr/sbin/sshd`, whether `fork()` succeeds, `/etc/apt`
6. One-shot bypass with objection: `objection --gadget com.target.app explore -s "ios jailbreak disable"`
7. Once it launches, hook NSURLSession with frida to capture traffic, or set up mitmproxy and install its system certificate

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| Still crashing after the objection bypass | The app used both SSL pinning and jailbreak detection | Enable `ios sslpinning disable` and `ios jailbreak disable` at the same time | 15min |
| The app detects before launch, so the hook lands too late | Jailbreak detection lives in `+load` or `__attribute__((constructor))` | Use `-f` spawn mode + `frida-trace --aux 'spawn=1'` | 20min |
| The app hangs after hooking stat | Hooking stat also affects some system calls | Only hook stat calls triggered by code inside the app bundle (filter by caller) | 30min |
| The app still detects frida-server after it starts | The app checked port 27042 and the string "frida" | Rename `frida-server` + change the default port (`-l 0.0.0.0:1234`), and connect with `-H ip:1234` on the client | 25min |
| Still getting SSL errors after installing the mitmproxy certificate | On iOS 14+, a system certificate needs a second switch under "General → About → Certificate Trust Settings" | After installing the certificate, go into Trust Settings and enable it | 10min |

## Toolchain Findings

- **objection** is the Swiss Army knife of iOS security testing, shipping jailbreak / sslpin / clipboard / keychain dump modules and more
- **r2frida** wires radare2 into frida, letting you disassemble and modify registers at runtime, far more capable than plain frida
- **Hopper / IDA** decompile iOS binaries (IDA 7+ or Ghidra both handle iOS Mach-O)
- **dumpdecrypted** is obsolete, use **frida-ios-dump** for decryption now

## Key Code / Commands

Generic jailbreak detection hook template:

```javascript
// Intercept NSFileManager fileExistsAtPath checks for jailbreak directories
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var path = ObjC.Object(args[2]).toString();
        var jbPaths = [
            '/Applications/Cydia.app',
            '/Library/MobileSubstrate/MobileSubstrate.dylib',
            '/bin/bash', '/usr/sbin/sshd',
            '/etc/apt', '/private/var/lib/apt/'
        ];
        if (jbPaths.indexOf(path) !== -1) {
            this.shouldFake = true;
            console.log('[+] Hide JB path: ' + path);
        }
    },
    onLeave: function (retval) {
        if (this.shouldFake) retval.replace(0);
    }
});

// Intercept fork(): a jailbroken device can fork, a non-jailbroken one returns -1
var fork = Module.findExportByName(null, 'fork');
Interceptor.replace(fork, new NativeCallback(function () {
    return -1;
}, 'int', []));
```

One-shot decryption (for feeding into decompilers such as jadx):

```bash
frida-ios-dump -l com.target.app
# Outputs Payload/TargetApp.app + the decrypted Mach-O
```

## Improvement Suggestions for This Package

- Add a new sub-skill `ios-reverse/` (parallel to `apk-reverse/`) covering: app decryption, jailbreak detection bypass, SSL pinning, Keychain dump, frida-ios-dump, `+load` timing
- The existing `apk-reverse/` should not carry iOS content, to avoid confusion

## Reusable Patterns / Script Snippets

**iOS security testing quick reference**:

```text
1. Prepare the jailbreak environment (Dopamine 16.x / older palera1n)
2. Decrypt with frida-ios-dump
3. Inspect the class hierarchy with otool / class-dump
4. Start an objection console
5. ios jailbreak disable
6. ios sslpinning disable
7. Capture traffic with mitmproxy (system certificate + Trust Settings, both enabled)
8. Once the key logic is located, dig into it statically with IDA / Hopper
```

## Evolution Actions
- [ ] **Suggest adding an ios-reverse skill** (the current routing matrix sends iOS to reverse-engineering/platforms.md, which is not detailed enough)
- [ ] Add frida-ios-dump to the bootstrap manifest
- [ ] Add an "iOS security testing checklist" to references/

## Environment Information
- Jailbroken device: iPhone X (iOS 16.5) + Dopamine 1.1.7
- Host: macOS 13+ / Kali (mitmproxy + frida-tools)
- frida-server-ios: 16.x

## Redaction Requirements
This entry is seed data, written from publicly known technical patterns, and does not involve any real target. The bundle ID `com.target.app` is a placeholder.
