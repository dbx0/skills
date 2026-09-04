# [Seed] Unity IL2CPP Game Reversing -> Restore Metadata + Modify Logic

## Scenario Category
Game security / Mobile reversing

## Target Overview
An Android game built with Unity in IL2CPP mode. The in-app purchase flow and core algorithms are written in C# but compiled down to native code. The goal is to restore method names, locate the key logic, and modify it by patching or hooking.

## Full Execution Chain

1. Unpack the APK and confirm it is IL2CPP
   ```bash
   unzip target.apk -d apk
   ls apk/lib/arm64-v8a/        # seeing libil2cpp.so means IL2CPP
   ls apk/assets/bin/Data/Managed/Metadata/
   # key file: global-metadata.dat
   ```
2. Restore the metadata with **Il2CppDumper**
   ```bash
   Il2CppDumper libil2cpp.so global-metadata.dat output/
   # outputs: DummyDll/ + script.json + il2cpp.h + dump.cs
   ```
3. Run the IDA IL2CPP script (`ida_with_struct.py`)
   - Load libil2cpp.so -> File -> Script File -> pick ida_with_struct.py -> pick script.json
   - IDA now shows C# method names, signatures, and strings
4. Search dump.cs for business keywords (`AddCoin` / `OnPurchase` / `Verify` / `IsVip` / `CheckSign`)
5. Take the offset of the key method, jump there in IDA, and read the disassembly / decompilation
6. Pick a modification approach:
   - **Static patch**: change the check directly in IDA to `mov w0, #1; ret`
   - **Dynamic hook**: hook the il2cpp method with Frida (using Frida-Il2CppBridge)
7. Verify by repackaging or by injecting

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| Il2CppDumper reports an unsupported metadata version | Newer Unity changed the metadata format | Upgrade Il2CppDumper to the latest version, or switch to Il2CppInspectorRedux | 30min |
| global-metadata.dat is encrypted | AntiCheatToolkit or custom encryption in use | Find the decryption routine used at game startup (usually around il2cpp_init), then dump with Frida after the mmap | 2h |
| Method names visible in dump.cs but IDA does not match them | script.json does not correspond to the .so | You must use the artifacts from a single dump run; clear the cache when switching IDA instances | 20min |
| Frida errors when hooking IL2CPP methods | IL2CPP methods are not standard Java/ObjC, the method offset has to be computed | Use the frida-il2cpp-bridge library instead of hand-writing Interceptor.attach | 1h |
| Game crashes after patching | File hash validation or anti-tamper | Find and patch the hash check too, or hook instead so no file changes | 2h |
| Crash on launch after repackaging | An apksigner v2 signature cannot be re-signed after bytes are modified | Delete META-INF + apktool b + apksigner sign in one pass | 30min |

## Toolchain Findings

- **Il2CppDumper** is the veteran tool and still the default choice
- **Il2CppInspectorRedux** is more modern, supports newer Unity, and emits plugin scripts for IDA / Ghidra / Binary Ninja
- **frida-il2cpp-bridge** is the de facto standard for hooking IL2CPP, orders of magnitude better than bare Frida
- **DnSpy** / **dnSpyEx** for browsing DummyDll (the pseudo .NET assemblies produced by the dump)
- **UnityCheat** family of helper tools (the GameGuardian family is out of scope here)

## Key Code/Commands

frida-il2cpp-bridge hook example:

```typescript
// hook.ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const Assembly = Il2Cpp.domain.assembly("Assembly-CSharp").image;

    // hook static method
    const PlayerData = Assembly.class("PlayerData");
    PlayerData.method("AddCoin").implementation = function (n: number) {
        console.log("[+] AddCoin called with:", n);
        return this.method("AddCoin").invoke(99999); // force it to 99999
    };

    // hook instance method
    const Purchase = Assembly.class("Purchase");
    Purchase.method("VerifyReceipt").implementation = function () {
        console.log("[+] VerifyReceipt -> always true");
        return true;
    };
});
```

```bash
# compile + inject
npm install frida-il2cpp-bridge
frida-compile hook.ts -o hook.js
frida -U -f com.target.game -l hook.js --no-pause
```

Static patching in IDA:

```text
1. Open libil2cpp.so and run il2cpp_load_metadata.py
2. Jump to the offset that dump.cs gives for IsPurchaseValid
3. Change the start of the function to MOV W0, #1; RET (ARM64)
4. Apply Patches -> Save -> put it back into the APK -> re-sign
```

## Suggested Improvements to This Package

- `game-security/SKILL.md` already covers Unity but lacks a **complete end-to-end workflow** case for IL2CPP
- Give `game-security/references/il2cpp-cheatsheet.md` its own document: dump tool comparison, frida-bridge templates, handling encrypted metadata
- Add frida-il2cpp-bridge to the bootstrap manifest

## Reusable Patterns/Script Snippets

**Standard IL2CPP workflow**:

```text
1. Confirm IL2CPP (check whether libil2cpp.so is under lib/abi)
2. Locate the metadata (assets/bin/Data/Managed/Metadata/global-metadata.dat, or encrypted)
3. Restore it with Il2CppDumper / Inspector
4. Load the metadata back into IDA with the script
5. Search dump.cs for business keywords
6. Decide between patching and hooking
7. Verify (launch the app + exercise the real scenario)
```

**Handling encrypted metadata**:

```text
1. Use Frida to hook the fopen/open family and see who reads global-metadata.dat
2. Dump the already-decrypted metadata from memory after the mmap/read
3. Feed the dumped memory to Il2CppDumper as the metadata file
```

## Evolution Actions
- [ ] Add a complete il2cpp chapter to game-security
- [ ] Add frida-il2cpp-bridge / Il2CppInspectorRedux to bootstrap-manifest
- [x] The routing matrix already covers Unity / IL2CPP

## Environment Details
- Windows / macOS (to run Il2CppDumper), target device Android arm64
- IDA Pro 7.7+ or Ghidra 11+
- frida-tools 16.x, frida-il2cpp-bridge 0.9+
- Unity versions: 2019.x - 2022.x (the metadata format differs slightly between versions)

## Redaction Requirements
This entry is seed data written from publicly documented technical patterns and does not involve any real game. The package name `com.target.game` is a placeholder.
