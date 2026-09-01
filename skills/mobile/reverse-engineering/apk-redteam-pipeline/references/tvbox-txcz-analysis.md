# Android TV Box APK + API Server Analysis — 2026-06-03

> Reference for `apk-redteam-pipeline` skill. Full analysis of a Rockchip RK3326 Android TV box's pre-loaded app store (`com.sszztxr.app`) and its backend API server.

## Device Summary

| Field | Value |
|-------|-------|
| **IP** | 192.168.0.19 |
| **MAC** | cc:f3:05:6c:78:f0 (Shenzhen Tian Xing Chuang Zhan Electronic) |
| **SoC** | Rockchip RK3326 (rk30board) |
| **Android** | 12 (SDK 32), build `rk3326_sgo-userdebug` Aug 2025 |
| **ADB** | Open on 5555, no auth |
| **mDNS identity** | Spoofs `AppleTV3,2` + `AndroidTV3,1` |
| **UPnP** | Rockchip Media Renderer on 38400 |
| **Serial** | c3d9b8674f4b94f6 |
| **Android ID** | 429b96f209cc734d |

## Network Connections (at time of scan)

| Port | Count | Service |
|------|-------|---------|
| 6881 | 55 | BitTorrent DHT (Stremio P2P) |
| 443 | 5 | Google HTTPS (YouTube TV) |
| 11470 | 1 | Stremio relay |

## APK Analysis: `com.sszztxr.app`

### What it is
Legitimate Chinese TV box app store/launcher (TXCZ platform). System-privileged app (`android.uid.system`) that manages app installs, updates, and has a kid-safe launcher mode.

### API Server
- **Base URL:** `http://api.example-tvbox.tld/` (IP: <host-ip>, Alibaba Cloud China)
- **Server:** nginx/1.18.0 on Ubuntu, Java/Spring Boot backend
- **Device registration:** Not registered (returns `{"code":444,"message":"Your device is not registered yet!"}`)

### API Endpoints (from decompiled Retrofit interface `g2/a`)

| Method | Endpoint | Request | Response |
|--------|----------|---------|----------|
| `POST` | `/videoadmin/api/appInfo/forceApps` | `{}` | `ResponseEntity<FocusApp>` |
| `POST` | `/videoadmin/api/appInfo/apps` | `AppRequestModel{page,pageSize,categoryId,keyword}` | `ResponseEntity<List<AppModel>>` |
| `GET` | `/videoadmin/api/appInfo/categorys?lan=en` | — | `ResponseEntity<List<CategoryModel>>` |
| `GET` | `/videoadmin/api/appInfo/getById?id=&packageName=` | — | `ResponseEntity<AppModel>` |

### Request Headers (HeadInterceptor)
`serial`, `model`, `product`, `androidCode`, `opened`, `lanMac`, `wifiMac`, `fingerPrint`, `versionCode`

### Response Encryption
- RSA/ECB/PKCS1Padding with hardcoded 1024-bit public key
- Server responses are RSA-encrypted in Base64
- Decrypted client-side via `EncryInterceptor` when `jimile` header flag is present

### Key Data Models
- **AppModel:** `packageName`, `appName`, `apkUrl`, `apkSize`, `versionCode`, `versionName`, `icon`, `describe`
- **AppRequestModel:** `page`, `pageSize`, `categoryId`, `keyword`
- **FocusApp:** `forceUpgrade: List<AppModel>`, `unInstall: List<AppModel>`
- **CustDesk:** `blackApkList: List<String>` (packages to block/hide)
- **ResponseEntity<T>:** `code: Int`, `message: String`, `data: T`

### APK Download Behavior
- Uses OkDownload library
- Downloads to SD card, filename = MD5(url) + `.apk`
- 5-minute timeout per download
- No signature verification observed (supply chain risk)

### Other Notable Packages on Device
- `com.stremio.one` — Stremio streaming (torrent P2P)
- `com.google.android.youtube.tv` — YouTube TV
- `com.netflix.mediaclient` / `com.netflix.ninja` — Netflix
- `com.bozee.usbdisplay` — USB display mirroring
- `com.shzhtxcz.txbox` — Chinese TV box launcher
- `com.rockchips.mediacenter` — Rockchip media center
- `com.internet.tvbrowser` — TV browser

## Lessons Learned

1. **Identity spoofing is normal** — Android TV boxes routinely spoof AppleTV in mDNS for casting compatibility. Always cross-reference mDNS + UPnP + MAC vendor.

2. **ADB on 5555 = game over** — Any device with ADB exposed on the network without auth is fully compromisable. This is common on cheap Android TV boxes.

3. **Retrofit interfaces are gold** — The obfuscated interface class (e.g., `g2/a`) contains the complete API contract: endpoints, HTTP methods, query params, body types. Finding it gives you the full API surface.

4. **Chinese OEM apps often use RSA response encryption** — Look for `RSA/ECB/PKCS1Padding` and `MIGfMA0G` (Base64 RSA public key header) in smali. The encryption is usually response-only (server→client), not request encryption.

5. **Device registration gates** — Many OEM app stores require device registration before serving content. The `getById` endpoint may work without registration (returns 200 with null data), while `forceApps` and `apps` return 444.

6. **Supply chain risk** — An app store that downloads APKs over HTTP (not HTTPS) with no signature verification is a supply chain attack vector. If you control the network, you can MITM the APK downloads.
