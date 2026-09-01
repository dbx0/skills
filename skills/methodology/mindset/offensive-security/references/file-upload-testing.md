# File Upload Security Testing

## example-auto.tld 2026-06 Findings

### SVG Upload - Stored XSS (Exploitable via "Open Image in New Tab")

**Target:** `/api/upload/thumbnail-url` → presigned S3 URL

**Behavior:**
- Server ignores the provided filename completely, generates a random key
- No content-type or magic byte validation
- Uploaded SVGs served with `Content-Type: image/svg+xml`
- No `X-Content-Type-Options: nosniff`, no `Content-Disposition: attachment`
- No `Content-Security-Policy` on the main site

**Exploitation Vector — "Open Image in New Tab":**
- SVG files uploaded as profile pictures or thumbnails are served with `Content-Type: image/svg+xml` and no `Content-Disposition: attachment`
- When a user **right-clicks on a profile picture → "Open image in new tab"**, the SVG opens as a standalone document in a new tab
- In this context, the browser renders the SVG as a full document (not an image), and **all `<script>` tags execute normally**
- This bypasses the `<img>` tag Content-Type restriction entirely
- **Impact**: Full XSS in the context of the CDN domain (`d3vlaibgctkr2s.cloudfront.net`)
- While this is on the CDN origin (not `example-auto.tld` itself), it can be used for:
  - Phishing attacks (rendering fake login forms on a CDN URL that victims trust)
  - Session token theft if any example-auto.tld cookies are scoped to parent domain
  - Reputation damage (malicious content served from the platform's CDN)
  - Redirect chains to phishing sites

**Attack Scenario:**
1. Attacker uploads a crafted SVG (disguised as a profile picture) containing JavaScript
2. The SVG is stored on the platform's CDN
3. Attacker sets this as their profile picture
4. Victim visits attacker's profile and right-clicks the profile picture → "Open image in new tab"
5. JavaScript executes in the context of `d3vlaibgctkr2s.cloudfront.net`

**Payloads tested (all stored successfully):**
- `<script>alert(1)</script>` — blocked in `<img>` context, executes when opened directly
- `onload="alert(1)"` on SVG element — blocked in `<img>` context
- `<animate onbegin="alert(1)">` — blocked in `<img>` context
- `xlink:href="javascript:alert(1)"` — blocked in `<img>` context
- `<foreignObject><script>alert(1)</script></foreignObject>` — blocked in `<img>` context
- XXE entities — preserved in stored file but not processed by browser
- `<image href="javascript:alert(1)">` — blocked in `<img>` context
- `<use href="javascript:alert(1)">` — blocked in `<img>` context
- `<set attributeName="href" to="javascript:alert(1)"/>` — blocked in `<img>` context

**Browser behavior:**
- Firefox 151: `NS_BINDING_ABORTED` in `<img>` context — request cancelled
- Chrome 131: Silent script stripping in `<img>` context
- **All browsers**: Scripts execute normally when SVG is opened as standalone document (not via `<img>`)

**Key insight:** Modern browsers block ALL script execution in SVG files loaded via `<img>` tags. However, this protection is **bypassed** when the user opens the SVG URL directly (right-click → "Open image in new tab"). In that context, the SVG is treated as a standalone document and scripts execute.

**Severity:** HIGH — stored XSS exploitable via common user action (right-click → open in new tab). No special tools or knowledge required.

### Profile Picture / Avatar Upload

Same endpoint used for profile pictures. Avatar rendered as:
```jsx
<img src={avatarUrl} alt="" className="size-6 shrink-0 rounded-full object-cover"/>
```
Appears in navigation bar on EVERY page. Same browser protections apply for `<img>` context, but **XSS executes when opened in new tab**.

### Video Thumbnail Upload

Same flow. Thumbnails embedded as `<img>` in video grid on `/studio` page.

---

## SVG XSS Rendering Context Quick Reference

| Context | Script Execution | Notes |
|---------|-----------------|-------|
| `<img src="xss.svg">` | ❌ Blocked | Browser "SVG as Image" context |
| `<iframe src="xss.svg">` | ✅ Executes | Treated as separate document |
| `<object data="xss.svg">` | ✅ Executes | Treated as separate document |
| `<embed src="xss.svg">` | ✅ Executes | Treated as separate document |
| **Direct URL in tab** | ✅ Executes | **"Open image in new tab"** |
| CSS `background-image` | ❌ Blocked | Image context |

### Key Takeaway for Future Tests

When testing SVG uploads, **do NOT conclude "not exploitable" just because scripts are blocked in `<img>` tags**. Always check:
1. Is there any way the SVG URL could be opened directly? (profile pictures, thumbnails — users right-click these)
2. Is the SVG served with `Content-Disposition: attachment`? (if not, browser opens it directly)
3. Is there a missing `X-Content-Type-Options: nosniff`? (MIME sniffing could trigger execution)
4. Could the SVG be embedded via `<iframe>` anywhere on the site?

If the SVG is user-uploaded and accessible via a direct URL, it's likely exploitable through the "open in new tab" vector even if `<img>` context blocks it. Severity should be HIGH, not MEDIUM.

---

## Advanced SVG XSS Techniques

### `<foreignObject>` — Embedding Full HTML Inside SVG

**Use case:** When you need `document.body`, `alert()`, `confirm()`, `prompt()`, or DOM manipulation in a standalone SVG document.

A standalone SVG document has no HTML `<body>` — `document.body` is `null`. To get full HTML DOM access, embed a `<foreignObject>` with XHTML namespace:

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">
  <!-- SVG visual content here -->
  
  <foreignObject x="0" y="0" width="800" height="600">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width:100%;height:100%;">
      <script type="text/javascript"><![CDATA[
        // Full HTML DOM access inside foreignObject
        alert("This works in standalone SVG!");
        document.body.style.background = "red";
        
        // Create HTML elements
        var div = document.createElement('div');
        div.textContent = "Injected HTML content";
        document.body.appendChild(div);
      ]]></script>
    </div>
  </foreignObject>
</svg>
```

**Key points:**
- The inner HTML element **must** have `xmlns="http://www.w3.org/1999/xhtml"` namespace
- `document.body` and all HTML APIs work inside the `<foreignObject>`
- `alert()`, `confirm()`, `prompt()` all work (they block the JS thread — if the browser console times out, the script is running)
- CSS animations and styles work normally
- This is ideal for prank/payload SVGs that need full browser interaction
- Works when SVG is opened as a standalone document (direct URL in browser tab)
- Does NOT work in `<img>` tag context (browser strips foreignObject content)

### CDATA Requirement for JavaScript in SVG

**Problem:** JavaScript inside SVG `<script>` tags containing `<`, `>`, `&`, or `"` characters causes XML parsing errors (`not well-formed`).

**Solution:** Wrap all JS code in `<![CDATA[...]]>`:

```xml
<!-- ❌ WRONG — XML parse error -->
<script type="text/javascript">
  if (x < 10 && y > 5) { alert("error"); }
</script>

<!-- ✅ CORRECT — CDATA escapes special chars -->
<script type="text/javascript"><![CDATA[
  if (x < 10 && y > 5) { alert("error"); }
]]></script>
```

**Rule of thumb:** Always use CDATA for JS in SVG. It's always safe and avoids escaping issues.

### Verifying Script Execution (When Console Times Out)

If `browser_console` times out after navigating to an SVG URL, this is actually **confirmation the script is running** — `alert()` blocks the JS thread, which blocks the console. To verify:
1. Press `Enter` or `Escape` to dismiss alert dialogs
2. Once dismissed, the console will respond again
3. Check `document.title` or DOM state to confirm script effects

### SVG Prank/PoC Template

For maximum impact when demonstrating SVG XSS via "Open Image in New Tab":

1. **Visual**: Animated SVG graphics (rainbow trails, floating characters, sparkles)
2. **Audio**: Web Audio API square-wave melody (no external files needed)
3. **Alerts**: Spam `alert()` with funny messages (15+ messages)
4. **Confirms**: Spam `confirm()` dialogs
5. **Prompts**: Spam `prompt()` dialogs
6. **Title**: Flashing `document.title` animation
7. **DOM effects**: Floating emoji rain via `foreignObject` + CSS animations
8. **Fullscreen**: SVG `position: fixed` + `100vw/100vh`

All of this works in a standalone SVG file opened directly in a browser tab — no server-side code needed.

---

### Full-Screen SVG Technique

To make SVG content fill the entire viewport when opened as standalone document:

```xml
<svg xmlns="http://www.w3.org/2000/svg"
     width="100%" height="100%"
     viewBox="0 0 100 100"
     preserveAspectRatio="none"
     style="position:fixed;top:0;left:0;width:100vw;height:100vh;">
```

Key points:
- Use `viewBox="0 0 100 100"` (not `0 0 800 600`) for percentage-based coordinates
- `preserveAspectRatio="none"` stretches content to fill viewport
- Inline `style` with `position:fixed` ensures full viewport coverage
- In JS: set `document.body.style.margin = '0'` and `overflow = 'hidden'`
- Use `vw`/`vh` units in CSS inside `<foreignObject>` for responsive sizing

### Nyan Cat Authentic PoC (example-auto.tld 2026-06)

**Official assets used**:
- GIF: `https://www.nyan.cat/cats/original.gif` → uploaded to CDN as `thumbnails/ZYlMfwShIum.jpeg`
- MP3: `https://www.nyan.cat/music/original.mp3` → uploaded to CDN as `thumbnails/KLG8Kr1wD0N.jpeg`

**Key design choices for authentic Nyan Cat**:
- **Background color**: Dark blue gradient `#003366` → `#001a33` (NOT black — the original Nyan Cat flies through space)
- **Star pattern**: White dots on blue background for space effect
- **Rainbow trail**: Classic 3-bar animated rainbow behind the cat
- **Animation**: Official GIF bounces up and down, rainbow trails scroll horizontally
- **Audio**: Official MP3 song loops continuously (with click/touch fallback for autoplay)
- **Prank effects**: alerts, confirms, prompts, emoji rain, floating text, flashing title

**Full-screen technique** (fixed in v4):
```xml
<svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="none"
     style="position:fixed;top:0;left:0;width:100vw;height:100vh;">
```
- Use `vw`/`vh` units for all foreignObject content
- Set `document.body.style.background = '#003366'` to match SVG background
- Set `document.body.style.margin = '0'` and `overflow = 'hidden'`

**PoC URLs**:
- v1 (black bg): `https://d3vlaibgctkr2s.cloudfront.net/thumbnails/y6rnsh7ROiF.jpeg`
- v4 (authentic blue bg, fullscreen): `https://d3vlaibgctkr2s.cloudfront.net/thumbnails/dphXYcv29UL.svgxml`

### Audio Playback in Standalone SVG

Browsers block `Audio.play()` without user interaction. Workarounds:

1. **Try autoplay first** — standalone SVG documents sometimes allow it:
```javascript
var audio = new Audio("URL");
audio.loop = true;
audio.play().catch(function(){});
```

2. **Hook user interaction events** as fallback:
```javascript
document.addEventListener('click', startAudio);
document.addEventListener('touchstart', startAudio);
```

3. **CORS consideration**: Audio/images must be on the same domain OR the remote domain must send `Access-Control-Allow-Origin: *` headers. When SVG is on a CDN, upload all assets to the **same CDN** to avoid CORS blocks.

---

## General File Upload Testing Checklist

**For authenticated upload workflows** (browser XHR + curl hybrid pattern): See `references/auth-upload-workflow.md`.

1. **Content validation:** Check magic bytes, not just extension
2. **Content-Type override:** Try uploading `.jpg` with SVG content
3. **Path traversal:** Try `../../../etc/passwd` as filename
4. **Size limits:** Try uploading very large files
5. **XXE in SVG:** Test if server processes SVG (image resize, thumbnail generation)
6. **SVG in `<img>`:** Test if browser blocks scripts (modern browsers do)
7. **SVG in `<iframe>` / `<object>`:** Test if server renders SVG in different context
8. **"Open Image in New Tab":** Always test this — bypasses `<img>` tag protections
9. **Content-Disposition:** Check if `attachment` header is set
10. **CORS on CDN:** Check if cross-origin requests are allowed

---

## RTMPS / Streaming Upload Testing

### Cloudflare Stream RTMPS Ingest

**Format:** `rtmps://live.cloudflare.com:443/live/<stream_key>`
**Stream key format:** `<account_id>k<stream_uid>`

**Testing with FFmpeg:**
```bash
ffmpeg -f lavfi -i "testsrc=duration=10:size=640x360:rate=30" \
  -f lavfi -i "sine=frequency=440:duration=10" \
  -c:v libx264 -preset ultrafast -tune zerolatency \
  -c:a aac -b:a 128k \
  -f flv "rtmps://live.cloudflare.com:443/live/<stream_key>"
```

**Security considerations:**
- Stream keys should be treated as secrets
- Check if stream keys are exposed in API responses
- Check if other users' streams can be stopped
- Check rate limiting on stream start
