# SVG XSS via File Upload - Browser Bypass Research

## Key Finding: Modern Browsers Block SVG XSS in `<img>` Tags

**Verified June 2026 (example-auto.tld engagement):** All modern browsers block SVG script execution when SVG is loaded via `<img>` tag. This is a fundamental browser security feature per the SVG spec's "SVG as Image" context.

### Browser Behavior

| Browser | Behavior | Error |
|---------|----------|-------|
| Firefox 151+ | Cancels request entirely | `NS_BINDING_ABORTED` |
| Chrome 131+ | Loads SVG, silently strips all JS | No error (silent) |
| Safari | Similar to Chrome | No error (silent) |

### SVG Contexts (SVG Spec)

1. **Standalone SVG** → scripts execute (direct URL, `<iframe>`, `<object>`)
2. **SVG as Image** → scripts stripped (`<img>`, CSS background)

### What Works vs What Doesn't in `<img>` Context

**✅ Renders (visual only):** shapes, text, gradients, CSS animations, foreignObject HTML
**❌ Blocked:** `<script>` tags, `onload`/`onerror`, `<animate onbegin/onend>`, `xlink:href="javascript:..."`, XXE entities

### Testing Protocol

1. Upload SVG with XSS payload via the app's upload flow
2. Find where it's embedded (`<img>`, `<iframe>`, `<object>`, CSS)
3. Test in Firefox first - look for `NS_BINDING_ABORTED` in Network tab
4. Test in Chrome - scripts silently stripped
5. Open SVG URL directly to verify payload works standalone
6. Rate severity based on actual execution, not just storage

### Severity Guidance

| Scenario | Severity |
|----------|----------|
| SVG stored, embedded as `<img>` only, no direct URL access | MEDIUM |
| SVG embedded as `<iframe>`/`<object>` | HIGH |
| SVG direct URL accessible (standalone) | HIGH |
| SVG as profile pic/thumbnail (open in new tab vector) | HIGH |

### example-auto.tld 2026-06 Findings

- Upload: `POST /api/upload/thumbnail-url` - server ignores filename, generates random key
- SVG served with `Content-Type: image/svg+xml`, NO security headers
- Embedded as `<img>` in studio and video pages
- Avatar also uses same flow, rendered in nav bar on every page
- XSS does NOT execute in any modern browser when loaded via `<img>`
- XSS DOES execute when SVG URL is opened directly in a browser tab
- XXE entities preserved in storage but no server-side processing endpoint found

---

## Advanced Technique: `<foreignObject>` for Full HTML in SVG

When building SVG XSS payloads that need `alert()`, `confirm()`, `prompt()`, or DOM manipulation, use `<foreignObject>` to embed XHTML inside the SVG:

```xml
<foreignObject x="0" y="0" width="800" height="600">
  <div xmlns="http://www.w3.org/1999/xhtml">
    <script type="text/javascript"><![CDATA[
      alert("XSS via foreignObject!");
      document.body.style.background = "red";
    ]]></script>
  </div>
</foreignObject>
```

**Critical:** The inner element must have `xmlns="http://www.w3.org/1999/xhtml"` or the browser won't treat it as HTML.

**Note:** `foreignObject` content is also blocked in `<img>` context — this only works when the SVG is rendered as a standalone document.

---

## Advanced Technique: CDATA for JS in SVG

Always wrap JavaScript in SVG `<script>` tags with CDATA to avoid XML parsing errors:

```xml
<script type="text/javascript"><![CDATA[
  // Safe: < > & " all work inside CDATA
  if (a < b && c > d) { alert("works"); }
]]></script>
```

Without CDATA, characters like `<` and `&` cause `not well-formed` XML parsing errors.

---

## Diagnostic: Console Timeout = Script Running

If `browser_console` times out after navigating to an SVG URL, this confirms the script is running — `alert()` blocks the JS thread. Dismiss alerts with Enter/Escape to regain console access.
