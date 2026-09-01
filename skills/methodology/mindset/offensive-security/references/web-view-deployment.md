# Web View Deployment Patterns

## Markdown Viewer Pattern

Instead of serving raw `.md` files directly (which browsers render as plain text or garbled unicode), create a `viewer.html` page with a client-side JavaScript markdown parser.

**Architecture:**
- `viewer.html` — standalone page with embedded JS markdown parser (no external dependencies)
- Fetches `.md` file via `fetch()` with `?file=REPORT-xxx.md` URL parameter
- Renders as styled HTML with dark theme
- Includes "View Raw" button that links directly to the `.md` file
- Includes "Back to Index" button

**URL pattern:** `viewer.html?file=REPORT-01-weight-hijack.md`

**All report links in `index.html` should point to `viewer.html?file=...`**, not directly to `.md` files.

## Unicode Safety in Markdown Files

Python's `http.server` does NOT send `charset=utf-8` in Content-Type headers by default. This causes unicode characters to render as mojibake.

**Fix:** Replace all unicode chars with ASCII equivalents in `.md` files:
- `—` (em dash) → `---`
- `→` (right arrow) → `->`
- `≈` (approximately equal) → `~`
- `…` (ellipsis) → `...`
- Smart quotes → straight quotes

**Also:** Use a custom server that sets `Content-Type: text/markdown; charset=utf-8` (see `scripts/charset_server.py`).

Best practice: do BOTH for maximum compatibility.

## HTML Code Block Safety

When embedding code snippets inline in HTML (inside `<pre><code>` blocks), any `<` character is interpreted by the browser as an HTML tag start. This silently truncates visible content.

**Example:** `struct.pack('<IQQ', 3, 0, 1)` — the `<IQQ` is parsed as an HTML tag, everything after disappears.

**Fixes:**
1. Escape as `&lt;` — but this breaks copy-paste
2. **Preferred:** Move code to external `.py` file and link to it, keeping only shell commands inline
3. Always verify rendered HTML output after editing code blocks

## File Path Gotcha

When deploying reports to a web view, copy files into the web server root directory. Links with `../` go above the root and return 404. Use relative paths without `../`.

## Deployment Checklist

1. Copy all report `.md` files into web server root
2. Replace unicode chars with ASCII equivalents
3. Verify no inline `<` characters in HTML code blocks
4. Update all links to use `viewer.html?file=...` pattern
5. Add "View Raw" button to viewer
6. Test all links render correctly in browser
