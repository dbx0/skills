# Ollama Research — Report Generation & Disclosure Workflow

**Date:** 2026-05-19
**Context:** After completing the Ollama v0.24.0 audit, bx0 requested a complete report package for individual CVE submission.

## Output Structure

For each research project, generate:

### 1. Individual Reports (one per vulnerability)
- `REPORT-01-<slug>.md` through `REPORT-NN-<slug>.md`
- Each contains: Summary, Root Cause, Attack Chain, Proof of Concept, Impact, Mitigation
- Self-contained — suitable for individual submission to researchers/CVE assigners
- Include tested versions, dates, and confirmed data
- **Include GGUF crafting scripts** when the vulnerability involves malicious GGUF files (weight hijack, DoS chains)

### 2. Combined Report
- `REPORT.md` — All vulnerabilities in a single document
- Executive summary table
- Disclosure timeline

### 3. Web View
- `site/index.html` — Dark-themed research landing page
- Vulnerability cards with severity badges
- Navigation links to each section
- Reports section with links to individual report files
- Tools section with scanner tool documentation
- AWS/cloud scan results section

### 4. Scanner Tools (if applicable)
- `ssrf_scanner.py` — Python scanner client
- `ssrf_oracle.py` — VPS-side oracle server
- `ssrf_scan.sh` — All-in-one deploy & scan script
- Copy oracle to VPS: `scp oracle.py root@VPS:/tmp/`

## Deployment Gotchas (VPS Oracle)

1. **Write scripts locally, copy via scp** — SSH heredoc escaping is fragile for Python
2. **Kill by port**: `fuser -k 7777/tcp` (more reliable than `pgrep` + `kill`)
3. **Clear .pyc cache** when updating: `find /tmp -name '*.pyc' -delete`
4. **nginx reverse proxy** needed for domain-based SSRF (Ollama rejects IP:port in registry)
5. **Cloudflare DNS** must be "DNS only" (proxy OFF) for direct TCP to oracle
6. **SSL cert** via certbot: `certbot certonly --nginx -d oracle.domain.com`
7. **Reset scan state** between runs: `echo 0 > /tmp/ssrf_scan_state`

## ⚠️ HTML `<` in Code Blocks Breaks Rendering

**Symptom:** A section of the web view (e.g., Proof of Concept) starts showing code, then abruptly jumps to the next section (e.g., Impact). Content in between is invisible.

**Cause:** Inline code snippets in HTML `<pre><code>` blocks that contain `<` characters (e.g., Python `struct.pack('<IQQ', 3, 0, 1)`) are interpreted by the browser as HTML tag starts. The browser silently eats everything from the `<` to the next valid tag close, truncating the visible content.

**Fix:**
1. **Preferred:** Move code with `<` characters to an external `.py` file and link to it (`<a href="poc_script.py">poc_script.py</a>`), keeping only shell commands (curl, bash) inline
2. **Alternative:** Escape `<` as `&lt;` — but this breaks copy-paste since users get `&lt;` instead of `<` when copying
3. **Always verify:** After editing code blocks in `index.html`, curl the page and grep for the expected content to confirm nothing was eaten

**Example of broken vs fixed:**
```html
<!-- BROKEN — browser eats everything after <IQQ -->
<pre><code>struct.pack('<IQQ', 3, 0, 1)</pre></code>

<!-- FIXED — link to external file -->
<p>Full PoC: <a href="poc_script.py">poc_script.py</a></p>
<pre><code>python3 poc_script.py --save-only --output /tmp/malicious.gguf</code></pre>
```

**The web server serves from `site/` directory** (set in `server.py`). Report files placed in the parent directory (`ollama_vulns/`) are NOT accessible.

**Symptom**: Clicking report links gives 404 "File not found"

**Fix**: Copy all report files into the `site/` directory:
```bash
cp /home/bx0/ollama_vulns/REPORT*.md /home/bx0/ollama_vulns/site/
```

**Link format**: Use relative paths without `../`:
```html
<!-- Correct -->
<a href="REPORT-01-weight-hijack.md">Report 01</a>

<!-- Wrong (goes above web root) -->
<a href="../REPORT-01-weight-hijack.md">Report 01</a>
```

## Web View Structure

```
index.html
├── Header (title, severity summary)
├── Navigation (links to each vuln + reports + tools)
├── Vuln Cards (01-07, each with full details)
├── Reports Section (grid of report cards)
├── Tools Section (scanner tools + detection table)
├── AWS Scan Results (port scan table)
└── Footer
```

## File Layout

```
ollama_vulns/
├── 01_weight_hijack_chain_i1.md
├── 02_model_exfiltration_chain_g1.md
├── ...
├── 07_ssrf_api_pull.md
├── REPORT.md (combined)
├── REPORT-01-weight-hijack.md (individual)
├── ...
├── REPORT-07-ssrf.md
├── ssrf_scanner.py
├── ssrf_oracle.py
├── ssrf_scan.sh
└── site/
    ├── index.html
    ├── server.py
    ├── REPORT.md          ← copy from parent
    ├── REPORT-01-*.md     ← copy from parent
    ├── ...
    └── REPORT-07-*.md     ← copy from parent
```
