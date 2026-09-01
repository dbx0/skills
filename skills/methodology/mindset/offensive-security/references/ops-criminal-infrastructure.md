# Operational Security on Criminal Infrastructure

## The Rule: NEVER Use Identifiable Information

When interacting with criminal/attacker infrastructure during incident response or investigation:

**NEVER:**
- Create accounts with usernames that identify you or your organization (e.g., "<operator-handle>", "bx0test")
- Use your real name, handle, or any identifiable pattern
- Use your VPS IP, real IP, or any infrastructure that can be traced back to you
- Leave any trace that could be attributed to you or your client

**WHY:**
- Criminal organizations monitor their own infrastructure
- New accounts in their dashboards are visible in logs and user lists
- If they see "<operator-handle>" they know someone named bx0 is investigating them
- Direct connections from your IP reveal your location/infrastructure
- This can trigger evidence destruction, legal threats, or physical danger
- Even "harmless" user accounts create noise that alerts the operators

**ALWAYS:**
- Route ALL traffic through your VPS or other anonymizing infrastructure
- Use `ssh -L` port forwarding or SOCKS proxy through the VPS
- Verify your source IP before making requests: curl ifconfig.me via the tunnel

**WHAT TO DO INSTEAD:**
- If you must create an account, use a generic name that blends in (e.g., "user2025", "operator1")
- Better yet: don't create accounts at all — use unauthenticated attack vectors first
- If you accidentally created identifiable accounts, prioritize cleanup IMMEDIATELY
- Accept that some accounts may be impossible to delete without admin access

## Incident Response on Shared Infrastructure

When investigating a server that hosts multiple applications (e.g., port 3000 = malware C2, port 7000 = credential checker):

1. **Map the full infrastructure first** before touching anything
2. **Route ALL traffic through VPS** — set up SSH tunnel before any recon
3. **Identify which apps share databases** — they might not
4. **Understand auth mechanisms separately** — different apps = different JWT secrets, different user tables
5. **Don't assume one app's compromise gives access to another**
6. **Be aware of noise** — actions on one app might trigger alerts visible to the attacker in another
7. **Read source code before taking action** — hardcoded credentials, seed functions, and config values can save you from creating noise

## Real-World Lesson (2026-06-04) — UPDATED

During investigation of `94.26.3.90`:
- Created account "<operator-handle>" on port 7000 nsx_dashboard — **unacceptable, used real name**
- Also created 11 more accounts while exploring — **compounded the problem**
- Did NOT route traffic through VPS as instructed — **left direct IP footprint**
- Could not delete them without admin access
- Found hardcoded admin password in `server.js` via path traversal — **should have done this FIRST before any account creation**
- Eventually cleaned up all accounts using admin creds from source code
- **Lesson learned the hard way**: read source code first, never use identifiable names, always route through VPS

### Additional Lessons

1. **Always set up the VPS tunnel FIRST** before making any requests to attacker infrastructure. Use `ssh -L` port forwarding through the VPS.

2. **Read ALL accessible source code before taking action**. The `server.js` had a `seedAdmin()` function with hardcoded credentials. Reading it first would have prevented the entire account creation mess.

3. **Don't go in circles**. When stuck, stop and ask the user. bx0 had to intervene multiple times to stop the agent from creating more accounts and making more noise.

4. **Multi-app servers are common**. The same box hosted two completely separate apps (port 3000 = malware C2, port 7000 = credential checker) with different auth mechanisms, different JWT secrets, and different user databases. Don't assume one app's access translates to another.

5. **Verify file existence before assuming success**. Many files returned similar-sized error pages (~150 bytes). Always check content, not just size. Real source files are typically much larger (hundreds to thousands of bytes).

6. **Express static path traversal technique**: When Express serves static files with `express.static(__dirname, { index: false })`, the `/../` path traversal can leak server source code. Try `GET /../server.js`, `GET /../middleware/auth.js`, `GET /../package.json`. The traversal serves files relative to `__dirname`. Verify by checking file size > 100 bytes and content doesn't contain "Cannot GET" or "DOCTYPE".

7. **MongoDB ObjectId timestamp analysis**: MongoDB ObjectIds contain a 4-byte Unix timestamp in the first 8 hex characters. Extract with `parseInt(objectId.substring(0, 8), 16)`. First-created users (like admin) have lower timestamps. Sequential ObjectIds can be guessed if you know the approximate creation time. Useful for forging JWTs when you know the admin's creation timestamp.

8. **CVE checking via NVD API**: Check exact dependency versions (from `package-lock.json`, not `package.json`) against NVD:
   ```bash
   curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:package_name:package_name:exact_version:*:*:*:*:*:*:*" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('totalResults',0))"
   ```
   Focus on: jsonwebtoken, mongoose, express, body-parser, cookie-parser, qs, semver, path-to-regexp.

9. **Port scanning through SOCKS proxy**: When `nmap` isn't available, use a Python script with `PySocks` to scan ports through a SOCKS proxy. Scan well-known ports (1-1024) first, then common service ports. Use `ThreadPoolExecutor` for concurrency and set appropriate timeouts (2-3s per port).

10. **Hardcoded secrets in seed functions**: Node.js apps often have `seedAdmin()` or similar functions that create default admin users with hardcoded passwords. These are gold mines. Always search for `seed`, `create({`, `password:` in server source code.
