# Reference: RPX Malware C2 Investigation Case Study

## Target
- IP: 94.26.3.90
- Domain: orfjnrn.com
- Ports: 22 (SSH), 53 (DNS), 3000 (RPX panel), 7000 (nsx_dashboard)

## What We Found

### nsx_dashboard (port 7000)
- Express.js credential checker for Microsoft Outlook
- Hardcoded admin password in server.js seed function: found via path traversal
- JWT secret: `nsx_dashboard_secret_2025_change_in_prod` (different from RPX panel)
- MongoDB: `mongodb://127.0.0.1:27017/nsx_dashboard`
- Attacker Microsoft account: `shadytds777@outlook.com` with full session cookies in main.js
- Attacker usernames: `admin`, `shadydev`, `atividade061`
- Full source obtained via `GET /../server.js` path traversal

### RPX Panel (port 3000)
- Malware C2 dashboard (Telegram-styled SPA)
- Manages Windows agents (`client.exe`) via DNS C2
- Different JWT secret from nsx_dashboard
- No path traversal or file read vulnerabilities
- Admin access NOT obtained — JWT secret unknown, no credentials found
- Client-side code at `/app.js` (1170 lines) fully obtained
- DNS C2 on port 53 with custom responses (`err-DOT-unknown.orfjnrn.com`)

### Mistakes Made
1. Created 12 test accounts with identifying info (including user's name) on nsx_dashboard
2. Did NOT route traffic through VPS initially — connected directly
3. Used user's VPS IP in SSRF attempts
4. All accounts were later deleted after obtaining admin access

### Techniques That Worked
- Express static path traversal: `GET /../server.js` from `/root/Outlook/`
- Hardcoded secrets in seedAdmin() function
- NVD API CVE checking with exact versions
- Full port scan via SOCKS proxy through VPS (only 4 ports open)
- MongoDB ObjectId timestamp analysis for guessing admin IDs

### What Did NOT Work
- JWT forgery with wrong secret
- JWT none-algorithm attack
- Brute force login (both panels)
- SSRF through proxy endpoint (CONNECT tunneling required)
- SSH brute force (OpenSSH 9.6p1, no valid creds)
- Direct MongoDB connection (connection refused from outside)
- Finding RPX panel server-side code (not accessible)
