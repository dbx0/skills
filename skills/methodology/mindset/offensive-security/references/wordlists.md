# Wordlist Reference

## Local Wordlists (from The-XSS-Rat/SecurityTesting repo)

Installation directory: `/home/bx0/.hermes/wordlists/`

### Directory Brute-Forcing
- `dir23.txt` — 220K entries, general directory/file discovery
- `dirlist.txt` — 13K entries, curated directory list

### Targeted Payload Wordlists (`bounty_pack/`)

| File | Purpose |
|---|---|
| `bounty_pack/xss_payloads.txt` | Basic XSS starter payloads |
| `bounty_pack/sqli_payloads.txt` | Basic SQL injection payloads |
| `bounty_pack/ssrf_payloads.txt` | SSRF test URLs (localhost, cloud metadata) |
| `bounty_pack/lfi_payloads.txt` | LFI traversal strings |
| `bounty_pack/parameters.txt` | Common IDOR/SSRF/LFI parameter names |
| `bounty_pack/headers.txt` | SSRF/testing headers (X-Forwarded-For, etc.) |
| `bounty_pack/jwt_secrets.txt` | Common JWT secrets for brute-forcing |
| `bounty_pack/passwords.txt` | Starter password list |
| `bounty_pack/subdomains.txt` | Common subdomain prefixes |
| `bounty_pack/directories.txt` | High-value directory names |
| `bounty_pack/methods.txt` | HTTP methods for method tampering |

### Usage Examples

```bash
# Directory brute-forcing with dir23
ffuf -u https://target.com/FUZZ -w /home/bx0/.hermes/wordlists/dir23.txt -mc 200,301,302,403

# Parameter fuzzing
ffuf -u https://target.com/page?FUZZ=1 -w /home/bx0/.hermes/wordlists/bounty_pack/parameters.txt

# JWT secret brute-force
hashcat -a 0 -m 16500 <jwt> /home/bx0/.hermes/wordlists/bounty_pack/jwt_secrets.txt
```

## External Wordlist Collections

The repo references these curated collections:
- [SecLists](https://github.com/danielmiessler/SecLists) — comprehensive wordlists
- [commonspeak2](https://github.com/assetnote/commonspeak2-wordlists) — subdomain wordlists
- [bruteforce-lists](https://github.com/random-robbie/bruteforce-lists) — various wordlists
- [assetnote wordlists](https://wordlists.assetnote.io) — high-quality subdomain/HTTP wordlists
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) — fuzzing payloads
- [big-list-of-naughty-strings](https://github.com/minimaxir/big-list-of-naughty-strings) — edge case strings
- [wfuzz wordlists](https://github.com/xmendez/wfuzz) — built-in wfuzz lists
