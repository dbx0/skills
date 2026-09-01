# Security News Monitoring — API Endpoints & Sources

## CVE Databases

### NVD (National Vulnerability Database)
- **Search API:** `https://services.nist.gov/rest/json/cves/2.0?pubStartDate=YYYY-MM-DDT00:00:00.000&pubEndDate=YYYY-MM-DDT23:59:59.000&resultsPerPage=20`
- **Single CVE:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-XXXXX`
- **Key JSON paths:**
  - `vulnerabilities[].cve.id` — CVE ID
  - `vulnerabilities[].cve.metrics.cvssMetricV31[0].cvssData.baseScore` — CVSS 3.1
  - `vulnerabilities[].cve.metrics.cvssMetricV40[0].cvssData.baseScore` — CVSS 4.0
  - `vulnerabilities[].cve.descriptions[?lang==en].value` — English description
  - `vulnerabilities[].cve.weaknesses[].description[?lang==en].value` — CWE

### CIRCL CVE Search
- **Last N CVEs:** `https://cve.circl.lu/api/last/30`
- **Single CVE:** `https://cve.circl.lu/api/cve/CVE-YYYY-XXXXX`
- **Key JSON paths:** `cvss`, `summary`, `references[]`, `id`
- **Note:** Also indexes PyPI (PYSEC-) and npm (MAL-) malicious packages

### GitHub Advisories
- **List:** `https://api.github.com/advisories?per_page=15&sort=published&direction=desc`
- **Key JSON paths:** `ghsa_id`, `cve_id`, `severity`, `summary`, `published_at`, `html_url`

## CISA KEV
- **Full catalog:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Key fields:** `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `shortDescription`, `dateAdded`, `dueDate`
- **Note:** Sorted by `dateAdded` descending (most recent first)

## Security News Sites (Browser)

| Site | URL | Bot Detection |
|------|-----|---------------|
| The Hacker News | thehackernews.com | None (works) |
| Krebs on Security | krebsonsecurity.com | None (works) |
| SecurityWeek | securityweek.com | None (works) |
| BleepingComputer | bleepingcomputer.com | Cloudflare (blocked) |
| Socket.dev | socket.dev | Cloudflare (blocked) |
| Ars Technica | arstechnica.com | Sometimes empty |

## NVD Date Format

ISO 8601: `YYYY-MM-DDTHH:MM:SS.sss`

Example (7 days back from May 24, 2026):
```
pubStartDate=2026-05-17T00:00:00.000&pubEndDate=2026-05-24T23:59:59.000
```
