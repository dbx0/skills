# CIRCL CVE JSON Structure

CIRCL's `/api/last/30` endpoint returns a list of CVE objects using the CVE 5.0 JSON format (not flat key-value).

## JSON Path Mapping

```python
import json

with open('/tmp/circl_last30.json') as f:
    data = json.load(f)

for entry in data:
    # CVE ID
    cve_id = entry.get('cveMetadata', {}).get('cveId',
               entry.get('cveMetadata', {}).get('id', '')
    
    # Dates
    published = entry.get('cveMetadata', {}).get('datePublished', '')
    updated   = entry.get('cveMetadata', {}).get('dateUpdated', '')
    
    # Description (English)
    desc_list = entry.get('containers', {}).get('cna', {}).get('descriptions', [])
    desc = next((d['value'] for d in desc_list
                 if isinstance(d, dict) and d.get('lang') == 'en'), '')
    
    # Affected products
    affected = entry.get('containers', {}).get('cna', {}).get('affected', [])
    products = [f"{a.get('vendor','')}/{a.get('product','')}" for a in affected if isinstance(a, dict)]
    
    # CVSS (check v4 first, then v3.1, then v3.0)
    metrics = entry.get('containers', {}).get('cna', {}).get('metrics', [])
    cvss_score = cvss_vector = None
    for m in metrics:
        if not isinstance(m, dict):
            continue
        for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0'):
            if key in m:
                cvss_score = m[key].get('baseScore')
                cvss_vector = m[key].get('vectorString', '')
                break
        if cvss_score is not None:
            break
```

## Malicious Package IDs

CIRCL indexes npm/PyPI malware under `MAL-YYYY-NNNN` IDs (not CVE IDs). These appear in the same `cveMetadata.cveId` field. Filter with:
`if cve_id.startswith('MAL-'):`

## Notes

- Empty/missing `cveMetadata` means the entry is malformed or reserved
- Not all CIRCL entries have CVSS scores — malicious package entries often don't
- The full CVE 5.0 schema nests everything under `containers.cna` (for CNA-provided data)
- Also check `containers.adp` for ADP-enriched data from NVD, MITRE, etc.
