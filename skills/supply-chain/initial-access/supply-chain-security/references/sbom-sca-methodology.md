# SBOM + SCA methodology

## Comparing SBOM standards

| Standard | Formats | Ecosystem | Best suited to |
|------|------|------|---------|
| SPDX | JSON/YAML/tag-value | Linux Foundation, Yocto | License compliance first |
| CycloneDX | JSON/XML | OWASP, Kubernetes | Security analysis first |
| SWID | XML | ISO standard | Enterprise asset management |

## SBOM generation toolchain

```bash
# cdxgen: generate a CycloneDX SBOM from source
cdxgen -o bom.json -t cyclonedx

# Syft: generate from a container or filesystem
syft nginx:latest -o spdx-json > sbom.spdx.json

# SBOM-Tool: Microsoft's toolchain
sbom-tool generate -b ./build -bc ./src -pn MyApp -pv 1.0
```

## Comparing SCA tools

| Tool | Free | Speed | Database | Reachability |
|------|:--:|------|--------|:--:|
| OSV-Scanner | ✅ | Very fast | OSV.dev | ❌ |
| Trivy | ✅ | Fast | Multi-source | ❌ |
| Dependency-Track | ✅ | Medium | NVD+OSV+GitHub | ❌ (needs a plugin) |
| Snyk | ❌ | Medium | Proprietary | ✅ |
| CodeQL | ✅ | Slow | Code-level | ✅ |

## Vulnerability prioritization strategy

```
CVSS ≥ 9.0 + public PoC + reachable → P0, fix immediately
CVSS ≥ 7.0 + PoC + reachable → P1, fix this week
CVSS ≥ 7.0 + no PoC, or unreachable → P2, fix next iteration
Everything else → normal process
```

## Three-step manual verification

```bash
# 1. Confirm the version (do not blindly trust the SBOM field)
# Inside the container: dpkg -l | grep <package>
# Node: cat node_modules/<pkg>/package.json | jq .version
# Python: pip show <package>

# 2. Confirm the vulnerability
# Search for the CVE: https://osv.dev / https://nvd.nist.gov
# Check the affected version range
# Find the GitHub Advisory or the oss-security mailing list thread

# 3. Verify the impact
# Search for a public PoC: GitHub / Exploit-DB
# Analyze the exploitation preconditions: authentication, local access, or a specific configuration
# Verify in an isolated environment: docker run --rm -it vulnerable-image bash
```

## Continuous monitoring

```yaml
# Daily SBOM refresh and scan
schedule:
  - cron: "0 6 * * *"  # every day at 6am
    steps:
      - cdxgen -o bom.json
      - osv-scanner scan --sbom bom.json
      - trivy fs --exit-code 1 --severity CRITICAL .
```

Source: OWASP CycloneDX, SPDX, Google OSV, CISA SBOM Guidance
