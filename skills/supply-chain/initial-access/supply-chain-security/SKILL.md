---
name: supply-chain-security
description: Software supply-chain security testing — SBOM generation and auditing, software composition analysis (SCA), vulnerability reachability verification, CI/CD pipeline security, container image scanning, and third-party dependency review. Use for supply-chain security assessments, open-source dependency scanning, build-artifact provenance, and compliance-driven SBOM work.
---

# Supply Chain Security Testing

> SBOM / SCA / CI/CD pipelines / dependency provenance
> Regulation-driven: US Executive Order SBOM, China national standards, EU CRA

## Use Cases

- Software supply-chain security assessment
- Open-source dependency vulnerability scanning and verification
- CI/CD pipeline security audit
- Container image security analysis
- Third-party component compliance review
- Build-artifact provenance and integrity verification

## Six-Layer Supply-Chain Governance Framework

```text
Layer 1: Source-code trust assessment → upstream repo/maintainer/release-history review
Layer 2: Build-pipeline integration → CI/CD security gates, signature verification
Layer 3: Artifact-distribution integrity → signing, checksums, SBOM attachment
Layer 4: Runtime protection → container scanning, admission control
Layer 5: Continuous monitoring → real-time CVE tracking, vulnerability reachability analysis
Layer 6: Incident response → supply-chain-attack response, rollback strategy
```

## Workflow

### 1. SBOM Generation and Auditing

```text
Generate SBOM:
□ CycloneDX format: cdxgen → bom.json
□ SPDX format: sbom-tool generate
□ Syft: syft <image|dir> -o spdx-json

Audit checkpoints:
□ Any unknown/unauthorized dependencies
□ Any deprecated/unmaintained packages
□ License-conflict detection
□ Direct-dependency vs transitive-dependency inventory
□ Release timeline and maintainer status of each component
```

### 2. Software Composition Analysis (SCA)

```bash
# OSV-Scanner (free, maintained by Google)
osv-scanner scan -r . --format json

# OWASP Dependency-Track (enterprise-grade continuous monitoring)
docker run -p 8080:8080 dependencytrack/apiserver
# → upload SBOM → auto-match against NVD/OSV/GitHub Advisory

# Snyk (commercial)
snyk test --all-projects
snyk monitor  # continuous monitoring

# Trivy (container + dependency + IaC)
trivy fs .          # filesystem scan
trivy image nginx   # container image
trivy config .      # IaC configuration
```

### 3. Vulnerability Reachability Verification

```text
An SCA alert ≠ actual risk! Most SCA tools have only ~15% of alerts that are actually reachable.

Verification steps:
1. Get the CVE list with Dependency-Track or Trivy
2. Filter for vulnerabilities with CVSS ≥ 7.0
3. Do reachability analysis on CVEs that have a PoC
   - Code Property Graph slicing: trace the path from user input to the vulnerable function
   - DEPTEX method: EPD (Execution Path Dominance) + LLM semantic verification
4. Verify the PoC in an isolated environment
5. Prioritize fixes for reachable vulnerabilities by actual impact
```

Tool references:
- CodeQL: GitHub code queries → data-flow analysis
- Snyk Code: reachability tagging
- DEPTEX: LLM-assisted context-aware risk assessment

### 4. CI/CD Pipeline Security

```text
Security checkpoints:
□ Code commit → pre-commit hook: gitleaks (secret scanning)
□ PR stage → SCA scan (Trivy/OSV-Scanner)
□ Build stage → artifact signing (cosign)
□ Push stage → SBOM attachment (syft + attest)
□ Deploy stage → admission control (OPA/Kyverno + image scan)
□ Runtime → continuous vulnerability monitoring (Dependency-Track)

Pipeline's own security:
□ Pipeline-as-Code audit (GitHub Actions / GitLab CI config injection)
□ Runner isolation (prevent a malicious build from breaking out of the container)
□ Secret management (Actions Secrets / Vault, no hardcoding)
□ Third-party Action review (pin to commit SHA, not tag)
```

### 5. Container Image Security

```bash
# Dockerfile audit
hadolint Dockerfile

# Image scan (multi-layer: OS + application dependencies + config)
trivy image --severity HIGH,CRITICAL nginx:latest

# Minimal base image
# Preference: distroless → alpine → slim → avoid latest
docker scout quickview nginx:latest

# Image signing
cosign sign --key cosign.key myimage:tag
cosign verify --key cosign.pub myimage:tag
```

### 6. Third-Party Dependency Review

```text
Checklist for adding a dependency:
□ Maintenance status: commits in the last 6 months? maintainer activity?
□ Security history: has it had malicious code planted in it before?
□ Dependency tree: how many transitive dependencies does adding it introduce?
□ License: compatible with the project's license?
□ Alternatives: is there a more secure replacement (Snyk Advisor / Socket.dev score)?

Risk-assessment matrix:
  high maintenance × low dependency count × compatible license → low risk
  low maintenance × high dependency count × license conflict → high risk
```

## Toolchain

| Tool | Purpose | Get it |
|------|------|------|
| OWASP Dependency-Track | enterprise-grade continuous SCA | `docker pull dependencytrack/apiserver` |
| OSV-Scanner | free SCA (OSV.dev ecosystem) | `go install github.com/google/osv-scanner` |
| Trivy | image + dependency + IaC scanning | `apt install trivy` |
| Syft | SBOM generation | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh` |
| cdxgen | CycloneDX SBOM generation | `npm install -g @cyclonedx/cdxgen` |
| Cosign | container signing | `go install github.com/sigstore/cosign/v2/cmd/cosign` |
| Gitleaks | secret/credential scanning | `go install github.com/gitleaks/gitleaks/v8` |
| Snyk | commercial SCA + reachability | `npm install -g snyk` |
| CodeQL | code queries + data flow | built into GitHub Actions |

## References

- `references/sbom-sca-methodology.md` — SBOM + SCA methodology
- `references/cicd-pipeline-security.md` — CI/CD pipeline security audit
