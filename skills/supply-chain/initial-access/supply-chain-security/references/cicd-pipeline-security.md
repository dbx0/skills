# CI/CD pipeline security audit

## Pipeline attack surface

```text
Threat model (STRIDE):
□ Spoofing: forged builds, signatures or provenance
□ Tampering: modified source, build artifacts or dependencies
□ Repudiation: malicious actions with no audit log
□ Information disclosure: pipeline logs or artifacts leaking secrets
□ Denial of service: exhausting CI resources or breaking builds
□ Elevation of privilege: runner escape or secret theft
```

## Audit checklist

### 1. Pipeline-as-code configuration

```yaml
# Key GitHub Actions audit points
# ❌ Dangerous patterns
on:
  pull_request_target:  # a PR trigger that can reach secrets
    types: [opened]

# ❌ Script injection
- run: echo "${{ github.event.issue.title }}"  # user input → shell

# ❌ Unrestricted token permissions
permissions: write-all

# ✅ Safe patterns
on:
  pull_request:  # no access to secrets
    types: [opened]

# ✅ Pin to a SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# ✅ Least privilege
permissions:
  contents: read
```

### 2. Secret management

```bash
# Scan historical commits for secrets
gitleaks detect --source . --verbose
trufflehog git file://. --only-verified

# Review how Actions secrets are used
gh secret list
# Confirm: no hardcoded secrets, regular rotation, least privilege

# Runtime secret injection
# ✅ Use OIDC instead of long-lived secrets
# ✅ Expose secrets only to the specific steps that need them
```

### 3. Build integrity

```bash
# Build provenance
# Produce a tamper-evident build record (SLSA L2+)
slsa-provenance generate --source . --output provenance.json

# Artifact signing
cosign sign-blob --key cosign.key artifact.tar.gz

# Verification
cosign verify-blob --key cosign.pub --signature artifact.tar.gz.sig artifact.tar.gz
```

### 4. Runner security

```text
□ Are GitHub-hosted runners used? (recommended, a fresh environment every run)
□ Self-hosted runners: do they run in an isolated VM or container?
□ Have fork PRs ever been run? (extremely risky on a self-hosted runner)
□ Do runners have outbound network restrictions?
□ Could the build cache leak across builds?
```

### 5. Dependency-fetch security

```text
□ npm: is package-lock.json committed? Disallow --force and --legacy-peer-deps
□ pip: are versions pinned in requirements.txt? Disallow pip install from unverified sources
□ Docker: is FROM pinned to a digest? Disallow the latest tag
□ Go: is go.sum committed?
□ Private packages: does registry authentication use short-lived tokens?
```

## Automated checking pipeline

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: SBOM Generate
        run: |
          npm install -g @cyclonedx/cdxgen
          cdxgen -o sbom.json
      
      - name: OSV Scan
        run: |
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          osv-scanner scan --sbom sbom.json --format sarif > osv-results.sarif
      
      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: 1
      
      - name: Secret Scan
        run: |
          docker run --rm -v $PWD:/src ghcr.io/gitleaks/gitleaks:latest \
            detect --source /src --verbose
      
      - name: Dependency-Track Upload
        run: |
          curl -X POST https://dtrack.example.com/api/v1/bom \
            -H "X-Api-Key: ${{ secrets.DTRACK_API_KEY }}" \
            -F "autoCreate=true" -F "project=myapp" -F "bom=@sbom.json"
```

Source: SLSA Framework, OWASP CI/CD Top 10, GitHub Security Lab
