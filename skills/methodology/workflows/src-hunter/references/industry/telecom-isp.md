# Telecom / carrier / ISP pentest playbook

> Perspective: black-box, targeting the three domestic carriers (Mobile / Unicom / Telecom) + Radio-TV + regional ISPs + IoT-SIM providers.
> Data basis: WooYun cases in the carrier sector center on three classes: weak passwords (7,513) / broken access (1,705) / unauthenticated access (1,891).

---

## 1. One-line positioning

Traits of carrier systems: **large asset scale + old systems + many internal interfaces**.
- Many entry points: web hall / mobile hall / H5 / official account / mini-program / SP-CP / per-province branch sites.
- Many backends: BOSS / OA / NMS / AAA / SMS gateway / IoT-SIM platform.
- Many bugs: dominated by **weak passwords + broken access + unauthenticated access**; the finance sector's payment tampering becomes "phone-credit/data recharge" in the carrier context.

**Gold mines**: provincial branches, SP/CP third-party access platforms, IoT-SIM management platforms.

---

## 2. Attack-surface panorama

```
                          Carrier attack surface
                                │
    ┌─────────┬─────────┬───────┴───────┬─────────┬─────────┐
    ▼         ▼         ▼               ▼         ▼         ▼
 internet portal  mobile app  value-added platform  internal systems  IoT platform  supply chain
    │         │         │               │         │         │
 ├─web hall ├─mobile hall ├─SP/CP access  ├─OA       ├─IoT SIM ├─outsourcing
 ├─points mall ├─H5     ├─SMS gateway   ├─mail     ├─M2M     ├─device vendor
 ├─business hall ├─SDK  ├─billing API   ├─VPN      ├─IoV     ├─ops provider
 └─marketing campaign     └─agent portal ├─NMS               └─printing house
```

---

## 3. High-severity vulnerability distribution

### 3.1 Weak passwords (7,513 cases, 58.2% high severity)

> The carrier's biggest mine — internal systems + employee-ID panels + legacy vendor equipment.

| Target system | Common weak passwords | GetShell likelihood |
|---------|----------|---------------|
| BOSS backend | admin/admin, empId/123456, empId/empId | ⭐⭐⭐⭐⭐ |
| Network management / NMS | root/root, huawei/huawei, admin/Huawei@123 | ⭐⭐⭐⭐⭐ |
| OA system | admin/admin, empId/123, 123/123 | ⭐⭐⭐⭐ |
| Database | sa/empty, root/root, postgres/postgres | ⭐⭐⭐⭐⭐ |
| Docker API | no authentication | ⭐⭐⭐⭐⭐ |
| Middleware | tomcat/tomcat, weblogic/weblogic, admin/123 | ⭐⭐⭐⭐⭐ |
| Monitoring | admin/zabbix, admin/admin (Grafana / Prometheus) | ⭐⭐⭐⭐ |
| Network devices | huawei/huawei, admin/admin, cisco/cisco | ⭐⭐⭐⭐ |

**Detection method**:
```bash
# Rate control (carrier SRC strictly forbids high-frequency brute force)
hydra -L users.txt -P top200.txt -t 4 -W 2 target ssh
hydra -l admin -P passwords-cn.txt -t 4 target http-post-form "/login:user=^USER^&pwd=^PASS^:F=fail|invalid"

# Note: single-IP rate control 4 threads, ≤ 50 attempts/hour
```

See `dictionaries/default-credentials-cn.md`.

### 3.2 Broken access (1,705 cases, 62.3% high severity)

**Carrier-specific broken-access points**:

| Feature | Key parameters | Impact |
|-------|---------|-----|
| Phone-credit query | `phone`, `mobile`, `mob` | query any user's phone credit |
| Call records / itemized bill | `cust_id`, `user_id`, `acc_nbr` | any user's call records (privacy) |
| Plan change | `order_id`, `pkg_id` | modify another user's plan |
| Real-name info | `id_card`, `cert_no` | leak ID-card scans |
| Data-package ordering | `phone`, `productId` | order paid packages for another user |
| Recharge records | `phone`, `month` | query recharge history |

**Bypass tricks**:
```
Parameter pollution: ?uid=self&uid=target
Array injection: uid[]=target
JSON nesting: {"user":{"id":target}}
GET / POST switch: GET is checked / POST is not
Province parameter: ?provinceCode=change to province-wide
```

### 3.3 Unauthenticated access (1,891 cases)

**High-frequency exposed paths**:

```
Backend
/admin           /manager          /console
/manage          /manager/html     /jmx-console

Monitoring
/zabbix          /grafana          /nagios
/server-status   /nginx_status

Middleware
/weblogic-console  /actuator      /druid
/dubbo-admin       /nacos         /xxl-job-admin

API docs
/swagger-ui       /api-docs       /v2/api-docs
/openapi.json

Database
/phpmyadmin      /pma            /myadmin
/adminer         /eshore-mongo

Custom systems (common at carriers)
/seeyon          /seeyon/m       /seeyon/management
/oa              /oa/login       /portal
/web-bbs         /sso-server     /CRM
/u2000           /eMaster        /M2000
```

See `dictionaries/chinese-srcfingerprints.md`.

---

## 4. Uncommon but high-value attack surface

### 4.1 SP / CP value-added platforms

```
Traits:
├── Third-party access, security requirements often lower than the carrier's main site
├── Directly wired to the billing system (find one and you can affect billing)
├── SP interfaces carry mobile / spid / accessNumber parameters
└── Most use legacy SOAP / WebService protocols

Entry points:
├── SMS / MMS delivery platform (SMS gateway)
├── Data top-up package interface
├── Video / music SP access interface
└── WAP push platform
```

**Typical cases**:
- SP platforms of the three carriers (involving wooyun-2015-0131337 and others)
- Mass injection in a provincial Telecom enterprise platform (wooyun-2015-0134241, parameter `PARENTTYPEID`)
- A comms vendor SQL + arbitrary file download (wooyun-2016-0205773, parameters `token, sameName, selfilePath, fileName, siteId`)

### 4.2 IoT-SIM management platforms

```
Attack surface:
├── IoT device management backend (card activation / status query)
├── Bulk provisioning interface (weak API authz)
├── M2M platform API
├── IoV (T-Box) callback interface
└── Industrial IoT platform
```

**Key parameters**: `iccid`, `imsi`, `imei`, `customerId`, `terminalId`, `cardId`.

### 4.3 Network Management System (NMS)

```
Huawei line:
├── U2000  — metro/access network NMS
├── M2000  — mobile core network NMS
├── eMaster — device master manager
└── iManager U2000  — default admin/Changeme_123

ZTE / Fiberhome / Alcatel Shanghai Bell:
├── NetNumen  — ZTE NMS
├── OTNM2000  — Fiberhome optical NMS
└── 5620 SAM  — Alcatel Shanghai Bell
```

> **Once you break into the NMS → you can control core network devices → extremely high value, but the red line is extremely strict**.

### 4.4 Billing systems

WooYun case: China Tietong billing-system GetShell + recharge-card generation (arbitrary card issuance).
Traits:
- Interface paths contain `/billing/`, `/recharge/`, `/payment/`
- Key parameters: `phone`, `amount`, `cardNo`, `cardPwd`, `recordId`

---

## 5. GetShell / lateral-movement paths

### 5.1 Path 1: direct web RCE

```
Priority order:
1. Struts2 RCE (S2-045/046/048/052/057/059)
   — many provincial-branch legacy systems still use it
2. WebLogic deserialization (CVE-2017-10271 / 2019-2725 / 2020-14882)
   — common in BOSS systems
3. Shiro rememberMe deserialization
   — internal OA / ticketing systems
4. Fastjson 1.2.x RCE
   — SP access platforms
5. File-upload bypass (FCKeditor / eWeb / UE / Kind)
   — many legacy OA + government/enterprise systems
6. SQL injection → xp_cmdshell / into outfile
   — legacy ASP / JSP sites
7. JBoss / WebLogic / Tomcat default credentials → war deployment
```

### 5.2 Path 2: edge devices

```
VPN:
├── Pulse Secure CVE-2019-11510
├── Fortinet CVE-2018-13379
├── Citrix CVE-2019-19781
└── Sangfor / Venustech / Topsec / DBAppSecurity devices

Network devices:
├── Huawei NE / S series default passwords (some still in use)
├── Cisco Smart Install protocol abuse
├── SNMP community string leaks (public / private / vendor-fixed)
└── Various RouterOS / Mikrotik older-version vulnerabilities
```

### 5.3 Path 3: supply chain

```
Entry:
├── Outsourced dev → test environment → production
├── Ops terminal → AD credentials → domain controller
├── Third-party devices → preset default accounts
└── Printing house → recharge-card secrets / IoT-SIM secrets
```

---

## 6. Lateral-movement targets

| Target system | Value | Difficulty |
|---------|-----|------|
| BOSS system | user data, billing control | high |
| AAA auth center | credentials for all users | high |
| SMS gateway | SMS hijacking (take over verification codes) | high |
| Core network devices (HSS / MME) | network control plane | very high |
| DNS server | traffic hijacking | medium |
| Billing / accounting | arbitrary card issuance / plans | high |
| Real-name system | ID-card / face database | very high |

> SMS gateway, core network, AAA, real-name — these four are a "sensitive-target no-go zone". Even with SRC authorization, do not go deep. Stop at proving reachability.

---

## 7. Practical checklist

### 7.1 Information gathering
- [ ] Subdomain enumeration (including per-province / city branches, e.g. provincial subdomains under *.10086.cn)
- [ ] Port scanning (non-standard ports; carriers commonly use 8085 / 8089 / 8443 / 8161)
- [ ] GitHub / Gitee code leaks (carriers have a high outsourcing ratio)
- [ ] Cyberspace mapping (Shodan / Fofa / 360 Quake)
- [ ] Download the app / mini-program / official account (note: each province may have its own app)
- [ ] H5 marketing campaigns / data-gift campaigns

### 7.2 Vulnerability discovery
- [ ] Weak-password brute force (mind the rate limit)
- [ ] Broken-access testing (phone number / employee ID / customer ID enumeration)
- [ ] Unauthenticated access (see `playbooks/unauth-access.md`)
- [ ] Framework-vulnerability scanning (Struts2 / WebLogic / Shiro / Fastjson)
- [ ] Unauthenticated interfaces (capture Swagger → call without a token)
- [ ] SP / CP access platforms (weak authz)
- [ ] IoT-SIM platforms

### 7.3 After GetShell
- [ ] Persistence (prove only, do not leave it long)
- [ ] Internal-network recon (only at the IP / hostname level)
- [ ] Credential access (screenshot only, do not exfiltrate)
- [ ] Lateral proof (stop at the second machine at most)
- [ ] Clean up immediately + note the cleanup time in the report

---

## 8. Real-case fingerprints

| Case | One-line fingerprint | Type |
|------|----------|------|
| A site involving the three carriers, wooyun-2015-0131337 | `/FrameAction/index.do` + empId / 123456 | weak password |
| A provincial Telecom enterprise platform, wooyun-2015-0134241 | parameter `PARENTTYPEID` SQL injection | SQLi |
| A comms vendor, 170K users, wooyun-2016-0205773 | `token / sameName / selfilePath` multi-param | SQLi + file download |
| China Tietong billing system | arbitrary card issuance via the billing interface | arbitrary operation |
| eXin wifi multi-system 1M users + 1M recharge cards | multi-bug chain | information disclosure |
| A State Grid site, wooyun-2016-0193221 | admin/123 + breaker close/open | weak password |
| A social platform core data-center roaming, wooyun-2015-095043 | OTNM2000 NMS 8089 | misconfiguration |

---

## 9. Red lines (telecom / carrier sector edition)

- **Never**: touch the SMS gateway / SMS-sending interface (even if callable). Any SMS sent counts as live testing and violates telecom regulations.
- **Never**: live-test breaker close/open / industrial-control interfaces (linked to power, gas, water). Stop at proving reachability.
- **Never**: invoke core-network commands (HSS, MME, network-element config).
- **Never**: perform any write operation on an NMS (even with root).
- **Never**: scan a carrier's public IP ranges. Only authorized assets + known subdomains.
- **Never**: exfiltrate real-name-system data. Any screenshot must be redacted beyond individual identification.
- **Test rate limit**: ≤ 4 concurrent per target, path fuzzing ≤ 5 rps.
- **Stop at GetShell**: prove RCE → clean up immediately → note the cleanup hash + time in the report.

---

## 10. Links to methodology / dictionaries

```
methodology/05-srctimebox-priority.md   →  weak-password/broken-access/unauth time box
playbooks/unauth-access.md               →  default credentials / Redis / Mongo / Actuator
playbooks/arbitrary-x-authz.md           →  arbitrary operation (recharge cards / plan ordering)
playbooks/sqli.md                        →  SQL in legacy ASP/JSP sites
playbooks/file-upload.md                 →  FCKeditor / eWeb / UE / Kind
playbooks/rce.md                         →  Struts2 / WebLogic / Shiro / Fastjson
dictionaries/default-credentials-cn.md   →  Huawei / ZTE / OA / NMS default credentials
dictionaries/chinese-srcfingerprints.md  →  Seeyon / Tongda / Wanhu / SP platform paths
```
