# Default credentials for CN services / OA / CMS / network devices

> Unlike the international generic wordlists (such as SecLists `default-passwords`), this table targets the **domestic SRC arena**: government/enterprise OA, carrier NMS, CN CMS, CN monitoring, CN middleware.
> Data compiled from 22,132 real WooYun cases + public vendor manuals.
> Usage: ≤ 5 attempts per entry, ≤ 4 concurrent per target, ≤ 50 attempts/hour — to avoid getting locked out by risk control.

---

## 1. CN OA / collaboration suites (the core battleground)

### 1.1 Seeyon OA

| Path | Default credentials | Note |
|------|---------|------|
| `/seeyon/` | system / system | Seeyon V5/V8 system account |
| `/seeyon/management/index.jsp` | `WLCCYBD@SEEYON` | management console super password |
| `/seeyon/main.do` | admin / 123456 / 000000 | ordinary administrator |
| `/seeyon/htmlofficeservlet` | — | A8 RCE path (CVE-2020-...) |
| `/seeyon/m/login` | empId / empId | mobile login |

**Fingerprint**: response header `Server: SEEYON-OA`, the login-page logo, `/seeyon/common/`.

**Real cases**: a Seeyon session leak / company-wide address book at an organization, wooyun-2015-0157444, wooyun-2015-0163955.

### 1.2 Tongda OA

| Path | Default credentials | Note |
|------|---------|------|
| `/general/` | admin / admin | default administrator |
| `/general/login.php` | hr / 123456 | HR account |
| `/general/login.php` | jhadmin / 123456 | group administrator |
| `/mobile/auth_mobi.php` | — | arbitrary-user login path (historical vulnerability) |

**Fingerprint**: `/general/login.php`, the page text `Tongda OA`, cookie `PHPSESSID`.

### 1.3 Wanhu ezOffice

| Path | Default credentials | Note |
|------|---------|------|
| `/defaultroot/login.jsp` | admin / 123456 | default administrator |
| `/defaultroot/dragpage/upload.jsp` | — | arbitrary file upload (truncation) |
| `/defaultroot/codesettree.jsp` | — | information disclosure |

**Real cases**: Wanhu OA truncation bypass, wooyun-2014-064031, wooyun-2015-0126541.

### 1.4 Weaver e-cology

| Path | Default credentials | Note |
|------|---------|------|
| `/login/Login.jsp` | sysadmin / 1 | system administrator |
| `/login/Login.jsp` | admin / 123456 | ordinary administrator |
| `/weaver/bsh.servlet.BshServlet` | — | BeanShell RCE endpoint |

**Fingerprint**: response contains `e-cology`, `Weaver`, redirect to `/login/Login.jsp`.

### 1.5 Yonyou collaboration platform / NC

| Path | Default credentials | Note |
|------|---------|------|
| `/oaerp/` | admin / 123456 | collaboration OA |
| `/oaerp/ui/sync/excelUpload.jsp` | — | arbitrary file upload |
| `/nc/` | system / 1 | Yonyou NC ERP |

### 1.6 Kingdee GSiS / Apusic

| Path | Default credentials | Note |
|------|---------|------|
| `/kdgs/` | admin / 888888 | Kingdee GSiS |
| `/kdgs/core/upload/upload.jsp` | — | arbitrary upload (registration is enough) |
| `/admin/login` | apusic / apusic | Apusic middleware |

### 1.7 Landray OA

| Path | Default credentials | Note |
|------|---------|------|
| `/sys/login/login.do` | sysadmin / landray | system management |
| `/sys/login/login.do` | admin / admin | default administrator |

---

## 2. CN middleware / database management

| Service | Default port | Path | Credentials |
|------|---------|------|------|
| Druid (Alibaba) | 8080 | `/druid/login.html` | admin / admin |
| Druid (no auth) | 8080 | `/druid/sql.html` | — direct access |
| Apache Skywalking | 12800 | `/graphql` | — |
| Nacos | 8848 | `/nacos/` | nacos / nacos |
| Apollo config center | 8080 | `/portal/` | apollo / admin |
| Sentinel Dashboard | 8080 | `/` | sentinel / sentinel |
| XXL-JOB | 8080 | `/xxl-job-admin/` | admin / 123456 |
| RuoYi backend | 80/8080 | `/login` | admin / admin123 |
| JeeCG-Boot | 8080 | `/login` | jeecg / jeecg / admin / 123456 |
| RuoYi-Cloud | 8080 | `/` | admin / 123456 / ry / admin123 |
| Eureka | 8761 | `/` | — / `eureka:eureka` |
| Apache DolphinScheduler | 12345 | `/dolphinscheduler/ui/` | admin / dolphinscheduler123 |

---

## 3. CN monitoring / ticketing / IT ops

| System | Default credentials |
|------|---------|
| BlueKing (Tencent) | admin / blueking |
| Legendsec SOC | admin / leadsec.com.cn |
| Venustech Tianqing SOC | admin / venus.com.cn |
| DBAppSecurity EDR | admin / dbappsecurity |
| Ruijie cloud desktop | admin / ruijie / ruijie@123 |
| H3C iMC | admin / admin |
| H3C IRF / devices | admin / h3capadmin |
| Legendsec SecGate | admin / firewall |
| Neusoft NetEye | admin / neusoft |
| 360 Tianqing | admin / 360@admin |
| Kaspersky China edition | admin / kaspersky |

---

## 4. CN CMS

| CMS | Default credentials | Note |
|-----|---------|------|
| DedeCMS | admin / admin | legacy PHP CMS |
| PHPCMS | phpcms / phpcms | common on education sites |
| EmpireCMS | admin / admin | common on government sites |
| SeaCMS | admin / admin | video sites |
| ECshop | admin / admin / consumer | e-commerce |
| Zhimeng / DedeCMS | admin / admin | default |
| FineCMS | admin / admin123 | race-condition upload case wooyun-2014-063369 |
| Jeecms | admin / password | multiple wooyun cases |
| Discuz! | admin / admin / 123456 | forum |
| MetInfo | admin / admin / 123456 | corporate sites |
| ThinkCMF | admin / 123456 | framework CMS |
| YzmCMS | admin / 123456 | Qingmiao |
| Ganqi site builder | — | unified key `lstate=515csmxSi1aTO9ysxvJ1Gpmnj7hHuPxjMdfZdEP49lJZ` (wooyun-2014-062247) |
| Zoomla CMS | admin / admin123 | backdoor wooyun-2014-062607 |

---

## 5. CN network devices / NMS (carrier scenarios)

| Device / system | Default credentials |
|------------|---------|
| Huawei routers / switches, NE series | admin / Admin@huawei / huawei / Huawei@123 |
| Huawei firewall USG | admin / Admin@123 |
| Huawei iManager U2000 | admin / Changeme_123 |
| Huawei home gateway (Telecom-customized) | telecomadmin / nE7jA%5m |
| Huawei home gateway (Mobile-customized) | CMCCAdmin / aDm8H%MdA |
| Huawei home gateway (Unicom-customized) | CUAdmin / CUAdmin |
| Huawei Echolife (optical modem) | useradmin / useradmin |
| ZTE router ZXR10 | admin / zxr10 |
| ZTE NetNumen | netnumen / netnumen |
| Fiberhome OTNM2000 | admin / admin |
| Alcatel Shanghai Bell 5620 SAM | admin / 5620sam |
| H3C series | admin / h3capadmin |
| Ruijie routers | admin / admin |
| Cisco IOS | admin / cisco / cisco / cisco |
| FortiGate | admin / "" / admin / fortinet |
| Sangfor SSL VPN | admin / admin / sangfor |
| Venustech SSL VPN | admin / venus / 123456 |
| DBAppSecurity SSL VPN | admin / dbappsecurity |

---

## 6. CN databases / caches

| Service | Port | Default credentials |
|------|------|---------|
| Dameng (DM) | 5236 | SYSDBA / SYSDBA |
| KingbaseES | 54321 | system / 123456 |
| Shentong (OSCAR) | 2003 | SYSDBA / szoscar55 |
| GBase | 5258 | gbasedba / gbase20110531 |
| Alibaba PolarDB | 3306 | root / "" |
| Tencent TDSQL | 3306 | mysql / "" |
| GoldenDB | 3306 | admin / 123456 |
| TDengine (CN time-series DB) | 6030 | root / taosdata |
| Apache Pulsar | 6650 | — |
| RocketMQ Console | 8080 | — / admin / admin |

---

## 7. CN cameras / IoT

| Vendor | Default credentials |
|------|---------|
| Hikvision | admin / 12345 |
| Dahua | admin / admin |
| Uniview | admin / 123456 |
| Xiongmai | admin / "" |
| Ezviz (Hikvision) | admin / Hik12345+ |
| Generic IPC (white-label) | admin / admin / admin / 123456 / root / admin |
| Industrial PLC (Siemens S7) | — / "" / 100 |
| Industrial HMI (MCGS/Kunlun) | admin / 123456 |

---

## 8. CN development / deployment tools

| Tool | Default credentials |
|------|---------|
| Apache DolphinScheduler | admin / dolphinscheduler123 |
| Alibaba Sentinel | sentinel / sentinel |
| Alibaba Druid | admin / admin |
| Ant SOFAStack | admin / admin |
| Tencent TARS | admin / tars |
| NetEase Yanxuan PaaS | admin / admin |
| Tencent Coding (older) | admin / admin |
| JiHu GitLab CN | root / 5iveL!fe (GitLab generic) |
| CN SonarQube image | admin / admin |
| GoCD (JiHu-customized) | admin / badger |

---

## 9. CN bastion hosts / jump servers

| Bastion host | Default credentials |
|--------|---------|
| JumpServer | admin / admin |
| Qizhi bastion | shterm / shterm |
| CloudBility bastion | admin / Admin@123 |
| Bangcle bastion | admin / bangcle |
| Palading bastion | admin / admin |

---

## 10. CN mobile-banking / financial-tool ops consoles

> Default credentials for bank backends are usually strictly changed; the following are common in ops / test environments, and **should only be used against SRC-authorized assets**.

| System | Default credentials |
|------|---------|
| Shenwan Hongyuan unified auth | hysec / 000000 (wooyun-2015-0119587) |
| Online-banking admin backend (several joint-stock banks) | admin / 123456 / Admin@123 |
| POS merchant terminal management | admin / pos@123456 |
| ChinaUMS | admin / 12345678 |
| TIPS (direct-connect auth) | tips / tips |

---

## 11. Usage-flow template

```bash
# 1. Port fingerprinting
nmap -sV -p 80,443,8080,8848,8761,12345,12800,8443,7001 target

# 2. Path fingerprinting (read the returned content first to identify the vendor)
curl -s http://target/ | grep -iE "(seeyon|tongda|weaver|yongyou|kingdee|landray|jeecg|ruoyi|nacos|druid)"

# 3. On a hit, only run that vendor's default credentials (do not blindly throw every wordlist)
hydra -l <user> -P <pass-list-for-vendor>.txt -t 4 -W 2 target http-post-form ...

# 4. On a hit, stop immediately + screenshot + do not enter business operations
```

---

## 12. Links to the playbooks

```
playbooks/unauth-access.md       →  the international generic part (Tomcat/Redis/Mongo/Actuator)
playbooks/file-upload.md         →  this dictionary adds OA upload paths (Wanhu, Yonyou, Kingdee)
playbooks/sqli.md                →  this dictionary adds OA SQL-injection entry points
playbooks/info-disclosure.md     →  this dictionary adds CN-component information disclosure
industry/banking-finance.md      →  this dictionary adds finance-ops default credentials
industry/telecom-isp.md          →  this dictionary adds NMS / network-element / home-gateway credentials
```

---

## 13. Red lines

- **Forbidden**: using an international wordlist's "brute-force credential-stuffing" mode against CN systems. CN SOC / risk control is highly sensitive and stuffing triggers immediate account lockout.
- **Forbidden**: any write operation after login (creating users, changing config, running commands). Only screenshot to prove you can log in + see the core features.
- **Forbidden**: using this dictionary against government / state-enterprise / bank / carrier systems without SRC authorization. These sectors are critical infrastructure.
- **Rate limit**: ≤ 4 concurrent per target, ≤ 50 attempts/hour; stop on a hit.
