# CN component fingerprints + paths + high-frequency parameter dictionary

> Unlike English wordlists (H1 / SecLists / OWASP), this directory fills CN-arena gaps:
> 1. Fingerprints for CN OA / CMS / middleware (how to identify them)
> 2. High-risk default paths for CN editors / OA / NMS
> 3. High-frequency parameters distilled from 27,732 WooYun SQLi cases = a CN SRC parameter dictionary

---

## 1. CN OA / middleware fingerprints

### 1.1 Seeyon OA

```
HTTP headers:
  Server: SEEYON-OA
  Set-Cookie: JSESSIONID=...
  X-Powered-By: SEEYON

URL traits:
  /seeyon/                      default root path
  /seeyon/main.do                post-login home page
  /seeyon/management/index.jsp   management console
  /seeyon/htmlofficeservlet      A8 RCE endpoint
  /seeyon/common/                shared resources

Page traits:
  <title>Seeyon Collaboration Management Software</title>
  COMMON.NEED_LOGIN
  ctp.* namespace

Log disclosure:
  /ctp.log (23 hits)
  /seeyon/logs/ctp.log
```

### 1.2 Tongda OA

```
URL traits:
  /general/                  default root path
  /general/login.php         login entry
  /mobile/auth_mobi.php      mobile auth
  /ispirit/                  early-version root path
  /Pda/                      mobile PDA interface

Page traits:
  <title>Tongda OA</title>
  Set-Cookie: PHPSESSID=...
  Historical vuln: /ispirit/interface/gateway.php

File structure:
  /general/skin/             skin resources
  /general/templates/        templates
```

### 1.3 Wanhu ezOffice

```
URL traits:
  /defaultroot/             root path
  /defaultroot/login.jsp    login
  /defaultroot/dragpage/    arbitrary upload point
  /defaultroot/codesettree.jsp information disclosure
  /defaultroot/upload.jsp   upload interface

Page traits:
  <title>Wanhu ezOFFICE</title>
  Wanhu Network logo
```

### 1.4 Weaver e-cology / e-office

```
URL traits:
  /login/Login.jsp                       e-cology login
  /weaver/bsh.servlet.BshServlet         BeanShell RCE endpoint
  /mobile/                               mobile
  /api/                                  API gateway
  /workflow/                             workflow

Page traits:
  the string e-cology
  Set-Cookie: JSESSIONID=...; ecology_JSessionId=...
```

### 1.5 Yonyou / Kingdee / Landray

```
Yonyou NC:
  /nc/                  root path
  /nc/servlet/          servlet path
  /portal/              portal
  fingerprint: <title>Yonyou NC</title>

Yonyou collaboration OA:
  /oaerp/
  /oaerp/ui/sync/excelUpload.jsp arbitrary upload

Kingdee GSiS / EAS:
  /kdgs/                root path
  /kdgs/core/upload/    upload point
  /eas/                 EAS main path
  fingerprint: KingdeeApp / kdgs

Landray OA:
  /sys/login/login.do
  /sys/web/index.jsp
  fingerprint: Landray
```

### 1.6 CN middleware / frameworks

```
Druid (Alibaba):
  /druid/index.html         monitoring dashboard
  /druid/sql.html           SQL monitoring
  /druid/weburi.html        URL monitoring
  /druid/login.html         login
  fingerprint: <title>Druid</title>

Apache Dubbo Admin:
  /dubbo-admin/             admin dashboard
  fingerprint: dubbo

Nacos:
  /nacos/v1/auth/users      users interface
  /nacos/                   console
  fingerprint: <title>Nacos</title>

XXL-JOB:
  /xxl-job-admin/           scheduling center
  fingerprint: <title>Task Scheduling Center</title>

Apollo config center:
  /portal/                  portal
  /eureka/apps              service list
  fingerprint: apollo / Apollo

Skywalking:
  /graphql                  GraphQL interface
  /                         UI
  fingerprint: <title>SkyWalking</title>

RuoYi / JeecgBoot:
  /login                    generic login
  /system/user              user management
  /jeecg-boot/              JeecgBoot prefix
  fingerprint: ruoyi / jeecg-boot
```

---

## 2. CN high-risk default paths

### 2.1 OA / collaboration (frequent file-upload / SQL-injection entry points)

| Path | System | Vulnerability type |
|------|------|---------|
| `/seeyon/htmlofficeservlet` | Seeyon OA | RCE |
| `/seeyon/thirdpartyController.do` | Seeyon OA | SSRF / information disclosure |
| `/general/login.php` | Tongda OA | weak password |
| `/mobile/auth_mobi.php` | Tongda OA | arbitrary-user login |
| `/ispirit/interface/gateway.php` | Tongda OA | RCE (historical vuln) |
| `/defaultroot/dragpage/upload.jsp` | Wanhu OA | arbitrary file upload |
| `/weaver/bsh.servlet.BshServlet` | Weaver e-cology | RCE |
| `/oaerp/ui/sync/excelUpload.jsp` | Yonyou collaboration | arbitrary file upload |
| `/kdgs/core/upload/upload.jsp` | Kingdee GSiS | arbitrary file upload |

### 2.2 Rich-text editors (42% of file-upload cases)

```
FCKeditor (48%):
  /FCKeditor/editor/filemanager/browser/default/connectors/test.html
  /FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector
  /FCKeditor/editor/filemanager/upload/test.html
  /FCKeditor/UserFiles/                 ← post-upload path

eWebEditor (28%):
  /ewebeditor/admin/default.jsp
  /ewebeditor/admin_login.asp
  /ewebeditor/admin_uploadfile.asp
  /ewebeditor/php/upload.php
  /ewebeditor/uploadfile/                ← post-upload path

UEditor (12%):
  /ueditor/controller.jsp?action=config
  /ueditor/jsp/controller.jsp
  /ueditor/net/controller.ashx
  /ueditor/php/controller.php
  /ueditor/php/upload/                   ← post-upload path

KindEditor (8%):
  /kindeditor/php/upload_json.php
  /kindeditor/jsp/upload_json.jsp
  /kindeditor/asp/upload_json.asp
  /kindeditor/attached/                  ← post-upload path
```

### 2.3 Information-disclosure paths (by WooYun-case hit rate)

```
Version-control disclosure (560 cases):
  /.git/config                          Git remote address
  /.git/HEAD                            branch
  /.git/index                           index
  /.svn/entries                         SVN 1.6
  /.svn/wc.db                           SVN 1.7+

Backup archives (530 cases of wwwroot.rar):
  /wwwroot.rar         /wwwroot.zip      /www.zip
  /web.rar             /web.zip          /backup.zip
  /site.tar.gz         /db.sql.gz        /{domain}.zip
  /{domain}.rar        /backup.sql.gz

SQL backups (136 cases of backup.sql):
  /backup.sql          /database.sql     /db.sql
  /dump.sql            /{dbname}.sql     /data.sql

Config backups (101 cases of config.php.bak):
  /config.php.bak      /web.config.bak   /.env.bak
  /config_global.php.bak                 /uc_server/data/config.inc.php.bak

PHP probes (47/38/34 cases):
  /phpinfo.php         /info.php         /test.php
  /1.php               /t.php            /probe.php
  /i.php               /debug.php

Logs (23 cases of Seeyon ctp.log):
  /ctp.log             /logs/ctp.log     /debug.log
  /error.log           /access.log       /application.log
  /runtime/logs/                         /storage/logs/

.NET config (36 cases of web.config):
  /web.config          /App_Data/        /bin/
  /connectionStrings.config
```

### 2.4 CN middleware admin panels (always scan for weak passwords)

```
Druid monitoring:
  /druid/index.html         /druid/sql.html
  /druid/weburi.html        /druid/login.html

Nacos:
  /nacos/                   /nacos/v1/auth/users

Apollo:
  /portal/                  /openapi/

Sentinel:
  /                         /resource/machineResource.json

XXL-JOB:
  /xxl-job-admin/           /xxl-job-admin/jobinfo

DolphinScheduler:
  /dolphinscheduler/ui/     /dolphinscheduler/login

RuoYi (must brute-force, almost wide open):
  /admin/                   /system/user
  /monitor/                 /tool/swagger

JeecgBoot:
  /jeecg-boot/              /sys/user

Alibaba Cloud SLS / Tencent CLS console (occasionally self-deployed on-cloud SaaS):
  /cls/                     /sls/
```

### 2.5 NMS / carrier systems

```
Huawei:
  /web/                     /eMaster/    /U2000/
  /uweb/                    /system/login.do

ZTE:
  /netnumen/                /web-portal/

Fiberhome:
  /OTNM2000_ch/             /OTNM2000/

Telecom operations systems:
  /BOSS/                    /CRM/      /AAA/
  /CSM/                     /partner/

Provincial-branch access:
  /webCompAction.do         parameter PARENTTYPEID
  /sso-server/
  /LoginLBS/
```

### 2.6 Monitoring / ticketing / internal systems

```
zabbix:
  /zabbix/                  /zabbix/api_jsonrpc.php

BlueKing (Tencent):
  /console/                 /uac/login

Grafana:
  /login                    /api/datasources

Prometheus:
  /                         /metrics

Jaeger / Skywalking:
  /jaeger/                  /api/

CN ticketing / BI:
  /smartbi/                 SmartBI reporting
  /finereport/              FanRuan FineReport
  /webroot/decision/        FineReport decision platform
```

---

## 3. High-frequency parameter dictionary (based on 27,732 SQLi + business cases)

### 3.1 High-frequency SQL-injection parameters (drop straight into a fuzz wordlist)

```
id (12 cases)     action (5 cases)  aid (3 cases)     typeid (2 cases)
typeId (2 cases)  username (2 cases) act (2 cases)    m (2 cases)
y (2 cases)       a (2 cases)       method (1 case)   bid (1 case)
mid (1 case)      out_trade_no (1 case)
fileName (1 case) siteId (1 case)   dir (1 case)      systemID (1 case)
PARENTTYPEID (1 case)  Channel (1 case) sameName (1 case)  selfilePath (1 case)
token (1 case)    ObjName (1 case)  MODE (1 case)     Target (1 case)
Title (1 case)    rd (1 case)       version (1 case)  newsid (1 case)
categoryid (1 case) puid (1 case)   c (1 case)        k (1 case)
o (1 case)        cmd (1 case)      trueName (1 case)
```

> Usage: feed the parameter names above into sqlmap `--param-filter` or your own fuzzer to scan first. Hit rate is a tier above generic `id/name/q`.

### 3.2 High-frequency business-logic parameters

```
Password reset:
  phone / mobile / username / userName / userAccount
  code / smsCode / verifyCode / captcha / authCode
  token / step / reset_token

Broken access / IDOR:
  id / uid / userId / user_id / oid / orderId / order_id
  addrid / hotelid / file_id / msg_id / doc_id
  account_id / tenant_id / cust_id / employeeid

Payment / order:
  amount / price / total / fee / total_fee
  quantity / count / num
  productId / sku / goodsId
  status / payStatus / orderStatus
  out_trade_no / trade_no / nonce_str
  mch_id / appid / sign / signature
  notify_url / return_url / callback_url

Authorization tampering:
  role / role_id / isAdmin / is_admin / level
  permissions / authorities / aid

Callback / redirect:
  url / redirect / redirect_uri / callback
  jumpurl / next / continue / returnUrl

File operations:
  fileName / file / path / dir / filepath
  filename / file_path / fileLocation

Telecom-specific:
  phone / mobile / mob / acc_nbr
  cust_id / serv_id / pkg_id
  cardId / iccid / imsi / imei

Log / debug:
  debug / test / sandbox / env
```

### 3.3 High-frequency fields for arbitrary-X sub-authorization

```
Stuff admin at registration:
  role=admin          is_admin=true       admin=1
  level=9             role_id=1           permissions=["*"]
  authorities=["ROLE_ADMIN"]              userType=0

Change the account at login:
  username=admin      userAccount=admin
  X-User-Id: 1        X-Real-User: admin  X-Original-User: admin
  Cookie: userId=1; isAdmin=1; role=admin

Signature bypass:
  sign=""             sign=null           remove the sign field
  signature=00000000  signature=anything

Forge internal source:
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  Forwarded: for=127.0.0.1
```

---

## 4. High-frequency URL path patterns (fuzzing wordlist)

### 4.1 Backend paths (common on CN sites)

```
/admin/             /admin.php          /admin/index.php
/manage/            /manage.php         /manager/
/houtai/            /admincp/           /system/login
/console/           /web-console/       /jmx-console/
/admin_login.aspx   /admin/Login.aspx   /Admin/Default.aspx
/login.do           /Login.jsp          /index.jsp?login
/web/login          /api/admin/login

Common on CN sites but easily overlooked:
/houtai             /guanli             /backstage
/bgmanage           /control            /portal/admin
/agent/             /shop/admin         /merchant/
/dealer/            /partner/login
```

### 4.2 API docs / debug

```
/swagger-ui.html    /swagger-ui/        /v2/api-docs
/v3/api-docs        /api-docs           /openapi.json
/swagger/           /swagger.json
/api/swagger
/druid/             /actuator/          /debug/
/test/              /dev/               /staging/
/api/v1/admin_is_login                  /api/configs
/api/debug          /api/version
```

### 4.3 CN mobile H5 / mini-program access

```
/wechat/            /weixin/            /mp/
/applet/            /miniapp/           /xcx/
/h5/                /m/                 /mobile/
/app/               /api/app/           /api/h5/
/wxLogin            /wx/login           /wechat/auth
/openid             /unionid
```

### 4.4 SP / CP / IoT (telecom-specific)

```
/sp/                /cp/                /sp-cp/
/sms/               /smsgw/             /sendSms
/iot/               /m2m/               /iot-card/
/billing/           /recharge/          /payment/
/order/charge       /api/charge

Parameters: phone / mobile / iccid / imsi / cardId / spid / appid
```

---

## 5. One-line fingerprint-detection command

```bash
# Check OA / middleware fingerprints
for path in /seeyon/ /general/login.php /defaultroot/login.jsp \
            /login/Login.jsp /oaerp/ /kdgs/ /sys/login/login.do \
            /druid/index.html /nacos/ /xxl-job-admin/ \
            /jeecg-boot/ /admin/ ; do
  curl -s -o /dev/null -w "%{http_code} $path\n" http://target$path
done

# Check for information disclosure
for path in /.git/config /.svn/entries /wwwroot.rar /backup.sql \
            /config.php.bak /phpinfo.php /web.config.bak /ctp.log ; do
  curl -s -o /dev/null -w "%{http_code} $path\n" http://target$path
done

# Check editors
for path in /FCKeditor/editor/filemanager/browser/default/connectors/test.html \
            /ewebeditor/admin/default.jsp \
            /ueditor/controller.jsp?action=config \
            /kindeditor/php/upload_json.php ; do
  curl -s -o /dev/null -w "%{http_code} $path\n" http://target$path
done
```

---

## 6. Links to playbooks / industry

```
playbooks/file-upload.md       →  this dictionary adds CN editor / OA upload paths
playbooks/info-disclosure.md   →  this dictionary adds the highest-hit-rate CN backup/log paths
playbooks/sqli.md              →  this dictionary adds high-frequency parameters from 27,732 SQLi cases
playbooks/unauth-access.md     →  this dictionary adds CN middleware / OA default paths
industry/banking-finance.md    →  common finance OA fingerprints (Seeyon / Yonyou / Kingdee)
industry/telecom-isp.md        →  common telecom NMS / SP platform paths
```

---

## 7. Red lines

- **Fingerprint ≠ vulnerability**. Identifying Seeyon OA is not the same as landing RCE; you still have to complete the evidence chain via the matching playbook.
- **Path requests** at ≤ 5 rps, to avoid fuzzing tripping a WAF / SOC.
- **After login**, do not perform write operations (creating users, uploading files, invoking commands).
- **The fingerprint library** is not for large-scale internet-wide scanning — use it only within SRC-authorized assets / HVV exercise scope.
