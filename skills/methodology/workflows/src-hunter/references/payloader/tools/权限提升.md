# Privilege Escalation

_3 tool commands_

### Linux Privilege Escalation Commands  `linux-privilege`
_Common Linux privilege escalation commands_

**Step 0**
> Get system version information
_platform: linux_
```
uname -a
cat /etc/issue
cat /etc/*-release
cat /proc/version
```

**Step 0**
> Get user information
_platform: linux_
```
id
whoami
w
last
cat /etc/passwd
cat /etc/shadow
```

**Step 0**
> Find files with the SUID permission
_platform: linux_
```
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```
**Syntax breakdown:**
- `-perm -4000` — SUID permission bit _parameter_
- `-type f` — file type _parameter_

**Step 0**
> Check SUDO permission configuration
_platform: linux_
```
sudo -l
cat /etc/sudoers
```

**Step 0**
> Find writable directories
_platform: linux_
```
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
```

**Step 0**
> Search for kernel vulnerabilities
_platform: linux_
```
searchsploit linux kernel $(uname -r)
./linux-exploit-suggester.sh
```

**Step 0**
> View scheduled tasks
_platform: linux_
```
cat /etc/crontab
ls -la /etc/cron*
crontab -l
```

**Step 0**
> View environment variables
_platform: linux_
```
env
set
echo $PATH
```

**Step 0**
> Find sensitive files
_platform: linux_
```
cat /root/.bash_history
cat ~/.ssh/authorized_keys
cat /etc/shadow
find / -name "*.key" 2>/dev/null
```

**Step 0**
> Detect a Docker environment
_platform: linux_
```
cat /proc/1/cgroup
fdisk -l
capsh --print
```

---

### WinPEAS  `winpeas-tool`
_Windows privilege escalation helper tool_

**Step 0**
> Run a full privilege escalation scan
_platform: windows_
```
winpeas.exe
```

**Step 0**
> Fast scan mode
_platform: windows_
```
winpeas.exe fast
```

**Step 0**
> Show detailed command output
_platform: windows_
```
winpeas.exe cmd
```

**Step 0**
> Save scan results
_platform: windows_
```
winpeas.exe > output.txt
```

---

### LinPEAS  `linpeas-tool`
_Linux privilege escalation helper tool_

**Step 0**
> Run a full privilege escalation scan
_platform: linux_
```
./linpeas.sh
```

**Step 0**
> Automatic discovery mode
_platform: linux_
```
./linpeas.sh -a
```

**Step 0**
> Check password policy
_platform: linux_
```
./linpeas.sh -P
```

**Step 0**
> Save scan results
_platform: linux_
```
./linpeas.sh > output.txt
```

---
