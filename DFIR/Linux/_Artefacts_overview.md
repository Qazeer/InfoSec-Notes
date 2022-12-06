# DFIR - Linux artefacts overview

### General

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| Audit `auditd` framework (`audit` logs) | - | Non default, can be configured to log multiple types of operations, such as authentication successes or failures, process executions, file accesses, user commands executed in a TTY, etc. | Each record / log entry contain a `msg` field, composed of a timestamp and an unique ID. Multiple records generated as part of the same Auditd event can share the same `msg` field. For example, `cat /etc/passwd` can generate `SYSCALL` + `EXECVE` records for the execution of `cat` and a `PATH` record for the access to the `/etc/passwd` file. <br><br> The `type` field contains the type of the record: <br><br> - User authentication and access: `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`, `USER_AUTH_SUCCESS`, `USER_AUTH_FAILED`, `USER_START_SUCCESS`, `USER_START_FAILED`, `SESSION_TERMINATED`. <br><br> - Process execution: `EXECVE` and `SYSCALL`. <br><br> - Filesystem access: `PATH` (for relative or absolute file access), `CWD` (current working directory, useful to reconstruct full path if a relative path has been recorded in `PATH` records) and `OPENAT`. <br><br> - Commands entered in a `TTY` console: `TTY` or by users: `USER_CMD`. <br><br> - Full command-line of process: `PROCTITLE`. The associated `proctitle` field MAY be encoded in hexadecimal. <br><br> - Network socket connections: `SOCKADDR`. The associated `saddr` field contains IP and port information, and can be interpreted directly at event generation (if `log_format = ENRICHED` is set), or with `ausearch -i` or [simple scripting](https://gist.github.com/Qazeer/3aaa6be263380483d68159cae6f33fd2). <br><br> - Account activity: `ADD_USER` or `ADD_GROUP`. <br><br> - More record types are listed in the [RedHat documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types). <br><br> If present, the `auid` field defines the ID of the user upon login and remains the same even if the user's identity changes (for instance with `su`). <br><br> If present, `uid` / `gid` and `euid` / `egid` fields define the user / group IDs and the effective user / group IDs of the audited process. <br><br> If present, the `tty` and `ses` fields define respectively the terminal and session from which the audited process was invoked. <br><br> For `SYSCALL` records, the `aX` field(s) define the arguments / parameters of the syscall, represented by unsigned long long integers and as such cannot be used to determine the values taken by the arguments. | Configuration file notably defining the path of the log files: <br> `/etc/auditd.conf` <br><br> Configuration defining the rules to apply: <br> `/etc/audit/audit.rules` <br> Rules best practice: https://github.com/Neo23x0/auditd <br><br> Current log files (default location): <br> `/var/log/audit/audit.log` <br> `/var/log/audit/audit.log.1` <br><br> Rotated log archives (default location): <br> `/var/log/audit/audit.log.*.gz` <br><br> The `aureport` and `ausearch` utilities can (and if possible should) be used to search the `auditd` log files. <br><br> Example: <br> `aureport -i [--login \| --executable \| ...] [--summary] -if <AUDIT_LOG_FILE>` | |

### System information

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `alternatives` logs | System information | Logs of the `update-alternatives` utility, used to manage *alternatives* (i.e symbolic links to a given command). | | `/var/log/alternatives.log` | |
| Environment variables information | System information. | Contains system-wide or user scoped persistent environment variables. | - | System-wide configuration file: <br> `/etc/environment` <br><br> Initialization scripts can also be used to define system-wide or user scoped environment variables. | - |
| Hostname information | System information | Contains the hostname of the system. | - | `/etc/hostname` | - |
| Mounted filesystems information | System information. | Contains information on the mounted file systems, such as partition types (ext3 / ext4, etc.). | | Configuration: <br> `/etc/fstab` <br><br> Mount logs (such as `Mounting` operation / keyword): <br> `/var/log/dmesg` | - |
| Timezone information | System information | Contains the timezone of the system. | - | `/etc/timezone` <br><br> `/etc/adjtime` <br><br> `/etc/localtime` | - |
| `Syslog` daemon configuration | System information | The `Syslog` deamon configuration file(s) notably define where the messages / events received by the `Syslog` daemon will be outputted. The messages are usually written as plaintext files under `/var/log/` but can also be sent over the network. | Example of a configuration file writing logs to common files: <br><br> auth,authpriv.* /var/log/auth.log <br> \*.\*;auth,authpriv.none -/var/log/syslog <br> kern.* -/var/log/kern.log <br> mail.* -/var/log/mail.log | `/etc/syslog.conf` <br> `/etc/rsyslog.conf` <br> `/etc/rsyslog.d/*.conf` <br> `/etc/syslog­ng.conf` <br> `/etc/syslog­ng/*` | - |

### Filesystem

###### Overview

Contrary to `NTFS` partitions, file information is not stored in a specific
location (such as the `MFT`) for `ext*` partitions but scattered across blocks
or groups of `blocks` (contiguous blocks combined) across the partition.
`Blocks` have a fixed size, determined at the time the filesystem is created.

On `ext4`, each `block group` notably store:
  - The `Super block`, only replicated at the beginning of a fraction of
    `block groups` however, which contains various information about the file
    system: block size, location of the `inode` tables, size of block groups,
    etc.

  - The `inode bitmap` and a `data block bitmap` that limit the number of
    `inodes` and `data blocks` of that particular `block group`.

  - An `inode table` which is a linear array of `inodes` (first to last
    `inode`) of that particular `block group`.

    `Inodes` are data struct that define a file and each file is associated
    with one `inode`. An `inode` stores metadata about the file (size, owner
    `UID` / `GID`, permissions, timestamps, etc.) and (direct or indirect)
    pointers to `data blocks` that contain the file data, but does not store
    the file name and file data.

  - `Data blocks`, that store file data.

###### Filesystem types supported timestamps

| Filesystem | atime (access) | mtime (modification) | ctime (metadata change) | crtime (creation / birth) | Comment |
|------------|----------------|----------------------|-------------------------|---------------------------|---------|
| `ext2` <br> `ext3` | x | x | x | - | |
| `ext4` | x | x | x | x | |
| `XFS` | x | x | x | x* | * Since `XFS v5` |

###### Filesystem timelining

```bash
find <DIRECTORY> -xdev -print0 | xargs -0 stat -c 'crtime="%w" crtime_epoch="%W" mtime="%y" mtime_epoch="%Y" ctime="%z" ctime_epoch="%Z" atime="%x" atime_epoch="%X" size_bytes="%s" userID="%u" username="%U" groupID="%g" groupname="%G" access="%a" access_pretty="%A" filetype="%F" filename="%n" filename_deref="%N"'
```

### Software installation and program execution

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `apt` / `apt-get` logs | Software installation | Logs of `apt-get` / `apt` operations, including packets installation. | | Current log file: <br> `/var/log/apt/history.log` <br><br> Rotated log archives: <br>`/var/log/apt/history.log.*.gz` |
| `aptitude` logs | Software installation. | Logs of the `aptitude` utility (front-end to `apt`) operations, including packets installation. | | `/var/log/aptitude` | |
| `dpkg` logs | Software installation. | Logs of `dpkg` operations, including packets installed / removed through the utility. | | Current log files: <br> `/var/log/dpkg.log` <br> `/var/log/dpkg.log.1` <br><br> Rotated log archives: <br>`/var/log/dpkg.log.*.gz` | |

### Files and folders access

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|

### Remote Access / Lateral movements

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `Authorization (auth)` logs | Remote Access / authentication information | Authentication information and `sudo` commands. More precisely, usage of authorization systems: successful or unsuccessful logins, sudo commands, etc. <br><br> Usually generated by the `AUTH` and `AUTHPRIV` facilities of the `syslog` daemon. `AUTH` regroups the authentication events / messages while `AUTHPRIV` regroups the elevation of privileges events / messages (such as commands executed through `sudo`). | Notably includes: <br><br> - Successful or unsuccessful logins to the `sshd` deamon. The authentication types (password, pubkey, etc.) or reason of failure (unknown user, invalid password) is specified. <br><br> - Commands executed with elevated privileges using `sudo`. | *Location of the `auth` logs depend of the `syslog` daemon configuration (refer to the "Syslog daemon configuration" artefact below for more information).* <br><br> [Debian / Ubuntu based systems] <br><br> Default location: <br> `/var/log/auth.log` <br> `/var/log/auth.log.1` <br><br> Rotated log archives: <br> `/var/log/auth.log.*.gz` <br><br> [RedHat / CentOS based systems] <br><br> Default location (for `AUTHPRIV` logs): <br> `/var/log/secure` | |
| Login records `*tmp` | Remote Access / authentication information | `utmp` / `utmpx`: currently logged users. <br><br> `wtmp` / `wtmpx`: all current and past logins, with additional details on system reboots, etc. <br><br> `btmp` / `btmpx`: all bad login attempts. <br><br> The `*tmpx` files are extended database files that supersede the `*tmp` files on some distributions. | | Linux: <br> `/var/run/utmp` <br> `/var/log/wtmp` <br> `/var/log/btmp` <br><br> Solaris: <br> `/var/adm/utmp` (deprecated) <br> `/var/adm/utmpx` <br> `/var/adm/wtmp` (deprecated) <br> `/var/adm/wtmpx` <br><br> FreeBSD 9.0: <br> `/var/run/utx.active` (`utmp` equivalent) <br> `/var/log/utx.log` (`wtmp` equivalent) | `*tmp` login records are not stored in clear-text and must be parsed with adequate utilities, such as `utmpdump <*TMP_FILE>`. |
| `SSH` known hosts | Lateral movement | Possible `SSH` outgoing connections. <br><br> System-wide or user scoped known `SSH` keys for remote hosts. Usually collected, and user-validated, from the remote hosts when connecting for the first time. | The remote hosts hostname and IP address can be either stored in clear-text or hashed if `HashKnownHosts` is set to "yes" in the `SSH` client `ssh_config` configuration file. <br> Even if the hosts information are hashed, the following command can be used to check whether the specified hostname is present in the given known hosts file: <br> `ssh-keygen -l -f <KNOWN_HOST_FILE> -F <HOSTNAME>`. <br> Additionally, `John` can be used to bruteforce known hosts files: <br> `john --format=known_hosts <KNOWN_HOST_FILE>` <br><br> `nmap -sL -Pn -n 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 \| grep '^Nmap scan report for' \| cut -d ' ' -f 5 > IP_list.txt` <br> `john --wordlist=IP_list.txt --format=known_hosts <KNOWN_HOST_FILE>` <br><br> One of the few endpoint disk artefacts to identify outgoing `SSH` connections. | System-wide known hosts: <br> `/etc/ssh/known_hosts` <br><br> `<USER_HOME_DIR>/.ssh/known_hosts` | |

### Local persistence

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `at` jobs (`atd` daemon) | Persistence | Scheduled jobs that are configured using the `at` command-line utility to be run exactly one time. By default, any user can create `at` jobs. The jobs are executed as shell (bash, zsh, etc.) scripts. | Each `at` jobs is represented by a file, which contains metadata information as comments, the environment variables for the execution, and the configured shell script / commands. <br><br> The filename follows a specific format (`[a=]<JOB_NUMBER_5_CHAR><TIMESAMP_8_CHAR>`) and gives additional information about the job. The following information can be deduced from the file name and the file itself: <br> - File created or last modified timestamp => when the `at` job was created. <br> - Username, `uid`, and `gid` of the user that created the job as shell comments in the file. <br> - Filename first char: `a` => job is pending or `=` => job is running. <br> - Filename 5 next chars => job id. <br> - Filename 8 next (and last) chars => hex-encoded minutes since `epoch` timestamp. Can be converted to retrieve the `epoch` timestamp of execution by converting to decimal and multiplying by 60. | Configured `at` jobs locations, each files representing a single `at` job: <br> `/var/spool/at/` <br> `/var/spool/cron/atjobs/` <br><br> Configuration files that define the users that can or cannot create `at` jobs: <br> `/etc/at.allow` <br> `/etc/at.deny` <br><br> Output of currently running `at` jobs, saved as email text files: <br> `/var/spool/at/spool/` <br> `/var/spool/cron/atspool/` <br><br> Number of `at` jobs that have been created (already executed, executing, or scheduled): <br> `/var/spool/at/.SEQ` <br> `/var/spool/cron/atjobs/.SEQ` <br><br> Trace of previous `at` jobs execution can be found in: <br> - Session opening by the `atd` daemon events in `syslog` or `journal` logs. <br> - `at` jobs email sent events in local email logs. | |
| `Run Control (RC)` scripts | Persistence | Deprecated mechanism, in favor of `Systemd` / `init.d`, to define and start services as shell scripts at the system startup. <br><br> Scripts are configured to be executed at different run levels, from `0` (stop) to `6` (reboot) through `1` (maintenance mode) and `2-5` (multi-users mode, such as desktop startup, etc.). | | `RC` scripts locations: <br> `/etc/rc.local` <br><br> `/etc/rc.common` <br><br> `/etc/rc<0-6>.d/*` <br> `/etc/rcS.d/*` | |
| Shell initialization scripts | Persistence | System-wide or user scoped scripts that are executed by shells during their different stages of their initialization. | | User scoped initialization script: <br> `<USER_HOME_DIR>/.profile` <br> `<USER_HOME_DIR>/.bash_profile` <br> `<USER_HOME_DIR>/.zprofile` <br> `<USER_HOME_DIR>/.bash_login` <br> `<USER_HOME_DIR>/.zlogin` <br><br> System-wide initialization scripts: <br> `/etc/profile` <br> `/etc/profile.d/*` <br> `/etc/skel/.profile` (Not used if `<USER_HOME_DIR>/.bash_profile` or `<USER_HOME_DIR>/.bash_login` exist). <br><br> Executed if an interactive shell is opened: <br> `<USER_HOME_DIR>/.bashrc` <br> `<USER_HOME_DIR>/.zshrc` <br><br> Executed at the end of the session: <br> `<USER_HOME_DIR>/.bash_logout` <br> `/etc/zlogout` <br> `<USER_HOME_DIR>/.zlogout` | |
| `SSH` authorization keys | Persistence | Specifies the `SSH` keys that can be used for logging into the user account for which the file is configured, thus allowing permanent access as that user. | | Configuration of the `SSH` authorization keys: <br> `/etc/ssh/sshd_config` `AuthorizedKeysFile`directive. <br><br> Default `SSH` authorization keys location: <br> `<USER_HOME_DIR>/.ssh/authorized_keys` <br> `<USER_HOME_DIR>/.ssh/authorized_keys2` | |
`XDG` autostart entries | Persistence | XDG compliant graphical / desktop systems support `XDG` autostart entries, allowing applications to automatically start during the startup of a desktop environment (after user logon). | Each `XDG` autostart entry is represented by a file, which contains the following notable keys: <br> - `Type` key that specifies the entry type (application, link, or directory). <br> - `Name` key that indicates an arbitrary name assigned by the autostart entry creator. <br> - `Exec` key that defines the application and command line arguments to be executed. | User scoped initialization autostart entries: <br> `<USER_HOME_DIR>/.config/autostart/*.desktop` <br><br> System-wide autostart entries: `/etc/xdg/autostart/*.desktop` | |
| Webshell | Command execution / Persistence. | Simply put, webshells are script files that are executed by a webserver. Webshells are notably leveraged to: <br><br> - execute code / commands on the underlying operating system following the exploitation of a web vulnerability (unrestricted file upload, remote code execution, etc.) <br><br> - maintain persistence following the compromise of an host exposing a webserver (usually Internet facing). | | Usual locations: <br> `/var/www/html` <br> `/usr/local/www/` <br><br> `/etc/nginx` <br><br> `/etc/apache2` <br><br> `/srv/` <br> `/srv/www` <br><br> `...` | Webshells can be uncovered by: <br> - Yara rules aimed at webshells such as [`Neo23x0's gen_webshells.yar`](https://github.com/Neo23x0/signature-base/blob/master/yara/gen_webshells.yar) or [`thor-webshells.yar`](https://github.com/nsacyber/WALKOFF-Apps/blob/master/AlienVault/signature-base/yara/thor-webshells.yar): <br> `yara -r <YARA_RULE_PATH> <WEBSERVER_ROOT>` <br><br> - Reviewing added files or modifications in legitimate files using code repository or a fresh install of the application if possible. <br><br> - Manually by looking for known webshell patterns (`Runtime.getRuntime().exec`, `eval`, `system`, etc.), obfuscated script files, or files modified during the targeted timeframe. <br><br> - Reviewing the webserver access logs if available, looking for exploitation IoCs, unusual requests, large response size, etc. |

### Web browsers and network usage

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `wget` HSTS history | Web browsers and network usage | `wget` utility's `HTTP Strict Transport Security (HSTS)` history. <br><br> `HSTS` is a mechanism to only allow access to a particular website in `HTTPS` if that website was accessed in `HTTPS` once and defines an `HSTS` policy. The `HSTS` policy to follow is define by the web server through the `Strict-Transport-Security` `HTTP` response header. The web browser or utility has to store the websites accessed in `HTTPS` (with `HSTS` implemented) for the duration specified in the header to support `HSTS`. | `wget`'s `HSTS` history is implemented as a plaintext file, with an entry per line. <br><br> For each entry, the following notable information are available: <br><br> - Hostname of the accessed website <br> - Created timestamp in `UTC` (in `epoch` format) that defines when the entry was created. As the entry is overwritten upon new access to a website defining an `HSTS` policy, the created timestamp matches the last access to the website. | `<USER_HOME_DIR>/.wget-hsts` | - |

### Web servers and third-party applications logs

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `Apache` webserver logs | Web servers logs | Logs of the `Apache` webserver. | | Debian / Ubuntu: <br> ` /var/log/apache2/access.log` <br> `/var/log/apache2/error.log` <br><br> RHEL / Red Hat / CentOS / Fedora : <br> `/var/log/httpd/access_log` <br> `/var/log/httpd/error_log` <br><br> FreeBSD: <br> `/var/log/httpd-access.log` <br> `/var/log/httpd-error.log` <br><br> Custom definition for access (`CustomLog ` section) or error (`ErrorLog` section) logs: <br> `/etc/httpd/conf/httpd.conf` <br> `/etc/apache2/apache2.conf` <br> `/usr/local/etc/apache22/httpd.conf` | |

### TODO

---

cron / anacron jobs

The cron and anacron programs allow you to schedule the execution of tasks. Unlike at, they allow you to create tasks that are executed repeatedly at a given frequency. There are two differences between cron and anacron:

If the system is not running when a cron job is planned, it is not executed until the next planned execution whereas missed anacron jobs are run as soon as the system boots;
Anacron jobs cannot be run more than once a day.

Only root can modify /etc/crontab or add files to /etc/cron.d. But, if some users are allowed to use the crontab command, their cron jobs are added to /var/spool/cron. Usage rights of cron are defined by /etc/cron.allow and /etc/cron.deny files. There are three possible cases:

If cron.allow exists, only root and users listed in this file can use cron. cron.deny is ignored;
If only cron.deny exists, all users except ones listed in this file can use cron;
If none of these files exists, only root can use cron.

/etc/crontab
/etc/anacrontab

/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/etc/cron.monthly/
/etc/cron.weekly/
/var/spool/cron/<USERNAME>/

/etc/cron.allow
/etc/cron.deny

Logs in:

---

journactl

---

| systemd services | Persistence | The `systemd service manager` is used for managing background daemon processes, known as `services`. <br><br> `systemd` relies on `service units`  |  |  System-wide `service unit` files: <br> `/usr/lib/systemd/system/*` <br> `/etc/systemd/system/*` <br><br> User-scoped `service unit` files for user-level persistence: <br> `<USER_HOME_DIR>/.config/systemd/user/` | yara rules |

Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the /etc/systemd/system and /usr/lib/systemd/system directories and have the file extension .service. Each service unit file may contain numerous directives that can execute system commands:

*Systemd* also defines several *unit types*:

 * *Service*: the unit starts, stops, restarts or reloads programs or daemons;
 * *Socket*: the unit is activated when it receives incoming traffic on a listening socket or in the context of inter-process communication;
 * *Target*: groups of units used at boot time to start the system in a particular state;
 * *Device*: the unit is activated when a device is connected to the Linux system;
 * *Mount*: the unit controls file system mount points;
 * *Automount*: the unit controls on-demand mounting of file system;
 * *Timer*: the unit is activated at specific times;
 * *Swap*: the unit encapsulates, activates or deactivates swap partitions or files;
 * *Path*: the unit is activated when a monitored file is modified;
 * *Slice*: group of units that manage system resources;
 * *Scope*: the unit organizes and manages foreign processes.

ExecStart, ExecStartPre, and ExecStartPost directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start.
ExecReload directive covers when a service restarts.
ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'.

[Unit] Description=Myservice
[Service] ExecStart=/tmp/46868461631.tmp/malw4re

https://attack.mitre.org/techniques/T1543/002/

---

shell history

shell histories are only filled in when the shell is closed

---

init.d

---

Network configuration

Before systemd:

Red Hat and SUSE systems
/etc/sysconfig/network-scripts/
/etc/sysconfig/network/
SUSE-only: /etc/wicked/

Debian-based systems

/etc/network/interfaces
/etc/network/interfaces.d/

Systemd:

systemd provides its own network management features. It is based on three types of file:

.link files to configure physical network devices;
.netdev files to configure virtual netowrk devices (VPN, tunnels...);
.network files to configure the network layer.
All these files are stored in the following directories:

/usr/lib/systemd/network/ (default files used by systemd daemons systemd-udevd and systemd-networkd);
/etc/systemd/network/ (customized files by the system administrator).

Network Manager can also be used to manage network configuration
/etc/NetworkManager.conf (general configuration information);
/etc/NetworkManager/system-connections/ (configurations for each individual connection, declined by name).

---

DNS nameservers and hosts

/etc/resolv.conf
/etc/resolv.conf.bak

The /etc/resolv.conf file is managed either by the openresolv resolvconf framwork or by the systemd's resolvconf framework. The systemd-resolved daemon is configured in the /etc/systemd/resolved.conf file. This file contains the daemon parameters, DNS servers, fallback servers and other DNS resolver configuration. The openresolv framwork stores the same information in the /etc/resolvconf.conf file.

/etc/hosts

---

/etc/network/if-up.d/upstart

/etc/apt/apt.conf.d - persistence

/etc/udev/rules.d/

`<USER_HOME_DIR>/.viminfo`

/etc/security/lastlog	Specifies the path to the lastlog file.

/etc/group	Contains the basic attributes of groups.

/etc/security/group	Contains the extended attributes of groups.

/etc/passwd	Contains the basic attributes of users.

/etc/security/passwd	Contains password information.
=> Check user with shell and that have a different uid / gid than default.

/etc/security/environ	Contains the environment attributes of users.

/etc/security/user	Contains the extended attributes of users.

/etc/security/limits	Contains the process resource limits of users.
https://www.ibm.com/docs/en/aix/7.1?topic=formats-lastlog-file-format

USB devices activity will generate kernel logs, usually in `/var/log/kern.log`
and `Syslog` centralized logs (such as `/var/log/syslog`) depending on the
syslog daemon configuration.

---

motd
message of the day

https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#10-boot-or-logon-initialization-scripts-motd

---

--------------------------------------------------------------------------------

### References

https://www.sciencedirect.com/science/article/pii/S1742287612000357

https://wiki.debian-fr.xyz/Consulter_les_logs_:_quoi,_o%C3%B9_et_comment_chercher_%3F

https://nostarch.com/download/samples/PracticalLinuxForensics_Ch5_072721.pdf

https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/

https://sematext.com/blog/auditd-logs-auditbeat-elasticsearch-logsene/

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files

https://www.elastic.co/fr/blog/grokking-the-linux-authorization-logs

https://unix.stackexchange.com/questions/31549/is-it-possible-to-find-out-the-hosts-in-the-known-hosts-file

https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/

https://en.wikipedia.org/wiki/Utmp

https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/

https://attack.mitre.org/techniques/T1547/013/
