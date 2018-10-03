# FTP - Methodology

### RECON

Nmap can be used to detect open FTP service and conduct basic recon scan:  

```
nmap -v -sV -sC -p <PORT> <TARGET>
```

### EXPLOITATION

#### Anonymous logging

The server may allow anonymous connections with the *anonymous* or *ftp*
accounts.
No password is required to connect as an anonymous.

#### Bruteforce

To bruteforce FTP credentials, the following tools can be used:

```
patator ftp_login host=<TARGET> user=FILE0 password=FILE1 0=<WORDLISTUSER> 1=<WORDLISTPASSWORD> -x ignore:mesg='Login incorrect.' -x ignore:mesg='User cannot log in.' -x ignore,reset,retry:code=500
```

### POST EXPLOITATION

To get the file integrity while downloading, use the binary mode:

```
ftp> binary
# 200 Type set to I.
```

Print file from FTP session:

```
get <FILE> -
```

Download file from FTP session:

```
get <FILE>
```

Download every files from the FTP server:

```
wget --mirror ftp://<USER>:<PASSWORD>@<IP>:<PORT>
```
