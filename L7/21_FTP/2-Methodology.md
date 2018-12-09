# FTP - Methodology

#### Overview

The **File Transfer Protocol** (FTP) is the standard network protocol used for
the **transfer of computer files between a client and server** on a computer
network.

FTP operates in the **Application Layer (L7)** of the Internet Protocol Suite
of the OSI model.

FTP is built on a **client-server model architecture** and uses separate control
and data connections between the client and the server.

FTP **users may authenticate themselves with a clear-text sign-in protocol**,
normally in the form of a username and password, but can connect anonymously if
the server is configured to allow it.

For **secure transmission** that protects the username and password, and
encrypts the content, FTP is often secured with **SSL/TLS (FTPS)**.
SSH File Transfer Protocol (SFTP) is sometimes also used instead;
it is technologically different.

### Network scan

Nmap can be used to detect open FTP service and conduct basic recon scan:  

```
nmap -v -sS -A -p 21 <HOST>
```

### Anonymous logging

The server may allow anonymous connections with the *anonymous* or *ftp*
accounts. No password is required to connect as an anonymous. Some FTP services
parse the password to ensure it looks like an email address, so in doubt, its
recommended to always provide an email address as password.

The default script (-sC, included with -A) nmap scan will try for anonymous
login. To specifically scan the network for FTP services supporting anonymous
login, the following command can be used:

```
nmap -v -p 21 --script ftp-anon.nse <RANGE/CIDR>

ftp <HOST | IP>
Name: anonymous
Password: fake@email.com
```

### Authentication brute force

The patator tool can be used to brute force credentials on the service:

```
patator ftp_login host=<TARGET> user=FILE0 password=FILE1 0=<WORDLIST_USERS> 1=<WORDLIST_PASSWORDS> -x ignore:mesg='Login incorrect.' -x ignore:mesg='User cannot log in.' -x ignore,reset,retry:code=500
```

### FTP clients

###### FTP Linux basic CLI client

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
wget --mirror ftp://anonymous:nopass@<IP>:<PORT>
wget --mirror ftp://<USER>:<PASSWORD>@<IP>:<PORT>
```
