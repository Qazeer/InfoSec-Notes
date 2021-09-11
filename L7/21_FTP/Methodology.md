# FTP - Methodology

### Overview

The `File Transfer Protocol (FTP)` protocol is a standard network protocol
used for the transfer of files between a client and server on a network. The
`FTP` protocol operates at the `Application Layer (L7)` layer of the `OSI`
model.

`FTP` is built on a client-server model architecture and uses separate control
and data connections between the client and the server. `FTP` users may
authenticate themselves with a clear-text sign-in protocol, normally in the
form of a username and password, but can connect anonymously if the server is
configured to allow it.

For secure transmission that protect, through encryption using cryptographic
protocols, the username and password as well as the data transferred, `FTP` is
often secured with an additional `SSL`/`TLS` layer (`FTPS`). The
technologically different `SSH File Transfer Protocol (SFTP)` protocol achieves
the same purpose, by providing file access, transfer, and management
capabilities over the `Secure Shell protocol (SSH)` protocol. `FTPS` is
associated by default with the `TCP` port 990 while `SFTP`, a subsystem of
`SSH`, is usually used over the `TCP` port 22.

For file transfers or directory listings, `FTP` opens additional `TCP`
connections on dynamic ports. In active mode the client creates a local
listener and let the server know about its IP and port combination using the
`PORT` command and the server then connects to the clients port (usually from
port 20 on the server side). In passive mode the server opens the port and let
the client know where it listens in response to the clients `PASV` command.

### Network scan

[`nmap`](https://nmap.org/) can be used to discover open `FTP` service and
conduct basic recon operations:  

```
nmap -v -sT -A -p 21 <IP | RANGE | CIDR>
```

### Anonymous login

`FTP` services may allow anonymous connections with the `anonymous` or `ftp`
accounts, i.e login that do not require the knowledge of a password to connect.
Some `FTP` services may however parse the password to ensure it looks like a
valid email address, so in doubt, it is recommended to always provide an email
address as password whenever attempting an anonymous login.

`nmap`'s default `NSE` script scan (`-sC` option, included with `-A`) will
attempt anonymous login on the discovered `FTP` services. To specifically scan
the network for `FTP` services supporting anonymous login, the following
command can be used:

```
nmap -v -p 21 -sV --script ftp-anon.nse <IP | RANGE | CIDR>

ftp <HOST | IP>
Name: anonymous
Password: fake@email.com
```

### Authentication brute force

The [patator](https://github.com/lanjelot/patator) Python multi-purpose
brute-forcer can be used to brute force credentials on exposed `FTP` / `FTPS`
services:

```
patator ftp_login host=<TARGET> user=FILE0 password=FILE1 0=<WORDLIST_USERS> 1=<WORDLIST_PASSWORDS> [tls=<0 | 1>]-x ignore:mesg='Login incorrect.' -x ignore:mesg='User cannot log in.' -x ignore,reset,retry:code=500
```

### FTP clients

###### [Linux | Windows] FTP Linux basic CLI client

The Linux or Windows built-in `ftp` clients can be used to connect and interact
with an `FTP` service.

```
# Connects to the specified FTP service.
ftp <HOSTNAME | IP>
ftp> open <HOSTNAME | IP>

# Lists the remote files.
ftp> dir
ftp> ls

# Changes the working directory on the remote system.
ftp> cd

# Changes the working directory on the local system.
ftp> lcd

# Sets the transfer mode to binary, which is required to maintain the integrity of non-ASCII files.
# Expected response: "# 200 Type set to I".
ftp> binary

# Toggles the interactive mode on and off, which can be used to avoid confirmation whenever using the mget or mput commands.
ftp> prompt

# Prints the specified file content without downloading the file locally.
ftp> get <REMOTE_FILE> -

# Downloads the specified file.
ftp> get <REMOTE_FILE> [<LOCAL_NAME>]

# Downloads the files matching the specified regex.
ftp> mget <* | *.txt | ...>

# Uploads the specified file.
ftp> put <LOCAL_FILE> [<REMOTE_NAME>]

# Uploads the files matching the specified regex.
ftp> mput <* | *.txt | ...>
```

###### [Linux] Recursive FTP download using wget

The `wget` utility can be used to recursively download every files from a given
FTP server:

```
wget --mirror ftp://anonymous:nopass@<IP>:<PORT>
wget --mirror ftp://<USER>:<PASSWORD>@<IP>:<PORT>

# The --no-passive option can be used to disable passive mode for FTP connections failing after the PASV command.
wget --no-passive --no-parent --mirror ftp://<USER>:<PASSWORD>@<IP>:<PORT>
```

###### [Linux | Windows] FileZilla

[`FileZilla`](https://filezilla-project.org/) is a cross-platforms, open source
and feature-rich client with a graphical user interface that support the `FTP`,
`FTPS`, and `SFTP` protocols.

--------------------------------------------------------------------------------

### References

https://linux.die.net/man/1/ftp
