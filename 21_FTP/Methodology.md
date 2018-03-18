# FTP - Methodology

### RECON

###### Scan Nmap
`nmap -A -p <PORT> <IP>`

###### Banner grabing
`ftp <IP>`

###### Anonymous logging
The server may allow anonymous connections with the *anonymous* or *ftp*
accounts.
No password is required with those accounts.

### EXPLOITATION

###### Bruteforce

```bash
patator ftp_login host=<IP> user=FILE0 password=FILE1 0=<wordlist_user> 1=<wordlist_password> -x ignore:mesg='Login incorrect.' -x ignore:mesg='User cannot log in.' -x ignore,reset,retry:code=500
```

### POST EXPLOITATION

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
