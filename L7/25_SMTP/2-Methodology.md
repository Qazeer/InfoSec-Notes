# Simple Mail Transfer Protocol (SMTP) - Methodology

### User Enumeration

The EXPN, VRFY and RCPT commands can be used, if they have not been disabled,
to enumerate valid username.  

The EXPN command is used to reveal the actual address of users aliases and lists
 of email. The VRFY command can confirm the existance of names of valid users.

The enumeration can be conducted manually using the telnet or netcat tools or
automatically using metasploit, nmap or smtp-user-enum.

#### Manual enumeration

The following commands can be used to check if the EXPN, VRFY and RCPT commands
are available and to manually enumerate valid usernames and emails:

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

#### Automatic enumeration

The smtp-user-enum can be used to automatically enumerate usernames:

```
smtp-user-enum [-M EXPN/VRFY/RCPT ] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )
```

Quick bash oneliner:

```
for x in $(cat <USERFILE>); do echo VRFY $x | nc -nv -w 1 <TARGET> <PORT> 2>/dev/null | grep ^’250’; done
```

The *smtp-enum-users* nmap script and the *auxiliary/scanner/smtp/smtp_enum*
metasploit module can be used as well.

### Open relay

An SMTP server that works as an open relay, is a email server that does not
verify if the user is authorised to send email from the specified email
address. Therefore, users would be able to send email originating from any
third-party email address.

While fully open relay is not that usual, "Partially Open Mail Relay" are more
common.  
This occurs when the mail relay can be used to do one of the following:
  - email from an external source address to an internal destination address ;
  - email from an internal source address to an internal destination address.

#### Manual exploitation

the following commands can be used to mannually exploit an open relay SMTP
server:

```
telnet/nc <IP> <PORT>
HELO
MAIL FROM:user@mydom.com
RCPT TO:user@otherdom.com
DATA
.
```

If relaying is not permitted, the server should respond with an erorr message
"Relaying denied".

#### Automatic detection and exploitation

The *smtp-open-relay.nse* nmap script can be used to detect open relay.  

The *scanner/smtp/smtp_relay* metasploit module can be used to exploit a
misconfigured server.
