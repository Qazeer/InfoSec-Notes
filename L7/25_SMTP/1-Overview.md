# Simple Mail Transfer Protocol (SMTP) - Overview

Simple Mail Transfer Protocol (SMTP) is an Internet standard for **electronic
mail transmission**.

SMTP operates in the **Application Layer (Layer 7 of the OSI model)** of the
Internet Protocol Suite.

First defined by RFC 821 in 1982, it was last updated in 2008 with Extended
SMTP additions by RFC 5321, which is the protocol in widespread use today.

Although electronic **mail servers** and other mail transfer agents use SMTP to
**send and receive mail messages**, **user-level client** mail applications
typically use SMTP only **for sending messages to a mail server** for relaying.
For retrieving messages, client applications usually use either IMAP or POP3.

SMTP communication between mail servers uses **TCP port 25**. Mail clients
on the  other hand, often submit the outgoing emails to a mail server on
port 587.

**SMTP connections secured by TLS, known as SMTPS**, can be made using STARTTLS.

Although proprietary systems (such as Microsoft Exchange and IBM Notes) and
webmail systems (such as Outlook.com, Gmail and Yahoo! Mail) use their own
non-standard protocols to access mail box accounts on their own mail servers,
**all use SMTP when sending or receiving email from outside their own systems.**

--------------------------------------------------------------------------------

### SMTP COMMANDS

A client computer communicates with an SMTP server (e-mail server) by using
SMTP commands.

There is a **core list of SMTP commands that all SMTP servers supports.**

To allow more flexibility and additional features most SMTP servers also
support extended SMTP commands (also called ESMTP commands).
In official documentation these ESMTP commands are also referred to as SMTP
service extensions.

###### Basic SMTP commands


**HELO (Hello)**

The client sends this command to the SMTP server to identify itself and
initiate the SMTP conversation.
The domain name or IP address of the SMTP client is usually sent as an argument
together with the command (e.g. “HELO client.example.com”).
If a domain name is used as an argument with the HELO command, it must be a
fully qualified domain name (also called FQDN).

**MAIL FROM**

Specifies the e-mail address of the sender.
This command also tells the SMTP server that a new mail transaction is starting
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

**RCPT TO (Recipient To)**

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

**DATA**

The DATA command starts the transfer of the message contents (body text,
  attachments etc).
After that the DATA command has been sent to the server from the client, the
server will respond with a 354 reply code.
After that, the message contents can be transferred to the server.
When all message contents have been sent, a single dot (“.”) must be sent in a
line by itself.
If the message is accepted for delivery, the SMTP server will response with a
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

**RSET (Reset)**

If the RSET command is sent to the e-mail server the current mail transaction
will be aborted.
The connection will not be closed (this is reserved for the QUIT command, see
  below) but
all information about the sender, recipients and e-mail data will be removed
and buffers and state tables will be cleared.

**VRFY (Verify)**

This command asks the server to confirm that a specified user name or mailbox
is valid (exists).
If the user name is asked, the full name of the user and the fully specified
mailbox are returned.
In some e-mail servers the VRFY command is ignored because it can be a security
hole.
The command can be used to probe for login names on servers.
Servers that ignore the VRFY command will usually send some kind of reply, but
they will not send the information that the client asked for.

**NOOP (No operation)**

The NOOP command does nothing else than makes the receiver to send an OK reply.
The main purpose is to check that the server is still connected and is able to
communicate with the client.

**QUIT**

Asks the server to close the connection.
If the connection can be closed the servers replies with a 221 numerical code
and then is the session closed.


### Extended SMTP (ESMTP) Commands

If a client initiates the SMTP communication using an EHLO (Extended Hello)
command instead of the HELO command some additional SMTP commands are often
available.
They are often referred to as Extended SMTP (ESMTP) commands or SMTP service
extensions.
Every server can have its own set of extended SMTP commands.
After the client has sent the EHLO command to the server, the server often
sends a list of available ESMTP commands back to the client.

**EHLO (Extended Hello)**

Same as HELO but tells the server that the client may want to use the Extended
SMTP (ESMTP) protocol instead.
EHLO can be used although you will not use any ESMTP command.
Servers that do not offer any additional ESMTP commands will normally at least
recognize the EHLO command and reply in a proper way.

**AUTH (Authentication)**

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


**STARTTLS (Start Transport Layer Security)**

E-mail servers and clients that uses the SMTP protocol normally communicate
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

**SIZE**

The SIZE command has two purposes: the SMTP server can inform the client what
is the maximum message size and
the client can inform the SMTP server the (estimated) size of the e-mail
message that will be sent.
The client should not send an e-mail message that is larger than the size
reported by the server, but normally it is no problem if the message is
somewhat larger than the size informed by the client to the server.


**HELP**

This command causes the server to send helpful information to the client, for
example a list of commands that are supported by the SMTP server.
