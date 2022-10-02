# DFIR - Email headers analysis

### Common headers

A number of email headers are common / mandatory for the email lifecycle, and
some headers can be of precious forensics value. Additionally, some headers are
linked to optional security mechanisms (`SPF`, `DKIM`, and `DMARC`) that can
help detect illegitimate / spoofed emails.

###### Received header

A `Received` header is added to the email headers by each
`Message Transfer Agent (MTA)` that relayed the email. `Received` headers are
ordered in reverse chronological order, with the last `Received` header
corresponding to the one added first by the `MTA` closer to the email sender
(and the first appearing `Received` header corresponding to the `MTA` closer to
destination). The last `Received` header (placed the closest from the
`From` / `To` headers and the message body) can thus be used to identify the
`MTA` from which the email originated. The reputation and legitimacy of the
sender `MTA`, in the email context, can be analysed to determine the legitimacy
of the email.

Each `Received` header logs the sending and receiving `MTA` hostname and IP
address as well as the time of reception. Example of the first `Received`
header of an email sent through `O365`:

```
Received: from XXX.PROD.OUTLOOK.COM
 ([<IP>]) by YYY.PROD.OUTLOOK.COM
 ([<IP>]) with mapi id 15.20.5250.018; <DATE>
```

###### From and Return-Path headers

The email of the sender is positioned in three headers:

  - The `From` header, that is displayed to the end-user as the sender of the
    email but is not verified by the `SPF` mechanism and can thus be spoofed.

  - The `Return-Path` header, whose value is based on the email specified in
    the `MAIL FROM` `SMTP` command. This header is verified by the `SPF`
    mechanism and is thus a more reliable source of information for determining
    the sender of an email. The `Return-Path` header is used to process the
    "bounces" that may occur with an email.

  - The `Reply-To` header, which simply specify the email to which human
    replies should be sent to (as the recipient of the new email). An
    arbitrary email can be specified with no incidence on email security
    mechanisms.

If the `From` and `Return-Path` headers differ, the `From` header may have been
spoofed for social engineering purpose. If `SPF` verification (detailed below)
fails, the `Return-Path` header may have been spoofed as well.

Note that the
`Domain-based Message Authentication Reporting and Conformance (DMARC)`
mechanism can be used to detect / prevent spoofing of the `From` header.

### SPF

###### Overview

`Sender Policy Framework (SPF)` is an email authentication mechanism, defined
in [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), designed to
detect and / or block spoofed emails by detecting illegitimate sender servers.
More specifically, the `SPF` mechanism will limit the domains a mail server can
use in the `MAIL FROM` of a email message.

`SPF` can be used by organizations to define servers authorized to send emails
for their domain name. `SPF` relies on specific `DNS` `TXT` records, that
identify authorized servers and the comportment the receiver should follow in
case of an email reception from a non authorized server.

`SPK` `DNS` records follow the format below, with mechanisms / rules evaluated
from left-to-right and stopping on the first match (except for the `INCLUDE`
mechanism).

```
# Only the version 1 of SPF is supported, so the version tag will always be set to v=spf1.

v=<spf1 | SPF_VERSION> <QUALIFIER><MECHANISM_1> ... <QUALIFIER><MECHANISM_N>
```

The following `mechanisms` are supported:

| Mechanism | Description |
|-----------|-------------|
| `all` | Always matches. |
| `include:<DOMAIN>` | Evaluate the `SPF` policy of the specified domain, returning a `PASS` / `Neutral` / `Fail` / `Softfail` result (or an error). <br><br> Only `PASS` result will however be processed, effectively stopping the following mechanisms evaluation. Non-matched results will resume processing of the other further mechanisms. |
| `a[:<DOMAIN>]` | Check if the sender email server `IP` address is included in the `A` or `AAAA` `DNS` records of the `MAIL FROM` / `HELO` domain or the domain specified in the mechanism. |
| `mx[:<DOMAIN>]` | Check if the sender email server `IP` address is included in the `MX` `DNS` records of the `MAIL FROM` / `HELO` domain or the domain specified in the mechanism. |
| `ip4:<IPV4 \| IPV4_CIDR>` | Check if the sender email server `IP` address is the specified IPv4 address or in the specified IPv4 address range. |
| `ip6:<IPV6 \| IPV6_CIDR>` | Check if the sender email server `IP` address is the specified IPv6 address or in the specified IPv6 address range. |

The `qualifiers` determine the comportment the receiving email server should
follow if the `mechanism` match. The following `qualifiers` are supported:

| Qualifier keyword | Qualifier description | Description |
|-------------------|-----------------------|-------------|
| `+` | `PASS` | Allow the message. <br><br> I.e if the associated `mechanism` match, the message should be accepted by the receiving email server. <br><br> Default if the `qualifier` is not specified. |
| `-` | `FAIL` | Reject the message. <br><br> I.e if the associated `mechanism` match, the message should be rejected by the receiving email server. |
| `?` | `NEUTRAL` | The authoritative domain explicitly state that it is not asserting whether the sender email server `IP` address is authorized. <br><br> Can be processed as if the `SPF` record did not exist. I.e if the associated `mechanism` match, the message could be process as if no `SPF` record was configured by the receiving email server. |
| `~` | `SOFTFAIL` | The authoritative domain explicitly state that it is not asserting whether the sender email server `IP` address is authorized. <br><br> Same comportment as `NEUTRAL`, with difference in processing left to the receiving email server. |

###### Spoofed email SPF headers example

The following email headers correspond to a spoofed email headers (assuming
that `SPF` records are correctly configured):

```
Authentication-Results: spf=fail (sender IP is <SENDING_SERVER_IP>)
[...]

Received-SPF: Fail (protection.outlook.com: domain of <MAIL_FROM_OR_HELO_DOMAIN>
 does not designate <SENDING_SERVER_IP> as permitted sender)
 receiver=protection.outlook.com; client-ip=<SENDING_SERVER_IP>;
 helo=<SENDING_SERVER_FQDN>;
```

### DKIM

##### Overview

`DomainKeys Identified Mail (DKIM)` is an email authentication mechanism,
defined in [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376), designed
to detect spoofed emails by digitally signing the email message body and (some)
headers. `DKIM` relies on `SHA-1` or `SHA-256` and  `RSA`, with 1024 or
2048-bit public / private keys, to sign (part of) the email message. The `RSA`
public key must be published in a `DNS` `TXT` record for the domain in order
for the receiving email server to be able to validate the signature.

Upon sending of an email, the sending email server will indeed generate a hash
of the message body and some headers, using one of a set of supported
canonicalization algorithm, then sign the generated hash with the `RSA` private
key. Whenever receiving a `DKIM`-signed email, the receiving email server will
compute the same hash, using the algorithm specified in the `DKIM` header, and
validate the signature using the published public key.

`SPK` `DKIM` records follow the format below:

```
```

###### Email DKIM headers example

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=<DOMAIN>;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Hc1c7LQy0IUrUHT9vHmJ40lUAc52d9HNeRZEQjDBk0k=;
 b=jp2hnMsaiRYukwae4DIAwb0Pc46j4cEBBN[...]GtfafZU4JZ3mpOmZ9zmWZpIRRpNLyQQttUGEOtnvRYzam8BYO3kMQoFw==
```

The following notable fields are defined:

| Field | Description |
|-------|-------------|
| `v=<1 \| VERSION>` | `DKIM` version (only the first version is supported). |
| `a=<rsa-sha1 \| rsa-sha256>` | The cryptographic algorithm used to generate the signature. <br><br> O |

### DMARC

TODO

--------------------------------------------------------------------------------

### References

https://www.trustedsec.com/blog/real-or-fake-spoof-proofing-email-with-spf-dkim-and-dmarc/

https://medium.com/@p.matkovski/email-forensics-2-headers-and-body-3e6280820983
