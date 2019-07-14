# Web Application - Hostnames discovery

### DNS

If a DNS service is accessible on the targeted server, multiple techniques can
be used to retrieve hostnames that could be linked to a web application: DNS
brute forcing, DNS zone transfer, etc. If an hostname for an Internet facing
web application is known, subdomain names may be found in public resources and
proprietary databases.    

For more information on these technique, refer to the
`[L7] DNS - Methodology` note.   

### SSL/TLS certificate

If an HTTPS service is exposed, the SSL / TLS certificate presented by the
service may disclose one or multiple hostnames in the `Subject` and
`Subject Alternative Name` fields. The ports and services scanning tool
`nmap` will automatically extract these information. A review can also be done
manually using a web browser in order to retrieve the SSL / TLS certificate.

### Virtual Hosts brute force

The term Virtual Host, or VHOST, refers to the practice of running more than
one web application on a single server. Virtual hosts can be "IP-based" or
"name-based".

When a webserver receive an HTTP request, routed to it using the IP address of
the TCP packet, it uses the hostname specified in the HTTP `Host` header to
determine the named virtual host queried.

Whenever using named virtual hosts over SSL / TLS, in an HTTPS configuration,
the HTTP request, headers included, can't be read until the SSL / TLS session
is established. In order to provide a practical solution, and present the SSL /
TLS certificate associated to the requested hostname, an extension to the SSL /
TLS protocol called `Server Name Indication (SNI)` was defined. The `SNI`
allows the client to include the requested hostname in the first message of
the SSL / TLS handshake during the session setup.

The `virtual-host-discovery` Ruby script and the `VHostScan` Python script can
be used to brute force VHOSTS (over HTTP or through an SSL / TLS session).

Note that whenever specifying a wordlist, both tools will replace `%s` by the
specified hostname. So a wordlist used for DNS brute forcing should be adapted
using:

```
awk '{print $0 ".%s"}' <ORIGINAL_WORDLIST> > <WORDLIST>
```  

```
ruby scan.rb --ip=<IP> --host=<DOMAIN>
ruby scan.rb --ssl=on --wordlist=<WORDLIST> --ignore-http-codes=<HTTP_ERROR_CODE, [...]> --ip=<IP> --host=<DOMAIN>

VHostScan -t <IP> -b <DOMAIN>
VHostScan -t <IP> --ssl -w <WORDLIST> -b <DOMAIN> --ignore-http-codes <HTTP_ERROR_CODE, [...]>
```
