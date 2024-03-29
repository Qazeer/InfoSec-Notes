# DNS - Methodology

### Overview

The Domain Name System (DNS) is a hierarchical decentralized naming system for
computers, services, or other resources connected to the Internet or a private
network.

It associates various information with domain names assigned to each of the
participating entities. Most prominently, it translates more readily memorized
domain names to the numerical IP addresses needed for locating and identifying
computer services and devices with the underlying network protocols.

By providing a worldwide, distributed directory service, the Domain Name System
has been an essential component of the functionality of the Internet since 1985.

###### DNS record types

The main DNS record types are:

Type | Description
-----|----------
`A`    | IPv4 Address record
`AAAA` | IPv6 Address record
`NS`   | Name Server record
`SOA`  | Master Name Server record
`MX`   | Mail Exchange record
`TXT`  | Arbitrary Text record


### Authority domain servers

To retrieve the `Domain Name System (DNS)` servers having authority over a
specific domain, the following command be used:

```
host -t ns <DOMAIN>

dig -t NS +short <DOMAIN>
```

### DNS lookup

To resolve the IP associated to a Domain/Fully Qualified Domain Name:

```
dig +short <FQDN>

host <DOMAIN/FQDN>
```

The following commands can be used to retrieve specific DNS records associated
with a domain:

```
# Relies on ANY, which is often blocked or filtered, to query all records
dig +nocmd +noall +answer <target_domain> ANY

# A/AAAA/NS/SOA/MX/TXT
dig +nocmd +noall +answer <DOMAIN> <RECORDTYPE>
```

### Reverse DNS lookup

To resolve the Domain/Fully Qualified Domain Name associated to an IP address:

```
dig +short -x <IP>
dig +short @<NAMESERVER> -x <IP>

host <IP>
host <IP> <NAMESERVER>

nmap -sn -Pn --dns-servers <NAMESERVER> (<IP> | <FQDN> | <CIDR> | <RANGE>)
```

### DNS zone transfers

A zone transfer is similar to a database replication act between related DNS
servers. This process includes the copying of the zone file from a master DNS
server to a slave server.
Zone transfers should usually be limited to authorized slave DNS servers (by IP
source or protected by a TSIG key) but a misconfigured DNS server could be
allowing zone transfer from anyone.

The following commands can be used to test for zone transfers:

```
dig -t AXFR @<NAMESERVER> <DOMAIN>

host -l <DOMAIN> <NAMESERVER>
```

The `DNSRecon` and `DNSenum` tools can be used to enumerate nameservers for a
domain and try a zone transfer for each enumerated nameserver:

```
dnsrecon -a -d <DOMAIN>
dnsrecon -a -n <NAMESERVER> -d <DOMAIN>

dnsenum <DOMAIN>
dnsenum --dnsserver <NAMESERVER> <DOMAIN>
```

### DNS zone walking

Due to a design flaw in the NSEC records used by
`Domain Name System Security Extensions (DNSSEC)`, it may be possible to
discover all subdomains of a particular domain for which `NSEC` records are
available.

`DNSSEC` is a number of security oriented specifications for DNS aiming at
securing the DNS protocol against a number of attacks, including the spoofing
and poising of records as well as man-in-the-middle attacks.

The integrity of DNS records is ensured by storing a digital signature
associated to a specific record, in a `RRSIG` record. The DNS resolver
retrieves the queried record along with its digital signature, and can
afterward query the DNS server for the public key, stored in a `DNSKEY` record.

The `NSEC` and `NSEC3` record types are defined in `DNSSEC` to handle the case
of inexistent records. As a non inexistent record cannot be digitally signed,
the need arise to securely inform the DNS resolver that the queried record does
not exist. `NSEC` records work by returning the "Next Secure" record stored
alphabetically in the zone, meaning a enumeration of all defined domains is
possible using the `NSEC` records of a zone. `NSEC3` addresses this issue, by
returning salted hashes of domain names instead of directly returning the
domain name.

The `DNSRecon` tool can be used to conduct DNS zone walking:

```
dnsrecon -t zonewalk -d <DOMAIN>
```

### Forward lookup brute force

Forward lookup brute force consist of guessing valid names, from a wordlist, of
servers by attempting to resolve a given name. If the guessed name does
resolve, the results might indicate the presence and even functionality of the
server.

###### Subdomains wordlists

The following wordlists of subdomains can be used:

```
# bitquark - Top 1000 to 1.000.000.
https://github.com/bitquark/dnspop/tree/master/results

# dnsscan - Top 100 to 10.000.
https://github.com/rbsec/dnscan

# SecList - 2.178.752 entries.
SecLists/Discovery/DNS/jhaddix-dns.txt
```

A custom wordlist based on already discovered subdomains or specific keywords
can also be generated using  [`Altdns`](https://github.com/infosec-au/altdns):

```
altdns -i <INPUT_SUBDOMAINS_FILE> -w <words.txt | INPUT_KEYWORDS_FILE> -o <OUTPUT_WORDLIST>
```

###### DNS brute force tooling

[`MassDNS`](https://github.com/blechschmidt/massdns) can be used for fast
`DNS` brute forcing using multiple resolvers. The `subbrute.py` Python script
provided in the `MassDNS` repository can first be used to generate a list of
subdomains, from a specified subdomains wordlist and root domains list, to
resolve with `MassDNS`.

```
python3 ./scripts/subbrute.py -d <DOMAIN_FILE> <SUBDOMAIN_WORDLIST> | ./bin/massdns -r <lists/resolvers.txt | RESOLVERS_FILE> -t A -o S -w <OUTPUT_RESULT>
```

The additional following tools can be used to conduct automated forward lookup
brute force:

```
# Subbrute.
python subbrute.py -v <DOMAIN>
python subbrute.py -v -s <WORDLIST> -c <THREADS> <DOMAIN>

# echo "<NAMESERVER>" > tmp_resolver.txt.
python subbrute.py -v -r tmp_resolver.txt -s <WORDLIST> -c <THREADS> <DOMAIN>

# Gobuster.
gobuster -m dns -w <WORDLIST> -t <THREADS> -i -u <DOMAIN>

Amass / dnscan / Nmap / Recon-Ng / DNSRecon / Fierce / DNSenum / AltDNS / ...
```

### Reverse Lookup Brute Force

If the `PTR records`, used for mail services, are configured for the domain,
reverse lookup brute force may possible.

If the DNS forward brute-force enumeration revealed a set of scattered IP
addresses, the following bash one liner can be used to conduct a reverse lookup
brute force:

```
for ip in $(seq <0> <255>);do host <x.x.x>.$ip;done |grep -v "not found"
```

--------------------------------------------------------------------------------

### References

https://medium.com/iocscan/how-dnssec-works-9c652257be0
