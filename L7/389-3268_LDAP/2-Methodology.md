# LDAP - Methodology

### Network scan

Nmap can be used to scan the network for LDAP services:

```
nmap -v -p 389,3268 -A -oA nmap_ldap <RANGE/CIDR>
```

### Anonymous bind

### NULL bind
