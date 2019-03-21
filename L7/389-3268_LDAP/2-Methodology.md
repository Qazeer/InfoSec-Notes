# LDAP - Methodology

### Network scan

`nmap` can be used to scan the network for LDAP services:

```
nmap -v -p 389,636,3268,3269 -sV -sC -oA nmap_ldap <RANGE/CIDR>
```

The connection to the LDAP service can be tested using `curl`:

```
curl -k <ldap | ldaps>://<HOSTNAME | IP>:<PORT>
```

### NULL & Anonymous binds

### LDAP queries

###### CLI

The Linux command-line utility `ldapsearch` can be used to make LDAP query to a
LDAP service:

```
# Bind DN authentication
ldapsearch -H <ldap | ldaps>://<HOSTNAME | IP>:<PORT> -D "CN=<USERNAME>,OU=<OU>[...],DC=AD,DC=COM" -w <PASSWORD>

# SASL authentication
```

If the connection fails with the following error message `ldap_result: Can't
contact LDAP server (-1)`, the SSL/TLS certificat presented by the service may
not be valid. The certificat verification can be bypassed by setting the
`LDAPTLS_REQCERT` to `never`:

```
LDAPTLS_REQCERT=never ldapsearch -H ldaps://[...]
```

###### GUI

The `Apache Directory Studio` can be used to retrieve and modify data stored in
a LDAP directory through a graphical interface. 
