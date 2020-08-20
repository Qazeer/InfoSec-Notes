# LDAP - Methodology

### Overview

LDAP directory services present data arranged in tree-like hierarchies in which
each entry may have zero or more subordinate entries. This structure is called
the Directory Information Tree, or DIT. Each tree has a single root entry,
which is called the naming context.

All LDAP services must expose a special entry, called the `root DSE`, whose DN
is the zero-length string and which contains, among others attributes, the
`namingContexts` and the LDAP features supported by the LDAP service.

### Network scan

`nmap` can be used to scan the network for LDAP services:

```
nmap -v -p 389,636,3268,3269 -sV -sC -oA nmap_ldap <RANGE | CIDR>
```

The connection to the LDAP service can be tested using `curl`:

```
curl -k <ldap | ldaps>://<HOSTNAME | IP>:<PORT>
```

### NULL / anonymous binds

A NULL or anonymous bind is a LDAP `Bind Request` using Simple Authentication
with a zero-length bind DN and/or a zero-length password.

A NULL / anonymous bind can be attempted using `ldapsearch`:

```
ldapsearch -x -h <HOSTNAME | IP> -s base namingcontexts
```

### LDAP queries

LDAP requires the specification of a search base DN for search queries, which
specifies the base of the subtree in which the search will be constrained. The
search base DN must be provided, but it may be the NULL DN. In such case, the
search will be constrained to the `Root DSE`.

###### CLI

The Linux command-line utility `ldapsearch` can be used to make LDAP query to a
LDAP service, using NULL / anonymous or bind DN authentication:

```
# NULL / anonymous bind
ldapsearch -x -h <HOSTNAME | IP> -p <PORT> [...]
ldapsearch -x -H <ldap | ldaps>://<HOSTNAME | IP>:<PORT> [...]

# Bind DN authentication
# <ROOT>: base domain distinguished name, i.e "DC=AD,DC=COM" for example
ldapsearch -x -h <HOSTNAME | IP> -p <PORT> -D "CN=<USERNAME>,OU=<OU>[...],<ROOT>" -w <PASSWORD> [...]
ldapsearch -H <ldap | ldaps>://<HOSTNAME | IP>:<PORT> -D "CN=<USERNAME>,OU=<OU>[...],<ROOT>" -w <PASSWORD> [...]

# Retrieves the namingContexts
# The base scope option - specified using "-s base" - indicates that only the entries at the level specified by the base DN (and none of its child entries) should be considered   
ldapsearch -x -h <HOSTNAME | IP> -s base namingcontexts

# Retrieves all objects in the specified base DN
# To retrieve all information in a tree, the naming context of the tree can be specified
# The sub scope option - specified using "-s sub" - indicates that the entries at the level and all of its subordinates to any depth should be considered
ldapsearch -x -h <HOSTNAME | IP> -s sub -b "<NAMING_CONTEXT | BASEDN>" "(objectclass=*)"
```

If the connection fails with the following error message `ldap_result: Can't
contact LDAP server (-1)`, the SSL/TLS certificate presented by the service may
not be valid. The certificate verification can be bypassed by setting the
`LDAPTLS_REQCERT` to `never`:

```
LDAPTLS_REQCERT=never ldapsearch -H ldaps://[...]
```

###### GUI

The `Apache Directory Studio` can be used to retrieve and modify data stored in
a LDAP directory through a graphical interface.

###### Automated dump

The `ldapdomaindump` utility can be used to automatically dump the content of
a LDAP directory. If no credentials are provided, the directory dumping will
be attempted through an anonymous bind.

```
ldapdomaindump <HOSTNAME | IP>
ldapdomaindump -at {NTLM,SIMPLE} -u <USERNAME> -p <PASSWORD> <HOSTNAME | IP>
```
