# NetBIOS - Methodology

### Overview

`Network Basic Input/Output System (NetBIOS)` is a Windows API providing
services related to the session layer (layer 5) of the OSI model, mostly for
systems on the same link-local subnetwork. `NetBIOS` runs over `TCP/IP` via
the `NetBIOS over TCP/IP (NBT)` protocol.

`NetBIOS` provides notably a name registration and resolution service: the
`NetBIOS Name Service (NBNS)`, which operates on `UDP` port 137 (and may
operate on `TCP` 137). `NetBIOS` names are 16 ASCII characters in length (with
out "\ / : * ? " < > |"), with the 16th character reserved for the resource
`NetBIOS Suffix`. The `NetBIOS-NS` protocol is used, along (and before) the
`Link-Local Multicast Name Resolution (LLMNR)` protocol, by Windows systems to
perform name resolution operation if the `Domain Name System (DNS)` resolution
fails. The name resolution is made through a `NBNS` `Name query NB` broadcast
request on the link-local broadcast address and can thus only be used to
resolve `NetBIOS` names for hosts on the same subnetwork.

A `NetBIOS` name table stores the `NetBIOS` records registered on the Windows
system. A record consists of a `NetBIOS` name, a status, and can be of two
type: `Unique` or `Group`. `Unique` record are unique among all systems on the
link-local subnetwork and a verification is made by the system registering the
`NetBIOS` name with the `Windows Internet Name Service (WINS)` server or
through a broadcast `Registration NB` request to ensure that the newly
registered name would effectively be unique. For example, such request is made
by a Windows system at boot time to register the system `NetBIOS` hostname in
the local-link subnetwork. On the contrary, `Group` records may take for value
a `NetBIOS` name shared by others systems.

The 16th character of a record `NetBIOS` name is reserved and corresponds to
the `NetBIOS Suffix`, which indicates the service type associated with the
`NetBIOS` record.

| Type | Suffix | Value | Description |
|------|--------|-------|-------------|
| `UNIQUE` | `00` | `NetBIOS` system hostname | Registered by the Windows `Workstation` service. Yields for value the system registered `NetBIOS` hostname. |
| `UNIQUE` | `20` | `NetBIOS` system hostname |  Registered by the Windows `Server` service. The `Server` service supports the sharing of shares and named-pipe over the network. |
| `UNIQUE` | `1B` | `NetBIOS` domain name | `Domain Master Browser`, part of the `Browser Service`, replaced by Windows Active Directory since `Windows XP` and only provided for backward compatibility reasons. Registered on the `Primary Domain Controller` Emulator of the Active Directory domain (only one server acts as the `Domain Master Browser` across an Active Directory domain). |   
| `UNIQUE` | `1D` | `NetBIOS` domain or workgroup name | `Master Browser`, part of the `Browser Service`,  replaced by Windows Active Directory since `Windows XP` and only provided for backward compatibility reasons. Only one server acts as the `Master Browser` in a link-local subnetwork. |
| `GROUP` | `00` | `NetBIOS` domain or workgroup name | Windows `Workstation` service. Registers the system in a workgroup or Active Directory domain and yields for value the Active Directory domain or workgroup the system is integrated to. |
| `GROUP` | `1C` | `NetBIOS` domain name | Registered on systems that are `Domain Controller` in an Active Directory domain. |

Additionally, while `NetBIOS` is completely independent from the `Server
Message Block (SMB)` protocol, `SMB` does rely on `NetBIOS` (`SMB` over `NBT`,
`TCP` port 139) for communication with systems that do not support direct
hosting of `SMB` over `TCP/IP`.

### Network scan

`nmap` can be used to scan the network for exposed `NetBIOS` services:

```
nmap -v -sS -sU -sV -sC -p U:137,T:137,138,139 -oA nmap_netbios <RANGE | CIDR>
```

### NetBIOS name resolution and name table enumeration

The Windows `nbtstat` and the Linux `nmblookup` utilities can be used to
resolve `NetBIOS` name and retrieve the remote system `NetBIOS` name table
information:

```
# Linux
# Performs NetBIOS name resolution
nmblookup <NETBIOS_NAME>
# Lists the remote machine's name table given its NetBIOS name / IP address
nmblookup -A <NETBIOS_NAME | IP>

# Windows
# Lists the remote machine's name table given its NetBIOS name / IP address
nbtstat -a <NETBIOS_NAME>
nbtstat -A <IP>
```

### SMB over NetBIOS

If the `NetBIOS` `session service` is accessible on the remote system, on
`TCP` port 139, but not the `SMB` service, `SMB` over `NBT` can be used to
access remote network shares or execute commands through `PsExec`-like
utilities.

```
# If no username provided, null session assumed
smbmap -P 139 [-d <DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | HASH>] (-H <HOSTNAME | IP> | --host-file <FILE>)  

# TARGETS can be IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containing a list of targets
crackmapexec <TARGETS> --port 139 [-M <MODULE> [-o <MODULE_OPTION>]] (-d <DOMAIN> | --local-auth) -u <USERNAME | USERNAMES_FILE> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>) [--sam] [-x <COMMAND> | -X <PS_COMMAND>]
```

For more information, refer to the `[L7] 445 - SMB` and `[Windows] Lateral
movements` notes.

### NBT-NS poisoning

Responses to the broadcasted `NBNS` name resolution requests can be spoofed,
in order to intercept local network traffic. The interception can, notably, be
used to capture, and eventually relay, local network `SMB` authentication
requests.

For more information, refer to the `[ActiveDirectory] NTLM Relaying` note.     

--------------------------------------------------------------------------------

### References

https://www.itprotoday.com/compute-engines/knowing-angles-netbios-suffixes
https://www.itprotoday.com/compute-engines/what-are-netbios-suffixes-16th-character
Network Security Assessment: Know Your Network
Windows NT TCP/IP Network Administration
