# Tunneling / ports forwarding

### Overview

###### Local port forwarding

In local port forwarding, a port on the local system is routed to a port on a
remote server. For example, a compromised Internet facing server exposing a
SSH service could be used to route traffic to the SMB ports of internal
servers to conduct `PsExec` like connections directly from the attacking system
without the need to deploy tools on the compromised server.

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

### SSH

SSH port forwarding is a mechanism that allows for connection tunneling
through a SSH service.

They are three main types of SSH port forwarding: local port forwarding, remote
port forwarding and dynamic port forwarding.

###### Local port forwarding

The following command can be used to configure a local port forwarding through
an SSH service:

```
# -n: no keyboard input to be expected (redirects stdin from /dev/null, actually preventing reading from stdin)
# -N & -T: prevents the opening of a tty session and specify that no command be executed

ssh -nNT -L <LOCAL_PORT>:<TARGET_HOSTNAME | TARGET_IP>:<TARGET_REMOTE_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>
```

Once the above command is completed, the specified target port will be
accessible locally on the attacking machine at the `<LOCAL_PORT>`.

Note: local port forwarding can be used to access locally (`localhost`) exposed
services on the SSH server.

###### Remote port forwarding

The following command can be used to configure a remote port forwarding through
an SSH service:

```
ssh -R <TARGET_REMOTE_PORT>:<TARGET_HOSTNAME | TARGET_IP>:<SSH_SERVER_LOCAL_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>
```

###### Dynamic ports forwarding

The following commands can be used to configure the SSH service in proxy mode
and redirect tools connections through it:

```
ssh -nNT -D <LOCAL_PORT> <USERNAME>@<SSH_HOSTNAME | SSH_IP>

# Edit proxychains.conf
socks5 127.0.0.1 <LOCAL_PORT>

# Run tools through proxychains
proxychains <[...]>
```

### Meterpreter

###### Unitary port forwarding

The `portfwd` command from within the `meterpreter` shell can be used to forward
TCP connections through a compromised machine.

Usage:

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

###### Dynamic port forwarding

Contrary to unitary port forwarding, dynamic port forwarding allows for the
complete tunneling of full IP and ports range. The `autoroute` command from
within the `meterpreter` shell can be used to forward TCP connections through a
compromised machine.

### Cobalt Strike

`Cobalt Strike` supports the following pivoting mechanisms:
  - Pivot listeners
  - Dynamic ports forwarding through a SOCKS proxy
  - VPN access

###### Pivot listeners

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

###### SOCKS proxy

A `SOCKS4` proxy service can be started on a beacon using the beacon built-in
function `[beacon] -> Pivoting -> SOCKS Server` or through the beacon CLI using
`socks <C2_LOCAL_SOCK_PORT>`.

The actives `SOCKS4` proxies can be viewed and managed through the `View ->
Proxy Pivots` interface. All the `SOCKS4` proxies running on a beacon can also
be stopped directly through the beacon CLI using `socks <SOCK_PORT>`.

Network traffic can be proxied through the `SOCKS` service started on the
C2 server network interfaces by `Cobalt Strike` using `proxychains`:

```
# /etc/proxychains.conf
[ProxyList]
socks4 <127.0.0.1 | LOCAL_C2_INTERFACE> <LOCAL_SOCKS_PROXY_PORT>

proxychains [...]
```

In `metasploit`, the
`setg Proxies socks4:<127.0.0.1 | LOCAL_C2_INTERFACE>:<LOCAL_SOCKS_PROXY_PORT>`
command can be used to tunnel modules through the `Cobalt Strike` `SOCKS`
proxy.

###### CovertVPN pivoting

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

```
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

### Web TCP tunnel

`reGeorg` and `ABPTTS` can be used to act as socks proxies and tunnel TCP
traffic over an HTTP/HTTPS connection made to a web application. A web page /
package must be deployed and executed by the web server, in similar fashion as
a classical web shell.

###### reGeorg

`reGeorg` supports the following web application / languages:
  - ashx
  - aspx
  - js
  - jsp
  - php
  - tomcat jsp

Once the page / package is deployed, `reGeorg` socks server can be started:

```
python reGeorgSocksProxy.py -p <LOCAL_SOCKS_PROXY_PORT> -u <http | https>://<HOSTNAME | IP>/<PATH>/<tunnel.xx>
```

`proxychains` can be used to easily redirect traffic a program traffic to
`reGeorg`'s socks server:

```
# /etc/proxychains.conf
[ProxyList]
socks4 <127.0.0.1 | LOCAL_C2_INTERFACE> <LOCAL_SOCKS_PROXY_PORT>

proxychains [...]
```

### [Windows] netsh

On Windows, the `netsh` built-in can be used to configure unitary port
forwarding.

```
# Display current configured port forwarding rule
netsh interface portproxy show all

# Configure a local port forwarding
netsh interface portproxy add v4tov4 listenaddress=<LHOST> listenport=<LPORT>  connectaddress=<RHOST> connectport=<RPORT>
```

### [Linux] iptables
