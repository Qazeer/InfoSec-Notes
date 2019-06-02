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
python reGeorgSocksProxy.py -p <LPORT> -u <http | https>://<HOSTNAME | IP>/<PATH>/<tunnel.xx>
```

`proxychains` can be used to easily redirect traffic a program traffic to
`reGeorg`'s socks server:

```
# /etc/proxychains.conf
[ProxyList]
socks4 	127.0.0.1 <LPORT>

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
