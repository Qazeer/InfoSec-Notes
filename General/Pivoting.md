# Pivoting

### Tunneling and port forwarding

### SSH port forwarding

Refer to the `[L7] SSH - Methodology ` note for information on how to tunnel
through SSH.

### Ping + netcat

The ping and `netcat` utilities can be used to quickly enumerate accessible
servers and their open ports from a compromised host.

Both utilities can be uploaded, if not already available on the compromised host,
as standalone binaries.

Refer to the [General] Port scan note for Bash one-liner to conduct a ping sweep
and port scan on responding hosts.  

### Meterpreter

###### Port scan

The `metasploit` modules in `auxiliary/scanner/portscan` can be used to scan
ports through a `meterpreter` session:

```
# SYN
run auxiliary/scanner/portscan/syn RHOSTS=<IP | CIDR> PORTS=<PORT | PORT_RANGE>
run auxiliary/scanner/portscan/tcp RHOSTS=<IP | CIDR> PORTS=<PORT | PORT_RANGE>
```

###### Unitary port forwarding

The *portfwd* command from within the `meterpreter` shell can be used to forward
TCP connections through the compromised machine.

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

###### Route forwarding

*Metasploit module*

*Nmap*
