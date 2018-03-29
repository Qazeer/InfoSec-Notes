# Web Application - Server exposure

X

--------------------------------------------------------------------------------
### Domain Registration


### Network Utilities

###### Ping
The hping utility tool can be used to send ICMP, TCP, UDP and raw packets:
```
# TCP SYN
hping -c 2 -S <target> -p 80

# UDP
hping --udp -c 2 <target> -p 111

# ICMP
hping --icmp -c 2 <target>
```

###### Traceroute
The traceroute utility tool can be used to map each successive host
(remote node) in the route to the target:
```
# UDP - UDP datagrams probes
traceroute <target>

# TCP - TCP SYN probes to default port 80
traceroute -T <open_port> <target>

# ICMP - ICMP echo probes
traceroute -I <target>
```
If some filters are present in the network path (firewalls, IDS, etc.), then
most probably any "unlikely" udp ports (as for default method) or even icmp
echoes (as for icmp) are filtered.
To bypass a network filter use the TCP probes on TCP services exposed by the
server.

### Exposed Services

Scan the server for open ports and exposed services:
```
# Open TCP ports
nmap -sS -sV -O -p- <target>

# Open UDP ports (top 1000)
nmap -sU -sV -O <target>
```

### Intermediate Network Equipment

###### Detect Load Balancers
Multiples technics can be used to determine the use of a load balancer:
-  Generate a lot of traffic to trigger a potential load balancer
-  Check incoherence in datetime as multiple servers may have different
internal clock
-  Inspect HTTP headers and cookies for load balancers known patterns
-  Check for DNS delegation

The following tools automate the technics above:
```
halberd <URL>
lbd <URL>
```

###### Detect Web Application Firewall (WAF)
The WAFW00F utility tool identifies and fingerprints WAF by sending normal and
malicious HTTP requests and analyzing the server response:
```
wafwoof <URL>
```
