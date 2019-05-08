# Web Application - Server exposure

The first step in the process of attacking a web application is to draw the
architecture of the server exposing the application.

--------------------------------------------------------------------------------

### Network Utilities

###### Ping

The hping utility tool can be used to send ICMP, TCP, UDP and raw packets ping:

```
# TCP SYN
hping3 -S -c 2 -p 80 <target>

# UDP
hping3 --udp -c 2 -p 111 <target>

# ICMP
ping -c 2 <targt>
hping3 --icmp -c 2 <target>
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
# Open TCP ports (all ports)
nmap -sS -sV -O -p- <target>

# Open UDP ports (top 1000)
nmap -sU -sV -O <target>
```

Further analysis can be conducted against each accessible services.

### Intermediate Network Equipments

###### Detect Load Balancers

Multiples technics can be used to determine the use of a load balancer:
-  Generate a lot of traffic to trigger a potential load balancer
-  Check incoherence in datetime as multiple servers may have different
internal clock
-  Inspect HTTP headers and cookies for load balancers known patterns
-  Check for DNS delegation

The following tools automate the technics above:

```
halberd <target_url>
lbd <target_url>
```

###### Detect Web Application Firewall (WAF)

The WAFW00F utility tool identifies and fingerprints WAF by sending normal and
malicious HTTP requests and analyzing the server response:

```
wafw00f <target>
```
