# Forensics - Windows - Windows event logs

### Export Windows event logs

The entirety of the `C:\Windows\System32\winevt\Logs` directory can be copied
to export all the Windows event logs EVTX hives. The event logs can also be
exported through the Windows GUI `Event Viewer (eventvwr.msc)` application and
the CLI `wevtutil` utilities. The PowerShell cmdlet `Get-WinEvent` does not
provide a way to export logs in the EVTX format.

To be able to view some event logs, notably the `Security` event logs, the
`Manage auditing and security log (SeSecurityPrivilege)` right is required.
Note that this right also grant the ability to clear the event logs.
Additionally, in order to remotely copy the `C:\Windows\System32\winevt\Logs`
directory, Administrator privileges are required to access the `C$` share.

The following commands can be used to unitary export a event logs hive in the
`evtx` format:

```
wevtutil epl <LOGNAME> <LOCAL_PATH | REMOTE_PATH>\<FILENAME.evtx>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> epl <LOGNAME> <LOCAL_PATH | REMOTE_PATH>\<FILENAME.evtx>
```

The following batch script can be used to retrieve all Windows event logs from
a remote specified target.

Usage:

```
export_logs.bat "<HOSTNAME | IP>" "<OUTPUTDIR_PATH>"
```

```
@echo off

REM GetEventLogs.cmd by Malcolm McCaffery
SETLOCAL ENABLEDELAYEDEXPANSION

SET remotePC=%1
SET OutputDir=%2

IF "%remotePC%" EQU "" set remotePC=%computername%

IF NOT EXIST %OutputDir% MD %OutputDir%

pushd "%OutputDir%"

echo Get Event Logs on System %remotePC%
for /F "delims=\" %%i IN ('wevtutil el /r:%remotePC%') DO (
echo Retreving Log %%i
for /F "tokens=1,2 delims=/" %%j IN ("%%i") DO (
   IF "%%k" EQU "" (
    SET OUTPUTFILE=%computername%-%%j.evtx
   ) ELSE (
   SET OUTPUTFILE=%computername%-%%j-%%k.evtx
   )
)
wevtutil epl "%%i" "!OUTPUTFILE!" /ow:true /r:%remotePC%
)

REM cleanup by deleting any empty event files…
for /R %%i IN (*.evtx) DO (
  echo Processing %%i
  REM if file is 69,632 bytes or less then delete it – don't want empty files
  IF %%~zi LEQ 69632 (
    echo empty event file…deleting…
    del "%%i" /q
  )
)

popd
echo.'
echo Completed - events stored in %OutputDir%
pause
```

### List and query Windows event logs

###### GUI event logs viewers

The Windows `Event Viewer` built-in application and the `Event Log Explorer`
application can be used to analyze event logs through graphical application.

`Event Log Explorer` offers the possibility to separate loaded hives by system,
parametrize and save advance filters and consolidate event logs hives from
different systems.   

###### CLI utilities

The PowerShell cmdlet `Get-WinEvent` and the `wevtutil` utility can be used to
list available event log hives and filter event log, from both local or remote
system.

The following commands can be used to enumerate the available event logs hives:

```
wevtutil el
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> el

Get-WinEvent -ListLog * | Where-Object { $_.RecordCount }
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -ListLog * | Where-Object { $_.RecordCount }
```

The following commands can be used to retrieve information and metadata about
the specified event logs hives:

```
# Display configuration information: enabled, DACL, hive path, etc.
wevtutil gl <LOGNAME>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> gl <LOGNAME>

# Display metadata information: creation time, last access / write time, number of events logged, hive size, etc.
wevtutil gli <LOGNAME>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> gli <LOGNAME>

# Both configuration and metadata information at once
Get-WinEvent -ListLog <LOGNAME> | Format-List -Property *
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -ListLog <LOGNAME> | Format-List -Property *
```

The following commands can be used to filter the event logs.

The `wevtutil` utility supports only `XPath` queries. The Windows Event Viewer
can be used to define a filter query through the GUI and export the filter in a XPath format.

```
wevtutil qe <LOGNAME> /q:"<XPATH_QUERY>"
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> qe <LOGNAME> /q:"<XPATH_QUERY>"

# Example query to find events matching the specified Event ID between two dates
# DATETIME = YYYY-MM-DDTHH:mm:SS
wevtutil qe <LOGNAME> /q:"*[System[(EventID=<EVENT_ID>) and TimeCreated[@SystemTime>='<DATETIME>' and @SystemTime<'<DATETIME>']]]"
```

The PowerShell cmdlet `Get-WinEvent` can be used to filter the event logs on
the following attributes:
  - LogName (`<String[]>`)
  - Path (`<String[]>`)
  - ID (`<Int32[]>`)
  - StartTime (`<DateTime>`)
  - EndTime (`<DateTime>`)
  - UserID (`<SID>`)
  - Data (`<String[]>`)

```
# Filter by event ID
Get-WinEvent -FilterHashtable @{Path="<HIVE_PATH>"; ID=<EVENT_ID | LIST_EVENT_IDs>} | Fl
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -FilterHashtable @{Path="<HIVE_PATH>"; ID=<EVENT_ID | LIST_EVENT_IDs>} | Fl

# Search the specified string in event data
Get-WinEvent -FilterHashtable @{Path="<HIVE_PATH>"; data="<STRING | LIST_STRINGs>"} | Fl
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -FilterHashtable @{Path="<HIVE_PATH>"; data="<STRING | LIST_STRINGs>"} | Fl
```

###### Convert Windows evtx to text / csv format

The Python utilities suite `python-evtx` can be used to parse and export to a
text format Windows event log hives. The `EvtxECmd` utility can also be used to
parse Windows event log hives into a CSV format.

It can notably be used to take advantage of Linux utilities such as `grep` and
`awk`.

```
# apt-get install python-evtx
evtx_dump.py <EVTX> > <DUMP_FILE>

EvtxECmd.exe [-f '<FILE>' | -d '<DIRECTORY>'] --inc <LIST_EVENT_IDs> --csv '<OUTPUT_DIRECTORY_CSV>'
EvtxECmd.exe [-f '<FILE>' | -d '<DIRECTORY>'] --exc <LIST_EVENT_IDs> --csv '<OUTPUT_DIRECTORY_CSV>'
```

###### CSV searching

The Linux `sort` utility can be used to sort CSV fields:

```
sort --field-separator='<DELIMITER>' --key=<COLUMN_NUMBER | COMMA_LIST_COLUMN_NUMBERS> <CSV_FILE>

```

`q` is a command line tool that allows direct execution of SQL-like queries on
CSV files.

```
# -H: indicate that the CSV file has an header
q -H -d '<DELIMITER>' "<SQL_STATEMENT>"

# Query example
q -d "," -H "SELECT TimeCreated,EventId,Provider,Channel,Computer,UserId,MapDescription,ChunkNumber,UserName,RemoteHost,PayloadData1 FROM <CSV_FILE> WHERE TimeCreated LIKE '2020-04-07%' AND (Provider='Microsoft-Windows-Security-Auditing' OR Provider='Microsoft-Windows-TaskScheduler' OR Provider='Microsoft-Windows-TerminalServices-RemoteConnectionManager')"
```

### Windows Event ID

###### Logs integrity

Event: `1102: The audit log was cleared`.<br/>
Location: victim `Security` hive.

This event  occurs whenever the `Security` audit log is cleared. This event
includes the SID, domain, username and `Logon ID` of the user that cleared the
logs.

Additionally, every event of a given event log hive has an `EventRecordID`
field representing an index number, sequentially incremented, of the event in
that particular hive. Any disparity in record ids may reflect a deletion of
event(s) in the hive.  

###### Local and remote logons

Event: `4624: An account was successfully logged on`.<br/>
Location: victim `Security` hive.

This event yields information such as:
  - The SID `SubjectUserSid`, account name `SubjectUserName`, and domain
    `SubjectDomainName` of the user logging in.
  - the source machine hostname `WorkstationName`, IP `IpAddress` and port
    `IpPort` if the event corresponds to remote login (otherwise the three
    aforementioned fields are set to `-`).
  - The authentication protocol in the `AuthenticationPackageName` field
    (`NTLM`, `Kerberos` or `Negotiate `) used for the logging. If the logon is
    made through the `NTLM` protocol, the `LmPackageName` field precisely
    identify the `NTLM` version in use (`LM`, `NTLM V1`, `NTLM V2`).
  - The logon type in the `LogonType` field (detailed below).
  - The privileges level in the `ElevatedToken` field. If set to `%%1842`
    (`Yes`), the session the event represents runs in a elevated context. The
    event can be correlated with the `Security` event `EID: 4672` to precisely
    identify the privilege tokens of the session.
  - The impersonation level of the event in the `ImpersonationLevel` field
    (detailed below).
  - the `LogonID` field identifying the logon session, which can be correlated
    with various other `Security` events.

The `LogonType` field provides information on how the logging was established:

| Logon Type | Description |
|------------|-------------|
| 2          | Interactive logon (on screen) |
| 3          | Network logon (share access, etc.) |
| 4          | Batch logon (scheduled task) |
| 5          | Service logon (service startup) |
| 7          | Unlock (on screen unlocking) |
| 8          | NetworkCleartext authentication (usually HTTP basic authentication) |
| 9          | NewCredentials authentication (does not seem to be in use) |
| 10         | RemoteInteractive authentication (Terminal Services, Remote Desktop or Remote Assistance) |
| 11         | CachedInteractive authentication (on screen logging using cached credentials when a domain controller cannot be reached) |

The `ImpersonationLevel` field may take the following values:

| Flag | Correspondence | Description |
|------|----------------|-------------|
| `-` | `SecurityAnonymous` | The server process cannot obtain security information about the client. |
| `%%1832` | `Identification` | The server process can obtain information about the client but cannot impersonate the client and thus the client has no privileges. |
| `%%1833 ` | `Impersonation` | The server process can obtain information and impersonate the client's security context on the local system. |
| `%%1840 ` | `Delegation` | The server process can impersonate the client's security context on remote systems. |

###### Logon with privileges

Event: `4672: Special privileges assigned to new logon`.<br/>
Location: victim `Security` hive.

This event occurs whenever an account is assigned one, or more, of the
following privileges:

  - SeTcbPrivilege
  - SeBackupPrivilege
  - SeCreateTokenPrivilege
  - SeDebugPrivilege
  - SeEnableDelegationPrivilege
  - SeAuditPrivilege
  - SeImpersonatePrivilege
  - SeLoadDriverPrivilege
  - SeSecurityPrivilege
  - SeSystemEnvironmentPrivilege
  - SeAssignPrimaryTokenPrivilege
  - SeRestorePrivilege
  - SeTakeOwnershipPrivilege

The `SubjectLogonId` field can be correlated with the `Security` event
`EID: 4624` in order to retrieve more information on the logon session.

###### Processes

Event: `4688: A new process has been created`.<br/>
Location: victim `Security` hive.<br/>
Requires `Audit Process Creation` to be enabled.

This event is logged upon the creation of every new process on the system.

The `NewProcessName` field stores the full path of the process's executable and
the `ProcessId` field the `Process ID (PID)` of the process. The
`ParentProcessName` field logs the parent process's executable full path and
can be used to identity suspicious processes activity, such as `outlook.exe` or
`iexplorer.exe` starting `cmd.exe` or `powershell.exe` processes.

This event includes the SID `SubjectUserSid`, account name `SubjectUserName`,
and domain `SubjectDomainName` of the user creating the process. Additionally,
the `SubjectLogonId` field can be used to correlate the process creation with
the logon session, event `EID: 4624`.

The `TokenElevationType` field represent the privileges of the process and can
take the following values:

| Flag | Correspondence | Description |
|------|----------------|-------------|
| `%%1936` | `TokenElevationTypeDefault` | The process is started with a full token with no privileges removed or groups disabled. A full token is only used if `User Account Control (UAC)` is disabled or if the user starting the process is the built-in `Administrator` (`RID: 500`), `NT AUTHORITY\SYSTEM` or service account. |
| `%%1937` | `TokenElevationTypeFull` | The process is started with an elevated token with no privileges removed or groups disabled. An elevated token is used when `User Account Control (UAC)` is enabled and the user chooses to start the program in a elevated security context (`Run as administrator` for example). |
| `%%1938` | `TokenElevationTypeLimited` | The process is started with limited privileges, and privileged tokens such as `SeImpersonatePrivilege`, `SeDebugPrivilege`, etc. are removed from the process security context. |


If the `ProcessCreationIncludeCmdLine_Enabled` audit policy is enabled, the
command line specified at the process creation will be logged in the
`ProcessCommandLine` field.

###### PowerShell activity

Windows PowerShell version 2.0, and prior versions, provide few useful audit
settings, thereby limiting the availability of evidence (such as a command history)

Upon executing any PowerShell command or script, either locally or using PS
remoting, Windows may write events to the following hives:
  - `Windows PowerShell.evtx`
  - `Microsoft-Windows-PowerShell\Operational.evtx`
  - `Microsoft-Windows-PowerShell\Analytic.etl` (non default)

As PowerShell implements its remoting functionality through the `Windows Remote
Management (WinRM)` service, remote PowerShell activity may induce events in
the following hives:
  - `Microsoft-Windows-WinRM\Operational.evtx`
  - `Microsoft-Windows-WinRM\Analytic.etl` (non default)

*The events linked to remote PowerShell activity, conducted through the `WinRM`
service, are detailed in the `Lateral movements` section.*

Additionally, if enabled, `AppLocker` will record PowerShell activity in the
`Microsoft-Windows-AppLocker\MSI and Script` hive.

Note that PowerShell 2.0, and prior versions, provide limited logging
capacities and thereby limit the availability of evidence, such as the
interactive command history executed through PowerShell console.

The events providing command line / command history information should be
searched for the following keywords (case insensitive search):
  - `-Enc`
  - `-nop`
  - `IEX` / `Invoke-Expression`
  - `ICM` / `Invoke-command`
  - `Net.WebClient`
  - `DownloadString` / `DownloadFile`
  - `&` / `|`
  - `//` / `http` / `ftp` / `cifs` / `smb` / etc.
  - `join` / `nioj` / `replace` / `ecalper` / `-f` / `CHAR` / `STRING` / `marshal` / `convert` / `env` / `{` / `}` (obfuscation detection)

While the occurrence of these keywords may entail malicious activities, their
absence is not a formal proof of lack of malicious PowerShell activity as
PowerShell code can be deeply obfuscated.

| Hive     | Event ID | Pre-requisite | Description |
|----------|----------|------|-------------|
| Windows PowerShell | 400 | PowerShell 2.0 | `Engine state is changed from None to Available`.<br/> Logged on the start of any local or remote PowerShell activity (execution of powershell.exe).<br/> The `HostApplication` field record the binary path at the origin of the powershell activity and contain the commandline arguments provided to powershell.exe. <br/> If the `Hostname` field is equal to : <br/> - `ConsoleHost`, the event concern a local activity <br/> - `ServerRemoteHost`,  the event occured du to PowerShell remoting activity.<br/> The `RunaspaceId` identify the PowerShell activity and can be linked to the session termination (`EID 403`). Note that however this event cannot be strictly correlated to a logon session. |
| Windows PowerShell | 403 | PowerShell 2.0 | `Engine state is changed from Available to Stopped`.<br/> Logged at the end of any local or remote PowerShell activity (execution of powershell.exe) and contains the same level of information as the `EID 400` events.<br/> The `RunaspaceId` identify the PowerShell activity and can be linked to the session start (`EID 400`). Note that however this event cannot be strictly correlated to a logon session. |
| Windows PowerShell | 500 | PowerShell 2.0<br/> Requires `$LogCommandLifeCycleEvent` to be set to true (non default) | `Command "<COMMAND>" is Started.`<br/> Logged whenever a PowerShell command is executed, but can be bypassed by starting PowerShell using the `-NoProfile` / `-nop` flag. |
| Windows PowerShell | 501 | PowerShell 2.0<br/> Requires `$LogCommandLifeCycleEvent` to be set to true (non default) | `Command "<COMMAND>" is Stopped.`<br/> Logged whenever a PowerShell command finish its execution, but can be bypassed by starting PowerShell using the `-NoProfile` / `-nop` flag. |
| Windows PowerShell | 600 | PowerShell 2.0 | `Provider "<PROVIDER_NAME>" is Started.`<br> Logs the start and stop of PowerShell providers.<br/> Similarly to the events `EID 400` and `EID 403`, this event include the `HostApplication` field.<br/> If the provider is `WSMan` ("Provider WSMan Is Started"), the event, logged on both the client and remote systems, indicate the use of PS remoting.<br/> If the PowerShell activity relies on built-in alias, such as `IEX`, an event will be generated for the `Alias` provider. |
| Windows PowerShell | 800 | PowerShell 3.0 | `Pipeline execution details for command line`.<br/> Inconsistently logged.<br/> Similarly to the events EID 400 and EID 403, this event include the `HostApplication` field and present the advantage of logging, in the `UserId` field, the user account executing PowerShell. |
| Microsoft-Windows-PowerShell\Operational | 4100 | PowerShell 5.0 | `Error message [...]`.<br/> Logged whenever an error occurs in a PowerShell activity.<br/> Includes an `HostApplication` field, the `<DOMAIN>\<USER>` executing PowerShell in the `User` field, and may include the script path of the executed script in the `ScriptName` field. |
| Microsoft-Windows-PowerShell\Operational | 40961<br/>40962 | PowerShell 3.0 | `PowerShell console is starting up` (`EID 40961`) followed by `PowerShell console is ready for user input` (`EID 40962`).<br/> Logged upon the start of a PowerShell activity (execution of powershell.exe).<br/> Includes the `<DOMAIN>\<USER>` executing PowerShell in the `User` field. |
| Microsoft-Windows-AppLocker\MSI and Script | 8005 | Require `AppLocker` to be enabled and running in `Audit only` mode | `<SCRIPT_PATH> was allowed to run`.<br/>Logged upon the execution of a local PowerShell script. |
| Microsoft-Windows-AppLocker\MSI and Script | 8006 | Require `AppLocker` to be enabled and running in `Audit only` mode | `<SCRIPT_PATH> was allowed to run but would have been prevented from running if the AppLocker policy were enforced`.<br/>Logged upon the execution of a local PowerShell script. |
| Security | 4688 | Requires `Audit Process Creation` to be enabled | `A new process has been created`.<br/> Logged upon the creation of every process. The `NewProcessName` field stores the full path of the process's executable and will contain `powershell.exe` for PowerShell activity.<br/>Refer to the `Processes` section for more information on this event. |

| Microsoft-Windows-PowerShell\Operational | 4103 | PowerShell 4.0 | `X`. |
| Microsoft-Windows-PowerShell\Operational | 4104 | PowerShell 5.0 | `X`. |
| Microsoft-Windows-PowerShell\Operational | 53504 | PowerShell 3.0 | `X`. |

https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks.pdf
https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
http://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm
https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html
https://www.powershellmagazine.com/2014/07/16/investigating-powershell-attacks/
https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging
https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
https://www.eventtracker.com/EventTracker/media/EventTracker/Files/support-docs/Integration-Guide-Windows-PowerShell.pdf

###### Lateral movements

Windows Security Log Event ID 4648
`4648: A logon was attempted using explicit credentials`
Logged on client. Includes information about the target server:
`Target Server Name` (hostname or IP) and `Additional Information` of the
service requested.

Windows Security Log Event ID 4624
`4624: An account was successfully logged on`
Logged on server. Includes information about the logon type.

*Remote job schedule registration, execution and deletion*

Location : Victim `Microsoft-Windows-TaskScheduler%4Operational.evtx` hive.

Artifact : Task Scheduler Event Log(since win7)
- Registering Job schedule ID : 106
  - Account Name used to registration
  - Job Name : Usually “At#” form

- Starting Job schedule ID : 200
  - The path of file executed for job

- Deleting Job schedule ID : 141
  - Account Name used for the deletion

*WinRM*

| Microsoft-Windows-WinRM/Operational | 6 | X | `Creating WSMan Session`.<br/> Logged on the client host. The event connection string field include the remote host address. |
| Microsoft-Windows-WinRM/Operational | 91 | X | `Session creation`. |
| Microsoft-Windows-WinRM/Operational | 161 | X | `The client cannot connect to the destination specified in the request.`<br/> Error event, logged on the remote system.<br/> The `User` and `Computer` event fields provide information on the client. |
| Microsoft-Windows-WinRM/Operational | 168 | X | `Session creation`. |

WinRM Operational event log entries indicating authentication prior to
PowerShell remoting on an accessed system
• Event ID 169: “User [DOMAIN\Account] authenticated successfully using [authentication_protocol]”

System event log entries indicating a configuration change to the Windows Remote Management service:
○ Event ID 7040 “The start type of the Windows Remote Management (WS-Management) service was changed from [disabled / demand start] to auto start.” – recorded when PowerShell remoting is enabled.
○ Event ID 10148 (“The WinRM service is listening for WS-Management requests”) – recorded upon reboot on systems where remoting has been enabled.

WinRM Operational event log entries indicating authentication prior to PowerShell remoting on an accessed system:
○ Event ID 169 (“User [DOMAIN\Account] authenticated successfully using [authentication_protocol]”)

###### Persistence mechanisms

Location: victim `Security` and `System` hives.

The following events could be indicator of persistence on the system:

| Hive     | Event ID | Description |
|----------|----------|-------------|
| Security | 4720 | `A user account was created`. Logged both for local SAM accounts and domain accounts and includes the creator SID, domain, username and `Logon ID`. |
| Security | 4722 | `A user account enabled`, logged both for local SAM accounts and domain accounts and is always logged after a Security event `4720 - user account creation`. |
| Security | 4723 | `An attempt was made to change an account's password`. Logged both for local SAM accounts and domain accounts when an user attempts to change his/her own password. This event is logged only if the user entered his/her correct password and reported as a failure if his/her new password fails to meet the password policy. Includes the SID, domain, username and `Logon ID` of the user that performed the password change. |
| Security | 4724 | `An attempt was made to reset an accounts password`. Logged both for local SAM accounts and domain accounts when an user attempts to change another user password. This event is logged only if the user correct password is specified, the user attempting the password reset as the necessary permissions to do so, and reported as a failure if his/her new password fails to meet the password policy. Includes the SID, domain, username and `Logon ID` of the user that performed the password change. |
| Security | 4670 | `Permissions on an object were changed`. This event generates when the permissions for an object are changed
| Security | 4738 | `A user account was changed`. Logged both for local SAM accounts and domain accounts when an user object attributes are modified. The old and new value for the updated attribute is logged. If all attributes are marked as "-", an update on a attribute that is not listed in the event log or a modification on the user DACL object has occurred. The `AD - Exploiting DACL` note can be consulted for more information on exploitable DACL on user principal object.<br/> In addition to a potential modification on the user object DACL, this event can be used to detect the following persistence means:<br/>  - addition of SID in the `SID History` of an user<br/>  - disabling of Kerberos `Require Preauth` to make the account vulnerable to `ASREPRoast`.<br/>  |
| Security | 4732 | `A member was added to a security-enabled local group`. Logged on domain controllers for Active Directory domain local groups and member computer for local SAM groups. |
| System   | 7030 | `Basic Service Operations`. Occurs when a service is configured as an interactive, which is not supported since Windows Vista and Windows Server 2008 (du to security risks posed by interactive services). |
| System   | 7045,4697 | `A service was installed in the system`. |
| System   | 7035, 7036 | `The <SERVICE_NAME> service was successfully sent a <start/stop> control.` and `The <SERVICE_NAME> service entered the <running/stopped> state.` A run / stop signal is sent then the service is effectively started / stopped. |
| Security | 4697 | `A service was installed in the system` from Windows Server 2016 and Windows 10 |
| System   | 7040 | Service start type was changed |  
| System   | 1056 | DHCP server oddities |
| Security | 4688 | `A new process has been created`. Occurs when a process is created and include information about the process: creator subject (SID, account domain and name as well as the Logon ID), creator PID, token elevation type. etc. If enabled, the "process command line" field include the command line of the process. |

TODO 4670 and 4662

Windows Security Log Event ID 4657: A registry value was modified
this event will only be logged if the key's audit policy is enabled for Set Value permission for the appropriate user or a group in the user is a member.

### ELK integration
