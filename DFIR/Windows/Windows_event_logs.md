# Forensics - Windows - Windows event logs

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
directory, Administrator privileges are required to access the `c$` share.

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

### Windows Event ID

###### Logs integrity

Location: victim `Security` hive.

The `Security` event `1102: The audit log was cleared` occurs
whenever the `Security` audit log is cleared. This event includes the SID,
domain, username and `Logon ID` of the user that cleared the logs.

Correlation ID TODO

###### User sessions

Location: victim `Security` hive.

The `Logon ID` field of various events can be correlated with the `Security`
event `4624: An account was successfully logged on` to find information about
the user session.

This event yields information such as:
  - the logon type
  - the SID, account name and domain of the user logging in
  - the source machine hostname, IP and port
  - the authentication protocol (NTLM, Kerberos, etc.) used

The `logon type` provides information on how the logging was established:

| Logon Type | Description |
|------------|-------------|
| 2  | Interactive logon (on screen) |
| 3  | Network logon (share access, etc.) |
| 4  | Batch logon (scheduled task) |
| 5  | Service logon (service startup) |
| 7  | Unlock (on screen unlocking) |
| 8  | NetworkCleartext authentication (usually HTTP basic authentication) |
| 9  | NewCredentials authentication (does not seem to be in use) |
| 10 | RemoteInteractive authentication (Terminal Services, Remote Desktop or Remote Assistance) |
| 11 | CachedInteractive authentication (on screen logging using cached credentials when a domain controller cannot be reached) |

###### Logon with privileges

Location: victim `Security` hive.

The `Security` event `4672: Special privileges assigned to new logon` occurs
whenever an account is assigned one, or more, of the following privileges:
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

###### Remote job schedule registration, execution and deletion

Location : Victim `Microsoft-Windows-TaskScheduler%4Operational.evtx` hive.

Artifact : Task Scheduler Event Log(since win7)
- Registering Job schedule ID : 106
  - Account Name used to registration
  - Job Name : Usually “At#” form

- Starting Job schedule ID : 200
  - The path of file executed for job

- Deleting Job schedule ID : 141
  - Account Name used for the deletion

###### Detect PowerShell activity via Windows Event logs

  Microsoft-Windows-PowerShell\Operational
  Event ID 4100 (Executing Pipeline)

  -> Error message / Host Application

### Lateral movements

Windows Security Log Event ID 4648
`4648: A logon was attempted using explicit credentials`
Logged on client. Includes information about the target server:
`Target Server Name` (hostname or IP) and `Additional Information` of the
service requested.

Windows Security Log Event ID 4624
`4624: An account was successfully logged on`
Logged on server. Includes information about the logon type.

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
