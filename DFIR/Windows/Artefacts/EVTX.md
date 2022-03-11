# DFIR Windows - Windows event logs

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
EvtxECmd.exe [-f '<FILE>' | -d '<DIRECTORY>'] --inc <LIST_EVENT_IDs> --csv '<OUTPUT_DIRECTORY_CSV>'
EvtxECmd.exe [-f '<FILE>' | -d '<DIRECTORY>'] --exc <LIST_EVENT_IDs> --csv '<OUTPUT_DIRECTORY_CSV>'

# apt-get install python-evtx - Unoptimized
evtx_dump.py <EVTX> > <DUMP_FILE>
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

### Automated analysis with DeepBlueCLI

The [`DeepBlueCLI`](https://github.com/sans-blue-team/DeepBlueCLI) PowerShell
script can be used to automate a basic analysis of Windows events logs. A
number of detection cases are implemented, related to:

  - Suspicious account behavior (user creation and group membership operations,
    bruteforce attempts, etc.)

  - Command line / Sysmon / PowerShell auditing (long command line, PowerShell
    obfuscated command or download one-liner, etc.)

  - Service operations (suspicious service creation, Windows Event Log service
    stating / stopping, etc.)


The following Windows event logs / providers are supported:
  - Windows Security (`Security.evtx`)
  - Windows System (`System.evtx`)
  - Windows Application (`Application.evtx`)
  - Windows PowerShell
  - Sysmon

```powershell
# Process the specified EVTX file.
.\DeepBlue.ps1 <EVTX_PATH>

# Process logs of the current system (must be executed with sufficient privileges to access the logs).
.\DeepBlue.ps1 [-log Security | System | Application | Powershell | Sysmon]
```
