# Forensics - Windows - Windows Event Logs

### Export Windows event logs

###### Windows XML Event Log (EVTX)

The entirety of the `C:\Windows\System32\winevt\Logs` directory can be copied
to export all the Windows event logs EVTX hives. The event logs can also be
exported through the Windows GUI `Event Viewer (eventvwr.msc)` application and
the CLI `wevtutil` utilities. The PowerShell cmdlet `Get-WinEvent` does not
provide a way to export logs in the EVTX format.

`wevtutil` presents the advantage to allows for the retrieval of local event
logs as well as event logs on a remote target.

To be able to view some event logs, notably the `Security` event logs, the
`Manage auditing and security log (SeSecurityPrivilege)` right is required.
Note that this right also grant the ability to clear the event logs.
Additionally, in order to remotely copy the `C:\Windows\System32\winevt\Logs`
directory, Administrator privileges are required to access the `c$` share.

Usage:

```
export_logs.bat "<HOSTNAME | IP>" "<OUTPUTDIR_PAHT>"
```

```
# Enumerate all event logs
wevtutil el
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> el
Get-WinEvent -ListLog *
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -ListLog *

# Display configuration information: enabled, DACL, hive path, etc.
wevtutil gl <LOGNAME>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> gl <LOGNAME>

# Display metadata information: creation time, last access / write time, number of events logged, hive size, etc.
wevtutil gli <LOGNAME>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> gli <LOGNAME>

# Both configuration and metadata information at once
Get-WinEvent -ListLog <LOGNAME> | Format-List -Property *
Get-WinEvent -Computer <HOSTNAME | IP> -Credential <PSCredential> -ListLog <LOGNAME> | Format-List -Property *

# Query using a XPath query the event logs to quickly identify matching events
# The Windows Event Viewer can be used to define a filter query through the GUI and export the filter in a XPath format
# DATETIME = YYYY-MM-DDTHH:mm:SS
wevtutil qe <LOGNAME> /q:"<XPATH_QUERY>"
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> qe <LOGNAME> /q:"<XPATH_QUERY>"
# Example query to find events matching the specified Event ID between two dates
wevtutil qe <LOGNAME> /q:"*[System[(EventID=<EVENT_ID>) and TimeCreated[@SystemTime>='<DATETIME>' and @SystemTime<'<DATETIME>']]]"

# Export unitary event logs hive
wevtutil epl <LOGNAME> <LOCAL_PATH | REMOTE_PATH>\<FILENAME.evtx>
wevtutil /r:<HOSTNAME | IP> /u:<DOMAIN | WORKGROUP>\<USERNAME> /p:<PASSWORD> epl <LOGNAME> <LOCAL_PATH | REMOTE_PATH>\<FILENAME.evtx>
```

The following batch script can be used to retrieve all Windows event logs from
a remote specified target:

Script from
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

### Manipulate Windows event logs

###### View logs

Windows Event Viewer. Got integrity problem with third parties.

###### Programmatically parse logs

apt-get install python-evtx

evtx_dump.py <EVTX> > <DUMP_FILE>

###### Splunk

TODO

### Detect PowerShell activity via Windows Event logs

Microsoft-Windows-PowerShell\Operational
Event ID 4100 (Executing Pipeline)

-> Error message / Host Application
