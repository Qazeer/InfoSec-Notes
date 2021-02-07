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

###### Extract accounts usage from the Security events

Extract security events 4624,4625,4634,4647,4648,4772,4778,4779,4800,4801,4802,4803

```
Author: Brian Maloney (idea by @0x47617279)

LogParser.exe -stats:OFF -i:EVT -o CSV "SELECT TO_UTCTIME(TimeGenerated) AS Date, EventID, CASE EventID WHEN 4624 THEN 'An account was successfully logged on' WHEN 4625 THEN 'An account failed to log on' WHEN 4634 THEN 'An account was logged off' WHEN 4647 THEN 'User initiated logoff' WHEN 4648 THEN 'A logon was attempted using explicit credentials' WHEN 4672 THEN 'Special privileges assigned to new logon' WHEN 4778 THEN 'A session was reconnected to a Window Station' WHEN 4779 THEN 'A session was disconnected from a Window Station' WHEN 4800 THEN 'The workstation was locked' WHEN 4801 THEN 'The workstation was unlocked' WHEN 4802 THEN 'The screen saver was invoked' WHEN 4803 THEN 'The screen saver was dismissed' END as Description, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 0, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 0, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 1, '|') END as Username, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 6, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 6, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 2, '|') END as Domain, CASE EventID WHEN 4648 THEN STRCAT(EXTRACT_TOKEN(Strings, 6, '|'),STRCAT('\\',EXTRACT_TOKEN(Strings, 5, '|'))) END AS CredentialsUsed, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 7, '|') WHEN 4624 THEN EXTRACT_TOKEN(Strings, 7, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 3, '|') END AS LogonID, CASE EventID WHEN 4778 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 4, '|') END AS SessionName, REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 8, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 10, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 4, '|') END,'2','Logon via console'),'3','Network Logon'),'4','Batch Logon'),'5','Windows Service Logon'),'7','Credentials used to unlock screen'),'8','Network logon sending credentials (cleartext)'),'9','Different credentials used than logged on user'),'10','Remote interactive logon (RDP)'),'11','Cached credentials used to logon'),'12','Cached remote interactive (similar to Type 10)'),'13','Cached unlock (similar to Type 7)') AS LogonType, CASE EventID WHEN 4625 THEN CASE EXTRACT_TOKEN(strings, 7, '|') WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request' WHEN '0xc0000064' THEN 'user name does not exist' WHEN '0xc000006a' THEN 'user name is correct but the password is wrong' WHEN '0xc000006d' THEN 'user logon with misspelled or bad password' WHEN '0xc000006e' THEN 'unknown user name or bad password' WHEN '0xc000006f' THEN 'user tried to logon outside his day of week or time of day restrictions' WHEN '0xc0000070' THEN 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)' WHEN '0xc0000071' THEN 'expired password' WHEN '0xc0000072' THEN 'account is currently disabled' WHEN '0xc00000dc' THEN 'Indicates the Sam Server was in the wrong state to perform the desired operation.' WHEN '0xc0000133' THEN 'clocks between DC and other computer too far out of sync' WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine' WHEN '0xc000018c' THEN 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed' WHEN '0xc0000192' THEN 'An attempt was made to logon, but the netlogon service was not started' WHEN '0xc0000193' THEN 'account expiration' WHEN '0xc0000224' THEN 'user is required to change password at next logon' WHEN '0xc0000225' THEN 'evidently a bug in Windows and not a risk' WHEN '0xc0000234' THEN 'user is currently locked out' WHEN '0xc00002ee' THEN 'Failure Reason. An Error occurred during Logon' WHEN '0xc0000413' THEN 'Logon Failure. The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine' ELSE EXTRACT_TOKEN(strings, 7, '|') END END AS Status, CASE EventID WHEN 4625 THEN CASE EXTRACT_TOKEN(strings, 9, '|') WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request' WHEN '0xc0000064' THEN 'user name does not exist' WHEN '0xc000006a' THEN 'user name is correct but the password is wrong' WHEN '0xc000006d' THEN 'user logon with misspelled or bad password' WHEN '0xc000006e' THEN 'unknown user name or bad password' WHEN '0xc000006f' THEN 'user tried to logon outside his day of week or time of day restrictions' WHEN '0xc0000070' THEN 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)' WHEN '0xc0000071' THEN 'expired password' WHEN '0xc0000072' THEN 'account is currently disabled' WHEN '0xc00000dc' THEN 'Indicates the Sam Server was in the wrong state to perform the desired operation.' WHEN '0xc0000133' THEN 'clocks between DC and other computer too far out of sync' WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine' WHEN '0xc000018c' THEN 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed' WHEN '0xc0000192' THEN 'An attempt was made to logon, but the netlogon service was not started' WHEN '0xc0000193' THEN 'account expiration' WHEN '0xc0000224' THEN 'user is required to change password at next logon' WHEN '0xc0000225' THEN 'evidently a bug in Windows and not a risk' WHEN '0xc0000234' THEN 'user is currently locked out' WHEN '0xc00002ee' THEN 'Failure Reason. An Error occurred during Logon' WHEN '0xc0000413' THEN 'Logon Failure. The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine' ELSE EXTRACT_TOKEN(strings, 9, '|') END END AS SubStatus, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(strings, 9, '|') WHEN 4625 THEN EXTRACT_TOKEN(strings, 11, '|') END AS AuthPackage, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 11, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 13, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 8, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 4, '|') END AS Workstation, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 18, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 19, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 12, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 5, '|') END AS SourceIP INTO <DESTINATION_FOLDER>\logparser-Logon-Logoff-events.csv' FROM '<SECURITY_EVTX_FILE>' WHERE EventID IN (4624;4625;4634;4647;4648;4672;4778;4779;4800;4801;4802;4803) AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')" -filemode:0
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
