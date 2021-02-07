# DFIR - Windows PowerShell activity

### Overview

Windows PowerShell version 2.0, and prior versions, provide few useful audit
settings, thereby limiting the availability of evidence (such as a command
history).

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
  - `-Enc` / `-e`
  - `-nop` / `bypass`
  - `IEX` / `Invoke-Expression`
  - `ICM` / `Invoke-command`
  - `Net.WebClient` / `io.`
  - `DownloadString` / `DownloadFile`
  - `&` / `|`
  - `//` / `http` / `ftp` / `cifs` / `smb` / etc.
  - `join` / `nioj` / `replace` / `ecalper` / `-f` / `CHAR` / `RAHC` / `STRING`
    / `GNIRTS` / `marshal` / `convert` / `env` / `{` / `}` (obfuscation
    detection)

While the occurrence of these keywords may entail malicious activities, their
absence is not a formal proof of lack of malicious PowerShell activity as
PowerShell code can be deeply obfuscated.

### PowerShell deobfuscation

The `PSDecode` PowerShell script can be used to deobfuscate malicious
PowerShell scripts that have several layers of encodings.

```
https://github.com/R3MRUM/PSDecode

Import-Module PSDecode.psm1

PSDecode <ENCODED_POWERSHELL_FILE>
```

### PowerShell Windows events

| Hive     | Event ID | Conditions | Description |
|----------|----------|------------|-------------|
| Windows PowerShell | 400 | PowerShell 2.0 | `Engine state is changed from None to Available`.<br/> Logged on the start of any local or remote PowerShell activity (execution of powershell.exe).<br/> The `HostApplication` field record the binary path at the origin of the powershell activity and contain the commandline arguments provided to powershell.exe. <br/> If the `Hostname` field is equal to : <br/> - `ConsoleHost`, the event concern a local activity <br/> - `ServerRemoteHost`,  the event occured du to PowerShell remoting activity.<br/> The `RunaspaceId` identify the PowerShell activity and can be linked to the session termination (`EID 403`). Note that however this event cannot be strictly correlated to a logon session. |
| Windows PowerShell | 403 | PowerShell 2.0 | `Engine state is changed from Available to Stopped`.<br/> Logged at the end of any local or remote PowerShell activity (execution of powershell.exe) and contains the same level of information as the `EID 400` events.<br/> The `RunaspaceId` identify the PowerShell activity and can be linked to the session start (`EID 400`). Note that however this event cannot be strictly correlated to a logon session. |
| Windows PowerShell | 500 | PowerShell 2.0<br/> Requires `$LogCommandLifeCycleEvent` to be set to true (non default) | `Command "<COMMAND>" is Started.`<br/> Logged whenever a PowerShell command is executed, but can be bypassed by starting PowerShell using the `-NoProfile` / `-nop` flag. |
| Windows PowerShell | 501 | PowerShell 2.0<br/> Requires `$LogCommandLifeCycleEvent` to be set to true (non default) | `Command "<COMMAND>" is Stopped.`<br/> Logged whenever a PowerShell command finish its execution, but can be bypassed by starting PowerShell using the `-NoProfile` / `-nop` flag. |
| Windows PowerShell | 600 | PowerShell 2.0 | `Provider "<PROVIDER_NAME>" is Started.`<br> Logs the start and stop of PowerShell providers.<br/> Similarly to the events `EID 400` and `EID 403`, this event include the `HostApplication` field.<br/> If the provider is `WSMan` ("Provider WSMan Is Started"), the event, logged on both the client and remote systems, indicate the use of PS remoting.<br/> If the PowerShell activity relies on built-in alias, such as `IEX`, an event will be generated for the `Alias` provider. |
| Windows PowerShell | 800 | PowerShell 3.0 | `Pipeline execution details for command line`.<br/> Inconsistently logged.<br/> Similarly to the events EID 400 and EID 403, this event include the `HostApplication` field and present the advantage of logging, in the `UserId` field, the user account executing PowerShell. |
| Microsoft-Windows-PowerShell\Operational | 4100 | PowerShell 5.0 | `Error message [...]`.<br/> Logged whenever an error occurs in a PowerShell activity.<br/> Includes an `HostApplication` field, the `<DOMAIN>\<USER>` executing PowerShell in the `User` field, and may include the script path of the executed script in the `ScriptName` field. |
| Microsoft-Windows-PowerShell\Operational | 4103 | PowerShell 3.0<br/> Requires PowerShell `Module Logging` to be enabled (`EnableModuleLogging` registry key set to 1) | `Module Logging`.<br/> Logged upon the execution of functions in the module(s) set to be logged.<br/> If the module names, configured in the `Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames` registry key, is set to `*`, the activity of the members of all modules are logged.<br/> Provides verbose information on the PowerShell activity and, in addition to user information, events may yields the parameters and output of the executed PowerShell cmdlets. |
| Microsoft-Windows-PowerShell\Operational | 4104 | PowerShell 5.0 | `Script block logging`: `Creating Scriptblock text [...]`.<br/>Logged upon the execution of PowerShell scripts and cmdlets.<br/>If the `Path` field is empty, the command was executed interactively through the PowerShell console.<br/>Includes, in the `ScriptBlockText` field, the script block (content of the PowerShell script or cmdlet and the commandline) being executed.<br/> This event provides valuable information but may be bypassed by malicious actors by starting PowerShell 2.0 (`powershell.exe -version 2.0`). |
| Microsoft-Windows-PowerShell\Operational | 40961<br/>40962 | PowerShell 3.0 | `PowerShell console is starting up` (`EID 40961`) followed by `PowerShell console is ready for user input` (`EID 40962`).<br/> Logged upon the start of a PowerShell activity (execution of powershell.exe).<br/> Includes the `<DOMAIN>\<USER>` executing PowerShell in the `User` field. |
| Microsoft-Windows-PowerShell\Operational | 53504 | PowerShell 3.0 | `Windows PowerShell has started an IPC listening thread on process: <PID> in `AppDomain`: <DOMAIN>`.<br/>Indicates that a PowerShell `AppDomain` was started.<br/> Usually logged upon the start of the PowerShell console, in between events `EID: 40961` and `EID: 40962`. |
| Microsoft-Windows-AppLocker\MSI and Script | 8005 | Require `AppLocker` to be enabled and running in `Audit only` mode | `<SCRIPT_PATH> was allowed to run`.<br/>Logged upon the execution of a local PowerShell script. |
| Microsoft-Windows-AppLocker\MSI and Script | 8006 | Require `AppLocker` to be enabled and running in `Audit only` mode | `<SCRIPT_PATH> was allowed to run but would have been prevented from running if the AppLocker policy were enforced`.<br/>Logged upon the execution of a local PowerShell script. |
| Security | 4688 | Requires `Audit Process Creation` to be enabled | `A new process has been created`.<br/> Logged upon the creation of every process. The `NewProcessName` field stores the full path of the process's executable and will contain `powershell.exe` for PowerShell activity.<br/>Refer to the `Processes` section for more information on this event. |
