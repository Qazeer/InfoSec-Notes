# DFIR Windows - AutoStart Extensibility Point (ASEP)

### Sysinternals' Autoruns

The `Autoruns` utility of the `Sysinternals` suite has the most comprehensive
knowledge of auto-starting locations on Windows hosts.

The following ASEP are notably listed:
  - Startup folders
  - ASEP registries
  - Services
  - Scheduled tasks
  - Drivers
  - WMI providers
  - Internet explorer extensions

`Autoruns` verifies the digital signatures of the files and white list the
files signed by known editors. The files appearing in yellow are usually
missing and the files appearing in red are usually not digitally signed or
not by a known editor.

Note that `Autoruns` **DOES NOT check the loaded DLL** by the programs that are
run from ASEP.

###### CLI AutorunsC

The `AutorunsC` utility can be used to run `Autoruns` in CLI mode either on
live host **or on read-write partition mounted from a disk image**.

The `Arsenal-Image-Mounter` open source utility can be used to mount disk
images to a partition for offline ASEP analysis. However, the verification of
files signature from trusted providers does not work as well as on live hosts.

```
# All ASEP (-a) exported to CSV (-c) format with VirusTotal digital signature verification (-v), exclusion of digitally signed Microsoft entries (-m) and files hashes.

# Live hosts
Autorunsc.exe -a * -c -v -m -s -h

# From a mounted partition
Autorunsc.exe -a * -c -v -m -s -h -z <PARTITION_DRIVE_LETTER>
```

### Local accounts

*This section only covers local accounts / groups and does not include
persistence through Active Directory domain accounts / groups.*

While not directly allowing remote code execution, local accounts may be used
as a mean of persistence, notably on machine exposing remote access services,
such as `SMB` or `Terminal Services`, on the Internet.

###### Live forensics

The Windows built-in `net` utility can be used to enumerate local users and
local groups:

```
# Enumerates the local users and the specified user attributes (including the accounts' password last set timestamp).
net user
net user "<Administrator | USERNAME>"

# Enumerates the local groups and the specified group members.
net localgroup
net localgroup "<Administrators | GROUP>"
```

###### Registry

The local users are stored in the `Securiry Account Manager (SAM)` registry
database, located at: `%WinDir%\System32\config\SAM`, under the following
registry keys:

  - `SAM\Domains\Account\Users`

The user's attributes (username, `RID`, Last Password Change, group
memberships, etc.) are stored in the `SAM`.

###### Windows EVTX logs

The following events could be indicators of persistence on the machine through
local accounts and / or groups:

| Hive     | Event ID | Conditions | Description | Information yield |
|----------|----------|------------|-------------|------------------ |
| `Security.evtx` | 4720 | Default configuration. <br><br> Logged whenever a local account is created. | Event `4720: A user account was created`. <br><br> Legacy: <br> Event `624: User Account Created`. | Creator's domain, username and `Logon ID`. <br><br> Created user's domaine and username. |
| `Security.evtx` | 4722 | Default configuration. <br><br> Always logged after a Security event `4720 - user account creation`. | Event `4722: A user account enabled` <br><br> Legacy: <br> Event `626: User Account Enabled`. | |
| `Security.evtx` | 4723 | By default, only logged whenever an user successfully change their own password. <br><br> Failures logged if `Audit User Account Management` is set to `(Success), Failure`. | Event `4723: An attempt was made to change an account's password`. <br><br> Logged as a success (`Audit Success`) if the user did change their password (which requires to enter the current correct password). <br><br> Otherwise reported as a failure (`Audit Failure`) if failures are logged and an error occurred (wrong current password given, new password fails to meet the password policy). <br><br> Legacy: <br> Event `627: Change Password Attempt`. | Domain, username and `Logon ID` of the user that performed the password change. <br><br> Target user's domain and username. |
| `Security.evtx` | 4724 | By default, only logged whenever an user successfully reset the specified user's password. <br><br> Failures logged if `Audit User Account Management` is set to `(Success), Failure`. <br> A Failure event is NOT generated if the user gets an `Access Denied` error while attempting the password reset. | Event `4724: An attempt was made to reset an accounts password`. <br><br> Logged as a success (`Audit Success`) if the user did reset the specified user password (which requires elevated rights for local accounts). <br><br> Otherwise reported as a failure (`Audit Failure`) if failures are logged and the new password failed to meet the password policy. <br><br> Legacy: <br> Event `628: User Account password set`. | Domain, username and `Logon ID` of the user that performed the password change. <br><br> Target user's domain and username. |
| `Security.evtx` | 4738 | Default configuration. <br><br> Logged when an user object attributes are modified (for password change, a successful update / reset). | Event `4738: A user account was changed`. <br><br> For password change, update to the `Password Last Set` field. <br><br> Legacy: <br> Event `642: User Account Changed`. | Domain, username and `Logon ID` of the user that performed the password change. <br><br> Target user's domain and username. |
| `Security.evtx` | 4732 | Default configuration. <br><br> Logged whenever an account is added to a local security group. | Event `4732: A member was added to a security-enabled local group`. <br><br> Legacy: <br> Event `636: Security Enabled Local Group Member Added`. | Domain, username and `Logon ID` of the user that performed the action. <br><br> Target group and added user's domain and username. |

### Windows startup folders

The Windows startup folders contains shortcut links (`.lnk`) that will be
executed upon any user log in (`All Users` start up folder) or when the
associated user logs in (`Current Users` start up folders).

###### Filesystem

```
# All Users startup folder.
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

# Current Users startup folders.
C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

The `Everything` tab of the `Sysinternals`' `Autoruns` utility can be used to
enumerate the programs starting through Windows startup folders on a live
system or on a partition mounted from a disk image.

In addition to the `Sysinternals`' `Autoruns` utility, the following PowerShell
script may be used as well:

```
. .\Get-StartupFoldersLnkTargets.ps1

Get-StartupFoldersLnkTargets
Get-StartupFoldersLnkTargets -Drive "F:"
```

```
<#
    .SYNOPSIS
        Get all the starting programs through start up folders

    .DESCRIPTION
      Enumerate all the startup folders lnk using Get-ChildItem and retrieve the lnk targets

    .EXAMPLE
        Get-StartupFoldersLnk -Drive D:
#>

function Get-StartupFoldersLnkTargets {

    param (
        [Parameter(Mandatory=$false)]
        [string]$Drive = "C:"
    )

    $Shell = New-Object -ComObject WScript.Shell

    Get-ChildItem -Force "$Drive\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            LnkFullPath = $_.FullName
            LnkTarget = $Shell.CreateShortcut($_).TargetPath
        }
    }

    $Usernames = Get-ChildItem -Force "$Drive\Users" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty  Name

    foreach ($Username in $Usernames) {
	    Get-ChildItem -ErrorAction SilentlyContinue -Force "$Drive\Users\$Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" | ForEach-Object {
            [pscustomobject]@{
                LnkFullPath = $_.FullName
                LnkTarget = $Shell.CreateShortcut($_).TargetPath
            }
        }
    }
}
```

### ASEP registry keys

A number of registry keys, known as `Auto-Start Extensibility Points (ASEP)`
registry keys, are run whenever the system is booted or a specific user logs
in. The `ASEP` keys under `HKEY_LOCAL_MACHINE (HKLM)` are run every time the
system is started, while the `ASEP` keys under `HKEY_CURRENT_USER (HKCU)` are
only executed when the user associated with the keys logs on to the system.

Indeed, each user with a configured profile has an associated `HKCU\<USERNAME>`
sub key, which contains the registries keys of the user. The `HKCU` keys are
stored in the `%SystemDrive%\Users\<USERNAME\NTUSER.DAT` file.

Each entry is composed of a key and an associated value that may contain a
program, and the program arguments if any, to be run.

The `RegistryExplorer.exe` / `RECmd.exe` utilities leverage transaction log
files, for example `ntuser.dat.LOG1`, to identify and recover deleted keys /
values. The transaction log files must be present in the same directory as
the analyzed hive.

The most commons ASEP keys can be automatically checked using the
`SysInternals`' GUI `Autoruns` and CLI `AutorunsC` utilities. The `RECmd` CLI
utility can also be used to access a predefined list of ASEP registries keys.
The `RegistryASEPs.reb` enumerate a comprehensive list of nearly ASEP 500
registry keys and 400 values. The results of `RECmd` can be analyzed using
`Timeline Explorer`.

Alternatively, `RegistryExplorer.exe` implements a number of `bookmarks` which
are well-known key / value pairs. The `bookmarks` include a number of `ASEP`
registry entries.

```
RECmd.exe -d <NTFS_VOLUME | FOLDER_CONTAINING_REGISTRY_HIVES> --bn .\BatchExamples\RegistryASEPs.reb --csv <OUTPUT_FOLDER>
```

The following run keys are commonly used for persistence:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup
HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar
HKLM\System\CurrentControlSet\Services

HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Shell
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
HKCU\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup
HKCU\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Logon
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

###### Windows EVTX logs

The following events could be indicators of execution on the machine of
persistence through ASEP registry keys:

| Hive     | Event ID | Conditions | Description | Information yield |
|----------|----------|------------|-------------|------------------ |
| `Microsoft-Windows-Shell-Core%4Operational.evtx` | 9707 <br><br> 9708 | Default configuration. <br><br> Introduced in Windows 10 and Windows Server 2016. <br><br> Logged whenever a program is executed through the `Run` / `RunOnce` registry keys. | Event `9707: Started execution of command '<COMMAND>'`. <br><br> Event `9708: Finished execution of command '<COMMAND>'`. | Username and domain of the user responsible for the execution. <br><br> Program / command executed. |
| `Security.evtx` | 4657 | Logged whenever an user modify a registry key for which the audit policy is set to audit usage of the `Set Value` rights (by the user.) <br><br> Requires: <br><br> - `Audit: Force audit policy subcategory settings` to be enabled. <br><br> - `Audit object access` set to `Success(, Failure)`. <br><br> - The `SACL` on the ASEP registry keys to define audit on the rights `Create Subkey`, `Set Value`, `Create Link`, `Write DAC`, and `Delete` for the user conducting the action (possibly through identity / group membership, such as, for example, `Everyone`). <br><br> **-> very likely not logged.** | Event `4657: A registry value was modified`. | Username, domain, and `LogonID` of the user conducting the modification. <br><br> Registry key modified and the new value defined. |

### Windows scheduled tasks

Scheduled tasks are used to automatically perform a task on the system whenever
the criteria associated to the scheduled task occurs. The scheduled tasks can
either be run at a defined time, on repeat at set intervals, or when a specific
event occurs, such as the system boot.

###### Live forensics

The `Scheduled Tasks` tab of the `Sysinternals`' `Autoruns` utility can be used
to enumerate the programs starting through Windows scheduled tasks. The
following DOS and PowerShell utilities may be used as well.

```
# Verbose - includes task name, task to run, status, hostname & logon mode, last run time, running user, periodicity, etc.
schtasks /query /fo LIST /v

# List scheduled task - minimal information
Get-ScheduledTask

# Retrieve information - task name, task to run, next and last run time
Get-ScheduledTaskInfo -TaskName "<TASK_NAME>"
```

The following PowerShell cmdlet can be used to export the configured scheduled
tasks to the specified csv file.

Usage:

```
. .\Export_ScheduledTasks.ps1

Export-ScheduledTasksToCsv -OutCsv <CSV_PATH>
```

```
function Export-ScheduledTasksToCsv {

    <#
    .SYNOPSIS
      Export the configured scheduled tasks to a csv using Get-ScheduledTask and Get-ScheduledTaskInfo

    .PARAMETER OutCsv
      File to export the CSV

    #>

    Param(
    [Parameter(Mandatory=$true)]
    [string] $OutCsv
    )

    Get-ScheduledTask |
        ForEach-Object { [pscustomobject]@{
            Server = $env:COMPUTERNAME
            Name = $_.TaskName
            Path = $_.TaskPath
            Description = $_.Description
            Author = $_.Author
            RunAsUser = $_.Principal.userid
            LastRunTime = $(($_ | Get-ScheduledTaskInfo).LastRunTime)
            LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
            NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
            Status = $_.State
            Command = $_.Actions.execute
            Arguments = $_.Actions.Arguments }
     } | Export-Csv -Path $OutCsv -NoTypeInformation
}
```

###### Filesystem

The scheduled tasks are stored in human readable `XML` file on the following
location, depending on the Windows Operating System in use:

  - <= `Windows XP` / `Windows Server 2003` (`Task Scheduler 1.0`): `C:\Windows\Tasks`

  - Starting from `Windows 7` / `Windows Server 2008` (`Task Scheduler 2.0`): `C:\Windows\System32\Tasks`


###### Registry

The scheduled tasks are stored under the following registry keys (as listed in
the `ASEP registry keys` section), located at
`%WinDir%\System32\config\SOFTWARE`:

  - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks`

  - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree`

###### Windows EVTX logs

The following events could be indicators of persistence on the machine through
scheduled tasks:

| Hive     | Event ID | Conditions | Description | Information yield |
|----------|----------|------------|-------------|------------------ |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 106 | Introduced in `Windows 7` / `Windows 2008`. <br><br> Logged whenever a scheduled task is registered.	| Event `106: User "<DOMAIN \| WORKGROUP>\<USERNAME>" registered Task Scheduler task "\<TASK_NAME>"`. <br><br> Can be correlated, after execution of the task, with an event `200` / `201` to determine the scheduled task's executable full path. | Registering user's domain and username. <br><br> Task name. |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 200 | Introduced in `Windows 7` / `Windows 2008`. <br><br> Logged whenever a scheduled task is executed. | Event `200: Task Scheduler launched action "<EXECUTABLE>" in instance "<GUID>" of task "<TASKNAME>"`. <br><br> The task name can be used to correlate the executed task with an event `106` to identify the user that registered the task. | Executed task's name and executable full path. |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 201 | Introduced in `Windows 7` / `Windows 2008`. <br><br> Logged whenever a scheduled task finish its execution. | Event `201: Task Scheduler successfully completed task "<TASKNAME>" , instance "<GUID>" , action "<EXECUTABLE>" with return code <INT>"`. <br><br> Similarly to event `200`, the task name can be used to correlate the executed task with an event `106` to identify the user that registered the task. | Executed task's name, executable full path and execution return code. |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 140 | Introduced in `Windows 7` / `Windows 2008`. <br><br> Logged whenever a scheduled task is updated. | Event `140: User "<DOMAIN \| WORKGROUP>\<USERNAME>"  updated Task Scheduler task "<TASKNAME>"`. | Domain and username of the user that conducted the update. |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 141 | Introduced in `Windows 7` / `Windows 2008`. <br><br> Logged whenever a scheduled task is deleted. | Event `141: User "<DOMAIN \| WORKGROUP>\<USERNAME>" deleted Task Scheduler task "<TASKNAME>"`. | Domain and username of the user that deleted the task. |
| `Security.evtx` | 4698 <br><br> 4700 <br><br> 4701 <br><br> 4702 <br><br> 4699 | Requires: <br><br> `Audit: Force audit policy subcategory settings` to be enabled. <br> And `Other Object Access Events` set to `Success(, Failure)`. | Event `4698: A scheduled task was created`. <br><br> Event `4700: A scheduled task was enabled`. <br><br> Event `4701: A scheduled task was disabled`. <br><br> Event `4702: A scheduled task was updated`. <br><br> Event `4699: A scheduled task was deleted`. <br><br> Legacy: <br> (Only) event `602: Scheduled Task created`. | Domain, username and Logon ID of the user that performed the action. <br><br> Impacted scheduled task detailed information: task name, action(s), trigger(s), privileges, etc. |

### Windows services

In Windows NT operating systems, a Windows service is a computer program that
operates in the background, similarly in concept to a Unix daemon.

A Windows service must conform to the interface rules and protocols of the
`Service Control Manager (SCM)`, the component responsible for managing Windows
services. Windows services can be configured to start with the operating
system, manually or when an event occur.

###### Live forensics

The `Services` tab of the `Sysinternals`' `Autoruns` utility can be used to
detect and delete service-related persistence. Information about the configured
services can also be retrieved using `WMI`:

```
Get-WmiObject -Class win32_service | Select-Object Name, DisplayName, PathName, StartName, StartMode, State, TotalSessions, Description

wmic service list config
```

###### Registry

The Windows services are stored under the following registry keys (as listed in
the `ASEP registry keys` section), located at
`%WinDir%\System32\config\SYSTEM`:

  - `HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>`

The registry keys hold the configuration information of the Windows services:
name, display name, start mode, service type, image path, required privileges
if any, etc.

The last written timestamp of the service sub key indicates the service
creation or last modification time.

###### Windows EVTX logs

The following events could be indicators of persistence on the machine through
Windows services:

| Hive     | Event ID | Conditions | Description | Information yield |
|----------|----------|------------|-------------|------------------ |
| `System.evtx` | 7045 | Default configuration. <br><br> Logged whenever a Windows service is created on the machine. | Event `7045: A service was installed in the system`. | Domain and username of the user that installed the service. <br><br> Information on the installed service: name, file name, type, start type and executing account. |
| `Security.evtx` | 4697 | Introduced in Windows Server 2016 and Windows 10. <br><br> Requires: <br><br> `Audit: Force audit policy subcategory settings` to be enabled. <br> And `Other Object Access Events` set to `Success(, Failure)`. <br><br> Logged whenever a Windows service is created on the machine. | Event `4697: A service was installed in the system`. <br><br> Legacy (Windows Server 2003 and Windows XP): <br> Event `601: Attempt to install service`. | Domain, username and Logon ID of the user that performed the action. <br> -> Often marked as `SYSTEM`. <br><br> Information on the installed service: name, file name, type, start type and executing account. |
| `System.evtx` | 7036 | Default configuration. <br><br> Logged whenever a Windows service is is effectively running / stopped. | Event `7036: The <SERVICE_NAME> service entered the <running/stopped> state`. | The name of the concerned service and the account used to execute the service (which may not be the account that instructed the service to start / stop). |
| `System.evtx` | 7035 | Logged only on <= `Windows XP` and `Windows Server 2003`. <br><br> Logged whenever a Windows service is instructed to start / stop. | Event `7035: The <SERVICE_NAME> service was successfully sent a <start/stop> control`. | The name of the concerned service and the account that instructed the service to start / stop (which is likely different that the account under which the service is executed). |
| `System.evtx`   | 7040 | Default configuration. <br><br> Logged whenever there is a change to a service start type. | Event `7040: The start type of the <SERVICE_NAME> service was changed from demand <OLD_START_TYPE> to <NEW_START_TYPE>`. | The name of the concerned service and the account that modified the service. |
| `System.evtx` | 7030 | Introduced in Windows Vista and Windows Server 2008. <br><br> Logged whenever a service is configured as an interactive service, which is not supported since Windows Vista and Windows Server 2008 (du to security risks posed by interactive services). | Event `7030: The <SERVICE_NAME> service is marked as an interactive service`. | |

### WMI event subscriptions

`Windows Management Instrumentation (WMI)` allows, through
`Event Subscription`, to maintain persistence on a Windows system. Permanent
`WMI` event subscriptions can be configured to persist across reboots.

Permanent event subscriptions are composed of:
  - An `event filter`, which is the event of interest that will trigger the
  consumer. Such event can be, for example, a logon success or system startup.

  - An `event consumer`, which is the action to perform upon trigger of the
  event filter. <br/>
  Five Consumer classes are available:
    - The `ActiveScriptEventConsumer` class that run arbitrary `VBScript`
      or `JScript` code.
    - The `CommandLineEventConsumer` class that run an arbitrary system
      command.
    - The `LogFileEventConsumer` class that write an arbitrary string to a
      text-based log file.
    - The `NtEventLogEventConsumer` class that write an arbitrary Windows `ETW`
      event.
    - The `SMTPEventConsumer` class that send an email.

  - A `filter to consumer binding` (`FilterToConsumerBinding`) which is the
    registration mechanism binding an event filter to an event consumer.

###### Live forensics

The `WMI` tab of the `Sysinternals`' `Autoruns` utility can be used to detect
and delete WMI-related persistence. The WMI event subscriptions can also be
enumerated with the PowerShell cmdlet `Get-WMIObject`:

```powershell
# From PowerShell forensic framework Kansa
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __EventFilter" }
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __EventConsumer" }
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __FilterToConsumerBinding" }
```

###### Process execution

The following process are related to `WMI` activity:

  - `wmic.exe`: command line utility to interact with `WMI` (locally or on a
    remote computer). The `process call` can indicate that process creation is
    done using `WMI` and `/node` can be used to specify a remote computer.

  - `WmiPrvSE.exe`: `WMI Provider Host` process spawn as a result of
    `WMI Event Subscription` execution. Suspicious child process of
    `WmiPrvSE.exe` (such as `powershell.exe` or `cmd.exe`) can be an indicator
    of persistence through `WMI`.

  - `scrcons.exe`: `WMI Standard Event Consumer` process that spawn for
    `ActiveScriptEventConsumer` execution.

  - `wsmprovhost.exe`: indicator of PowerShell remoting activity (not
    particularly relevant to detect local persistence).

As `WMI` can be used legitimately in the environment, the execution of a `WMI`
related program may not necessarily be an indicator of malicious activity.

###### Filesystem

The persistent `WMI Event Subscription` are written to disk in the
(undocumented) `WMI` Repository files at `%WINDIR%\System32\wbem\Repository\` /
`%WINDIR%\System32\wbem\Repository\FS\`:
  - `OBJECTS.DATA`: contains the `CIM objects` with, among other things, the
    event subscriptions data (event consumer, filter, and filter to consumer
    binding).
  - `INDEX.BTR`: paged file in B-tree struct, "used to efficiently lookup CIM
     entities in the objects.data file". May contain
  - `MAPPING<1-3>.MAP`: correlate / map pages from `OBJECTS.DATA` and
    `INDEX.BTR`.

All three files are required to properly conduct forensics analysis on WMI
persistence.

`WMI Event Subscription` data can be extracted from `OBJECTS.DATA` files using
the [`PyWMIPersistenceFinder`](https://github.com/davidpany/WMI_Forensics)
Python script (that rely on regexes to extract the data):

```bash
PyWMIPersistenceFinder.py <OBJECTS.DATA_FILE>
```

If a deeper analysis is required, for example if a consumer reference other
`WMI` objects, [`python-cim`](https://github.com/mandiant/flare-wmi) can be
leveraged to extract data from the `WMI` repository:

```
python3 samples/dump_class_layout.py win7 "<WMI_REPOSITORY_FOLDER>" "<ROOT\cimv2 | WMI_NAMESPACE>" "<WMI_CLASS_NAME>"
```

###### Windows EVTX / text logs

| Hive     | Event ID | Conditions | Description | Information yield |
|----------|----------|------------|-------------|------------------ |
| `Security` | 4688 | Requires `Audit process tracking` to be enabled. <br><br> For the process arguments to be logged, `Include command line in process creation events` must be enabled as well. | Event `4688: A new process has been created`. <br><br> Can be used to track the execution of the aforementioned process related to `WMI` activity. | Current logged-on user's domain, username and `LogonID`. <br><br> Parent and child process. <br><br> Process command line if enabled. |
| `Microsoft-Windows-WMI-Activity/Operational` | 5858 | | Event `5858: Operation_ClientFailure`. <br><br> | Client machine hostname, domain and username of the user, and details about the failed operation. |
| `Microsoft-Windows-WMI-Activity/Operational` | 5859 | | Event `5859: Operation_EssStarted: `. | |
| `Microsoft-Windows-WMI-Activity/Operational` | 5860 | | Event `5860: Operation_TemporaryEssStarted`. | |
| `Microsoft-Windows-WMI-Activity/Operational` | 5861 | | Event `5861: Operation_ESStoConsumerBinding`. | |
| Shimcache <br><br> Amcache <br><br> Other process execution artefacts. | `HKLM\SYSTEM` registry hive <br><br> `Amcache.hve` <br><br> ... | | Programs execution Windows artefacts. <br><br> Can be used to track the execution of the aforementioned binaries. | The information yield will depend on the given artifact, but will generally be limited. |

### Legitimate startup PE hooking

One of the most covert technique to implement persistence on a system is
through the hooking of a legitimate `Portable Executable (PE)` (executable and
DLL) that normally starts up after boot time or whenever an user logs in.

For example, malicious code can be injected into a legitimate binary using a
PE infector such as `Shellter`. If done correctly, the injection will not alter
the normal functioning of the legitimate binary and is likely to evade
anti-virus detection. For even more stealthiness, the injection can be
conducted in a DLL loaded by a legitimate program, as loaded DLL are not
enumerated by the `Sysinternals`' `Autoruns` utility. An actually loaded DLL
can be modified or the path of a loaded DLL may be hijacked.

While PE injection invalidates the digital signature of the file, many
legitimates PE are not digitally signed, or are signed by an unrecognized
authority, and verifications of digital signatures are bound to raise an
important volume of false-positives.

###### Filesystem

Detecting PE hooking is a **difficult and fallible process**. An analysis of
the NTFS partition's `$MFT` and `$UsnJrnl` entries can give information about
the creation and modification of legitimate PE on the system. Refer to the
`DFIR - Filesystem history` note for more information. Additionally, if the
malware strain could be retrieved, a reverse engineering of its functionalities
may permit the identification of `Indice of Compromise (IoC)` for later
detection.

--------------------------------------------------------------------------------

### References

https://www.mandiant.com/resources/windows-management-instrumentation-wmi-offense-defense-and-forensics

https://netsecninja.github.io/dfir-notes/wmi-forensics/

https://www.mandiant.com/sites/default/files/2021-09/wp-windows-management-instrumentation.pdf
