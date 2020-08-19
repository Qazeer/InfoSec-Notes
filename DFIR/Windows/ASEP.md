# DFIR Windows - AutoStart Extensibility Point (ASEP)

### Sysinternals' Autoruns

The `Autoruns` utility of the `Sysinternals` suite has the most comprehensive
knowledge of auto-starting locations on Windows hosts. The following ASEP are
notably listed:
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
live host or on read-write partition mounted from a disk image.

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

### Windows startup folders

The Windows startup folders contains shortcut links (`.lnk`) that will be
executed upon any user log in (`All Users` start up folder) or when the
associated user logs in (`Current Users` start up folders).

```
# All Users startup folder
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

# Current Users startup folders
C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

The `Everything` tab of the `Sysinternals`' `Autoruns` utility can be used to
enumerate the programs starting through Windows startup folders. The
following PowerShell script may be used as well.

Usage:

```
. .\Get-StartupFoldersLnkTargets.ps1

Get-StartupFoldersLnkTargets
```

```
<#
    .SYNOPSIS
        Get all the starting programs through start up folders  

    .DESCRIPTION
      Enumerate all the startup folders lnk using Get-ChildItem and retrieve the lnk targets  

    .EXAMPLE
        Get-StartupFoldersLnk
#>

function Get-StartupFoldersLnkTargets {
    $Shell = New-Object -ComObject WScript.Shell

    Get-ChildItem -Force "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" | ForEach-Object {
        [pscustomobject]@{
            LnkFullPath = $_.FullName
            LnkTarget = $Shell.CreateShortcut($_).TargetPath
        }
    }


    $Usernames = get-childitem C:\Users | Select-Object -ExpandProperty  Name
    foreach ($Username in $Usernames) {			
	    Get-ChildItem -ErrorAction SilentlyContinue -Force "C:\Users\$Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk" | ForEach-Object {
            [pscustomobject]@{
                LnkFullPath = $_.FullName
                LnkTarget = $Shell.CreateShortcut($_).TargetPath
            }
        }
    }
}
```

### ASEP registries keys

Windows runs keys and services are registries entries that run whenever the
system is booted or a specific user logs in. The ASEP
`HKEY_LOCAL_MACHINE (HKLM)` keys are run every time the system is started while
ASEP `HKEY_CURRENT_USER (HKCU)` keys are only executed when the user associated
with the keys logs on to the system. Indeed, each user with a configured
profile has an associated `HKCU\<USERNAME>` sub key, which contains the
registries keys of the user.

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

### Windows scheduled tasks

Scheduled tasks are used to automatically perform a task on the system whenever
the criteria associated to the scheduled task occurs. The scheduled tasks can
either be run at a defined time, on repeat at set intervals, or when a specific
event occurs, such as the system boot.

The `Scheduled Tasks` tab of the `Sysinternals`' `Autoruns` utility can be used
to enumerate the programs starting through Windows scheduled taks. The
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

### Windows services

In Windows NT operating systems, a Windows service is a computer program that
operates in the background, similarly in concept to a Unix daemon.

A Windows service must conform to the interface rules and protocols of the
`Service Control Manager (SCM)`, the component responsible for managing Windows
services. Windows services can be configured to start with the operating
system, manually or when an event occur.

Note that services are stored in the registry key
`HKLM\SYSTEM\CurrentControlSet\Services`, listed as an ASEP run key in the
`ASEP registries keys` section.

The `Services` tab of the `Sysinternals`' `Autoruns` utility can be used to
detect and delete service-related persistence. Information about the configured
services can also be retrieved using `WMI`:

```
Get-WmiObject -Class win32_service | Select-Object Name, DisplayName, PathName, StartName, StartMode, State, TotalSessions, Description

wmic service list config
```

### WMI event subscriptions

`Windows Management Instrumentation (WMI)` allows, through
`Event Subscription`, to maintain persistence on a Windows system. Permanent
`WMI` event subscriptions can be configured to persist across reboots.

Permanent event subscriptions are composed of:
  - An `event filter`, which is the event of interest that will trigger the
  consumer. Such event can be, for example, a logon success or system startup.
  - An `event consumer`, which is the action to perform upon trigger of the
  event filter. Five Consumer classes are available, the
  `ActiveScriptEventConsumer` and `CommandLineEventConsumer` classes allowing,
  respectively, for the execution of a predefined script or an arbitrary
  program, in the local system context.
  - A `filter to consumer binding` which is the registration mechanism binding
  an event filter to an event consumer.

The `WMI` tab of the `Sysinternals`' `Autoruns` utility can be used to detect
and delete WMI-related persistence. The WMI event subscriptions can also be
enumerated with the PowerShell cmdlet `Get-WMIObject`:

```
# From PowerShell forensic framework Kansa
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __EventFilter" }
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __EventConsumer" }
ForEach ($NameSpace in "root\subscription","root\default") { Get-WMIObject -Namespace $Namespace -Query "SELECT * FROM __FilterToConsumerBinding" }
```

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

Detecting PE hooking is a **difficult and fallible process**. An analysis of
the NTFS partition's `$MFT` and `$UsnJrnl` entries can give information about
the creation and modification of legitimate PE on the system. Refer to the
`DFIR - Filesystem history` note for more information. Additionally, if the
malware strain could be retrieved, a reverse engineering of its functionalities
may permit the identification of `Indice of Compromise (IoC)` for later
detection.         
