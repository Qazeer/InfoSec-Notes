# AutoStart Extensibility Point (ASEP)

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

`Autoruns` DOES NOT check the loaded DLL, so   

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

### Scheduled tasks

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

### ASEP registries

https://digital-forensics.sans.org/blog/2019/05/07/malware-persistence-recmd

Common:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\System\CurrentControlSet\Services
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9
HKCU\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup
HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup
HKCU\Software\Policies\Microsoft\Windows\System\Scripts\Logon
HKLM\Software\Policies\Microsoft\Windows\System\Scripts\Logon
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman
HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
HKLM\Software\Microsoft\Internet Explorer\Toolbar
```

### WMI

```
Get-WMIObject -Namespace root\Subscription -Class __EventFilter

Get-WMIObject -Namespace root\Subscription -Class __EventConsumer

Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```


C:\Windows\System32\randomnumber\
C:\Windows\System32\tasks\randomname
C:\Windows\[randomname]
C:\users[myusers]\appdata\roaming[random]
%appdata%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup [Randomname].LNK. file in the startup folder
