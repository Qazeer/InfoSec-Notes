# DFIR - Windows lateral movements analysis

### Generic artefacts

The artefacts presented below are generated independently of the lateral
movement technics used.

#### Active Directory

#### Destination machine

###### Summary

| Artefact | Location | Conditions | Description |
|----------|----------|------------|-------------|
| EVTX | `Security.evtx` | Default configuration. | Event `4624: An account was successfully logged on`. <br><br> Legacy: <br> Events `528: Successful Logon` and `540: Successful Network Logon`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4625: XXX`. <br><br> Legacy: <br> Event `XXX`. |
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged on for logon with elevated privileges. | Event `4672: Special privileges assigned to new logon`. <br><br> Legacy: <br> Events `576: Special privileges assigned to new logon`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4634: An account was logged off`. <br><br> Legacy: <br> Events `538: User Logoff`. |
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged on for `Interactive` and `RemoteInteractive` logons. | Event `4647: User initiated logoff`. <br><br> Legacy: <br> Events `551: User initiated logoff`. |
| EVTX | `Security.evtx` | Requires `Audit Other Logon/Logoff Events`. | Event `4649: A replay attack was detected`. <br><br> Event `4778: A session was reconnected to a Window Station`. <br><br> Event `4779: A session was disconnected from a Window Station`. <br><br> Event `4800: The workstation was locked`. <br><br> Event `4801: The workstation was unlocked`. <br><br> Event `4802: The screen saver was invoked`. <br><br> Event `4803: The screen saver was dismissed`. <br><br> Event `5378: The requested credentials delegation was disallowed by policy`. <br><br> Event `5632: A request was made to authenticate to a wireless network`. <br><br> Event `5633: A request was made to authenticate to a wired network`. <br><br> |

###### Security Event ID 4624

Location: destination machine `Security.evtx`.<br>
Event ID: `4624: An account was successfully logged on`.

Privileged logon will generate an additional `Security` event: `4672: Special
privileges assigned to new logon`.

The `4624` event yields information such as:
  - The SID `SubjectUserSid`, account name `SubjectUserName`, and domain
    `SubjectDomainName` of the user logging in.
  - the source machine hostname `WorkstationName`, IP `IpAddress` and port
    `IpPort` if the event corresponds to remote login (otherwise the three
    aforementioned fields are set to `-`).
  - The authentication protocol in the `AuthenticationPackageName` field
    (`NTLM`, `Kerberos` or `Negotiate `) used for the logging. If the logon is
    made through the `NTLM` protocol, the `LmPackageName` field precisely
    identify the `NTLM` version in use (`LM`, `NTLM V1`, `NTLM V2`).
  - The logon type in the `LogonType` field (detailed below).
  - The privileges level in the `ElevatedToken` field. If set to `%%1842`
    (`Yes`), the session the event represents runs in a elevated context. The
    event can be correlated with the `Security` event `EID: 4672` to precisely
    identify the privilege tokens of the session.
  - The impersonation level of the event in the `ImpersonationLevel` field
    (detailed below).
  - the `LogonID` field identifying the logon session, which can be correlated
    with various other `Security` events.

The `LogonType` field provides information on how the logging was established:

| Logon Type | Description |
|------------|-------------|
| 2          | Interactive logon (on screen) |
| 3          | Network logon (share access, etc.) |
| 4          | Batch logon (scheduled task) |
| 5          | Service logon (service startup) |
| 7          | Unlock (on screen unlocking) |
| 8          | NetworkCleartext authentication (usually HTTP basic authentication) |
| 9          | NewCredentials authentication (does not seem to be in use) |
| 10         | RemoteInteractive authentication (Terminal Services, Remote Desktop or Remote Assistance) |
| 11         | CachedInteractive authentication (on screen logging using cached credentials when a domain controller cannot be reached) |

The `ImpersonationLevel` field may take the following values:

| Flag | Correspondence | Description |
|------|----------------|-------------|
| `-` | `SecurityAnonymous` | The server process cannot obtain security information about the client. |
| `%%1832` | `Identification` | The server process can obtain information about the client but cannot impersonate the client and thus the client has no privileges. |
| `%%1833 ` | `Impersonation` | The server process can obtain information and impersonate the client's security context on the local system. |
| `%%1840 ` | `Delegation` | The server process can impersonate the client's security context on remote systems. |

###### Security Event ID 4672

Location: destination machine `Security.evtx`.<br>
Event ID: `4672: Special privileges assigned to new logon`.

This event occurs whenever an account is assigned one, or more, of the
following privileges:

  - SeTcbPrivilege
  - SeBackupPrivilege
  - SeCreateTokenPrivilege
  - SeDebugPrivilege
  - SeEnableDelegationPrivilege
  - SeAuditPrivilege
  - SeImpersonatePrivilege
  - SeLoadDriverPrivilege
  - SeSecurityPrivilege
  - SeSystemEnvironmentPrivilege
  - SeAssignPrimaryTokenPrivilege
  - SeRestorePrivilege
  - SeTakeOwnershipPrivilege

The `SubjectLogonId` field can be correlated with the `Security` event
`EID: 4624` in order to retrieve more information on the logon session.

###### Security Event ID 4634 / 4647

Location: destination machine `Security.evtx`.<br>
Event ID: `4634: An account was logged off` <br>
Event ID: `4647: User initiated logoff`.

#### Source machine

###### Summary

| Artefact | Location | Conditions | Description |
|----------|----------|------------|-------------|
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged whenever alternate credentials are used. | Event `4648: A logon was attempted using explicit credentials`. <br><br> Legacy: <br> Events `552: Logon attempt using explicit credentials`.  |

###### Security Event ID 4648

Windows Security Log Event ID 4648
`4648: A logon was attempted using explicit credentials`
Logged on client. Includes information about the target server:
`Target Server Name` (hostname or IP) and `Additional Information` of the
service requested.

### Remote Desktop artefacts

#### Destination machine

| Artefact | Location | Conditions | Description | Information yield |
|----------|----------|------------|-------------|-------------------|
| EVTX | `Security.evtx` | Default configuration. | Event `4624: An account was successfully logged on`. <br><br> `LogonType` field: <br><br> `LogonType 10` for standard `RemoteInteractive` authentication. <br><br> Replaced by `LogonType 7` (`This workstation was unlocked`) for existing session unlocking. <br><br> Replaced by `LogonType 3` for `RDP` `RestrictedAdmin` mode. <br><br> Eventual prior event `4624` `LogonType 3` for `NLA` authentication. | Source user domain and username. <br><br> Source machine hostname / IP. |
| EVTX | `Security.evtx` | Requires `Audit Other Logon/Logoff Events`. | Event `4778: A session was reconnected to a Window Station`. <br><br> Event `4779: A session was disconnected from a Window Station`. | Source user domain and username. <br><br> Source machine hostname / IP. |
| EVTX | `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | Default configuration. | Event `1149: Remote Desktop Services: User authentication succeeded` <br><br> **Does not indicate a successful session opening but an access to the Windows login screen.** | Source user domain and username. <br><br> Source machine IP. <br><br> This event followed by unusual / suspicious activity of `NT AUTHORITY\SYSTEM` may indicate the use of a `Sticky Keys` or `Utilman` backdoor. |
| EVTX | `Log: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | Default configuration. | Event `21: Remote Desktop Services: Session logon succeeded`. <br><br> Event `22: Remote Desktop Services: Shell start notification received`. <br><br> Event `23: Remote Desktop Services: Session logoff succeeded`. <br><br> Event `25: Remote Desktop Services: Session reconnection succeeded`. <br><br> With `Source Network Address` != `LOCAL`. | Source user domain and username. <br><br> Source machine IP. <br><br> |
| EVTX | `Microsoft-WindowsRemoteDesktopServicesRdpCoreTS%4Operational.evtx` | Default configuration. <br><br> Introduced in `>= Windows Server 2012`. | Event `131: The server accepted a new TCP connection from client <IP>`. <br><br> **Does not indicate a successful session opening but a network access to the RDS service.** | Source machine IP. |
| Prefetch | `C:\Windows\Prefetch\` |  Only generated on Windows desktop OS by default. | Prefetch files related to `RDP` activity: <br><br> `TSTHEME.EXE-<RANDOM>.pf` <br><br> `RDPCLIP.EXE-<RANDOM>.pf` | Timestamp of last runs and overall number of executions. |
| Filesystem <br><br> MFT <br><br> UsnJrnl |  `C:\Windows\Prefetch\` <br><br> `$MFT` <br><br> `\$Extend\$UsnJrnl` | Only generated on Windows desktop OS by default. | Entries for Prefetch files related to `RDP` activity: <br><br> `TSTHEME.EXE-<RANDOM>.pf` <br><br> `RDPCLIP.EXE-<RANDOM>.pf` | The most recent Prefetch file `LastModified` timestamp correspond to the last `RDP` activity. <br><br> The `MFT` and `UsnJrnl` may yield information about `RDP` historic activity. |
| Shimcache <br><br> Amcache | `HKLM\SYSTEM` registry hive <br><br> `Amcache.hve` | Unreliably generated. | Entries for `rdpclip.exe` and / or `tstheme.exe`. |

#### Source machine

| Artefact | Location | Conditions | Description | Information yield |
|----------|----------|------------|-------------|-------------------|
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged if `NLA` is enabled on the destination AND alternate credentials are used. | Event `4648: A logon was attempted using explicit credentials`. <br><br> Legacy: <br> Events `552: Logon attempt using explicit credentials`.  | Current logged-on user's domain and username. <br><br> Alternate user's domain and username. <br><br> Destination machine's hostname. The `Network Information` section only yields information about the client. |
| EVTX | `Microsoft-WindowsTerminalServicesRDPClient%4Operational.evtx` | Default configuration. | Event `1024: RDP ClientActiveX is trying to connect to the server (<HOSTNAME>)`. <br><br> Event `1102: The client has initiated a multi-transport connection to the server <IP>.` | Current logged-on user's domain and username. <br><br> Event `1024`: destination machine's hostname. <br><br> Event `1102`: destination machine's IP. |
| Registry | `C:\Users\<USERNAME>\NTUSER.DAT` <br> `NTUSER\Software\Microsoft\Terminal Server Client\Servers` | Default configuration. |
| EVTX | `Security.evtx` | Requires `Audit process tracking` to be enabled. <br><br> For the process arguments to be logged, `Include command line in process creation events` must be enabled as well. | Event `4688: A new process has been created`. <br><br> `New Process Name`: `C:\Windows\System32\mstsc.exe`. | Current logged-on user's domain, username and `LogonID`. <br><br> Parent process. <br><br> If the destination machine is specified in the command line, and the command line logged, yields the destination machine's hostname / IP. |

### PsExec artefacts

### Remote Scheduled Tasks artefacts

*Remote job schedule registration, execution and deletion*

Location : Victim `Microsoft-Windows-TaskScheduler%4Operational.evtx` hive.

Artifact : Task Scheduler Event Log(since win7)
- Registering Job schedule ID : 106
  - Account Name used to registration
  - Job Name : Usually “At#” form

- Starting Job schedule ID : 200
  - The path of file executed for job

- Deleting Job schedule ID : 141
  - Account Name used for the deletion


### Remote Windows Services artefacts

### WMI artefacts

### WinRM artefacts

| Microsoft-Windows-WinRM/Operational | 6 | X | `Creating WSMan Session`.<br/> Logged on the client host. The event connection string field include the remote host address. |
| Microsoft-Windows-WinRM/Operational | 91 | X | `Session creation`. |
| Microsoft-Windows-WinRM/Operational | 161 | X | `The client cannot connect to the destination specified in the request.`<br/> Error event, logged on the remote system.<br/> The `User` and `Computer` event fields provide information on the client. |
| Microsoft-Windows-WinRM/Operational | 168 | X | `Session creation`. |

WinRM Operational event log entries indicating authentication prior to
PowerShell remoting on an accessed system
• Event ID 169: “User [DOMAIN\Account] authenticated successfully using [authentication_protocol]”

System event log entries indicating a configuration change to the Windows Remote Management service:
○ Event ID 7040 “The start type of the Windows Remote Management (WS-Management) service was changed from [disabled / demand start] to auto start.” – recorded when PowerShell remoting is enabled.
○ Event ID 10148 (“The WinRM service is listening for WS-Management requests”) – recorded upon reboot on systems where remoting has been enabled.

WinRM Operational event log entries indicating authentication prior to PowerShell remoting on an accessed system:
○ Event ID 169 (“User [DOMAIN\Account] authenticated successfully using [authentication_protocol]”)
### DCOM artefacts
