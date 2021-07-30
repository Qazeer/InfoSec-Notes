# DFIR - Windows lateral movements analysis

**The artefacts generated independently of the lateral movement technics used
are introduced in the `[DFIR] Windows - Account Usage` note. The artefacts
presented below are associated with a given lateral movement technique.**

### Remote Desktop artefacts

#### Destination machine

| Artefact | Location | Conditions | Description | Information yield |
|----------|----------|------------|-------------|-------------------|
| EVTX | `Security.evtx` | Default configuration. | Event `4624: An account was successfully logged on`. <br><br> `LogonType` field: <br><br> `LogonType 10` for standard `RemoteInteractive` authentication. <br><br> Replaced by `LogonType 7` (`This workstation was unlocked`) for existing session unlocking. <br><br> Replaced by `LogonType 3` for `RDP` `RestrictedAdmin` mode. <br><br> Eventual prior event `4624` `LogonType 3` for `NLA` authentication. | Source user domain and username. <br><br> Source machine hostname / IP. |
| EVTX | `Security.evtx` | Requires `Audit Other Logon/Logoff Events`. | Event `4778: A session was reconnected to a Window Station`. <br><br> Event `4779: A session was disconnected from a Window Station`. | Source user domain and username. <br><br> Source machine hostname / IP. |
| EVTX | `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | Default configuration. | Event `1149: Remote Desktop Services: User authentication succeeded` <br><br> **Does not indicate a successful session opening but an access to the Windows login screen.** | Source user domain and username. <br><br> Source machine IP. <br><br> This event followed by unusual / suspicious activity of `NT AUTHORITY\SYSTEM` may indicate the use of a `Sticky Keys` or `Utilman` backdoor. |
| EVTX | `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational` | Default configuration. | Event `21: Remote Desktop Services: Session logon succeeded`. <br><br> Event `22: Remote Desktop Services: Shell start notification received`. <br><br> Event `23: Remote Desktop Services: Session logoff succeeded`. <br><br> Event `25: Remote Desktop Services: Session reconnection succeeded`. <br><br> With `Source Network Address` != `LOCAL`. | Source user domain and username. <br><br> Source machine IP. <br><br> |
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

(SourceName = 'Microsoft-Windows-TerminalServices-LocalSessionManager' AND (EventID = 21 or EventID = 22 or EventID = 23 or EventID = 24 or EventID = 25 or EventID = 39 or EventID = 40))
(SourceName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager' AND EventID = 1149)"

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

  The creation, execution and deletion of a scheduled task will notably, in
  addition to `Security` `EID 4624` and `EID 4672` events, generate the following
  Windows events:
    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 106: User
      "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" registered Task Scheduler task
      "\<TASK_NAME>"`.

    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 140: User
      "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" updated Task Scheduler task
      "\<TASK_NAME>"`.

    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 141: User
      "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>" deleted Task Scheduler task
      "\<TASK_NAME>"`.

    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 129: Task
      Scheduler launch task "\<TASK_NAME>", instance "<INSTANCE>"  with process
      ID <PID>`.

    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 100: Task
      Scheduler started "<INSTANCE>" instance of the "\<TASK_NAME>" task for
      user "NT AUTHORITY\SYSTEM | <DOMAIN | HOSTNAME>\<USERNAME> | <SID>"`.

    - `Microsoft-Windows-TaskScheduler/Operational` hive, `EID 140: User
      "<DOMAIN | HOSTNAME>\<USERNAME> | <SID>"  updated Task Scheduler task
      "\<TASK_NAME>"`.

    - `Security`, if `Audit object access` is enabled for `Success` and
      `Failure`, `EID 4698: A scheduled task was created`. Includes the scheduled
      task detailed configuration (author, triggers, executing user, command and
      eventual command argument, etc.) and can be correlated to a logon session
      using the event `Logon ID`.

    - `Security`, if `Audit object access` is enabled for `Success` and
      `Failure`, `EID 4702: A scheduled task was updated`. Specifies the user
      at the origin of the modification, the task name of the updated scheduled
      task and can be correlated to a logon session using the event `Logon ID`.

    - `Security`, if `Audit object access` is enabled for `Success` and
      `Failure`, `EID 4699: A scheduled task was deleted`. Specifies the user
      at the origin of the modification, the task name of the updated scheduled
      task and can be correlated to a logon session using the event `Logon ID`.

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
