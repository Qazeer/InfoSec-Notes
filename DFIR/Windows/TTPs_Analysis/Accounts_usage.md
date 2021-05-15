# DFIR - Accounts usage analysis

### Automated accounts usage extraction and parsing

The following `LogParser.exe` query extract and parse multiple `Security`
events related to Windows logon into an output `CSV` file. The following
`events ID` are processed: 4624, 4625, 4634, 4647, 4648, 4772, 4778, 4779,
4800, 4801, 4802, and 4803.

This query can prove useful for analysis of events from both Domain Controllers
and Windows servers or workstations.

The query is implemented in `KAPE` as the `Logon-Logoff-events` module.

```bash
# Author: Brian Maloney (idea by @0x47617279).

LogParser.exe -stats:OFF -i:EVT -o CSV "SELECT TO_UTCTIME(TimeGenerated) AS Date, EventID, CASE EventID WHEN 4624 THEN 'An account was successfully logged on' WHEN 4625 THEN 'An account failed to log on' WHEN 4634 THEN 'An account was logged off' WHEN 4647 THEN 'User initiated logoff' WHEN 4648 THEN 'A logon was attempted using explicit credentials' WHEN 4672 THEN 'Special privileges assigned to new logon' WHEN 4778 THEN 'A session was reconnected to a Window Station' WHEN 4779 THEN 'A session was disconnected from a Window Station' WHEN 4800 THEN 'The workstation was locked' WHEN 4801 THEN 'The workstation was unlocked' WHEN 4802 THEN 'The screen saver was invoked' WHEN 4803 THEN 'The screen saver was dismissed' END as Description, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 0, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 0, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 1, '|') END as Username, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 6, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 6, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 1, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 2, '|') END as Domain, CASE EventID WHEN 4648 THEN STRCAT(EXTRACT_TOKEN(Strings, 6, '|'),STRCAT('\\',EXTRACT_TOKEN(Strings, 5, '|'))) END AS CredentialsUsed, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 7, '|') WHEN 4624 THEN EXTRACT_TOKEN(Strings, 7, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4647 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4672 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 2, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 3, '|') END AS LogonID, CASE EventID WHEN 4778 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 3, '|') WHEN 4800 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4801 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4802 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4803 THEN EXTRACT_TOKEN(Strings, 4, '|') END AS SessionName, REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(REPLACE_STR(CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 8, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 10, '|') WHEN 4634 THEN EXTRACT_TOKEN(Strings, 4, '|') END,'2','Logon via console'),'3','Network Logon'),'4','Batch Logon'),'5','Windows Service Logon'),'7','Credentials used to unlock screen'),'8','Network logon sending credentials (cleartext)'),'9','Different credentials used than logged on user'),'10','Remote interactive logon (RDP)'),'11','Cached credentials used to logon'),'12','Cached remote interactive (similar to Type 10)'),'13','Cached unlock (similar to Type 7)') AS LogonType, CASE EventID WHEN 4625 THEN CASE EXTRACT_TOKEN(strings, 7, '|') WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request' WHEN '0xc0000064' THEN 'user name does not exist' WHEN '0xc000006a' THEN 'user name is correct but the password is wrong' WHEN '0xc000006d' THEN 'user logon with misspelled or bad password' WHEN '0xc000006e' THEN 'unknown user name or bad password' WHEN '0xc000006f' THEN 'user tried to logon outside his day of week or time of day restrictions' WHEN '0xc0000070' THEN 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)' WHEN '0xc0000071' THEN 'expired password' WHEN '0xc0000072' THEN 'account is currently disabled' WHEN '0xc00000dc' THEN 'Indicates the Sam Server was in the wrong state to perform the desired operation.' WHEN '0xc0000133' THEN 'clocks between DC and other computer too far out of sync' WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine' WHEN '0xc000018c' THEN 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed' WHEN '0xc0000192' THEN 'An attempt was made to logon, but the netlogon service was not started' WHEN '0xc0000193' THEN 'account expiration' WHEN '0xc0000224' THEN 'user is required to change password at next logon' WHEN '0xc0000225' THEN 'evidently a bug in Windows and not a risk' WHEN '0xc0000234' THEN 'user is currently locked out' WHEN '0xc00002ee' THEN 'Failure Reason. An Error occurred during Logon' WHEN '0xc0000413' THEN 'Logon Failure. The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine' ELSE EXTRACT_TOKEN(strings, 7, '|') END END AS Status, CASE EventID WHEN 4625 THEN CASE EXTRACT_TOKEN(strings, 9, '|') WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request' WHEN '0xc0000064' THEN 'user name does not exist' WHEN '0xc000006a' THEN 'user name is correct but the password is wrong' WHEN '0xc000006d' THEN 'user logon with misspelled or bad password' WHEN '0xc000006e' THEN 'unknown user name or bad password' WHEN '0xc000006f' THEN 'user tried to logon outside his day of week or time of day restrictions' WHEN '0xc0000070' THEN 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)' WHEN '0xc0000071' THEN 'expired password' WHEN '0xc0000072' THEN 'account is currently disabled' WHEN '0xc00000dc' THEN 'Indicates the Sam Server was in the wrong state to perform the desired operation.' WHEN '0xc0000133' THEN 'clocks between DC and other computer too far out of sync' WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine' WHEN '0xc000018c' THEN 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed' WHEN '0xc0000192' THEN 'An attempt was made to logon, but the netlogon service was not started' WHEN '0xc0000193' THEN 'account expiration' WHEN '0xc0000224' THEN 'user is required to change password at next logon' WHEN '0xc0000225' THEN 'evidently a bug in Windows and not a risk' WHEN '0xc0000234' THEN 'user is currently locked out' WHEN '0xc00002ee' THEN 'Failure Reason. An Error occurred during Logon' WHEN '0xc0000413' THEN 'Logon Failure. The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine' ELSE EXTRACT_TOKEN(strings, 9, '|') END END AS SubStatus, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(strings, 9, '|') WHEN 4625 THEN EXTRACT_TOKEN(strings, 11, '|') END AS AuthPackage, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 11, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 13, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 8, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 4, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 4, '|') END AS Workstation, CASE EventID WHEN 4624 THEN EXTRACT_TOKEN(Strings, 18, '|') WHEN 4625 THEN EXTRACT_TOKEN(Strings, 19, '|') WHEN 4648 THEN EXTRACT_TOKEN(Strings, 12, '|') WHEN 4778 THEN EXTRACT_TOKEN(Strings, 5, '|') WHEN 4779 THEN EXTRACT_TOKEN(Strings, 5, '|') END AS SourceIP INTO <DESTINATION_FOLDER>\logparser-Logon-Logoff-events.csv' FROM '<SECURITY_EVTX_FILE>' WHERE EventID IN (4624;4625;4634;4647;4648;4672;4778;4779;4800;4801;4802;4803) AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')" -filemode:0
```

### Active Directory

#### Summary

Note that the events presented below are only the ones related to account
usage centralized on the Domain Controllers from activity on the remote systems
integrated in the Active Directory domain.   
The events logged for account usage on the Domain Controllers themselves are
similar to standard Windows systems (and are thus detailed in the sections
[Destination machine](#destination-machine) and
[Source machine](#source-machine) below).


| Artefact | Location | Conditions | Description |
|----------|----------|------------|-------------|
| EVTX | `Security.evtx` | Default configuration. | [Event `4624: An account was successfully logged on`.](#security-event-id-4624) |
| EVTX | `Security.evtx` | Default configuration. | Event `4625: An account failed to log on`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4768: A Kerberos authentication ticket (TGT) was requested`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4769: A Kerberos service ticket was requested`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4771: Kerberos pre-authentication failed`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4776: The domain controller attempted to validate the credentials for an account`. |

#### LogonTracer

`LogonTracer` is a tool to display Active Directory logon-related events as a
graph. Logon events are represented as two nodes, the host (hostname or IP
address) and the account name, linked by the event information (`event ID`,
number of occurrences, etc.).

The following `events ID` are processed: 4624, 4625, 4768, 4769, 4776, and
4672.

Events can be filtered on a number of criteria:
  - The host(s) (hostname or IP) or user(s) concerned by the logon.
  - If the authentication provider is `NTLM` (AuthName: NTLM).
  - The logon type: `RDP` (Logon type 10), `Network` (Logon type 3), `Batch`
    (Logon type 4), and `Service` (Logon type 5).
  - If the logon was associated to special privileges (`event ID` 4672).
  - etc.

```bash
# LogonTracer default username: neo4j
# LogonTracer default password: password

# Pulls and installs the Docker container.
docker pull jpcertcc/docker-logontracer

# Runs the LogonTracer container.
docker run --detach --publish=7474:7474 --publish=7687:7687 --publish=8080:8080 -e LTHOSTNAME=<IP> jpcertcc/docker-logontracer

# Deletes the example data present by default in the container.
docker exec <CONTAINER_ID> python /usr/local/src/LogonTracer/logontracer.py --delete -u '<USERNAME>' -p '<PASSWORD>' -s <IP>

# It is advised to add Security.evtx hives through the web interface, exposed by default on the TCP port 8080.
Upload Event Log (bottom left) -> Browse -> One or multiple files can be selected -> Upload

# Alternatively, the Security.evtx hives can be upload using the logontracer.py Python script.
python3 logontracer.py [-e <EVTX> | -x <EVTX_XML>] -z <TIME_ZONE> -u '<USERNAME>' -p '<PASSWORD>' -s <IP>
```

### Destination machine

#### Summary

| Artefact | Location | Conditions | Description |
|----------|----------|------------|-------------|
| EVTX | `Security.evtx` | Default configuration. | [Event `4624: An account was successfully logged on`.](#security-event-id-4624) <br><br> Legacy: <br> Events `528: Successful Logon` and `540: Successful Network Logon`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4625: An account failed to log on`. <br><br> Legacy: <br> Events `529`, `530`, `531`, `532`, `533`, `534`, `535`, `536`, `537`, and `539`. |
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged on for logon with elevated privileges. | [Event `4672: Special privileges assigned to new logon`.](#security-event-id-4672) <br><br> Legacy: <br> Events `576: Special privileges assigned to new logon`. |
| EVTX | `Security.evtx` | Default configuration. | Event `4634: An account was logged off`. <br><br> Legacy: <br> Events `538: User Logoff`. |
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged on for `Interactive` and `RemoteInteractive` logons. | Event `4647: User initiated logoff`. <br><br> Legacy: <br> Events `551: User initiated logoff`. |
| EVTX | `Security.evtx` | Requires `Audit Other Logon/Logoff Events`. | Event `4649: A replay attack was detected`. <br><br> Event `4778: A session was reconnected to a Window Station`. <br><br> Event `4779: A session was disconnected from a Window Station`. <br><br> Event `4800: The workstation was locked`. <br><br> Event `4801: The workstation was unlocked`. <br><br> Event `4802: The screen saver was invoked`. <br><br> Event `4803: The screen saver was dismissed`. <br><br> Event `5378: The requested credentials delegation was disallowed by policy`. <br><br> Event `5632: A request was made to authenticate to a wireless network`. <br><br> Event `5633: A request was made to authenticate to a wired network`. <br><br> |

### Source machine

#### Summary

| Artefact | Location | Conditions | Description |
|----------|----------|------------|-------------|
| EVTX | `Security.evtx` | Default configuration. <br><br> Only logged whenever alternate credentials are used. | Event `4648: A logon was attempted using explicit credentials`. <br><br> Legacy: <br> Events `552: Logon attempt using explicit credentials`.  |

### Events details

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
| 2          | Interactive logon. <br><br> *Logon type generated for on screen login at the keyboard as well as some remote access with specific tools. <br> Note that access made using `PsExec` with an user specified using the `-u` option will result in an interactive logon.* |
| 3          | Network logon (share access, etc.). <br><br> *Logon type generated for access over the network (access to `SMB` share, `PsExec`, `WMI` / `WinRM`, etc.).* |
| 4          | Batch logon (scheduled task) |
| 5          | Service logon (service startup) |
| 7          | Unlock (on screen unlocking) |
| 8          | NetworkCleartext authentication (usually HTTP basic authentication) |
| 9          | NewCredentials authentication (does not seem to be in use) |
| 10         | RemoteInteractive authentication (Terminal Services, Remote Desktop or Remote Assistance) |
| 11         | CachedInteractive authentication (logging using cached credentials when a domain controller cannot be reached) |

**Interactive logons (`Logon type 2` and `Logon type 10`) will result in the
storing of the given users secrets (`NTLM` hash or `Kerberos` tickets) in
`LSASS` memory.** Knowing which users logged on interactively on a system can
help determine which accounts could be compromised following the takeover of a
system by an attacker.

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

###### Security Event ID 4648

Windows Security Log Event ID 4648
`4648: A logon was attempted using explicit credentials`
Logged on client. Includes information about the target server:
`Target Server Name` (hostname or IP) and `Additional Information` of the
service requested.
