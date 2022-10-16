# DFIR - Windows - Program execution

### Security.evtx - 4688: A new process has been created

Event: `4688: A new process has been created`.<br/>
Location: victim `Security` hive.<br/>
Requires `Audit Process Creation` to be enabled.

This event is logged upon the creation of every new process on the system.

The `NewProcessName` field stores the full path of the process's executable and
the `ProcessId` field the `Process ID (PID)` of the process. The
`ParentProcessName` field logs the parent process's executable full path and
can be used to identity suspicious processes activity, such as `outlook.exe` or
`iexplorer.exe` starting `cmd.exe` or `powershell.exe` processes.

This event includes the SID `SubjectUserSid`, account name `SubjectUserName`,
and domain `SubjectDomainName` of the user creating the process. Additionally,
the `SubjectLogonId` field can be used to correlate the process creation with
the logon session, event `EID: 4624`.

The `TokenElevationType` field represent the privileges of the process and can
take the following values:

| Flag | Correspondence | Description |
|------|----------------|-------------|
| `%%1936` | `TokenElevationTypeDefault` | The process is started with a full token with no privileges removed or groups disabled. A full token is only used if `User Account Control (UAC)` is disabled or if the user starting the process is the built-in `Administrator` (`RID: 500`), `NT AUTHORITY\SYSTEM` or service account. |
| `%%1937` | `TokenElevationTypeFull` | The process is started with an elevated token with no privileges removed or groups disabled. An elevated token is used when `User Account Control (UAC)` is enabled and the user chooses to start the program in a elevated security context (`Run as administrator` for example). |
| `%%1938` | `TokenElevationTypeLimited` | The process is started with limited privileges, and privileged tokens such as `SeImpersonatePrivilege`, `SeDebugPrivilege`, etc. are removed from the process security context. |

If the `ProcessCreationIncludeCmdLine_Enabled` audit policy is enabled, the
command line specified at the process creation will be logged in the
`ProcessCommandLine` field.

This event is followed by the `Security` event `4689: Process Termination:
Success and Failure` upon the termination of the process.

### Artefacts

For an overview of the artefacts related to programs execution (`SRUM`,
`UserAssist`, `BAM` / `DAM`, `Shimcache`, `Amcache`, `Prefetch`, ...), refer to
the [artefacts overview note](../Artefacts/_Artefacts_overview.md).

--------------------------------------------------------------------------------

### References

https://digital-forensics.sans.org/media/dfir_poster_2014.pdf
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688
