# Cobalt Strike

### TeamServer

###### TeamServer Overview

`Cobalt Strike` is split into a server, named the `teamserver`, and client
components. The `teamserver` is at the core of the `Cobalt Strike`
infrastructure, with the `beacons` calling back (directly or through a
redirector) to the `teamserver` for actions.

The `teamserver` expose the `TCP` port 50050 for clients access (using the
`Cobalt Strike` client component). The port should not be publicly exposed on
the Internet, notably because scans are conducted by blue teams to identify
Internet-facing `Cobalt Strike` `teamservers`. A remote access service
(`SSH`, `VPN`, etc.) should be used instead for collaborative access.

Additionally, the `beacons` should not call back directly to the
`teamserver`, but should instead call back to a redirector (such as
`Azure CDN` for example). This  greatly limit the exposure of the
`teamserver`, and reduce the risk of the `teamserver` being identified by
the blue team.

```bash
# Starts the teamserver over the given IP and with the specified shared password (for clients access).

./teamserver <LISTENING_IP> <PASSWORD> [<C2_PROFILE_PATH>] [<BEACON_KILL_DATE_YYYY-MM-DD>]
```

Note that exposure of the `teamserver` (port `TCP` 50050) should be restricted
at a network level (for example through a `security group` in `AWS` or a
`network security group` in `Azure`). An Internet-facing `teamserver` could be
leveraged by blue teams to retrieve the `beacons` configuration by emulating
staged `beacons` callbacks. This can be for instance achieved using
[`melting-cobalt`](https://github.com/splunk/melting-cobalt). `ssh` may be
used, for example, to forward the `teamserver` `TCP` port on attacking systems:

```bash
# forwards locally the Cobalt Strike teamserver on port TCP 50050.
# The Cobalt Strike client can then be used on attacking systems to connect to the teamserver (at 127.0.0.1).
ssh [-i <PRIVATE_KEY>] -nNT -L 50050:127.0.0.1:50050 <USERNAME>@<TEAMSERVER_PUBLIC_IP>
```

###### Malleable C2 Profiles overview

The way `Cobalt Strike` beacons interact with the `teamserver` can be
customized through an optional `Malleable C2 profile`, chosen upon the start of
the `teamserver`. **A custom `Malleable C2 profile` should always be used for
operations, in order to limit the risk of detection.**

The `Malleable C2 Profile` notably controls:
  - The default `beacons` sleep time and optional jitter (to randomize the
    effective `beacons` sleep time).

  - Staging process, which is recommended to keep disabled
    (`set host_stage "false"`) for OPSEC issues (identification of
    `teamserver` by simulating a staged beacons). If disabled, only stageless
    `beacons` will be usable.

  - The `SSL` / `TLS` certificate used by `HTTPS` listeners.

  - The `HTTP` `beacons` requests `URI` and parameters, the `team-server`
    `HTTP` responses content, as well as headers (`User-Agent`, `Referer`,
    `Server`, etc.).

  - The `TCP` `beacons` listening port, `SMB` `beacons` named pipe, `SSH`
    `beacons` banner and pipe name, `DNS` `beacons` parameters (subhost for
    `A`, `AAAA`, `TXT` records, max query size, etc.).

  - Post-exploitation jobs behavior, such as the program used to spawn process
    for injection, activation of automated `AMSI` bypass in PowerShell jobs,
    Windows `API` leveraged for process injection (memory allocation and code
    injection), etc.

Detailed information about `Cobalt Strike` `Malleable C2 profile` various
options can be found on:
  - [threatexpress's `malleable-c2` GitHub repository](https://github.com/threatexpress/malleable-c2/blob/master/MalleableExplained.md)
  - [SpecterOps's A Deep Dive into Cobalt Strike Malleable C2 blog post](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)

###### Public Malleable C2 profiles

A number of public `Malleable C2 Profiles` can be used as templates /
references for further customization (publicly shared profiles shouldn't be
used as is, due to known markers being already defined by security products).

| Malleable profile(s) | Description |
|----------------------|-------------|
| [malleable-c2's jquery-cX.X.X.profile](https://github.com/threatexpress/malleable-c2) | Profiles attempting to mimic a jquery.js request. |
| [rsmudge's Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles) | A number of profiles to mimic various services (Gmail, OCSP,  wikipedia, etc.) as well as attacker groups (based on mostly outdated threat intelligence however). |

`Cobalt Strike`'s `c2lint` utility can be used to check the validity of the
specified profile: `c2lint <C2_PROFILE_PATH>`.

### Beacons obfuscation

###### Arsenal kit overview

https://www.cobaltstrike.com/scripts

###### Artefact kit: custom beacons PE

###### Resource kit: custom beacons scripts

The `resource kit` is part of `Cobalt Strike` property `Arsenal` and contains
`PowerShell`, `Python`, and `VBA` templates used by `Cobalt Strike` for
related operations. The `resource kit` is notably used for:
  - Script based beacon stagers (`PowerShell` and `Python`).

  - `VBA` macro for generated `Office` documents.

  - PowerShell operations (commands and download)

  - PowerShell command and download one-liner for operations related to
    PowerShell (`powershell`, `winrm`, `psexec_psh`, etc.) or requiring file
    download (`powershell-import`, `elevate`, `spawnas` / `spawnu`, etc.).

The `resource kit` can be loaded / reloaded using the script manager:

```
Cobalt Strike -> Script Manager -> Load / Reload -> resources.cna
```

| File | Description |
|------|-------------|
| `resources.cna` | `Aggressor` script to load in order to instruct `Cobalt Strike` to use the templates defined in the `resource kit` over the built-in ones. |
| `compress.ps1` | PowerShell template to compress PowerShell scripts (by default using `IO.Compression.GzipStream`). <br><br> Affected components: <br> - Beacons PowerShell payloads. <br> - Scripted Web Delivery (PowerShell). <br> - beacons' `powershell-import`, `psexec_psh`, and `wmi` commands. |
| `template.x86.ps1` | PowerShell template for x86 PowerShell beacon stagers.  <br><br> Affected components: <br> - Windows EXE x86 stage-less PowerShell payload. <br> - Scripted Web Delivery (PowerShell). <br> - beacons' `spawnas` / `spawnu`, `psexec_psh`, and `winrm` / `wmi` commands. <br> - HTML Application (`PowerShell` method). |
| `template.x64.ps1` | PowerShell template for x64 PowerShell beacon stagers. <br><br> Affected components: <br> - Windows EXE x64 stage-less PowerShell payload. |
| `template.x86.vba` | VBA template for x86 payloads. <br><br> Affected components: <br> - Microsoft Office Macro Attack. <br> - HTML Application (`VBA` method). - Scripted Web Delivery (`regsvr32` method). |
| `template.vbs` | `VBScript` template used to execute `VBA` payloads (such as a payload generated from `template.x86.vba`).  |
| `template.exe.hta` | `HTA` template for HTML application (`Attacks -> Packages -> HTLM Application`) generated with the `Executable` method. |
| `template.psh.hta` | `HTA` template for HTML application (`Attacks -> Packages -> HTLM Application`) generated with the `PowerShell` method. |
| `template.py` | Python for x86 and x64 payloads. <br><br> Affected components: <br> - Scripted Web Delivery (Python). |

###### Sleep kit: custom obfuscation for beacons sleeps

TODO

###### Custom beacon shellcode generator

The [`Cobalt Strike Shellcode Generator`](https://github.com/RCStep/CSSG)
aggressor script can be used to generate and format `beacon` shellcode. The
generated shellcode can be encrypted using `XOR` or `AES-256-CBC`, as well as
encoded in `base64` or compressed (in `gzip`).

###### Custom beacon shellcode loader

Refer to the `[Windows] - Shellcode and PE loader` note for more information
on shellcode loaders that can be leveraged to execute `Cobalt Strike` beacons.

### Beacons commands (built-in and with third party Aggressor script)

Numerous `beacon` commands are available, allowing a number of actions to be
performed through `Cobalt Strike`'s `beacons`. The commands arguments and
description were largely taken from `Cobalt Strike` help message, while the
OpSec considerations were established using the very comprehensive
[official Cobalt Strike documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf),
public resources (referenced at the end of the present note), and tests done in
[`DetectionLab`](https://github.com/clong/DetectionLab).

###### Beacon Object Files OpSec considerations

A number of `beacon` commands are implemented as `Beacon Object Files (BOF)`.
`BOF` are compiled C programs, with certain limitations, that execute within a
`beacon` process. After completion of the execution, `BOF` are cleaned from
memory. **`BOF` leverage by default `RWX` memory, which is suspicious and may
get flagged by security products.** This behavior can be changed through the
`Malleable C2`'s profile `process-inject` section:

```bash
process-inject {
     # [...]
     set startrwx "false";
     set userwx    "false";
     # [...]
}
```

Additionally, the built-in commands can be overridden / supplemented with
`Aggressor` scripts and third-party `BOFs`.

The commands build around an internal `BOF` will be specified in the following
sections (as `Beacon Object Files OpSec considerations`).

###### Spawn and run pattern OpSec considerations

A number of `beacon` commands (`execute-assembly`, `powerpick`, ...) spawn a
sacrificial process and inject code in the newly created process to conduct
their operations.

A number of considerations should be taken into account for commands using the
spawn and run pattern:
  - By default, `rundll.exe` is spawned as the sacrificial process, which can
    (and should) be changed using the `spawnto <x86 | x64> <BINARY_FULL_PATH>`
    command.

  - By default, the sacrificial process will be spawned as a child of the
    `beacon` process. This behavior can (and in most case should) be changed
    using the `ppid <PID>` command.

  - The spawned process may be monitored by security products through userland
    `DLL` hooking even if the parent process is in an "unhooked" state. Under
    certain circumstances, the `blockdlls start` command can be used to prevent
    userland hooking by leveraging a signature policy that blocks non-Microsoft
    `DLLs` from loading in the child process memory space.

The commands build around the spawn / fork and run pattern will be specified in
the following sections (as `Spawn and run pattern OpSec considerations`).

###### Process injection OpSec considerations

Some commands will default to spawning a new process (fork and run pattern) but
will allow for the specification of an existing target process to inject into.
Limited commands will also require injection into a remote process
(`browserpivot` and `psinject`) with no possible alternative.

A number of considerations should be taken into account for code injection (and
the `beacon` commands build around it):
  - Injection across process arch require the use of more visible / monitored
    Windows `APIs`. As some commands require to be executed in a `x64` process
    on a `x64` system, it is recommended to make use of `x64` beacons as much
    as possible (to avoid `x86` -> `x64` noisy injections).

  - Self-injection uses the much less scrutinized `CreateThread` `API` (by
    default). Specifying the current `beacon` process for commands allowing the
    specification of a target process will result in self-injection. The
    tradeoff of self-injection is a potential `beacon` lose if the injected
    code crashes or get detected and induce a kill of the process.

  - While having other OpSec tradeoffs, the `spawnu` and `runu` commands can be
    used to avoid code injection by spawning, respectively, a new `beacon` or
    binary under another parent process. The child process created will inherit
    the security context of the parent process.

The `Windows API` leveraged for the code injection are defined in the
`Malleable C2`'s profile `process-inject->execute` section:

```bash
# More information on the configuration can be found in the official Cobalt Strike documentation at:
# https://www.cobaltstrike.com/blog/cobalt-strikes-process-injection-the-details-cobalt-strike/
process-inject {
    # Set the remote memory allocation API.
    set allocator "NtMapViewOfSection";

    # Set the content and properties of the injected memory section.
    set min_alloc "16384";
    set startrwx "false";
    set userwx    "false";

    # Set padding instructions, used if needed to reach minimal allocation size.
    transform-x86 {
        prepend "\x90";
    }

    transform-x64 {
        prepend "\x90";
    }

    # Specify the Windows API used for starting the code execution.
    # The API will be used in order if prerequisites are matched.
    # The execute section should cover the following cases: self injection, injection into suspended temporary processes, cross-session remote process injection, x86 -> x64 / x64 -> x86 injection, and injection with or without passing an argument.
    execute {

        # Self injection attempted only if the target process is equal to the current process.
        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;

        # Only called if the targeted process is suspended.
        # Process arch limitations: x86 -> x86, x64 -> x64, or x64 -> x86.
        # Can be choosen over NtQueueApcThread-s.
        # SetThreadContext

        # Only called if the targeted process is suspended.
        # Current and targeted process should be of the same arch (x86 -> x86 or x64 -> x64).
        NtQueueApcThread-s;

        # Creates a RWX stub and register it to the APC queue of every thread in the remote process.
        # If a thread enters an "alertable" state, the stub will execute and call CreateThread on the injected code (to quickly let the original thread continue its normal execution).
        # Current and targeted process should be of the same arch (x86 -> x86 or x64 -> x64).
        # NtQueueApcThread

        # Very visible / monitored API.
        # Process arch limitations: x86 -> x86, x64 -> x64, or x64 -> x86.
        CreateRemoteThread;

        # Very visible / monitored API.
        # No process arch limitation (covers x86 -> x86, x86 -> x64, x64 -> x64, and x64 -> x86).
        # Uses RWX memory for x86 -> x64 injection.
        # Allows code injection across session boundaries.
        RtlCreateUserThread;
    }
}
```

The commands build around process injection (both optional or required) will be
specified in the following sections (as
`Process injection OpSec considerations`).

###### PowerShell OpSec considerations

As specified in the "Resource kit: custom beacons scripts" section above, a
number of commands rely on executing `powershell.exe`.

###### Opsec Aggressor Profiles

A number of
[Opsec Aggressor Profiles](https://github.com/bluscreenofjeff/AggressorScripts/tree/master/OPSEC%20Profiles)
can be loaded to overwrite and disable some of the built-in `beacon` commands.
Each profile disable a class of commands relying an a (potentially) dangerous
/ expensive OpSec pattern (such as execution of `cmd.exe` or process
injection). Note that these `Aggressor` scripts do NOT limit the operations
that are conducted through the `Cobalt Strike` GUI client.

The following profiles are available:
  - `cmd-execution.cna`: prevents commands that rely on `cmd.exe`.
  - `powershell.cna`: prevents commands that rely on `powershell.exe`
  - `process-execution.cna`: prevents commands that spawn a new process.
  - `process-injection.cna`: prevents commands that rely on process injection.
  - `service-creation.cna`: prevents commands that create new services.
  - `template.cna`: template that may be used for any custom commands enabling
    / disabling.

The `Aggressor` scripts also had a `opsec` command that can be used to list all
the `beacon` commands and their activation status.

###### General commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `help` <br><br> `help <COMMAND>` | Print the help menu. | None (no communication with the `beacon`). |
| `checkin` | Call home and post data | |
| `sleep` | Set beacon sleep time | |
| `note` | Assign a note to this Beacon | |
| `history` | Show the command history | |
| `jobs` | List long-running post-exploitation tasks | |
| `jobkill` | Kill a long-running post-exploitation task | |
| `kill` | Kill a process | |
| `unlink` | Disconnect from parent Beacon | |
| `clear` | Clear beacon queue | |
| `exit` | Terminate the beacon session | |
| `screenshot` | Take a single screenshot | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `printscreen` | Take a single screenshot via `PrintScr` method | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `screenwatch` | Take periodic screenshots of desktop | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `spawnto <x86 \| x64> <BINARY_FULL_PATH>` | Set the executable used to spawn processes into for spawn and run commands. <br><br> If spawning a process from `%SystemRoot%\System32`, the path should be specified using `%SystemRoot%\sysnative\` or `%SystemRoot%\syswow64\` instead. <br> The `%SystemRoot%\System32` path is indeed resolved differently for `x86` and `x64` processes ([`%SystemRoot%\System32` is mapped to `%SystemRoot%\syswow64\` for `x86` processes on 64 bits systems](https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)). | |

###### Local system enumeration and interaction commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `ps` | Show process list | |
| `net` | Network and host enumeration tool | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) <br><br> Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `reg query <x86 \| x64> <HIVEROOT\PATH>` <br><br> `reg queryv <x86 \| x64> <HIVEROOT\PATH> <subkey>` | Query the specified key in the registry registry. The `breg` `BOF` should be used for registry modifications. <br><br> Query the specified subkey in the registry registry. <br><br> The `HIVEROOT` should be: <br>`HKLM`, `HKCR`, `HKCC`, `HKCU`, or `HKU`. | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `breg <COMMAND> <HIVEROOT\PATH> [/v <VALUE>] [/t <TYPE>] [/d <DATA>] [/a <x32 \| x64>]` <br><br> Supported commands: `query`, `add`, or `delete`. <br><br> The specified key can be local (`HIVEROOT` = `HKLM`, `HKCR`, `HKCC`, `HKCU`, or `HKU`) or on a remote computer (`\\<HOSTNAME \| IP\HIVEROOT[\<PATH]>`). <br><br> Supported types: `REG_SZ`, `REG_NONE`, `REG_DWORD`, `REG_QWORD`, and `REG_EXPAND_SZ`. | Query, add, or delete keys/values in the registry. | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) <br><br> Specific OpSec considerations depending on the key modified (such as persistence operations through `ASEP` registry keys). |
| `setenv` | Set an environment variable | |

###### Filesystem interaction commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `pwd` | Print current directory | |
| `drives` | List drives on target | |
| `ls` | List files | |
| `cd` | Change directory | |
| `mkdir` | Make a directory | |
| `mv` | Move a file | |
| `cp` | Copy a file | |
| `rm` | Remove a file or folder | |
| `desktop` | View and interact with target's desktop | |
| `upload <LOCAL_FILE_PATH>` | Upload a file to the current working directory. <br><br> The [`better-upload.cna`](https://github.com/mgeeky/cobalt-arsenal/blob/master/better-upload.cna) Aggressor Script can be used to override the `upload` command with an alternative allowing the specification of the output file path: <br> `upload <LOCAL_FILE_PATH> <OUTPUT_FILE_PATH>`. | |
| `download` | Download a file | |
| `downloads` | Lists file downloads in progress | |
| `cancel` | Cancel a download that's in-progress | |

###### Command / code execution commands

*New local beacon session*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `spawn [<x86 \| x64>] <LISTENER>` | Spawn a new process and inject a shellcode for a `beacon` session (calling back to the specified listener). | [Spawn and run pattern OpSec considerations.](#spawn-and-run-pattern-opsec-considerations) |
| `spawnu <PID> <LISTENER>` | Similar to `spawn` except the `beacon` process is spawned as a child of the process specified by `PID`. | While not fully following the spawn and run pattern, the process spawned will default to `rundll.exe` and should be updated using the `spawnto` command. |
| `inject <PID> <x86 \| x64> <LISTENER>` | Spawn a new `beacon` session by injecting a shellcode in the process specified by <PID>. | [Process injection OpSec considerations.](#process-injection-opsec-considerations) |

*Basic commands / programs execution*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `shell <COMMAND> [<ARGUMENTS>]` | Execute the specified command via `cmd.exe`. | Not OpSec friendly and should generally be avoid. <br><br> The `beacon` process will spawn a new `cmd.exe` process, which in turn may spawn a third process executing the specified binary. |
| `execute` | Execute a program on target (no output) |
| `runu` | Execute a program under another PID |

*PowerShell*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `powershell` | Execute a command via powershell.exe | [PowerShell OpSec considerations.](#powerShell-ppsec-considerations) |
| `powerpick` | Execute a command via Unmanaged PowerShell | [Spawn and run pattern OpSec considerations.](#spawn-and-run-pattern-opsec-considerations) |
| `psinject` | Execute PowerShell command in specific process | [Process injection OpSec considerations.](#process-injection-opsec-considerations) |
| `powershell-import` | Import a PowerShell script | |

*In memory .NET assembly execution*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `execute-assembly <ASSEMBLY_FULL_PATH> [<ARGUMENTS>]` | Execute a local `.NET` assembly in-memory through a newly spawned sacrificial process. The main advantage of the sacrificial process is to prevent the `beacon` being impacted by crash or killing (if detected) of the executed `.NET` assembly. <br><br> (Very) Simplified overview of a `.NET` assembly execution via unmanaged code as (possibly) implemented by `execute-assembly`: <br><br> 1. Spawning of a new process and injection of code in the new process. All the next steps described below will be done by the injected code in this new process. <br><br> 2. Loading, if available, of the appropriate version of the `Common Language Runtime (CLR)` for the `.NET` assembly executed (`CLR 2.X` for <= `.NET Framework 3.5` or `CLR 4.X` for `.NET Framework 4.0+` assemblies). <br><br> 3. Instantiation of an `AppDomain` object and loading of the assembly using `AppDomain.Load(byte[] assembly)` or `_AppDomain->Load_3((SAFEARRAY) assembly, _Assembly** pRetVal)`) methods. <br><br> 4. Retrieval of the assembly `EntryPoint` (for example with `Assembly->EntryPoint`) and invocation of the `EntryPoint` with `MethodInfo->Invoke_3`. | [Spawn and run pattern OpSec considerations.](#spawn-and-run-pattern-opsec-considerations) <br><br> The `InlineExecute-Assembly` `BOF` may be used to avoid this pattern (with potential `beacon` stability impact as a tradeoff). |
| [`InlineExecute-Assembly`](https://github.com/anthemtotheego/InlineExecute-Assembly) <br><br> `inlineExecute-Assembly --dotnetassembly <ASSEMBLY_FULL_PATH> [--assemblyargs <ARGUMENTS>]` <br><br> Additional options: <br> `--amsi`: disable `AMSI` <br> | Execute a local `.NET` assembly in-memory directly in the `beacon` process. | `InlineExecute-Assembly` helps avoiding the spawn and run of `execute-assembly` that may be detected by security products. <br><br> As the `.NET` assembly is loaded and executed directly in the `beacon` process however, any crash or detection inducing a kill of the process will result in losing the `beacon`. |

*Beacon Object File (BOF) execution*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `inline-execute` | Run a Beacon Object File in this session | |

*Shellcode / process injection*

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `shinject` | Inject shellcode into a process | |
| `shspawn` | Spawn process and inject shellcode into it | |
| `dllinject` | Inject a Reflective DLL into a process | |
| `dllload` | Load DLL into a process with LoadLibrary() | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |

###### Defense evasion commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `timestomp` | Apply timestamps from one file to another | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `ppid` | Set parent PID for spawned post-ex jobs | |
| `argue` | Spoof arguments for matching processes | |
| `blockdlls` | Block non-Microsoft DLLs in child processes | |

###### Credentials usage commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `runas` | Execute a program as another user | |
| `runasadmin` | Execute a program in an elevated context | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `spawnas` | Spawn a session as another user | |
| `pth` | Pass-the-hash using Mimikatz | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `kerberos_ccache_use` | Apply Kerberos ticket from cache to this session | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `kerberos_ticket_purge` | Purge Kerberos tickets from this session | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `kerberos_ticket_use` | Apply Kerberos ticket to this session | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |

###### Privileges and local privilege escalation commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `make_token` | Create a token to pass credentials | |
| `steal_token` | Steal access token from a process | |
| `rev2self` | Revert to original token | |
| `elevate` | Spawn a session in an elevated context | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |

###### Lateral movement commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `portscan` | Scan a network for open services | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `run` | Execute a program on target (returns output) | |
| `jump` | Spawn a session on a remote host | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |
| `link` | Connect to a Beacon peer over a named pipe | |
| `connect` | Connect to a Beacon peer over TCP | |
| `remote-exec` | Run a command on a remote host | [Beacon Object Files OpSec considerations.](#beacon-object-files-opsec-considerations) |

###### Pivoting commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `browserpivot` | Setup a browser pivot session | [Process injection OpSec considerations.](#process-injection-opsec-considerations) |
| `rportfwd` | Setup a reverse port forward | |
| `rportfwd_local` | Setup a reverse port forward via Cobalt Strike client | |
| `covertvpn` | Deploy Covert VPN client | [Spawn and run pattern OpSec considerations.](#spawn-and-run-pattern-opsec-considerations) |
| `spunnel` | Spawn and tunnel an agent via rportfwd | |
| `spunnel_local` | Spawn and tunnel an agent via Cobalt Strike client rportfwd | |
| `ssh` | Use SSH to spawn an SSH session on a host | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `ssh-key` | Use SSH to spawn an SSH session on a host | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `socks` | Start SOCKS4a server to relay traffic | |
| `socks stop` | Stop SOCKS4a server ||

###### Post-exploitation commands

| Command | Description | OpSec considerations |
|-------------|---------|---------------------|
| `keylogger` | Start a keystroke logger | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `chromedump` | Recover credentials from Google Chrome | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `hashdump` | Dump password hashes | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `logonpasswords` | Dump credentials and hashes with mimikatz | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `dcsync` | Extract a password hash from a DC | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |
| `mimikatz` | Runs a mimikatz command | Default to [spawn and run pattern](#spawn-and-run-pattern-opsec-considerations), supports explicit [process injection](#process-injection-opsec-considerations). |

--------------------------------------------------------------------------------

`mode dns`                  Use DNS A as data channel (DNS beacon only)

`mode dns-txt`              Use DNS TXT as data channel (DNS beacon only)

`mode dns6`                 Use DNS AAAA as data channel (DNS beacon only)

--------------------------------------------------------------------------------

### References

https://www.cobaltstrike.com/help-start-cobaltstrike

https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm

https://www.ired.team/offensive-security/red-team-infrastructure/cobalt-strike-101-installation-and-interesting-commands

https://www.cobaltstrike.com/help-malleable-c2

https://github.com/threatexpress/malleable-c2

https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b

https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet

https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
