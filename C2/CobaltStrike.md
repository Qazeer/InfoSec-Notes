# Cobalt Strike

### Team server & client

###### Team server overview

Cobalt Strike is split into a server, named the `team server`, and client
components. The `team server` is at the core of the `Cobalt Strike`
infrastructure, with the `beacons` calling back (directly or through a
redirector) to the `team server` for actions.

The `team server` expose the `TCP` port 50050 for clients access (using the
`Cobalt Strike` client component). The port should not be publicly exposed on
the Internet, notably because scans are conducted by blue teams to identify
Internet-facing `Cobalt Strike` `team servers`. A remote access service
(`SSH`, `VPN`, etc.) should be used instead for collaborative access.

Additionally, the `beacons` should not call back directly to the
`team server`, but should instead call back to a redirector (such as
`Azure CDN` for example). This  greatly limit the exposure of the
`team server`, and reduce the risk of the `team server` being identified by
the blue team.

```
# Starts the team server over the given IP and with the specified shared password (for clients access).

./teamserver <LISTENING_IP> <PASSWORD> [<C2_PROFILE_PATH>] [<BEACON_KILL_DATE_YYYY-MM-DD>]
```

###### Malleable C2 Profiles

The way `Cobalt Strike` beacons interact with the `team server` can be
customized through an optional `Malleable C2 profile`, chosen upon the start of
the `team server`. **A custom `Malleable C2 profile` should always be used for
operations, in order to limit the risk of detection.**

The `Malleable C2 Profile` notably controls:
  - The default `beacons` sleep time and optional jitter (to randomize the
    effective `beacons` sleep time).

  - Staging process, which is recommended to keep disabled
    (`set host_stage "false"`) for OPSEC issues (identification of
    `team server` by simulating a staged beacons). If disabled, only stageless
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

A number of public `Malleable C2 Profiles` can be used as templates /
references for further customization (publicly shared profiles shouldn't be
used as is, due to known markers being already defined by security products).

| Malleable profile(s) | Description |
|----------------------|-------------|
| [malleable-c2's jquery-cX.X.X.profile](https://github.com/threatexpress/malleable-c2) | Profiles attempting to mimic a jquery.js request. |
| [rsmudge's Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles) | A number of profiles to mimic various services (Gmail, OCSP,  wikipedia, etc.) as well as attacker groups (based on mostly outdated threat intelligence however). |

`Cobalt Strike`'s `c2lint` utility can be used to check the validity of the
specified profile: `c2lint <C2_PROFILE_PATH>`.

###### Cobalt Strike client

```
./cobaltstrike
```

### Cobalt Strike beacons

###### Listeners

###### Beacons generation

###### Artefact kit

###### Resource kit

The `resource kit` is part of `Cobalt Strike` property `Arsenal` and contains
`PowerShell`, `Python`, and `VBA` templates used by `Cobalt Strike` for
related operations. The `resource kit` is notably used for:
  - Script based beacon stagers (`PowerShell` and `Python`).

  - `VBA` macro for generated `Office` documents.

  - PowerShell operations (commands and download)

  - PowerShell command and download one-liner for operations related to
    PowerShell (`powershell`, `winrm`, `psexec_psh`, etc.) or requiring file
    download (`powershell-import`, `elevate`, `spawnas` / `spawnu`, etc.).

| File | Description |
|------|-------------|
| resources.cna | `Aggressor` script to load in order to instruct `Cobalt Strike` to use the templates defined in the `resource kit` over the built-in ones. |
| compress.ps1 | PowerShell template to compress PowerShell scripts (by default using `IO.Compression.GzipStream`). <br><br> Affected components: <br> - Beacons PowerShell payloads. <br> - Scripted Web Delivery (PowerShell). <br> - beacons' `powershell-import`, `psexec_psh`, and `wmi` commands. |
| template.x86.ps1 | PowerShell template for x86 PowerShell beacon stagers.  <br><br> Affected components: <br> - Windows EXE x86 stage-less PowerShell payload. <br> - Scripted Web Delivery (PowerShell). <br> - beacons' `spawnas` / `spawnu`, `psexec_psh`, and `winrm` / `wmi` commands. <br> - HTML Application (`PowerShell` method). |
| template.x64.ps1 | PowerShell template for x64 PowerShell beacon stagers. <br><br> Affected components: <br> - Windows EXE x64 stage-less PowerShell payload. |
| template.x86.vba | VBA template for x86 payloads. <br><br> Affected components: <br> - Microsoft Office Macro Attack. <br> - HTML Application (`VBA` method). - Scripted Web Delivery (`regsvr32` method). |
| template.vbs | `VBScript` template used to execute `VBA` payloads (such as a payload generated from `template.x86.vba`).  |
| template.exe.hta | `HTA` template for HTML application (`Attacks -> Packages -> HTLM Application`) generated with the `Executable` method. |
| template.psh.hta | `HTA` template for HTML application (`Attacks -> Packages -> HTLM Application`) generated with the `PowerShell` method. |
| template.py | Python for x86 and x64 payloads. <br><br> Affected components: <br> - Scripted Web Delivery (Python). |

This is the VBA template Cobalt Strike uses to run x86 payloads.

Affected features:
  HTML Application (VBA)
  Microsoft Office Macro Attack
  Scripted Web Delivery (regsvr32)


--------------------------------------------------------------------------------

### References

https://www.cobaltstrike.com/help-start-cobaltstrike

https://www.ired.team/offensive-security/red-team-infrastructure/cobalt-strike-101-installation-and-interesting-commands

https://www.cobaltstrike.com/help-malleable-c2

https://github.com/threatexpress/malleable-c2

https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b
