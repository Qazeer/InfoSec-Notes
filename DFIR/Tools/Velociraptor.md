# Velociraptor

### Overview

`Velociraptor` is an opensource tool designed for the collection of forensic
artefacts on live machines running the Microsoft Windows or Linux operating
systems.

`Velociraptor` relies on `Velocidex Query Language (VQL)` queries to collect
artefacts. `Velociraptor` notably implements a `KAPE "Targets"` collection mode
which uses glob expressions defined in the [`KapeFiles`
repository](https://github.com/EricZimmerman/KapeFiles) to collect files (with
out any post processing).

While `Velociraptor` can be deployed in an server / clients mode for
continuously collecting endpoint events, it can also be used as a standalone
binary to conduct one-time collection. For instance, artefacts retrieved this
way can be parsed latter using, among others, `Kape`.

[Pre-compiled released `Velociraptor` binaries are available on
GitHub](https://github.com/Velocidex/velociraptor/releases).

### System drive independent collect

The following command can be used to collect the `KAPE` default triage
artefacts and the anti-virus logs of a number of products. The artefacts are
collected on the system drive (retrieved from the system environment variable).

```
.\velociraptor.exe artifacts collect -v Windows.KapeFiles.Targets --output "$(hostname).zip" --args Device=$($Env:SystemDrive) --args KapeTriage=Y --args Avast=Y --args AviraAVLogs=Y --args Bitdefender=Y --args ESET=Y --args FSecure=Y --args HitmanPro=Y --args Kaseya=Y --args Malwarebytes=Y --args McAfee=Y --args McAfee_ePO=Y --args Kaseya=Y --args SentinelOne=Y --args Sophos=Y --args Symantec_AV_Logs=Y --args TeamViewerLogs=Y --args TrendMicro=Y --args VIPRE=Y --args WindowsDefender=Y
```

### Offline collector binaries

Standalone collector binary can be executed, without any argument, to conduct
the artefacts collection on a live system.

The pre-compiled released `Velociraptor` binaries may be used to generate the
collector binary, which will collect the artefacts as defined in the provided configuration file:

```
velociraptor.exe config repack <CONFIG_YAML> <COLLECTOR_BINARY.exe>
```

###### [Windows] Standard collection - no autoruns

The following configuration file will collect the artefacts defined in the
`KapeFiles.Targets` as well as a number of other targets (web browsers logs,
remote admins tools logs, anti-virus logs for around 20 solutions, ...) for the
specified drive and its associated `VSS` volumes. The `RecycleBin` artefact can
be removed to better control the resulting collection file.

**Note that the `MFT` will not be collected from the `VSS`**. To collect the
`MFT` from the `VSS`, refer to the more advanced configuration below.

The collected files will be placed in a `ZIP` file `<HOSTNAME>.zip`.

```
# Build standalone collector binary:
# .\velociraptor-v0.6.6-2-windows-amd64.exe config repack velo_light.yaml velo_light.exe
autoexec:
  argv: ["artifacts", "collect", "-v", "Windows.KapeFiles.Targets",
         "--output", "$COMPUTERNAME.zip", "--password", "<PASSWORD>",
         "--args", "Device=C:",
         # Run the collection across all VSS and collect only unique changes.
         "--args", "VSSAnalysis=Y",
         # Kape default triage.
         "--args", "KapeTriage=Y",
         # In completion to KapeTriage
         # The RecycleBin artefact can be removed to better control the resulting collection file.
         "--args", "RecycleBin=Y",
         "--args", "_MFTMirr=Y",
         "--args", "PowerShellConsole=Y",
         "--args", "RDPCache=Y",
         "--args", "ScheduledTasks=Y",
         "--args", "StartupFolders=Y",
         "--args", "CloudStorage_Metadata=Y",
         "--args", "CombinedLogs=Y",
         # Web browsers history, bookmarks, ...: Edge, Chrome, Firefox, and Internet Explorer
         "--args", "WebBrowsers=Y",
         "--args", "InternetExplorer=Y",
         # Remote admin tools.
         "--args", "RemoteAdmin=Y",
         # Windows Firewall Logs
         "--args", "WindowsFirewall=Y",
         # USB devices log files: Setupapi.log XP, Setupapi.log Win7+
         "--args", "USBDevicesLogs=Y",
         # Anti-virus logs
         "--args", "Antivirus=Y",
         # Transfer tools.
         "--args", "BITS=Y",
         "--args", "CertUtil=Y",
         # Webservers logs.
         "--args", "WebServers=Y",
         # Exchange server related logs.
         "--args", "Exchange=Y",
         "--args", "ExchangeClientAccess=Y",
         # WSL files.
         "--args", "WSL=Y",
         "--args", "LinuxOnWindowsProfileFiles=Y",
         # Windows text editors apps.
         "--args", "MicrosoftOneNote=Y",
         "--args", "MicrosoftStickyNotes=Y",
         "--args", "Notepad__=Y",
         # MS SQL ErrorLogs : MS SQL Errorlog, MS SQL Errorlogs
         "--args", "MSSQLErrorLog=Y"
        ]
```

###### [Windows] Standard collection - with autoruns & MFT VSS

The following configuration file can be used to additionally:
  - Execute `autoruns` to produce `JSON` / `CSV` output files for persistence
    entries.
  - Collect all the `MFT` (even duplicate ones) from the `VSS`.

It is however advised to generate the collector directly from the
`velociraptor` server so the `autoruns` binaries will be embedded in the binary
(otherwise `autoruns` will be downloaded at runtime, requiring internet access
on the collected system).

The collected files will be placed in a ZIP file
`Collection-<HOSTNAME>-<OS>-<TIMESTAMP>.zip`.

```
# Build standalone collector binary:
# .\velociraptor-v0.6.6-2-windows-amd64.exe config repack velo_light_autoruns.yaml velo_light_autoruns.exe
autoexec:
  argv:
  - artifacts
  - collect
  - Collector
  - --logfile
  - Velociraptor_collect.log
  - -v
  - --require_admin
  artifact_definitions:
  - name: Collector
    parameters:
    - name: Artifacts
      default: |-
        [
         "Windows.KapeFiles.Targets",
         "Windows.Search.FileFinder",
         "Windows.Sysinternals.Autoruns",
         "Windows.Forensics.ProcessInfo"
        ]
      type: json_array
    - name: Parameters
      default: |-
        {
         "Windows.KapeFiles.Targets": {
           "VSSAnalysis": "Y",
           "_MFTMirr": "Y",
           "Antivirus": "Y",
           "BITS": "Y",
           "CertUtil": "Y",
           "CloudStorage_Metadata": "Y",
           "CombinedLogs": "Y",
           "Exchange": "Y",
           "ExchangeClientAccess": "N",
           "InternetExplorer": "Y",
           "KapeTriage": "Y",
           "LinuxOnWindowsProfileFiles": "Y",
           "MSSQLErrorLog": "Y",
           "MicrosoftOneNote": "Y",
           "MicrosoftStickyNotes": "Y",
           "Notepad__": "Y",
           "PowerShellConsole": "Y",
           "RDPCache": "Y",
           "RecycleBin": "Y",
           "RemoteAdmin": "Y",
           "ScheduledTasks": "Y",
           "StartupFolders": "Y",
           "USBDetective": "Y",
           "WSL": "Y",
           "WebBrowsers": "Y",
           "WebServers": "Y",
           "WinDefendDetectionHist": "Y",
           "WindowsFirewall": "Y"
         },
         "Windows.Search.FileFinder": {
          "Upload_File": "Y",
          "SearchFilesGlob": "*\\$MFT",
          "Accessor": "ntfs"
         }
        }
      type: json
    - name: Template
    - name: Password
      default: <PASSWORD>
    - name: Level
      default: "5"
      type: int
    - name: Format
      default: csv
    - name: OutputPrefix
    - name: CpuLimit
      default: "0"
      type: int
    - name: ProgressTimeout
      default: "0"
      type: int
    - name: Timeout
      default: "0"
      type: int
    - name: target_args
      default: |-
        {
         "bucket": "",
         "GCSKey": "",
         "credentialsKey": "",
         "credentialsSecret": "",
         "region": "",
         "endpoint": "",
         "serverSideEncryption": ""
        }
      type: json
    sources:
    - query: |
        // Add all the tools we are going to use to the inventory.
        LET _ <= SELECT inventory_add(tool=ToolName, hash=ExpectedHash)
         FROM parse_csv(filename="/inventory.csv", accessor="me")
         WHERE log(message="Adding tool " + ToolName)

        LET baseline <= SELECT Fqdn FROM info()

        // Make the filename safe on windows but we trust the OutputPrefix.
        LET filename <= OutputPrefix + regex_replace(
            source=format(format="Collection-%s-%s",
                          args=[baseline[0].Fqdn,
                                timestamp(epoch=now()).MarshalText]),
            re="[^0-9A-Za-z\\-]", replace="_")

        LET _ <= log(message="Will collect package " + filename)
        LET report_filename <= if(condition=Template, then=filename + ".html")
        SELECT * FROM collect(artifacts=Artifacts, report=report_filename,
            args=Parameters, output=filename + ".zip", template=Template,
            cpu_limit=CpuLimit,
            progress_timeout=ProgressTimeout,
            timeout=Timeout,
            password=Password, level=Level, format=Format)
  - name: Generic.Utils.FetchBinary
    parameters:
    - name: SleepDuration
      default: "0"
      type: int
    - name: ToolName
    - name: ToolInfo
    - name: IsExecutable
      default: "Y"
      type: bool
    sources:
    - query: |
        LET RequiredTool <= ToolName

        LET matching_tools <= SELECT ToolName, Filename
        FROM parse_csv(filename="/inventory.csv", accessor="me")
        WHERE RequiredTool = ToolName

        LET get_ext(filename) = parse_string_with_regex(
              regex="(\\.[a-z0-9]+)$", string=filename).g1

        LET temp_binary <= if(condition=matching_tools,
        then=tempfile(
                 extension=get_ext(filename=matching_tools[0].Filename),
                 remove_last=TRUE,
                 permissions=if(condition=IsExecutable, then="x")))

        SELECT copy(filename=Filename, accessor="me", dest=temp_binary) AS FullPath,
               Filename AS Name
        FROM matching_tools
```

###### [Windows] More comprehensive collection - OST/PST + memory dump files + users files

The following configuration file will collect the artefacts, in the system
drive, defined in the `KapeFiles.Targets` as well as anti-virus logs, web
browsers artefacts, web servers logs, users files (`C:\Users\*`), `Outlook`
`PST` and `OST` files, etc. Depending on the triaged machine usage and `I/O`
performance, collection may requires several hours and generate a resulting
archive of multiple gigabytes.

The collected files will be placed in a `ZIP` file `<HOSTNAME>.zip`.

```
# Build standalone full collector binary
# .\velociraptor-v0.6.6-2-windows-amd64.exe config repack velo_full.yaml velo_full.exe
autoexec:
  argv: ["artifacts", "collect", "-v", "Windows.KapeFiles.Targets",
         "--output", "$COMPUTERNAME.zip", "--password", "<PASSWORD>",
         "--args", "Device=C:",
         # Run the collection across all VSS and collect only unique changes.
         "--args", "VSSAnalysis=Y",
         # Kape default triage.
         "--args", "KapeTriage=Y",
         # In completion to KapeTriage
         # The RecycleBin artefact can be removed to better control the resulting collection file.
         "--args", "RecycleBin=Y",
         "--args", "_MFTMirr=Y",
         "--args", "PowerShellConsole=Y",
         "--args", "RDPCache=Y",
         "--args", "ScheduledTasks=Y",
         "--args", "StartupFolders=Y",
         "--args", "CloudStorage_Metadata=Y",
         "--args", "CombinedLogs=Y",
         # Web browsers history, bookmarks, ...: Edge, Chrome, Firefox, and Internet Explorer
         "--args", "WebBrowsers=Y",
         "--args", "InternetExplorer=Y",
         # Remote admin tools.
         "--args", "RemoteAdmin=Y",
         # Windows Firewall Logs
         "--args", "WindowsFirewall=Y",
         # USB devices log files: Setupapi.log XP, Setupapi.log Win7+
         "--args", "USBDevicesLogs=Y",
         # Anti-virus logs
         "--args", "Antivirus=Y",
         # Transfer tools.
         "--args", "BITS=Y",
         "--args", "CertUtil=Y",
         # Webservers logs.
         "--args", "WebServers=Y",
         # Exchange server related logs.
         "--args", "Exchange=Y",
         "--args", "ExchangeClientAccess=Y",
         # WSL files.
         "--args", "WSL=Y",
         "--args", "LinuxOnWindowsProfileFiles=Y",
         # Windows text editors apps.
         "--args", "MicrosoftOneNote=Y",
         "--args", "MicrosoftStickyNotes=Y",
         "--args", "Notepad__=Y",
         # MS SQL ErrorLogs : MS SQL Errorlog, MS SQL Errorlogs
         "--args", "MSSQLErrorLog=Y",
         # Files collection.
         # Users folders files.
         "--args", "LiveUserFiles=Y",
         # Memory dump files: hiberfil.sys, pagefile.sys, swapfile.sys
         "--args", "MemoryFiles=Y",
         # Current Group Policy Enforcement: Local Group Policy INI Files, Local Group Policy Files - Registry Policy Files, Local Group Policy Files - Startup/Shutdown Scripts
         "--args", "GroupPolicy=Y",
         # Managed Object Format (MOF) files
         "--args", "MOF=Y",
         # Outlook PST and OST files: PST XP, OST XP, PST, OST - may generate a lot of data
         "--args", "OutlookPSTOST=Y",
         # Windows explorer-like utilities.
         "--args", "FileExplorerReplacements=Y"
        ]
```

###### [Windows] Offline collector build process

The process to generate the collector from the `velociraptor` server web
interface is as follow:

```
- Server Artifacts -> Build offline collector
    -> Select `Windows.KapeFiles.Targets`, `Windows.Search.FileFinder`,
       `Windows.Forensics.ProcessInfo`, and `Windows.Sysinternals.Autoruns`.

       -> `Windows.KapeFiles.Targets` configuration:
          -> Check "If set we run the collection across all VSS and collect only unique changes."

          -> Modules for standard collection: `_MFTMirr`, `Antivirus`, `BITS`,
             `CertUtil`, `CloudStorage_Metadata`, `CombinedLogs`, `Exchange`,
             `InternetExplorer`, `KapeTriage`, `LinuxOnWindowsProfileFiles`,
             `MSSQLErrorLog`, `MicrosoftOneNote`, `MicrosoftStickyNotes`,
             `Notepad__`, `PowerShellConsole`, `RDPCache`, `RecycleBin`,
             `RemoteAdmin`, `ScheduledTasks`, `StartupFolders`, `USBDetective`,
             `WSL`, `WebBrowsers`, `WinDefendDetectionHist`, `WindowsDefender`,
             `WindowsFirewall`.

          -> Modules for the more comprehensive collection:
             `FileExplorerReplacements`, `GroupPolicy`, `LiveUserFiles`,
             `MemoryFiles`, `MOF`, `OutlookPSTOST`.

       -> `Windows.Search.FileFinder` configuration:
          -> "SearchFilesGlob": `*\$MFT`
          -> "Accessor": `ntfs`
          -> Check "Upload_File"

    -> Configure collection:
       -> "Password": <PASSWORD>
       -> "Output format": "CSV and JSON"

    -> Launch
```
