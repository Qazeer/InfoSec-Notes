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

### Standalone binary

Standalone collector binary can be executed, without any argument, to conduct
the artefacts collection on a live system.

The pre-compiled released `Velociraptor` binaries may be used to generate the
collector binary, which will collect the artefacts as defined in the provided configuration file:

```
velociraptor.exe config repack <CONFIG_YAML> <COLLECTOR_BINARY.exe>
```

###### [Windows] Example standard collection

The following configuration file will collect the artefacts defined in the
`KapeFiles.Targets` as well as the anti-virus logs (for around 20 solutions)
for the system drive.

The collected files will be placed in a `ZIP` file `<HOSTNAME>.zip`.

```
# --- Kape default triage
# --- Anti-virus logs (~20 AV solutions)
autoexec:
  argv: ["artifacts", "collect", "-v", "Windows.KapeFiles.Targets",
         "--output", "$COMPUTERNAME.zip",
         "--args", "Device=$SYSTEMDRIVE",
         # Kape default triage
         "--args", "KapeTriage=Y",
         # Anti-virus logs
         "--args", "Avast=Y",
         "--args", "AviraAVLogs=Y",
         "--args", "Bitdefender=Y",
         "--args", "ESET=Y",
         "--args", "FSecure=Y",
         "--args", "HitmanPro=Y",
         "--args", "Kaseya=Y",
         "--args", "Malwarebytes=Y",
         "--args", "McAfee=Y",
         "--args", "McAfee_ePO=Y",
         "--args", "Kaseya=Y",
         "--args", "SentinelOne=Y",
         "--args", "Sophos=Y",
         "--args", "Symantec_AV_Logs=Y",
         "--args", "TeamViewerLogs=Y",
         "--args", "TrendMicro=Y",
         "--args", "VIPRE=Y",
         "--args", "WindowsDefender=Y"]
```


###### [Windows] Example comprehensive collection

The following configuration file will collect the artefacts, in the system
drive, defined in the `KapeFiles.Targets` as well as anti-virus logs, web
browsers artefacts, web servers logs, users files (`C:\Users\*`), `Outlook`
`PST` and `OST` files, etc. Depending on the triaged machine usage and `I/O`
performance, collection may requires several hours and generate a resulting
archive of multiple gigabytes.

The collected files will be placed in a `ZIP` file `<HOSTNAME>.zip`.

```
# --- Kape default triage
# --- Web browsers history, bookmarks (Edge, Chrome, Firefox, and Internet Explorer)
# --- Web servers logs (IIS, Apache & nginx)
# --- Anti-virus logs (~20 AV solutions)
# --- Users files and deleted files
# --- Outlook PST and OST files
# --- Cloud Storage Contents and Metadata (Box User, Dropbox, OneDrive, and Google Drive)
# --- etc.
autoexec:
  argv: ["artifacts", "collect", "-v", "Windows.KapeFiles.Targets",
         "--output", "$COMPUTERNAME.zip",
         "--args", "Device=$SYSTEMDRIVE",
         # Kape default triage
         "--args", "KapeTriage=Y",
         # Web browsers history, bookmarks, etc.: Edge, Chrome, Firefox, and Internet Explorer
         "--args", "WebBrowsers=Y",
         # Web servers logs
         "--args", "ApacheAccessLog=Y",
         "--args", "IISLogFiles=Y",
         "--args", "NGINXLogs=Y",
         # Anti-virus logs
         "--args", "Avast=Y",
         "--args", "AviraAVLogs=Y",
         "--args", "Bitdefender=Y",
         "--args", "ComboFix=Y",
         "--args", "ESET=Y",
         "--args", "FSecure=Y",
         "--args", "HitmanPro=Y",
         "--args", "Kaseya=Y",
         "--args", "Malwarebytes=Y",
         "--args", "McAfee=Y",
         "--args", "McAfee_ePO=Y",
         "--args", "Kaseya=Y",
         "--args", "SentinelOne=Y",
         "--args", "Sophos=Y",
         "--args", "Symantec_AV_Logs=Y",
         "--args", "TeamViewerLogs=Y",
         "--args", "TrendMicro=Y",
         "--args", "VIPRE=Y",
         "--args", "WindowsDefender=Y",
         # Users files and deleted files - may generate a lot of data
         "--args", "RecycleBin=Y",
         "--args", "LiveUserFiles=Y",
         # Others
         # Remote Desktop Software Ammyy Admin
         "--args", "Ammyy=Y",
         # IBM Aspera Connect files transfer
         "--args", "AsperaConnect=Y",
         # Cloud Storage Contents and Metadata (Box User, Dropbox, OneDrive, and Google Drive)
         "--args", "CloudStorage=Y",
         # FileZilla XML and SQLite Log Files (by Dennis Reneau): FileZilla XML Log Files, FileZilla SQLite3 Log Files
         "--args", "FileZilla=Y",
         # Current Group Policy Enforcement: Local Group Policy INI Files, Local Group Policy Files - Registry Policy Files, Local Group Policy Files - Startup/Shutdown Scripts
         "--args", "GroupPolicy=Y",
         # Managed Object Format (MOF) files
         "--args", "MOF=Y",
         # MS SQL ErrorLogs : MS SQL Errorlog, MS SQL Errorlogs
         "--args", "MSSQLErrorLog=Y",
         # Notepad++ backup
         "--args", "Notepad__=Y",
         # OpenVPN Client Config and Log: OpenVPN Client Config, OpenVPN Client Config, OpenVPN Client Config
         "--args", "OpenVPNClient=Y",
         # Outlook PST and OST files: PST XP, OST XP, PST, OST - may generate a lot of data
         "--args", "OutlookPSTOST=Y",
         # P2P Clients: Soulseek Chat Logs, Soulseek Search History/Shared Folders/Settings, Gigatribe Files Windows Vista/7/8/10, Gigatribe Files Windows XP, Gigatribe Files Windows XP, Shareaza Logs, DC++ Chat Logs
         "--args", "P2PClients=Y",
         # Skype: main.db (App <v12), skype.db (App +v12), main.db XP, main.db Win7+, s4l-[username].db (App +v8), leveldb (Skype for Desktop +v8)
         "--args", "Skype=Y",
         # Sublime Text 2/3 Auto Save Session
         "--args", "SublimeText=Y",
         # TeraCopy log history
         "--args", "TeraCopy=Y",
         # Torrent Files
         "--args", "Torrents=Y",
         # USB devices log files: Setupapi.log XP, Setupapi.log Win7+
         "--args", "USBDevicesLogs=Y",
         # Web-Based Enterprise Management (WBEM)
         "--args", "WBEM=Y",
         # Windows Error Reporting (by Troy Larson): Crash Dumps, WER Files, Crash Dumps
         "--args", "WER=Y",
         # Windows Firewall Logs
         "--args", "WindowsFirewall=Y",
         # If set we run the collection across all VSS and collect only unique changes.
         "--args", "VSSAnalysis=Y"]
```
