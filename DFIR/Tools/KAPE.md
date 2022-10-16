# DFIR - Tools - KAPE

[`KAPE`](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape)
is configurable triage and parsing tools, that rely on `target` or `module` to,
respectively, collect or parse, using independent utilities, artefacts.

A comprehensive documentation can be found at:
[ericzimmerman.github.io](https://ericzimmerman.github.io/KapeDocs/#!index.md).

### Compound module

The following `module` can be used to parse a number of artefacts on a
collected data. The required tools are specified directly in the module and
must be setup.

```
Description: Compound module.
Category: Modules
Author: Qazeer (Thomas DIOT)
Version: 1.0
Id: f1ada04f-d562-4340-8f68-e258d2820946
BinaryUrl:
ExportFormat: csv
Processors:
    # Requires LogParser.exe binary (https://www.microsoft.com/en-us/download/confirmation.aspx?id=24659) to be in "KAPE\Modules\bin\LogParser.exe"
    # -- LogParser_ApacheAccessLogs.mkape
    # -- LogParser_DetailedNetworkShareAccess.mkape
    # -- LogParser_LogonLogoffEvents.mkape
    # -- LogParser_RDPUsageEvents.mkape
    # -- LogParser_SMBServerAnonymousLogons.mkape
    -
        Executable: LogParser.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires Eric Zimmerman tools to be in "KAPE\Modules\bin\*.exe"
    # -- AmcacheParser.mkape, AppCompatCacheParser.mkape
    # -- EvtxECmd.mkape
    # -- JLECmd.mkape
    # -- LECmd.mkape
    # -- MFTECmd.mkape
    # -- PECmd.mkape
    # -- RBCmd.mkape, RecentFileCacheParser.mkape, RECmd_Kroll.mkape
    # -- SBECmd.mkape, SQLECmd.mkape, SrumECmd.mkape, SumECmd.mkape
    # -- WxTCmd.mkape
    -
        Executable: "!EZParser.mkape"
        CommandLine: ""
        ExportFormat: ""
    # Requires SRUM-Repair.ps1 to be in (https://github.com/AndrewRathbun/DFIRPowerShellScripts/blob/main/SRUM-Repair.ps1).
    -
        Executable: PowerShell_SrumECmd_SRUM-RepairAndParse.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires SUM-Repair.ps1 to be in (https://github.com/AndrewRathbun/DFIRPowerShellScripts/blob/main/SRUM-Repair.ps1).
    -
        Executable: PowerShell_SumECmd_SUM-RepairAndParse.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires CCM_RUA_Finder (https://github.com/esecrpm/WMI_Forensics/raw/master/CCM_RUA_Finder.exe) to be in "KAPE\Modules\bin\CCM_RUA_Finder.exe".
    -
        Executable: CCMRUAFinder_RecentlyUsedApps.mkape
        CommandLine: ""
        ExportFormat: ""
    -
        Executable: EvtxECmd_RDP.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires Chainsaw.exe (https://github.com/WithSecureLabs/chainsaw/releases/download/v2.0.0/chainsaw_x86_64-pc-windows-msvc.zip) to be in "KAPE\Modules\bin\chainsaw\Chainsaw.exe."
    # Also requires Windows sigma rules (https://github.com/SigmaHQ/sigma) to be in "KAPE\Modules\bin\chainsaw\sigma".
    -
        Executable: Chainsaw.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires hayabusa.exe (https://github.com/Yamato-Security/hayabusa/releases/) to be in "KAPE\Modules\bin\hayabusa.exe".
    -
        Executable: hayabusa_UpdateRules.mkape
        CommandLine: ""
        ExportFormat: ""
    -
        Executable: hayabusa_OfflineEventLogs.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires Snap2HTML (https://www.rlvision.com/script/download.php?ref=rlv.com&file=Snap2HTML.zip) to be in "KAPE\Modules\bin\Snap2HTML\Snap2HTML.exe".
    -
        Executable: Snap2HTML.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires RECmd.exe binary
    # -- RECmd_AllRegExecutablesFoundOrRun.mkape
    # -- RECmd_BasicSystemInfo.mkape
    # -- RECmd_BCDBootVolume.mkape
    # -- RECmd_InstalledSoftware.mkape
    # -- RECmd_Kroll.mkape
    # -- RECmd_RECmd_Batch_MC.mkape
    # -- RECmd_RegistryASEPs.mkape
    # -- RECmd_SoftwareASEPs.mkape
    # -- RECmd_SoftwareClassesASEPs.mkape
    # -- RECmd_SoftwareWoW6432ASEPs.mkape
    # -- RECmd_SystemASEPs.mkape
    # -- RECmd_UserActivity.mkape
    # -- RECmd_UserClassesASEPs.mkape
    -
        Executable: RECmd_AllBatchFiles.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires Nirsoft's BrowsingHistoryView (https://www.nirsoft.net/utils/browsinghistoryview-x64.zip) to be in "KAPE\Modules\bin\browsinghistoryview.exe".
    -
        Executable: NirSoft_BrowsingHistoryView.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires Hindsight (https://github.com/obsidianforensics/hindsight/releases) to be in "KAPE\Modules\bin\hindsight.exe".
    -
        Executable: ObsidianForensics_Hindsight.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires woanware's wmi-parser (https://github.com/woanware/wmi-parser/releases/download/v0.0.2/wmi-parser.v0.0.2.zip) to be in "KAPE\Modules\bin\wmi-parser\wmi-parser.exe
    # TODO: Fix error "Unhandled Exception: System.IO.FileNotFoundException: Could not load file or assembly".
    #-
    #    Executable: WMI-Parser.mkape
    #    CommandLine: ""
    #    ExportFormat: ""
    # Requires OneDriveExplorer (https://github.com/Beercow/OneDriveExplorer/releases/) to be in "KAPE\Modules\bin\OneDriveExplorer.exe".
    -
        Executable: OneDriveExplorer.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires DetectionHistory Parser (https://github.com/jklepsercyber/defender-detectionhistory-parser/raw/main/dhparser.exe) to be in "KAPE\Modules\bin\dhparser.exe".
    -
        Executable: DHParser.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires SEPparser (https://github.com/Beercow/SEPparser/raw/master/bin/SEPparser.exe) to be in "KAPE\Modules\bin\SEPparser.exe".
    -
        Executable: SEPparser.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires bmc-tools.exe (compiled version of bmc-tools.py, from https://github.com/dingtoffee/bmc-tools/raw/master/dist/bmc-tools.exe) to be in "KAPE\Modules\bin\bmc-tools.exe".
    # TODO: Fix non finishing execution.
    #-
    #    Executable: BMC-Tools_RDPBitmapCacheParser.mkape
    #    CommandLine: ""
    #    ExportFormat: ""
    # Requires Thor Lite (https://www.nextron-systems.com/thor-lite/, newsletter subscription required) to be in "KAPE\Modules\bin\thor-lite".
    # Refer to the Thor-Lite_Scan.mkape module documentation (in file-comments) for more information on the setup.
    -
        Executable: Thor-Lite_Scan.mkape
        CommandLine: ""
        ExportFormat: ""
    # Requires DensityScout (https://www.cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_windows.zip) to be in "KAPE\Modules\bin\densityscout.exe".
    -
        Executable: DensityScout.mkape
        CommandLine: ""
        ExportFormat: ""
```
