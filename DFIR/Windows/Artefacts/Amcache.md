# DFIR - Windows - Amcache

Location: `%systemroot%\AppCompat\Programs\Amcache.hve`

ProgramDataUpdater (a task associated with the Application
Experience Service) uses the registry file Amcache.hve to store
data during process creation.

The `Amcache` behavior depends on the version of the associated libraries, and not the version of the operating system. The `Amcache` on an up-to-date Windows 7 and Windows 10 will thus behave the same way.

The PowerShell cmdlet `Get-ForensicAmcache` of the `PowerForensics` suite
can be used to parse the `Amcache.hve` registry hive. The `AmcacheParser`,
supporting Windows 10, utility can be used to parse exported `Amcache.hve`
registry hive.

For a very comprehensive analysis of the `Amcache` artefact, and its evolution
across different release of the underlying `DLL`, refer to the
[ANSSI's ANALYSIS OF THE AMCACHE v2 white paper](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-amcache_investigation.pdf).

```
# Deploy the PowerShell PowerForensics module
.\PowerForensics.psd1
Import-Module .\PowerForensics.psd1

# Default to C:\Windows\AppCompat\Programs\Amcache.hve
Get-ForensicAmcache | Out-File <OUTPUT_FILE>

# From hive / mounted disk image
Get-ForensicAmcache -HivePath "<C:\Windows\AppCompat\Programs\Amcache.hve | EXPORTED_HIVE_PATH>" | Out-File <OUTPUT_FILE>

AmcacheParser.exe -f "<C:\Windows\AppCompat\Programs\Amcache.hve | EXPORTED_HIVE_PATH>" -i on --csv <OUTPUTDIR_PATH>
```
