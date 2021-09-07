# DFIR - Windows - Amcache

Location: `%systemroot%\AppCompat\Programs\Amcache.hve`

ProgramDataUpdater (a task associated with the Application
Experience Service) uses the registry file Amcache.hve to store
data during process creation

The PowerShell cmdlet `Get-ForensicAmcache` of the `PowerForensics` suite
can be used to parse the `Amcache.hve` registry hive. The `AmcacheParser`,
supporting Windows 10, utility can be used to parse exported `Amcache.hve`
registry hive.

https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-amcache_investigation.pdf

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
