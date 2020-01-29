# Windows - Forensics - Programs execution

### Prefetch

Location `C:\Windows\Prefetch`

Windows enables prefetching to make system boots or applications startups
faster. Prefetch files `*.pf` store data and files accessed during boot or
application start-up

```
PECmd -d <DIRECTORY>
PECmd -f <PF_FILE>
```

### Application Compatibility Cache (Shimcache)

Tracks the executables file name, file size, last modified time,
and in Windows XP the last update time.

Location
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache`
or `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`.

The "LastModifiedTime" corresponds to a `$Standard_Information` "Last Modified"
time.

https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html

```
# Deploy the PowerShell PowerForensics module
.\PowerForensics.psd1
Import-Module .\PowerForensics.psd1

Get-ForensicShimcache | Out-File <OUTPUT_FILE>

# Live
AppCompatCacheParser.exe -t --csv <OUTPUT_FOLDER>
# From hive
AppCompatCacheParser.exe -t -h <SYSTEM_HIVE_FILE> --csv <OUTPUT_FOLDER>

python ShimCacheParser.py --local -o <OUTPUT_FILE>
python ShimCacheParser.py --hive <SYSTEM_HIVE_FILE> -o <OUTPUT_FILE>
python ShimCacheParser.py --reg <REG_FILE> -o <OUTPUT_FILE>
```

### Amcache

ProgramDataUpdater (a task associated with the Application
Experience Service) uses the registry file Amcache.hve to store
data during process creation

Location: `C:\Windows\AppCompat\Programs\Amcache.hve`

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

Get-ForensicAmcache -HivePath <EXPORTED_HIVE_PATH> | Out-File <OUTPUT_FILE>
AmcacheParser.exe -f "<HIVE_PATH>" -i on --csv <OUTPUTDIR_PATH>
```

### RecentFilecache

RecentFilecache.bcf

Only Windows 7 and Windows Server 2008 R2.
