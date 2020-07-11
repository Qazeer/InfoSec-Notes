# Windows - Forensics - Programs execution

### Prefetch

Location `%systemroot%\Prefetch`. **Not present by default on Windows Server
Operating System**

Windows Prefetch is a performance enhancement feature that enables prefetching
to make system boots or applications startups faster. Prefetch files `.PF`,
in the directory `%systemroot%\prefetch`, store data and files accessed during
boot or application start-up.

Parsing the contents of these files can yield:
  - Date and time of first execution (corresponding to the prefetch file
    creation date)
  - Last run time (stored within the prefetch file)
  - Number of times executed (stored within the prefetch file)
  - List of files accessed during the first ten seconds of execution
    (stored within the prefetch file)
  - Full path to executable file (derived from accessed file list)

The `POWERSHELL.EXE-[...].pf` Prefetch file may contain references to
recently executed PowerShell scripts. For an entry to be created in the
Prefetch file, the given script must be executed within the first ten seconds
of the `powershell.exe` execution.

The accessed file list does retain entries from previous instances of a program
execution. Accessed files information may thus persist through `powershell.exe`
subsequent runs.

```
PECmd -d <C:\Windows\Prefetch | DIRECTORY>
PECmd -f <PF_FILE>
```

### Application Compatibility Cache (Shimcache)

Location
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache`
or `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`.

Tracks the executables file name, file size, last modified time,
and in Windows XP the last update time.

The "LastModifiedTime" corresponds to a `$Standard_Information` "Last Modified"
time.

https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html

```
# Deploy the PowerShell PowerForensics module
.\PowerForensics.psd1
Import-Module .\PowerForensics.psd1

# Live
Get-ForensicShimcache | Out-File <OUTPUT_FILE>
AppCompatCacheParser.exe -t --csv <OUTPUT_FOLDER>
python ShimCacheParser.py --local -o <OUTPUT_FILE>

# From hive / mounted disk image
AppCompatCacheParser.exe -t -f <SYSTEM_HIVE_FILE> --csv <OUTPUT_FOLDER>
python ShimCacheParser.py --hive <SYSTEM_HIVE_FILE> -o <OUTPUT_FILE>
python ShimCacheParser.py --reg <REG_FILE> -o <OUTPUT_FILE>
```

### Amcache

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

### RecentFilecache

Location: `%systemroot%\AppCompat\Programs\RecentFileCache.bcf`

Only Windows 7 and Windows Server 2008 R2.
