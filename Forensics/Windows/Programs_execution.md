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

### Amcache

ProgramDataUpdater (a task associated with the Application
Experience Service) uses the registry file Amcache.hve to store
data during process creation

Location: `C:\Windows\AppCompat\Programs\Amcache.hve`

```
# Install
Unzip PowerForensics.zip in C:\Program Files\WindowsPowerShell\Modules\

Import-Module PowerForensics

# Default to C:\Windows\AppCompat\Programs\Amcache.hve
Get-ForensicAmcache | Out-File <OUTPUT_FILE>

Get-ForensicAmcache -HivePath <HIVE_PATH> | Out-File <OUTPUT_FILE>
```

### Shimcache

Tracks the executables file name, file size, last modified time,
and in Windows XP the last update time.

Location `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache` or `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`

```
Get-ForensicsShimcache | Out-File <OUTPUT_FILE>

python ShimCacheParser.py --local -o <OUTPUT_FILE>
python ShimCacheParser.py --hive <HIVE_FILE> -o <OUTPUT_FILE>
python ShimCacheParser.py --reg <REG_FILE> -o <OUTPUT_FILE>
```
