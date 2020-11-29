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
