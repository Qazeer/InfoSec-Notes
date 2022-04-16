# DFIR - Windows - Application Compatibility Cache (Shimcache)

### Overview

- Files: <br>
  `%WinDir%\System32\config\SYSTEM`

- Registry keys:

  - `>= Windows Server 2003` and `Windows XP 64-bit` <br>
    `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`

  - `Windows XP 32-bit` <br>
    `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache`

Yield information related to **programs execution**.

The `Application Compatibility Cache`, also known as `Shimcache`, was
introduced in `Windows XP` as part of the `Application Compatibility
Infrastructure (Shim Infrastructure)` feature. The `Shim Infrastructure` is
designed to identify application compatibility issues and maintain support of
existing software to new versions of the `Windows` operating system. As stated
in the Microsoft documentation, the `Shim Infrastructure` "implements a form of
application programming interface (API) hooking" in order to redirect API calls
made by an application to an alternative library containing stub functions,
known as the `Shim`. The process of making an application compatible to a new
version of Windows through `Shims` is referred to as "`shimming`".

As a part of this framework, the `Application Compatibility Database`
references the applications that have known `shimming` solutions. Upon
execution of an application, the `Shim Engine` will query this database to
determine whether the applications require `shimming`. The `Shimcache` contains
metadata about the files that have been subject to such lookup, for
optimizing and improve the speed of eventual later lookups.

A `Shimcache` entry is created whenever a program is executed from a specific
path. However, starting from the `Windows Vista` and `Windows Server 2008`
operating systems, entries may also be created for files in a directory that is
accessed interactively. Indeed, browsing a directory using `explorer.exe` will
generate `Shimcache` entries for the executables stored within the directory.

**`Shimcache` entries are only written to the registry upon shutdown of the
system. The `Shimcache` entries generated since the last system boot are
thus only stored in memory.**

While the `Shimcache` entry is not removed upon deletion of the associated
file, `Shimcache` entries may be overwritten and information lost as the oldest
entries are replaced by new data. A maximum of 512 `Shimcache` entries are
stored in `Windows Server 2003` and up to 1024 entries starting can be stored
starting from the `Windows Vista` and `Windows Server 2008` operating systems.

### Information of interest

Each `Shimcache` entries contain the following information, varying depending
on the version of the Windows operating system in use:
  - The associated **file full path**.

  - The **`LastModifiedTime` (`$Standard_Information`) timestamp** of the file,
    which does not necessarily reflect the execution time.

  - On `Windows 2003 and XP 64-bit` and older, **the file size**.

  - Introduced in the `Windows Vista` and `Windows Server
    2008`, **the (undocumented) `Process Execution Flag` flag** which seems to
    indicate whether the entry was executed.

  - On `Windows XP 32-bit`, the file `Last Update Time` timestamp.

### Parsing

###### Entries stored on disk

Eric Zimmerman's `AppCompatCacheParser.exe` tool (`KAPE`'s
`'AppCompatCacheParser` module) and the `ShimCacheParser.py` Python script
can be used to parse `Shimcache` entries.

By default, both tools will parse all the `ControlSet` found in the `SYSTEM`
hive.

```
# Parses the live system Registry.
AppCompatCacheParser.exe --csv <OUTPUT_FOLDER>
python ShimCacheParser.py --local -o <OUTPUT_FILE>

# Parses the specified SYSTEM hive.
# --nl: option to force the parsing of the hive even if the even is in a "dirty" state and no transaction logs are available.
AppCompatCacheParser.exe [--nl] -f <SYSTEM_HIVE_FILE> --csv <OUTPUT_FOLDER>

python ShimCacheParser.py [--hive <SYSTEM_HIVE_FILE> | --reg <EXPORTED_SYSTEM_FILE>] -o <OUTPUT_FILE>
```

###### Entries only present in memory

The `Volatility2`'s `shimcache` plugin can be used to extract the `Shimcache`
entries living in memory (generated since the last system boot).

For more information on how to capture memory and use `Volatility` for memory
analysis, refer to the `[DFIR] Memory` note.

```
vol.py -f win7.vmem --profile=Win7SP1x86 shimcache
```

--------------------------------------------------------------------------------

### References

https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf
https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html
http://www.alex-ionescu.com/?p=39
https://docs.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database
https://lifars.com/wp-content/uploads/2017/03/Technical_tool_Amcache_Shimcache.pdf
https://github.com/mandiant/ShimCacheParser
