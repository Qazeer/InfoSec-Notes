# DFIR - Windows - System Resource Usage Monitor (SRUM)

### Overview

Introduced in Windows 8.

Location:

 - `SRUM` database: `%SystemRoot%\System32\SRU\SRUDB.dat`.

 - (Optionnal) `SOFTWARE` (`%SystemRoot%\System32\config\SOFTWARE`) registry
   hive to translate some information in the database (user `SID` to username
   and network interfaces information notably).

Yield information related to the system usage, including **programs execution**
and **executed programs' network usage**. **Historical data for the
last 30 days** is stored in the `SRUM` database.

The `System Resource Usage Monitor (SRUM)` is a feature that records numerous
metrics of system activities. Among the various information stored, the
following two tables hold the most commonly valuable data for forensics
investigations:

  - Resources usage (table `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`), that can
    help track programs execution. For each execution entry, the following
    information may be recorded:
    - Timestamp of execution.
    - Full path of the executable or application information / description for
      built-in components.
    - User `SID` of the user executing the process.
    - Metrics on CPU usage (CPU time in foreground and background).
    - Metrics on I/O operations (foreground / background number of read / write
      operations and bytes read / written).

  - Network data usage (table `{973F5D5C-1D90-4944-BE8E-24B94231A174}`), that
    can help track programs execution and network usage of the executed
    programs. For each execution entry, the following information may be
    recorded:
    - Timestamp of execution.
    - Full path of the executable or application information / description for
      built-in components.
    - Metrics on network data usage (bytes sent and receive on a given network
      interface)

Some of the information recorded in the `SRUM` database be viewed using the
Windows `Task Manager` ("App history" tab).

More information on the tables in the `SRUM` database is referenced in the
[`srum-dump`](https://github.com/MarkBaggett/srum-dump) project's
[mapping file](https://github.com/MarkBaggett/srum-dump/blob/master/SRUM_TEMPLATE2.xlsx).

### Parsing

###### Reparaing the SRUDB.dat database

As the copied `SRUM` database will likely not be in a "clean state", the
database will have to be repaired. This can be accomplished using the
`esentutl` utility. It is recommended to make a copy of the `SRU` directory
before reparing the database.

```
# The following commands should be executed in the directory containing the UAL database files.

esentutl.exe /r sru /i

esentutl.exe /p SRUDB.dat
```

###### SrumECmd

The `SrumECmd` utility (`KAPE`'s `SrumECmd` module) can parse and extract
information from the `SRUDB.dat` database, and correlates information from the
`SOFTWARE` registry hive.

```
# Parses the specified SRUM database, using the optionally provided SOFTWARE registry hive.
SrumECmd.exe -f <SRUDB.dat | SRUM_DB_FILE> [-r <SOFTWARE>] --csv <OUTPUT_DIRECTORY>

# Recursively look for SRUDB.dat and SOFTWARE files in the specified directory.
SrumECmd.exe -d <DIRECTORY> --csv <OUTPUT_DIRECTORY>
```

--------------------------------------------------------------------------------

### References

https://isc.sans.edu/forums/diary/System+Resource+Utilization+Monitor/21927/

https://www.youtube.com/watch?v=Uw8n4_o-ETM
