# DFIR - Windows - User Access Logging artefacts

### Overview

Location: `%SystemRoot%\System32\Logfiles\SUM\` folder.

Yield Information related to **user access and activity**. <br>
On Domain Controllers, yield information on **sessions opening on domain-joined
computers** (if the given DC was reached for authentication / `Group Policy`
retrieval).

`User Access Logging (UAL)` is a feature introduced, and enabled by default, in
`Windows Server 2012` that consolidates data on client activity. Among other
information, user access on specific Windows Server roles (such as
`Active Directory Domain Services` on Domain Controller) are logged by the
`UAL`. The specific activity triggering an entry to be logged for a given role
is not documented.

The information is stored locally in up to five
`Extensible Storage Engine (ESE)` database files (`.mdb`):
  - `Current.mdb` which contains data for the last 24-hour.
  - Up to three `<GUID>.mdb` files, which contain data for an entire year
    (first to last day), going back to 2 years. The data in the `Current.mdb`
    database is copied each day to the corresponding (`<GUID>.mdb`) database
    for the current year.
  - `Systemidentity.mdb` which contains metadata on the local server, including
    a mapping on roles' GUIDs and names.

Historical data going back to 2 years (2020 as of 2022) may thus be retrieved
in the `UAL` database files.

### Information of interest

The `CLIENTS` table of the aforementioned database files contain multiple
information of interest:
  - Accessed Windows Server role `GUID` and description. Among others, the
    following roles can be encountered:
      - `Active Directory Domain Services` (GUID:
        `ad495fc3-0eaa-413d-ba7d-8b13fa7ec598`).
      - `File Server` (GUID: `10a9226f-50ee-49d8-a393-9a501d47ce04`).
      - `Active Directory Certificate Services` (GUID:
        `c50fcc83-bc8d-4df5-8a3d-89d7f80f074b`).

  - The client domain and username.

  - Total number of access.

  - First, last, and daily access timestamps.

  - Client `IPv4` or `IPv6` address. On Domain Controllers, the hostname
    associated the `IP` address at that time may be retrievable as machine
    accounts of domain-joined computers also authenticate on `AD DS`.

Each entry in the `CLIENTS` table is composed of a unique set of a Windows
Server role, a client's domain / username, and a source `IP` address.

The `DNS` table of the aforementioned database files contain information about
`DNS` resolutions: hostname, associated `IP` address, and timestamp of last
resolution.

### Parsing

###### Live forensics

The PowerShell cmdlets of the `UserAccessLogging` module can be used to
retrieve `UAL` data on a live system:

```bash
# Enumerates the roles installed on the system.
Get-UalOverview

# Retrieves UAL data for user access (data stored in the CLIENTS table).
Get-UalUserAccess

# Retrieves UAL data for client access by device for a given service, ordered by date (data stored in the CLIENTS table).
# The cmdlets returns the date that the client accessed the service and how many times the client accessed the service during that day.
Get-UalDailyAccess

# Retrieves information on DNS resolutions (data stored in the DNS table).
Get-UalDns
```

###### Triaged UAL database files

A direct copy of the `UAL` database files is not possible as the files are
being locked due to continued access. The files should be copied through a
`shadow copy` volume or using utilities implementing raw disk reads (such as
[`Velociraptor`](https://github.com/Velocidex/velociraptor) or
[`RawCopy`](https://github.com/jschicht/RawCopy)).

```bash
# Example of low level file copy bypassing file locking using RawCopy.
RawCopy64.exe /FileNamePath:"<C:\Windows\System32\LogFiles\Sum\Current.mdb | UAL_DB_FILE>" /OutputPath:"<OUTPUT_DIRECTORY>"
```

As the databases copied will not be in a "clean state", the database files will
have to be repaired. This can be accomplished using the `esentutl` utility:

```
# The following commands should be executed in the directory containing the UAL database files.

esentutl.exe /r sru /i

esentutl.exe /p <Current.mdb | UAL_DB_FILE>
```

The Eric Zimmerman's `SumECmd.exe` tool or
the [`KStrike`](https://github.com/brimorlabs/KStrike) Python script can be
used to parse `UAL` database files:

```bash
# Parses the specified individual UAL database file.
KStrike.py <Current.mdb | UAL_DB_FILE>

# Parses the UAL database files (Current.mdb, SystemIdentity.mdb, etc.) in the specified directory.
# The results will be aggregated in single CSV files per category (client access, DNS requests, etc.).
SumECmd.exe --csv <CSV_DIRECTORY_OUTPUT> -d <DIRECTORY_WITH_UAL_DB_FILES>
```

--------------------------------------------------------------------------------

### References

https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html

https://www.youtube.com/watch?v=rVHKXUXhhWA

https://docs.microsoft.com/en-us/windows-server/administration/user-access-logging/get-started-with-user-access-logging

https://www.crowdstrike.com/blog/user-access-logging-ual-overview/
