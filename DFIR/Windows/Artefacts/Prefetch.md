# DFIR - Windows - Prefetch artefacts

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### Overview

Location: `%systemroot%\Prefetch\<EXECUTABLE.EXE>-<RANDOM_ID>.pf`
Filename example: `POWERSHELL.EXE-022A1004.pf`

Yield Information related to **programs execution**.

**Not present by default on Windows Server Operating Systems.**

`Windows Prefetch` is a performance enhancement feature that enables
prefetching of applications to make system boots or applications startups
faster. `Prefetch` files are created whenever a program is executed from a
specific path. If the same binary is executed from different locations,
separate `Prefetch` files will be created for each different location.
A `Prefetch` file can be created even if the executable did not successfully
run.

Whether the `Prefect` feature is enabled is configured by the
`EnablePrefetcher` registry key:
  - `0` / undefined: disabled (default on Windows Server Operating Systems).
  - `0x1`: Partially enabled (application prefetching only).
  - `0x2`: Partially enabled (boot prefetching only).
  - `0x3`: Enabled (application and boot prefetching).

### Information of interest

`Prefetch` files are not automatically deleted if the related executable is
deleted and can thus be a source of historical information. However, as the
`Prefetch` directory is limited to 128 entries on `Windows XP` to `Windows 7`
and 1024 entries starting from `Windows 8`, Prefetch files may be overwritten
and information lost.

The `Prefecth` filenames are based on the executed program name and a hash,
computed using a proprietary algorithm and based on the full path (and
for some binaries, such as `dllhost.exe` or `svchost.exe`, command line
parameters) of the executed program.

The `Prefecth` files can yield the following information of forensic interest:
  - The file name and size of the binary executed.
  - The first and, starting from Windows 8, last eight executions timestamps.
  - The `Prefecth` file `NTFS` created and last modified timestamps also
    indicate the first and last time the program was executed.
  - Run count (number of time the binary was executed).
  - List of files and directories accessed during the first ten seconds of
    execution (including the eventual `DLL` loaded).
    The full path to executable file can often be determined from the list of
    files accessed (duplicate possible if a given binary access another binary
    with the same name).

Note that the `Prefecth` files can be easily deleted, potentially invalidating
the trace of execution and timestamps (notably of first execution).

*Prefecth files indirect information*

The creation or modification of `Prefecth` files observed in others artefacts
(`$MFT`, `UsnJrnl`, etc.) reflect an execution of the binary linked to the
`Prefecth` file (and whose name can be deducted from the `Prefecth` filename).

*Prefecth information related to PowerShell execution*

The `POWERSHELL.EXE-[...].pf` Prefetch file may contain references to
recently executed PowerShell scripts. For an entry to be created in the
Prefetch file, the given script must be executed within the first ten seconds
of the `powershell.exe` execution.

The accessed file list does retain entries from previous instances of a program
execution. Accessed files information may thus persist through `powershell.exe`
subsequent runs.

### Parsing

Eric Zimmerman's `PECmd.exe` tool (`KAPE`'s `PECmd` module) can be used to
parse `Prefecth` file(s):

```
# Parses the specified Prefecth file.
PECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -f <PF_FILE>

# Recursively retrieves and parses the Prefecth files in the specified directory.
PECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -d <C:\Windows\Prefetch | C:\ | DIRECTORY>
```
