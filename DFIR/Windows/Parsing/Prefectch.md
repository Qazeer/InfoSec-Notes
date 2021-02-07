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
