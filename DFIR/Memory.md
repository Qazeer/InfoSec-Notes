# Memory analysis

### Memory Acquisition (TODO)

###### winpmem

```
-o Output file location
-p <path to pagefile.sys> Include page file
-e Extract raw image from AFF4 file
-l Load driver for live memory analysis
 winpmem_<version>.exe -o F:\mem.aff4
 winpmem_<version>.exe F:\mem.aff4 -e PhysicalMemory -o mem.raw
```

###### DumpIt

```
/f Output file location
/s <value> Hash function to use
/t <addr> Send to remote host (set up listener with /l)
DumpIt.exe /f F:\mem.raw /s 1
```

### Volatility

`Volatility` is a complete volatile memory analysis framework, composed of a
number of different modules. `Volatility` is implemented in Python and is
completely open source.

`Volatility` supports the following memory dump file format:
  - Raw/Padded Physical Memory
  - 32-bit and 64-bit Windows Crash Dump
  - 32-bit and 64-bit Windows Hibernation
  - 32-bit and 64-bit MachO files
  - Virtualbox Core Dumps
  - VMware Saved State (`.vmss`) and Snapshot (`.vmsn`)
  - Firewire (IEEE 1394)
  - Expert Witness (EWF)
  - HPAK Format (FastDump)
  - LiME (Linux Memory Extractor)
  - QEMU VM memory dumps

And the analyze of the memory from the following systems:
  - 32- and 64-bit Windows 10 and Server 2016
  - 64-bit Windows Server 2012 and 2012 R2
  - 32- and 64-bit Windows 8, 8.1, and 8.1 Update 1
  - 32- and 64-bit Windows 7 (all service packs)
  - 32- and 64-bit Windows Server 2008 (all service packs)
  - 64-bit Windows Server 2008 R2 (all service packs)
  - 32- and 64-bit Windows Vista (all service packs)
  - 32- and 64-bit Windows Server 2003 (all service packs)
  - 32- and 64-bit Windows XP (SP2 and SP3)
  - 32- and 64-bit Linux kernels from 2.6.11 to 4.2.3+

For a more detailed modules documentation, the following official documentation
can be consulted:

```
https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
```

###### Analysis process steps

The memory analysis of a compromised system is dependent of the investigations
context. For example, if a workstation is suspected to have been compromised
from a phishing attack, extracting the `.pst` / `.ost` files, associated with
`Outlook`, using the `filescan` and `dumpfiles` modules, for analysis may be
a good first step.       

The general, context-independent, steps below can be followed for investigating
the memory of a system:
  - Suspicious process hierarchy, such as `outlook.exe` or `iexplorer`
  executing `cmd.exe` or `powershell.exe` process
  - Identification of rogue / unlinked processes
  - review of network artifacts, notably in correlation with known C2 IP
  addresses
  - TODO...


######  Usage

`Volatility` works using modules / plugins, executed individually as follow:

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> <PLUGIN>

# The Linux environments variables VOLATILITY_LOCATION and VOLATILITY_PROFILE may be used in place of command line options to specify the memory dump file path and the volatility profile to use
export VOLATILITY_LOCATION=file://<MEMORY_DUMP_FILE_PATH>
export VOLATILITY_PROFILE=<PROFILE>
volatility <PLUGIN>
```

###### Image identification

The `imageinfo` and `kdbgscan` modules can be used to retrieve the image
profile needed for further analysis of the image. **It is recommended to
retrieve the `Volatility` profile of the image using the `kdbgscan` module.**

`imageinfo` will provide basic information on the image such as the operating
system, service pack, and hardware architecture of the original system as well
as the time the sample was collected and suggested `Volatility` profiles.      

Contrary to `imageinfo`, `kdbgscan` is designed to positively identify the
correct profile by scanning for `KDBGHeader` signatures linked to `Volatility`
profiles.

```
volatility -f <MEMORY_DUMP_FILE> imageinfo

# Recommended for Volatility profile identification
volatility -f <MEMORY_DUMP_FILE> kdbgscan
```

###### Processes and DLLs

*Processes listing*

The `pslist`, `pstree`, `psscan` and `psxview` modules may be used to list the
processes in the memory of the system. **It is recommended to start the processes
analysis using the `psxview` module as it integrates multiples techniques for
`rootkit` detection.**

`psxview` combines multiples modules / information source for listing, both
linked or unlinked / hidden processes, and shows which technique(s) was able
to detect each process:
  - The `pslist` and `psscan` modules, both of which are detailed below.
  - The `thrdscan` module to scan the memory for `executive thread (ETHREAD)`
    objects (used by the system scheduler) and then use the `EPROCESS` block of
    the data structure to identify the process that the thread belongs to.    
  - The `PspCidTable` data structure which keeps track of all the processes
    and threads.
  - The `Windows subsystem process (Csrss)` handle table and internal
    independent structures.
  - The `sessions` module, which analyzes the unique `_MM_SESSION_SPACE`
    objects and, among others features, display the details related to the
    processes running in each logon session  
  - The `deskscan` module, which enumerates desktops, desktop heap allocations,
    and associated threads

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> psxview
```

The `pslist` module print the processes in the list pointed to by
`PsActiveProcessHead`. The `pstree` module orders the result of the `pslist`
module in a hierarchical tree form, from parent to child(s) process(es). The
`pslist` and `pstree` modules present the advantage of being able to retrieve
the process name, `process ID (PID)`, the `parent process ID (PPID)`, number of
threads, number of handles, and date/time when the process started and exited.

Both `pslist` and `pstree` modules can not detect rogue unlinked processes.

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> pslist

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> pstree

# Graphical graph output format that can be opened using xdot
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> pstree --output=dot --output-file=<OUTPUT_DOT_FILE>
```

The `psscan` module attempt to list the processes by scanning the entirety of
the memory dump for `_POOL_HEADER` objects and automatically perform sanity
checks to reduce false positives. The `_POOL_HEADER` structure prepend each and
every memory allocation made by the kernel whenever an object (process, file,
etc.) is created in memory and identify the subsequent object type in the
structure `PoolTag` field. The tag `Proc` is used to identify processes and
thus parsing the memory for `_POOL_HEADER` objects having the `PoolTag` field
set to `Proc` may be used to identify processes.        
The `psscan` module can thus be used to show unlinked processes.

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> psscan
```

*DLLs listing*

The `dlllist` and `ldrmodules` modules may be used to list the loaded DLLs
in the memory of the system. **It is recommended to start the loaded DLLs
analysis using the `ldrmodules` module as it integrates multiples techniques
for rootkit detection.**

The `dlllist` module lists the loaded DLLs, of all processes or for the
specified process, by walking the list of `_LDR_DATA_TABLE_ENTRY` structures
pointed to by each process `_EPROCESS`'s '`Process Environment Block (PEB)`
`InLoadOrderModuleList` list entry. DLLs are automatically added to this list
when a process calls the `LoadLibrary` function (or others derivatives) and
aren't removed until the `FreeLibrary` function is called and the reference
count of the DLL reaches zero.

However, rootkit may hide DLLs by unlinking the DLLs from one or all of the
linked lists of a process `PEB` (`InLoadOrderModuleList`,
`InMemoryOrderModuleList` and `InInitializationOrderModuleList`). In which
case, the `dlllist` module will not be able to identify the hidden DLL(s).

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlllist

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlllist -p <PID>

# In order to display unlinked process loaded DLLs, the physical offset of the EPROCESS object must be specified
# The offset can be retrieved using the psxview module
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlllist --offset=<EPROCESS_PHYSICAL_OFFSET>
```

The `ldrmodules` module parses the `Virtual Address Descriptor (VAD)` tree
(referenced in a process `_EPROCESS` object's `VadRoot` attribute) of each,
or of the specified, process in order to find `_FILE_OBJECT` structure. The
base address and the full path on disk of memory mapped files can be
cross-referenced with the process `PEB` DLL lists to find rogue unlinked
DLL(s).        

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> ldrmodules -v

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> ldrmodules -v -p <PID>
```
*Handles*

The `handles` module display the open handles for all processes or for the
specified process by walking the `HandleTableList` linked list of each process
`_EPROCESS`'s `ObjectTable` (structure `HANDLE_TABLE`).  

The handles can be of the following types:
  - `File`
  - `Directory`
  - `Process`
  - `Thread`
  - `Key`
  - `Token`
  - `Mutant`
  - `Event`
  - `Port`
  - `FilterCommunicationPort`
  - `DebugObject`
  - `WmiGuid`
  - `Controller`
  - `Profile`
  - `Type`
  - `Section`
  - `SymbolicLink`
  - `EventPair`
  - `Desktop`
  - `Timer`
  - `WindowStation`
  - `Driver`
  - `KeyedEvent`
  - `Device`
  - `IoCompletion`
  - `Adapter`
  - `Job`
  - `WaitablePort`
  - `FilterConnectionPort`
  - `Semaphore`
  - `Callback`

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> handles

# Display the specified process open handles
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> handles -p <PID>

# Display the open handles of the specified type
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> handles -t <HANDLE_TYPE | COMMA_SEPARATED_HANDLE_TYPE_LIST>
```

*Process(es) / DLL(s) dump*

The `procdump` module can be used to reconstruct a process `Portable
Executable (PE)` file from memory, as close as possible to the original file.
The `memdump` module dump the process `PE` as well as all the process
addressable address space. **The `procdump` module may be used to retrieve an
executable for static or dynamic reverse engineering while the `memdump` module
can be used to analyze the comportment of the process on the system (runtime
variables, opened files, etc.)**

The `procdump` module uses the process `Process Environment Block (PEB)`'s
`ImageBaseAddress` to retrieve the `PE` file loaded in memory and automatically
realign the memory sections (`.text`, `.data`, `.bss`, etc.).
Additionally, `procdump` performs sanity checks on the `PE` header.

Overly simplistically put, the `memdump` module dumps all the process' memory
pages from the process page table, retrieved from the process' `_EPROCESS`
object `Process control block (Pcb)` (`_KPROCESS` structure)
`DirectoryTableBase`.

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> procdump -D <OUTPUT_DIR> -p <PID>

# Disable sanity checks on PE header, which may be exploited by malware to prevent the dumping
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> procdump --unsafe -D <OUTPUT_DIR> -p <PID>

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> memdump -D <OUTPUT_DIR> -p <PID>
```

The `dlldump` module reconstructs the DLL(s) from memory for all processes, a
specified process, the base address of a DLL in memory or using a regular
expression specifying the DLL(s) name.

The `dlldump` module lists the loaded DLLs using the same process as the
`dlllist` module, and dumps the DLLs using each DLL base address `DllBase`,
retrieved in the module entry from, each or the specified, process
`Process Environment Block (PEB)`'s `InLoadOrderModuleList` list (list of
`_LDR_DATA_TABLE_ENTRY` structures).

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlldump -D <OUTPUT_DIR>
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlldump -D <OUTPUT_DIR> --ignore-case --regex=<REGEX>

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> procdump -D <OUTPUT_DIR> -p <PID>

# In order to dump unlinked process loaded DLLs, the physical offset of the EPROCESS object must be specified
# The offset can be retrieved using the psxview module
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> procdump -D <OUTPUT_DIR> --offset=<EPROCESS_PHYSICAL_OFFSET>

# In order to dump unlinked DLLs, the base address of the DLL must be specified
# The DLL base address can be retrieved using the ldrmodules module
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> procdump -D <OUTPUT_DIR> --base <DLL_BASE_ADDRESS>
```

*Processes security context and privileges*

The `getsids` and `privs` modules retrieve the `Security Identifiers (SID)` and
the privileges associated with all or the specified process. Both modules parse
the `Token` attribute (structure `EX_FAST_REF` referencing a `_TOKEN` object)
of the process `_EPROCESS` object in order to retrieve, respectively
the `SIDs` in the `UserAndGroups` attribute and the privileges in the
`Privileges` attribute.

The `UserAndGroups` attribute is an array of `_SID_AND_ATTRIBUTES` objects, of
size `UserAndGroupCount`, containing a `SID` value (`_SID` structure) and the
`SID` state in the `Attributes` flag.

The `Privileges` attribute is an array of `_LUID_AND_ATTRIBUTES` objects, of
size `PrivilegeCount`, containing a `LUID` value, representing a privilege, and
the privilege state in the `Attributes` flag (combination of the following
values `SE_PRIVILEGE_ENABLED`, `SE_PRIVILEGE_ENABLED_BY_DEFAULT`,
`SE_PRIVILEGE_USED_FOR_ACCESS` and `SE_PRIVILEGE_REMOVED`).

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> getsids
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> getsids -p <PID>

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> privs
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> privs -p <PID>

# Display processes having the privilege(s) matching the regular expression
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> privs --regex="regex"

# Display privileges that processes explicitly enabled (i.e. that were not enabled by default but are currently enabled).
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> privs --silent
```

###### Process command line arguments

The `cmdline` module retrieves the command line argument(s) of all or the
specified process, which are stored in each process `Process Environment
Block (PEB)`'s `ProcessParameters` (`_RTL_USER_PROCESS_PARAMETERS` structure)
`CommandLine` attribute. The command line is specified as an argument of the
`CreateProcessA` function.

Note that command line arguments as stored in memory in a process `PEB` may be
maliciously altered.

```
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> cmdline
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> cmdline -p <PID>
```
