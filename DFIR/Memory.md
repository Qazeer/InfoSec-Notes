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

TODO

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
correct profile by scanning for KDBGHeader signatures linked to `Volatility`
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
pointed to by each process `Process Environment Block (PEB)`'s
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
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dlllist --offset=<PHYSICAL_OFFSET>
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

`handles`

*Process / DLL dump*

`procdump`, `memdump` and `dlldump`

*Commands usage*

`cmdscan` and `consoles`

*Processes security context and privileges*

`getsids` and `privs`
