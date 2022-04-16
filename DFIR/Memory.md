# DFIR - Memory analysis

### Memory collection

###### RAM acquisition on Windows systems

*WinPmem*

[`WinPmem`](https://github.com/Velocidex/WinPmem) is a (maintained) utility
that can be used to conduct a local capture of memory.

As stated in the documentation, `WinPmem` implements three acquisition methods:
  - PTE remapping mode, the default method and the most stable one.
  - MMMapIoSpace mode, which leverage the `MMMapIoSpace` kernel API.
  - PhysicalMemory mode, which passes a handle to the tradition
    `\\.\PhysicalMemory` device.

`WinPmem` used to output capture in the `Advanced Forensics File Format 4
(AFF4)` format (which include metadata about the capture, compression of the
output, etc.) but the updated version produces images in the `RAW`
format.

[`WinPmem` older versions](https://github.com/Velocidex/c-aff4).

```bash
winpmem.exe <OUTPUT_RAW_DUMP>
winpmem.exe \\<IP | HOSTNAME>\<SHARE>\<OUTPUT_RAW_DUMP>

# --- Older versions
# -p <PAGEFILE_PATH>: instructs WinPmem to also collect the page file.

# Retrieves the page file path.
wmic pagefile list

winpmem.exe -p <PAGEFILE_PATH> -o <OUTPUT_DUMP_AFF4>
```

*DumpIt*

`DumpIt` is a reliable utility that can be used to conduct a local capture of
memory on Windows systems.

Depending on the version used, different options are implemented. In a basic
and standard use case, `DumpIt` can be simply executed with out being provided
any argument to create a memory dump in the local folder.

```bash
DumpIt.exe
```

###### RAM acquisition on Linux systems

*Volatility profiles*

Contrary to Windows systems, `Volatility` integrates a limited number of
profiles for Linux systems. It is thus often necessary to generate the profile
of the system to analyze directly on the system itself or on a system which
matches the target system (identical Linux distribution, kernel version, and
CPU architecture).

A number of tools must be installed on the target system (or system emulating
the target system) in order to generate the Volatility profile:
  - `dwarfdump`
  - `GCC` and `make`
  - `kernel-devel` or `linux-headers-generic` package

Refer to the [official Volatility documentation
](https://github.com/volatilityfoundation/volatility/wiki/Linux#Linux-Profiles)
for more information on how to install the necessary tools and the build steps
to generate a Volatility profile for Linux systems.

```bash
# Installs the prerequisite tools on Debian / Ubuntu systems.
apt-get install dwarfdump
apt-get install build-essential
# If "uname -a" returns something different than "generic" after the version number it may be necessary to install the specific kernel headers.
apt-get install linux-headers-generic / apt-get install linux-headers-<SPECIFIC>

# Generates the Volatility profile (which is a ZIP file).
# The generated ZIP file must be transferred to the system with Volatility installed (in the <VOLATILITY_INSTALL>/volatility/plugins/overlays/linux/ folder or the plugin folder specified as parameter to volatility using --plugins=).
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility/tools/linux && make
zip $(uname)_$(uname -r)_$(uname -m)_profile.zip module.dwarf /boot/System.map-$(uname -r)
```

*Acquire Volatile Memory for Linux (AVML)*

[`AVML`](https://github.com/microsoft/avml) is a memory acquisition utility
written in Rust and open-sourced by Microsoft.

The memory dumps can be generated in the `LiME` output format or in a
compressed format that can be uncompressed using `avml-convert`. The
compression significantly reduces the size of the memory dump.

`AVML` supports upload to `Azure Blob Store` or through `HTTP` `PUT` requests.

```bash
# Generates a memory dump in the LIME format.
avml <OUTPUT_DUMP_LIME>

# Generates a compressed memory dump that can then be uncompressed using avml-convert.
avml --compress <OUTPUT_DUMP_COMPRESSED>
avml-convert --format lime_compressed <OUTPUT_DUMP_COMPRESSED> <OUTPUT_DUMP_LIME>

# Uploads to the specified URL using a HTTP PUT request and delete the file upon successful upload.
avml --put <URL> --delete <OUTPUT_DUMP_LIME>
```

*Linux Memory Extractor (LiME)*

[`LiME`](https://github.com/504ensicsLabs/LiME) is another memory acquisition
utility that can be used to capture memory of Linux systems.


`LiME` is implemented as a `Loadable Kernel Module (LKM)` that can be loaded
and executed using the `insmod` command.

```bash
sudo insmod lime.ko path=<OUTPUT_DUMP_LIME> format=<raw | lime>
```

###### RAM acquisition of Virtual machines

*VMWare*

*Hyper-V*

*Oracle VM VirtualBox*

### Volatility

`Volatility` is a complete volatile memory analysis framework, composed of a
number of different modules. `Volatility` is implemented in Python and is
completely open source.

`Volatility 3` is a major rework of `Volatility 2` with a few notable changes
: removal of profiles, read once of the memory image for performance
improvement, etc.

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

Microsoft releases new Windows 10 versions significantly more frequently than
what was the norm in the past years (with nowadays to versions being released
each year). Due to this rapid release cycle, supporting the latest Windows
versions has become a challenge for memory forensics tools (as it requires
debugging / reverse engineering of each new version to keep structure
definitions and symbols up to date). This is partially why the `Rekall` memory
forensics tool (based on a fork of `Volatility` with consequential subsequent
rewrites of the code base) was discontinued and is no longer maintained.
`Volatility 3` addresses this challenge by implementing an extensive library of
symbol tables and attempting to generate new tables for Windows memory images
from the memory image itself.

For a more detailed modules documentation, the following official documentation
can be consulted:

```
https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
```

###### Analysis steps

The memory analysis of a compromised system is dependent of the investigations
context. For example, if a workstation is suspected to have been compromised
from a phishing attack, extracting the `.pst` / `.ost` files, associated with
`Outlook`, using the `filescan` and `dumpfiles` modules, for analysis may be
a good first step.

The general, context-independent, steps below can be followed for investigating
the memory of a system:
  - Suspicious process hierarchy, such as `outlook.exe` or `iexplorer.exe`
  executing `cmd.exe` or `powershell.exe` process
  - Identification of rogue / unlinked processes
  - review of network artifacts, notably in correlation with known C2 IP
  addresses
  - scan of memory for known pattern / strings using `Yara` rules
  - ...

######  Usage

`Volatility` works using modules / plugins, executed individually as follow:

```bash
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> <PLUGIN>

# The Linux environments variables VOLATILITY_LOCATION and VOLATILITY_PROFILE may be used in place of command line options to specify the memory dump file path and the volatility profile to use
export VOLATILITY_LOCATION=file://<MEMORY_DUMP_FILE_PATH>
export VOLATILITY_PROFILE=<PROFILE>
volatility <PLUGIN>
```

###### Plugins overview

`Volatility` implements two main types of plugins, each using a distinct
approach:
  - the "`list`" plugins, that will navigate through Kernel data structures to
    extract information from memory. The plugins implemented using this
    approach will work similarly to the native operating system `APIs` (and
    will thus be vulnerable to the same potential anti-forensics techniques).

  - the "`scan`" plugins, that will carve memory for known specific data
    structures. Carving is a general term for extracting structured
    data (in case of memory, `EPROCESS` objects for example) out of raw data.
    While a bit slower and more prone to false positives, this approach can
    retrieve information for objects no longer referenced by the operating
    system (such as a process that have exited) or hidden using anti-forensics
    techniques.

List of `Volatility 2` plugins (either included in the base code or from the
community) that can be useful for general memory forensics. Some plugins below
are ported, under a different naming nomenclature, to `Volatility 3`.

Note that all the plugins below may not be compatible with every operating
systems memory image.

| Plugin Vol. 2 | Plugin Vol. 3 |  Description |
|---------------|---------------|--------------|
| `amcache` | | Extracts information from the `AmCache` registry hive. |
| `apihooks` | | Attempts to detect hooked functions and displays information about the hooks found (impacted process, hook type, function hooked, dissambly code of the hook, etc.). |
| `autoruns` | | (Custom) Lists processes executed from an `Auto-Start Extensibility Points (ASEP)`. |
| `cachedump` | | Dumps the `MsCacheV1` / `MsCacheV2` hashes of locally cached Active Directory domain accounts. |
| `clipboard` | | Extracts the content of the Windows clipboard. |
| `cmdscan` | | Scans the memory image for `COMMAND_HISTORY` structures which contain the (limited) history of commands entered in a `console shell` (`cmd.exe`). |
| `connscan` <br><br> `netscan` | `windows.netscan.NetScan` | Scans the memory image for respectively connections that have since been terminated and network artifacts (TCP / UDP connections and listeners). |
| `consoles` | | Scans the memory image for `CONSOLE_INFORMATION` structures which contain the (limited) history of commands typed as well as the screen buffer (commands input and output). |
| `dlldump` | | Extracts the DLL(s) loaded by each or the specified process. |
| `dlllist` | | Lists the `DLL` loaded by each or the specified process. |
| `dumpfiles` | | Dumps all the files mapped in memory (or the ones matching a specified regex). | `mftparser` | Scans the memory image for potential `Master File Table (MFT)` entries to reconstrcut the `MFT`. |
| `dumpregistry` | | Dumps all or the specified (using its virtual offset) registry hive to a file. |
| `envars` | | Displays the environment variables of each or the specified process. |
| `filescan` | | Scans the memory image for `FILE_OBJECTs` which correspond to files loaded in memory. |
| `getsids` <br> `getservicesids` | | Lists the `Security Identifiers (SID)` present, respectively, in each processes token or services. |
| `handles` | | Lists the handles (and information about the handles) for each or the specified process. |
| `hashdump` | | Dumps the local accounts `LM` / `NTLM` hashes from the `SAM` registry hive loaded in memory. |
| `imagecopy` | | Converts a memory dump (such as a crashdump, hibernation file, `VirtualBox` core dump, `VMware` snapshot, etc.) to a `raw` memory image. |
| `imageinfo` | `windows.verinfo.VerInfo` | Prints high level information about the memory image. |
| `ldrmodules` | | Lists the `DLL` loaded by each or the specified process but, in contrary to `dlllist`, from a process's `VirtualAddressDescriptor (VAD)` which can be used to find unlinked `DLL`. |
| `lsadump` | | Dumps decrypted `LSA` secrets (account cleartext passwords for Windows autologon or  Windows services / scheduled tasks, etc.) from the memory image. |
| `malfind` | | Scans the memory image for injected code, that is memory pages marked with the `read`, `write`, and `execute` permissions that contains data not associated with a file on disk. <br><br> Due to its very nature, this plugin is prone to false positives. |
| `mimikatz` | | (Custom) Dumps the accounts secrets from the `LSASS` process in memory, similarly to what can be achieved on a running system using `mimikatz`. |
| `moddump` | | Extracts a kernel driver to a file. |
| `printkey` | | Prints the subkeys, values, data, and data types contained within a specified registry key. |
| `privs` | | Lists the privileges present in each processes token and indicates if the privileges are enabled explicitly or by default. |
| `procdump` | | Extracts a process's executable to a file that more or less closely resembles the original process executable. |
| `pslist` | `windows.pslist.PsList` | Lists the processes of the memory image. |
| `psscan` <br> `psdispscan` | `windows.psscan.PsScan` | Enumerates the processes of the memory image through carving. |
| `pstree` | `windows.pstree.PsTree` | Lists the processes of the memory image in tree form (parent-child relationships). |
| `psxview` | | Uses different process listing / scanning techniques to find hidden processes. |
| `shellbags` | | Parses and prints Shellbag information (file name and `MAC` timestamps associated which entry) from all user hives loaded in memory. |
| `shimcache` | | Parses the Application Compatibility Shim Cache registry key. |
| `sockets` | | Lists the listening sockets of any protocol (`TCP`, `UDP`, `RAW`, etc.). |
| `sockscan` | | Scans the memory image for `_ADDRESS_OBJECT` structures which contain sockets information. |
| `svcscan` | | Scans the memory image for Windows services and returns information about each service (service name and display name, service state, associated binary path, etc.). |
| `timeliner` | | Creates a timeline from multiples artifacts in memory (processes creation and exit times, sockets creation time, registry keys `LastWriteTime` etc.). |
| `yarascan` | | Scans the image memory for the specified `YARA` rule. |

###### [Volatility 2] Image identification

The `imageinfo` and `kdbgscan` modules can be used to retrieve the image
profile needed for further analysis of the image. **It is recommended to
retrieve the `Volatility` profile of the image using the `kdbgscan` module.**

`imageinfo` will provide basic information on the image such as the operating
system, service pack, and hardware architecture of the original system as well
as the time the sample was collected and suggested `Volatility` profiles.

Contrary to `imageinfo`, `kdbgscan` is designed to positively identify the
correct profile by scanning for `KDBGHeader` signatures linked to `Volatility`
profiles.

**Note that (contrary to `Volatility 2`) `Volatility 3` does not rely on
profiles and instead attempts to generate the equivalent information directly
from the memory image itself.**

```bash
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

```bash
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> psxview
```

The `pslist` module print the processes in the list pointed to by
`PsActiveProcessHead`. The `pstree` module orders the result of the `pslist`
module in a hierarchical tree form, from parent to child(s) process(es). The
`pslist` and `pstree` modules present the advantage of being able to retrieve
the process name, `process ID (PID)`, the `parent process ID (PPID)`, number of
threads, number of handles, and date/time when the process started and exited.

Both `pslist` and `pstree` modules can not detect rogue unlinked processes.

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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

```bash
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> cmdline

volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> cmdline -p <PID>
```

###### Network activity

Different plugins can be used in `Volatility 2` and `Volatility 3` to enumerate
the active network connections of the system when the memory dump was taken.
Some plugins, that rely on scanning the memory for known structures, may be able
to retrieve information about ended connections, as the related memory struct
may persist in memory after a connection is terminated.

```bash
# For Windows Vista / Windows 2008 and later.

# Scans memory for network object structures (TCP endpoints _TCP_ENDPOINT, TCP listeners _TCP_LISTENER, and UDP endpoints _UDP_ENDPOINT).
# Equivalent of connscan + sockscan for Windows XP and Windows 2003 Server.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> netscan
volatility3 -f <MEMORY_DUMP_FILE> windows.netscan.NetScan

# Lists all UDP Endpoints (in UdpPortPool or UdpCompartmentSet), TCP Listeners (TcpPortPool or TcpCompartmentSet) and TCP Endpoints (in TCP Endpoint partition table) residing in the tcpip.sys driver memory space.
# Starting from Windows 10.14xxx, the UdpPortPool and TcpPortPool were replaced by the UdpCompartmentSet and TcpCompartmentSet structs.
volatility3 -f <MEMORY_DUMP_FILE> windows.netstat.NetStat

# For Windows XP and Windows 2003 Server (x86 or x64) ONLY.

# Enumerates the active connections by following the TCBTable table in the tcpip.sys driver memory space.
# Memory from hibernated system may not show any connections as Windows closes the connections before hibernating.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> connections

# Scans the memory for _TCPT_OBJECT structures.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> connscan

# Enumerates listening sockets by following a non non-exported struct in the tcpip.sys driver memory space.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> sockets

# Scans the memory for _ADDRESS_OBJECT sockets structures.
# May retrieve information about terminated sockets, similarly to connscan.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> sockscan
```

###### In memory file objects enumeration and retrieval

Files present in memory, i.e files currently loaded by processes, can be
listed and extracted using, respectively, the `filescan` /
`windows.filescan.FileScan` and `dumpfiles` / `windows.dumpfiles.DumpFiles`
plugins.

The plugins scan the memory image for `_FILE_OBJECT` structures, and thus
present the advantage of being able to locate / dump files possibly hidden by
malware (as opposed to walking structures such as `_LDR_DATA_TABLE_ENTRY`).

```bash
# Scan the given memory image for FILE_OBJECT structures.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> filescan
volatility3 -f <MEMORY_DUMP_FILE> windows.filescan.FileScan

# Extract all the files (_FILE_OBJECT structures) present in the given memory dump.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dumpfiles -n --dump-dir=<OUTPUT_FOLDER> -S <OUTPUT_SUMMARRY_FILE>
volatility3 -f <MEMORY_DUMP_FILE> windows.dumpfiles.DumpFiles

# Extract the files (_FILE_OBJECT structures) whose names match the specified regex.
# Regex examples: -r ".*\.doc" | -r ".*\.[op]st.*"
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dumpfiles -n --dump-dir=<OUTPUT_FOLDER> -r <REGEX>

# Extract the files (_FILE_OBJECT structures) present in the specified process(es) memory space.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dumpfiles -n --dump-dir=<OUTPUT_FOLDER> -S <OUTPUT_SUMMARRY_FILE> --pid=<PID | PID_COMMA_LIST>
volatility3 -f <MEMORY_DUMP_FILE> windows.dumpfiles.DumpFiles --pid <PID>

# Extrat a single file (_FILE_OBJECT structure) at the given virtual / physical offset.
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> dumpfiles -n --dump-dir=<OUTPUT_FOLDER> -Q <PHYSICAL_ADDRESS>
volatility3 -f <MEMORY_DUMP_FILE> windows.dumpfiles.DumpFiles [--virtaddr <VIRTUAL_ADDRESS> | --physaddr <PHYSICAL_ADDRESS>]
```

###### Malware finder

*malfind plugin*

`Volatility` `malfind` / `windows.malfind.Malfind` plugin detect suspicious
memory pages that may be the result of code injection (shellcode or `DLL`
injection). The `malfind` plugin uses a number of criteria, in combination, to
identify code injection:
  - Private memory region (i.e memory without an associated mapped file).
  - Executable memory (such as `PAGE_EXECUTE_READWRITE`) region.
  - Memory with a `PE` header (`MZ` magic number) with no associated entry in
    the process's `PEB` module list.
  - etc.

```bash
volatility -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> malfind

volatility3 -f <MEMORY_DUMP_FILE> windows.malfind.Malfind
```

*yarascan plugin*

TODO

###### Local persistence

The `Volatility2`'s
[`autoruns`](https://github.com/tomchop/volatility-autoruns) and
[`winesap`](https://github.com/reverseame/winesap) plugins can be used to
detect local persistence from a memory image. The plugins are complimentary
as, while having some overlap, enumerate different persistence `ASEP`.

The `ASEP` are covered by the `autoruns` plugin are `HKLM\SOFTWARE` and
`NTUSER.DAT` registry `ASEP` keys, Windows services and scheduled tasks,
`Winlogon` `ASEP` entries, Active Setup
(`Microsoft\Active Setup\Installed Components`) and Microsoft Fix-it
(`Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`) entries.
More details can be found in the project README. The persistence `ASEP` covered
by `winesap` can be found in the
[following diagram](https://github.com/reverseame/winesap/blob/master/img/taxonomy.png).

```bash
volatility --plugins <VOLATILITY_AUTORUNS_FOLDER_PATH> -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> autoruns

volatility --plugins <VOLATILITY_AUTORUNS_FOLDER_PATH> -f <MEMORY_DUMP_FILE> --profile <MEMORY_DUMP_PROFILE> autoruns
```

--------------------------------------------------------------------------------

### References

https://github.com/volatilityfoundation/volatility/wiki/Command-Reference

https://www.youtube.com/watch?v=BMFCdAGxVN4

https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=4

Learning Malware Analysis: Explore the concepts, tools, and techniques to analyze and investigate Windows malware (English Edition)

https://www.aldeid.com/wiki/

https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html

https://blog.scrt.ch/2010/11/22/manipulation-des-jetons-des-processus-sous-windows/

https://andreafortuna.org/2017/07/24/volatility-my-own-cheatsheet-part-5-networking/

https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal

https://volatility3.readthedocs.io/en/develop/_modules/volatility3/plugins/windows/netstat.html

http://redplait.blogspot.com/2016/06/tcpip-port-pools-in-fresh-windows-10.html
