# DFIR - Tools - Dissect

### Overview

[`Dissect`](https://github.com/fox-it/dissect) is a digital forensics &
incident response Python toolset that allows access and parsing of forensic
artefacts from various disk and file formats.

###### Dissect supported targets

`Dissect` supports the [following targets](https://docs.dissect.tools/en/latest/overview/):

  - Raw disk images and evidence containers (`.E01`).

  - Virtual disks (`.vmdk`, `.vhdx`, etc.).

  - Virtual machine descriptor files (`.vmx`, `.vmcx`, etc.). By using a VM
    descriptor file, `dissect` will load the all the virtual disks associated
    with the VM.

  - Local live systems (`\\.\PhysicalDrive0`, `/dev/sda`, etc.).

  - `.tar` archives created by `acquire`

  - Directories, such as `KAPE` or `velociraptor` (`KapeTargets`) collection
    outputs.

###### Dissect tools

`Dissect` is composed of the following tools:

  - [`acquire`](https://docs.dissect.tools/en/latest/tools/acquire.html): to
    gather forensic artifacts from disk images or the live system.

  - [`target-fs`](https://docs.dissect.tools/en/latest/tools/target-fs.html):
    to interact with the filesystem of a target, using a set of familiar Unix
    commands.

  - [`target-mount`](https://docs.dissect.tools/en/latest/tools/target-mount.html):
    to mount the filesystem of a target to an arbitrary directory on the
    analysis machine (similar to the `mount` utility).

  - [`target-query`](https://docs.dissect.tools/en/latest/tools/target-query.html):
    to parse data and artefacts from the specified target, mostly as `records`
    outputs.

  - [`target-reg`](https://docs.dissect.tools/en/latest/tools/target-reg.html):
    to tool query the registry of Windows targets.

  - [`rdump`](https://docs.dissect.tools/en/latest/tools/rdump.html): to
    interact and manipulate `dissect`'s `records` outputs.

###### Installation

The `dissect` toolset can be easily installed through `Python3`'s `pip`:

```bash
python3 -m pip install dissect
python3 -m pip install acquire
```

### acquire

`acquire` can be used to extract artifacts either from the local system or the
specified targets, and place the collected artefacts in a `tar` archive (or
output folder).

`acquire` supports three levels of profiles, that specify the artefacts that
will be collected depending on the target operating system: `minimal`,
`default`, and `full`.

```bash
# OUTPUT_TYPE: tar or dir

acquire -p <minimal | default | full> -o <OUTPUT_FOLDER> [-ot <OUTPUT_TYPE>] <TARGET | local>
```

### target-fs

`target-fs` can be used to interact with the filesystem of a target, to list or
copy individual or multiple files from the target to the analysis destination.

```bash
target-fs <TARGET> <ls | cat | walk> <TARGET_DIR | TARGET_FILE>

target-fs <TARGET> cp <TARGET_DIR | TARGET_FILE> -o <OUTPUT_DIR>
```

### target-query

`target-query` can be used to parse artefacts from the target, often (but not
always) resulting in `dissect`'s `records` outputs. `target-query`'s `records`
can be converted to `CSV` or `JSON` outputs as well as filtered with `rdump`.

Multiple artefacts sources are implemented, as `target-query`'s `function`. The
implemented functions can be listed using `target-query -l`. The following
notable functions are implemented:

  - Windows operating systems: `activitiescache`, `amcache`, `lnk`,
    `evt` / `evtx`, `powershell_history`, `prefetch`, `recyclebin`, `registry`
    (`bam`, `shimcache`, etc.), `shellbags`, `shimcache`, `sru`, `ual`,
    `userassist`, etc.

  - Filesystem: `mft`, `usnjrnl`, `walkfs`

  - Linux / Unix operating systems: `bashhistory`, `cronjobs`, `dpkg`, `audit`,
    `btmp`, `lastlog`, `messages`, `services`, `ssh.authorized_keys`,
    `ssh.known_hosts`, `suid`

  - Web browsers: `browser.history` (Chrome, Firefox, Edge, and Internet Explorer
    histories)

  - remote access applications: `remoteaccess.remoteaccess` (AnyDesk and
    TeamViewer logs)

  - Yara scans: `yara`

```bash
# Example: target-query windows_vm.vmdk -f mft
target-query -f <FUNCTION> <TARGET>

# Retrieves basic information about the target operating system.
target-query -f hostname,domain,version,ips <TARGET>

# Outputs the records as JSON (only for functions that return records).
target-query -s --json -f <FUNCTION> <TARGET>

# Uses rdump to transform the records outputs as CSV or JSON.
# --multi-timestamp: deduplicate a record if it contains multiple timestamps to create a timeline.
target-query [--multi-timestamp] -f <FUNCTION> <TARGET> | rdump <--csv | --json | --jsonlines> [--fields <FIELDS_FOR_OUTPUT>]

# Example Linux functions.
target-query --multi-timestamp -f bashhistory,browser.history,capability_binaries,cronjobs,dpkg,audit,btmp,lastlog,messages,wtmp,services,ssh.authorized_keys,ssh.known_hosts,ssh.private_keys,suid <TARGET>
```
