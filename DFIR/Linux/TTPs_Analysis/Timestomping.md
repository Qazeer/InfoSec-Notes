# DFIR - Linux - Timestomping

### Overview

Timestomping is the action of modifying the timestamps of a file (on Linux
systems, generally on a `ext3` or `ext4` partition). It can notably be used to
evade digital forensic investigation by making malicious files look legitimate
or being out of the presupposed attack timeframe.

This technique is identified by
[MITRE ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/).

###### Linux ext3 / ext4 partitions timestamps

On Linux `ext3` partitions each file (and folders) is associated with three
timestamps:
  - `atime`, for `access time`, which corresponds to the last access to the
    file (but is in practice not completely reliability updated).
  - `mtime`, for `modification time`, which corresponds to the last
    modification to the file content or addition / renaming / deletion of a
    file in the folder.
  - `ctime`, for `change time`, which corresponds to the last modification to
    the file or folder's metadata (name, owner, permissions, etc.). If
    the content of a file / folder is modified, the `ctime` timestamp is also
    updated (in addition to the `mtime` timestamp).

The `crtime`, for `creation time`, was introduced on Linux `ext4` partitions.
This timestamp records the creation / birth time of a file or folder.

###### Timestomping on Linux systems

Modification of files timestamps are generally conducted on Linux operating
systems using the `touch` built-in utility. This utility can be used to set
the `mtime` and `atime` timestamps of a file or folder to the current date,
arbitrary values, or the timestamps of a file of reference.

The `touch` utility only can be used to modify the `ctime` timestamp of a file
or folder but only to the current system time. It is thus possible to modify
the `ctime` timestamp of a file or folder by updating the current system time,
using `touch` on the given file or folder, and resetting the system time back
to its previous value.

**The `crtime` timestamp of the file or folder is however not updatable by
`touch`.** Modifying a file or folder `crtime` timestamp would require to
access the disk image directly (using `debugfs` for example) which is not
doable while the filesystem is mounted.

Files or folders with `mtime` or `ctime` timestamps preceding their birth time
(`crtime` timestamp) can thus be indicative of timestomping on `ext4`
partitions.

### Detection of timestomping on ext4 partitions

```bash
# Finds on which device reside the specified file or folder.
df <FILE | FOLDER> | (read a; read a b; echo "$a")

# Returns the inode number of the specified file or folder.
stat -c %i <FILE | FOLDER>

# Displays the crtime as well as the ctime, atime, and mtime timestamps of the specified file or folder.
# Note that the <> surrounding the inode number are mandatory.
debugfs -R 'stat <<INODE_NUMBER>>' <DEVICE>
```
