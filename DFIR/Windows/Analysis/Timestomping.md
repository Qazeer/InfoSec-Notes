# DFIR - Timestomping

### Overview

Timestomping is the action of modifying the timestamps of a file (on Windows
systems, on a `NTFS` partition). It can notably be used to evade digital
forensic investigation by making malicious files look legitimate or being out
of the presupposed attack timeframe.

This technique is identified by
[MITRE ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/).

###### $STANDARD_INFORMATION & $FILENAME MACB timestamps

On `NTFS` filesystems, each file posses (at least) two attributes that hold
(among other information) `Modification, Access, Change and Birth (MACB)`
timestamps:
  - `$STANDARD_INFORMATION`
  - `$FILENAME`

Depending on its filename length, a given file may have one or two `$FILENAME`
attributes:
  - file with short name will have a single `$FILENAME` attribute.
  - file with long name will be associated to two `$FILENAME` attributes,
    one for the long file name and a second for the MS-DOS-compatible short
    file name (`FILENA~1.TXT` for example).

Additionally, another `$FILENAME` attribute can be found for each file in the
directory index of their directory of residency. Indeed directory are stored
on `NTFS` partitions as `B+ tree data structure` with the keys, representing
files and subdirectories, stored as `$FILENAME` attributes. `MACB` timestamps
for each files and subdirectories of a given directory can thus be found in the
directory index. The directory index are stored in `NTFS Index Attribute`
files, also known as `INDX` files and named `$I30` on disk.

A given file may thus be associated with either:
  - **12 timestamps**: `$STANDARD_INFORMATION` + `$FILENAME` + `NTFS $I30`'s
    `$FILENAME`.
  - **20 timestamps**: `$STANDARD_INFORMATION` + 2 * `$FILENAME` +
    2 * `NTFS $I30`'s `$FILENAME` (duplicate timestamps for files with long
    name).

The `MACB` timestamps in the `$STANDARD_INFORMATION` attributes can be modified
by standard users while the `$FILENAME` attributes can only be modified by /
through the Windows kernel. The modification of a file `$STANDARD_INFORMATION`
attribute requires the rights to modify the file attributes (`FullControl`,
`Modify`, `Write`, `WriteAttributes`) which is granted by default to the file
owner.

Note that in addition to being the ones that can be easily modified, the
`MACB` timestamps from the `$STANDARD_INFORMATION` attribute are conveniently
the ones (generally) displayed by the `Windows Explorer`.
