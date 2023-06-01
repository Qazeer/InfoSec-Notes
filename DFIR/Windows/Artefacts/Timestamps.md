# DFIR - Windows timestamps

### NTFS $STANDARD_INFORMATION & $FILENAME MACB timestamps

On `NTFS` filesystems, each file posses (at least) two attributes that hold
(among other information) `Modification, Access, Change and Birth (MACB)`
timestamps:
  - `$STANDARD_INFORMATION`
  - `$FILENAME`

The impact of a number of operations on each timestamps for the
`$STANDARD_INFORMATION` and `$FILENAME` attributes are detailed in the
[SANS's `Windows Time Rules` poster](https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download).
Globally, the following points should be noted:

  - `$FILENAME` `MACB` timestamps are updated on file creation / copy / volume
    move with the date of the operation itself but are not reliability updated
    on regular file operations (access, modification, rename, deletion).
    **However as the `$FILENAME` `MAB` timestamps are updated / copied from the
    `$STANDARD_INFORMATION` `MAB` timestamps on file rename or volume-local
    file move, they are prone to false-negatives.** Indeed, by timestomping the
    `$STANDARD_INFORMATION` timestamps then renaming or moving the file, the
    `$FILENAME` timestamps will be indirectly timestomped as well.

  - On file copy (between two `NTFS` partitions): the `$STANDARD_INFORMATION`
    `MC` timestamps are inherited from the original file but the
    `$STANDARD_INFORMATION` `AB` timestamps (and the `$FILENAME` `MACB`
    timestamps) are the ones of the copy itself.

  - On local file moves (on the same `NTFS` partition), the
    `$STANDARD_INFORMATION` `C` `$FILENAME` `C` timestamps are updated with the
    timestamp of the move). On file moves (between `NTFS` partitions), the
    `$STANDARD_INFORMATION` `AC` timestamps are updated, also with the
    timestamp of the move.

  - The update of the `$STANDARD_INFORMATION` `A` timestamp is unreliable and
    depends on the value of the
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate`
    registry key. The following values may be encountered:

      - `0` (default on Windows XP), `80000000` (User managed), `80000002`
        (System managed) means that last access updates are enabled. Starting
        from `Windows Redstone 4` (`Build 1803` of 04/2018), last access
        updates seem to be enabled (back) by default if the system partition
        size is <= to 128 GiB. Starting from `Windows 10 20H1` (`Build 18970`
        of 05/2020) last access updates seem to be enabled by default
        independently of the system partition size.

      - `1` (default from Windows Vista to early Windows 10 versions),
        `80000001` (User managed), `80000003` means that last access updates
        are disabled.

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

### Registry last write timestamps

The last write / modified timestamp of a registry key correspond to the last
time a write operation occurred on the key. Multiple types of write operation
may trigger an update of the last write / modified timestamp of the key:

  - Addition / modification / deletion of one (or multiple) values under the
    key.

  - Addition / deletion of a sub-key under the key.

  - Change in the security descriptor (including `Access Control List (ACL)`)
    of the key.

The last write / modified timestamp of a registry key is the only generic
timestamp available regarding registry keys.

### Convert UNIX time to human readable format

Timestamps in Windows are often stored as `UNIX time`: 32-bit value containing
the number of seconds elapsed since 1/1/1970.

Note that Active Directory generally store time values of objects (stored in
each object's attributes) in `Greenwich Mean Time (GMT)`.

The following one-liners can be used to convert an `UNIX time` to an human
readable format:

```
# Display both the time in GMT and in the local time zone of the system.
w32tm.exe /ntte <UNIX_TIMESTAMP>
```

--------------------------------------------------------------------------------

### References

https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

https://forensicswiki.xyz/wiki/index.php?title=MAC_times

https://dfir.ru/2018/12/08/the-last-access-updates-are-almost-back/amp/
