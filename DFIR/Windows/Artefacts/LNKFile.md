# DFIR - Windows - shortcut files (.LNK)

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### Overview

Location:

  - Automatically created `shortcut files`:

  `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`

  - Additional likely locations of `shortcut files`:

    - Automatically created for documents opened using `Microsoft Office`
      products:<br/>
      `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Microsoft\Office\Recent\*.lnk`

    - On the users' `Desktop`:<br/>
      `%SystemDrive%:\Users\<USERNAME>\Desktop`

    - in the `Startup folders`:<br/>
      `%SystemDrive%:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`<br/>
      `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

Yield information related to **files and folders access**.

`Shortcut files (*.lnk)` are `Windows Shell Items` that reference to an
original file, folder, or application. The effect of double-clicking a
`shortcut file` is intended to be the same as double-clicking the application
or file to which it refers. In addition, command line parameters and the folder
in which the target should be opened can be specified in the shortcut. The
`shortcut files` have a magic number of `0x4C` (`4C 00 00 00`).

While `shortcut files` can be created manually, the Windows operating system
also creates `shortcut files` under numerous user activities, such as opening
of a non-executable file. For instance, a `shortcut file` is created under
`[...]\AppData\Roaming\Microsoft\Windows\Recent\` whenever a file is opened
from the `Windows Explorer`. `Shortcut files` created in such circumstances are
referenced in the
`NTUSER.DAT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
registry keys.

The `shortcut files` format is also used for entries within the
`AutomaticDestinations` and `CustomDestinations` `JumpLists` files (introduced
in `Windows 7`). For more information on the `JumpLists` files, refer to the
`[DFIR] Windows - Artefacts - Jumplist` note.

### Information of interest

As the `shortcut files` are not automatically deleted if the target file is
deleted, they can be a source of historical information.

The `shortcut files` yield the following information of forensic interest:
  - the **target file's absolute path, size and attributes** (hidden,
    read-only, etc.). The size and attributes are updated at each access to the
    target file (that induce an update to the `shortcut file`).

  - the **target file and the `shortcut file`** (source) itself **`Modified,
    Access, and Created (MAC)` timestamps at the time of the last access to the
    target file**.

  - whether the **target file was stored locally or on a remote network share**
    through the specification of a `LocalPath` or `NetworkPath`.

  - occasionally **information on the volume that stored the target file**:
    drive type (fixed vs removable storage media), serial number, and label /
    name if any.

  - occasionally **information on the host on which the shortcut file is
    present**: system's NetBIOS hostname and MAC address.

The `source timestamps` stored in the `shortcut file`, as well as the
**`Creation` and `Modification timestamps` of the shortcut file itself**, will
also usually respectively indicate when the **target file was first and last
opened**.

### Parsing

Eric Zimmerman's `LECmd.exe` tool (`KAPE`'s
`LECmd` module) can be used to process `shortcut files`.

```
# Parses the specified shortcut file.
LECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -f <LNK_FILE>

# Recursively retrieves and parses the shortcut files in the specified directory.
LECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -d <C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\ | C:\ | DIRECTORY>
```

--------------------------------------------------------------------------------

### References

https://www.youtube.com/watch?v=wu4-nREmzGM
https://forensicswiki.xyz/page/LNK
https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/#:~:text=LNK%20files%20are%20a%20relatively,LNK%20extension
