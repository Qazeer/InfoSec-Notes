# DFIR - Windows - Jumplist

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### Overview

Location:

  - `AutomaticDestinations`:

    `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\<APP_ID>.automaticDestinations-ms`

    Filename example: `590aee7bdd69b59b.automaticDestinations-ms`

  - `CustomDestinations`:

    `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\<APP_ID>.customDestinations-ms`

    Filename example: `fb3b0dbfee58fac8.customDestinations-ms`


Yield information related to **files and folders access**.

Introduced in `Windows 7`, `Jumplists` are linked to a taskbar user
experience-enhancing feature that allows users to "jump" to files, folders
or others elements by right clicking on open applications in the `Windows
taskbar`. The `Windows Explorer`'s `Quick Access` feature also stores entries
in `Jumplists`.

Two forms of `Jumplists` are created:
  - automatic entries for recently accessed items, stored in
    `*.automaticDestinations-ms` files.

  - custom entries in `*.customDestinations-ms` files for items manually
    "pinned" elements (by users or the applications themselves) to the
    `Windows taskbar` or an application's `Jumplist`.

Each application `AutomaticDestinations` and `CustomDestinations` `JumpLists`
information are thus stored in two unique and separated files, of different
format:
  - `AutomaticDestinations` `JumpLists` files are stored as
    `AUTOMATICDESTINATIONS-MS` file, in the `MS OLE Structured Storage` format.
    This file format contains multiple streams, each stream composed of data
    similar to `shortcut files (.LNK)`.

  - `CustomDestinations` `JumpLists` are stored as `CUSTOMDESTINATIONS-MS`
    file, also assimilable to a series of `shortcut files`.

### Information of interest

`JumpLists` hold information similar in nature to `shortcut files` for each
file referenced in an application's `AutomaticDestinations` /
`CustomDestinations` `JumpLists`:
  - the target file's **absolute path, size and attributes** (hidden,
    read-only, etc.).

  - the target file **`Modified, Access, and Created (MAC)` timestamps**,
    updated whenever the file is "jumped" to.

  - the **number of times the target file was "jumped" to**.

As `JumpLists` are linked to an application, through an `AppId`, knowledge of
the application that was used to open the files can be deducted if the
application associated to the `AppId` is known. A number of `AppId` is
documented in
[`EricZimmerman` 's `JumpList` GitHub repository](https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt).

Specific applications may define custom `JumpLists` entries that store
information of forensic interest. For example, the `Google Chrome` and
`Microsoft Edge` web browsers store the recently closed tabs in their
respective `CustomDestinations` `JumpLists`.

### Parsing

Eric Zimmerman's `JumpListExplorer.exe` and `JLECmd.exe` tools (`KAPE`'s
`JLECmd` module) can be used to process `JumpLists` files.

```
# Parses the specified JumpLists file.
JLECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -f <JUMPLIST_FILE>

# Recursively retrieves and parses the JumpLists files in the specified directory.
JLECmd.exe [-q --csv <CSV_DIRECTORY_OUTPUT>] -d <C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\ | C:\ | DIRECTORY>
```

--------------------------------------------------------------------------------

### References

https://www.youtube.com/watch?v=wu4-nREmzGM

https://forensicswiki.xyz/page/LNK

https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/#:~:text=LNK%20files%20are%20a%20relatively,LNK%20extension
