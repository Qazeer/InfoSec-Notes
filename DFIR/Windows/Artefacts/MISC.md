# DFIR - Windows - MISC

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### NTFS file attributes

A number of forensic artefact files, such as the `$MFT` or the `$UsnJrnl`
files, have both the `NTFS` `Hidden (H)` and `System (S)` attributes set. The
`System` attribute is used to identify system-critical files that are
"necessary for Windows to operate properly" and are not shown by the Windows
Explorer application or the `dir` utility by default.

Following a collect of these files, that may be locked by Windows and require
utilities such as `Velociraptor` or `KAPE` for triage, the files will remain
hidden. The `attrib.exe` utility can be used to remove the `Hidden (H)` /
`System (S)` attributes:

```
# Shows the specified file or files in the working directory NTFS attributes.
attrib [<FILE>]

# Removes the Hidden and System attributes from the specified file.
attrib -h -s <FILE>
```

Alternatively, hidden / system files can be displayed in the Windows Explorer
application (View -> Check "Hidden Items") or with `dir` utility /
`Get-ChildItem` cmdlet the if needed:

```
dir /x /a

Get-ChildItem -Attributes Hidden,!Hidden
```
