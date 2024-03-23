# DFIR - Windows - $UsnJrnl

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### Overview

The `Update Sequence Number Journal (USN) Journal` is a feature of NTFS,
activated by default on Vista and later, which maintains a record of changes
made to the NTFS volume. The creation, deletion or modification of files or
directories are for instance journalized.

Similarly to the `MFT`, entries for deleted files are progressively overwritten
in the `UsnJrnl`.

The journal is located in `\$Extend\$UsnJrnl` (`$Max` and `$J` data streams)
but can not be accessed through the Windows explorer as it is a system file.

The journal is composed of the `$Max` and `$J` data streams. The `$Max` data
stream stores the meta data of the change and the `$J` data stream stores the
actual change log records.

The change log records are notably composed of:
  - an `Update Sequence Number (USN)`
  - the timestamp of the change
  - the reason the record was logged (`USN_REASON_FILE_CREATE`,
    `USN_REASON_FILE_DELETE`, `USN_REASON_DATA_OVERWRITE`,
    `USN_REASON_RENAME_NEW_NAME`, etc.)
  - MFT reference and reference sequence number

### UsnJrnl metadata

The Windows `fsutil` and the PowerShell cmdlet `Get-ForensicUsnJrnlInformation`
of the `PowerForensics` suite can be used to retrieve metadata about the
`UsnJrnl`:

```
# First and current USN, maximum size notably
fsutil usn queryjournal <NTFS_VOLUME>

Get-ForensicUsnJrnlInformation
Get-ForensicUsnJrnlInformation -VolumeName <NTFS_VOLUME>
Get-ForensicUsnJrnlInformation -Path <USN_JRNL_PATH>
```

### UsnJrnl extraction and parsing

###### MFTECmd

The `MFTECmd` utility can parse and extract information from the
`UsnJrnl`'s `$J` stream (as well as other filesystem artefacts such as the
`$MFT`, the file ownership `$Secure:$SDS` data stream, and the transaction log
file `$Logfile`).

```bash
# A UsnJrnl's $J file on a mounted partition should be specified.
# For instance, to extract UsnJrnl's $J data from a forensics image, the image should first be mounted and the UsnJrnl's $J file specified as <DRIVER_LETTER>:\$Extend\$J to MFTECmd.exe.

MFTECmd.exe -f '<USNJRN_J$>' --csv <OUTPUTDIR_PATH>
```

###### ExtractUsnJrnl / UsnJrnl2Csv

The `ExtractUsnJrnl.exe` with `UsnJrnl2Csv.exe` utilities as well as the
PowerShell cmdlet `Get-ForensicFileRecord` of the `PowerForensics` suite can be
used to parse and extract information from the `UsnJrnl`. The tools below do
not support the `UsnJrnl`'s `USN_RECORD_V4` format yet.

```
ExtractUsnJrnl64.exe /DevicePath:<NTFS_VOLUME> [/OutputPath:<FULL_OUTPUT_PATH> | /OutputName:<OUTPUT_FILE>]
ExtractUsnJrnl64.exe /ImageFile:<IMAGE_PATH> [/OutputPath:<FULL_OUTPUT_PATH> | /OutputName:<OUTPUT_FILE>]

# Starts the UsnJrnl2Csv GUI
UsnJrnl2Csv64.exe
  UsnJrnl2Csv64.exe /UsnJrnlFile:<INPUT_USN_JRNL> /OutputPath:<OUTPUT_FOLDER> /TimeZone:"<-12.00 ... 14.00>" /Separator:"<CSV_SEPARATOR>"

# May not work properly on newer Windows operating systems
Get-ForensicUsnJrnl
Get-ForensicUsnJrnl -VolumeName <NTFS_VOLUME>
Get-ForensicUsnJrnl -Path <USN_JRNL_PATH>
```

--------------------------------------------------------------------------------

### References

http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf
https://countuponsecurity.com/2017/05/25/digital-forensics-ntfs-change-journal/
