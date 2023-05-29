# DFIR - Windows - Master File Table (MFT)

### Overview

The `Master File Table (MFT)`, filename `$MFT`, is the main element of any
`New Technology File System (NTFS)` partition. The `Partition Boot Sector`
`$Boot` metadata file, which starts at sector 0 and can be up to 16 sectors
long, describes the basic `NTFS` volume information and indicates the location
of the `$MFT`.

The `MFT` contains an entry for all existing files written on the partition.
Deleted files that were once written on the partition may also (temporally)
still have a record in the `MFT`.

Each record entry in the `MFT` notably includes:
  - The filename.
  - The file size.
  - The file unique (under the `NTFS` volume) `Security ID` in the
    `$STANDARD_INFORMATION` attribute.
  - The file creation, last modified, last accessed, and last changed `SI`
    timestamps in the `$STANDARD_INFORMATION` attribute.
  - The file creation, last modified, last accessed, and last changed `FN`
    timestamps in the `$FILE_NAME` attribute.
  - The file access permissions.

The `$MFT` file has both the `Hidden (H)` and `System (S)` attributes and will
thus not be shown by the Windows Explorer application or the `dir` utility by
default.

###### $Secure

The `$Secure` file contains the `security descriptor` for all the files and
folders on a `NTFS` volume. The `security descriptors` are stored within the
`$SDS` named data stream of the `$Secure` file. The `$Secure` file additionally
defines two other named streams (`$SDH` and `$SII`) for lookup in the `$SDS`
stream.

Each file or folder is referenced in the `$Secure` file with its volume-unique
`Security ID` and `security descriptor`. The `Security ID` of the file is
referenced in the `MFT` file record associated with the file (in the
`$STANDARD_INFORMATION` attribute). While no metadata information are present
in the `$Secure` file (only the file's `security descriptor`), the file's
`Security ID` can be used to map the file's information / data from the `MFT`
to its `security descriptor` in the `$Secure` file.

The `security descriptor` (`SECURITY_DESCRIPTOR` data structure) references:
  - The owner of the file (as a pointer to a `SID` structure).
  - The access rights to the file in the
    `Discretionary Access Control List (DACL)` attribute.
  - The audit rights that control how access is audited (which access will
    generate events) in the `System Access Control List (SACL)` attribute.

###### $LogFile

The `$LogFile` is part of a journaling feature of `NTFS`, activated by default,
which maintains a low-level record of changes made to the `NTFS` volume.
Every disk operation is journalized prior to being committed. In case of
failure, such as a crash during an update, the `$LogFile` can be used to revert
disk operations. As low-level operations are journalized, the `$LogFile`
contains very limited historical data, usually only of the last few hours at
most.

###### $STANDARD_INFORMATION vs $FILE_NAME

The `$STANDARD_INFORMATION` and `$FILE_NAME` attributes are updated
differently for the same file action. The changes produced on the attributes
for a file creation, access, modification, renaming, etc. can be found on the
[SANS `Windows Forensic Analysis` poster](https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download).

For more information on Windows timestamps, refer to the
`[DFIR] Windows - Timestamps` note.

### Parsing

###### MFTECmd

The `MFTECmd` utility can parse and extract information from the `$MFT` (as
well as other filesystem artefacts such as the `UsnJrnl`'s `$J` stream, the
file ownership `$Secure:$SDS` data stream, and the transaction log file
`$Logfile`).

```bash
# A $MFT file on a mounted partition should be specified.
# For instance, to extract $MFT data from a forensics image, the image should first be mounted and the $MFT specified as <DRIVER_LETTER:\$MFT to MFTECmd.exe.

MFTECmd.exe -f '<$MFT_FILE>' --csv <OUTPUTDIR_PATH>
```

###### Mft2Csv

The [`Mft2Csv`](https://github.com/jschicht/Mft2Csv) utility can parse, decode,
and log information from the MFT to a CSV. It supports getting the `$MFT` from
a variety of sources and notably:
  - a raw/dd image of disk or partition
  - an extracted `$MFT` file
  - a live host

Note that `Mft2Csv` can only output in one format at a time.

```bash
# Get machine time zone
tzutil /g

# Opens a GUI
Mft2Csv.exe

# Command line
# UTC + 1
Mft2Csv.exe /Volume:<NTFS_VOLUME> /OutputPath:"<OUTPUT_FOLDER>" /OutputFormat:all /TimeZone:"<-12.00 ... 14.00>" /Separator:"<CSV_SEPARATOR>"
Mft2Csv.exe /MftFile:<MFT_FILE> /OutputPath:"<OUTPUT_FOLDER>" /OutputFormat:all /TimeZone:"<-12.00 ... 14.00>" /Separator:"<CSV_SEPARATOR>"
```

`Mft2Csv` will produce a CSV containing all the MFT entries. To parse the CSV,
the Python utility `q` can be used to run SQL-like queries directly against
the CSV:

```bash
q -d '|' -H -O "SELECT FN_FileName,FilePath,FileSizeBytes,SI_FilePermission,SI_CTime,SI_ATime,SI_MTime,SI_RTime,FN_CTime,FN_ATime,FN_MTime,FN_RTime FROM <MFT_CSV_PATH> WHERE SI_CTime >= '<YYYY-MM-DD HH:mm:SS.0000000>' AND SI_CTime < '<<YYYY-MM-DD HH:mm:SS.9999999>' ORDER BY SI_CTime"
```

###### PowerShell PowerForensics Get-ForensicFileRecord

The PowerShell cmdlet `Get-ForensicFileRecord` of the `PowerForensics` suite
parses the `$MFT` file and returns an array of FileRecord entries. By default,
`Get-ForensicFileRecord` will parse the `$MFT` file on the C:\ drive.

`Get-ForensicFileRecord` can be used to retrieve record for a specified file.

```powershell
# Deploy the PowerShell PowerForensics module
.\PowerForensics.psd1
Import-Module .\PowerForensics.psd1

Get-ForensicFileRecord | Out-File <OUTPUT_FILE>
Get-ForensicFileRecord -VolumeName <NTFS_VOLUME> | Out-File <OUTPUT_FILE>
Get-ForensicFileRecord -MftPath <EXPORTED_MFT_PATH> | Out-File <OUTPUT_FILE>

Get-ForensicFileRecord -Path <FILE_TO_GET_RECORD_OF>
```

--------------------------------------------------------------------------------

### References

https://docs.velociraptor.app/docs/forensic/ntfs/
