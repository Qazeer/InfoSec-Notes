### Master File Table (MFT)

The `Master File Table (MFT)` is a main element of any `New Technology File
System (NTFS)` partition and the MFT, filename `$MFT`, is the first file of the
partition.  

The MFT contains an entry for all existing files written on the partition.
Deleted files that were once written on the partition may also still have a
record in the MFT.

The record entry includes:
  - the filename
  - the file size
  - the file creation, file last altered, file last read, file last MFT entry
  update datetimes in the `$STANDARD_INFORMATION` attribute
  - the file creation, file last altered, file last read, file last MFT entry
  update datetimes in the `$FILE_NAME` attribute          
  - access permissions

###### $STANDARD_INFORMATION vs $FILE_NAME

The `$STANDARD_INFORMATION` and `$FILE_NAME` attributes are updated
differently for the same file action. The changes produced on the attributes
for a file creation, access, modification, renaming, etc. can be found on the
SANS `Windows Forensic Analysis` poster:

`https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download`

###### Mft2Csv

file. It supports getting the `$MFT` from a variety of sources and notably:
The `Mft2Csv` tool can parse, decode and log information from the MFT to a CSV
  - a raw/dd image of disk or partition
  - an extracted `$MFT` file
  - a live host

Note that `Mft2Csv` can only output in one format at a time.

```
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

```
q -d '|' -H -O "SELECT FN_FileName,FilePath,FileSizeBytes,SI_FilePermission,SI_CTime,SI_ATime,SI_MTime,SI_RTime,FN_CTime,FN_ATime,FN_MTime,FN_RTime FROM <MFT_CSV_PATH> WHERE SI_CTime >= '<YYYY-MM-DD HH:mm:SS.0000000>' AND SI_CTime < '<<YYYY-MM-DD HH:mm:SS.9999999>' ORDER BY SI_CTime"
```

###### PowerShell PowerForensics Get-ForensicFileRecord

The PowerShell cmdlet `Get-ForensicFileRecord` of the `PowerForensics` suite
parses the `$MFT` file and returns an array of FileRecord entries. By default,
`Get-ForensicFileRecord` will parse the `$MFT` file on the C:\ drive.

`Get-ForensicFileRecord` can be used to retrieve record for a specified file.

```
# Deploy the PowerShell PowerForensics module
.\PowerForensics.psd1
Import-Module .\PowerForensics.psd1

Get-ForensicFileRecord | Out-File <OUTPUT_FILE>
Get-ForensicFileRecord -VolumeName <NTFS_VOLUME> | Out-File <OUTPUT_FILE>
Get-ForensicFileRecord -MftPath <EXPORTED_MFT_PATH> | Out-File <OUTPUT_FILE>

Get-ForensicFileRecord -Path <FILE_TO_GET_RECORD_OF>
```