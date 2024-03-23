# DFIR - Windows - Timestomping

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### Overview

Timestomping is the action of modifying the timestamps of a file (on Windows
systems, on a `NTFS` partition). It can notably be used to evade digital
forensic investigation by making malicious files look legitimate or being out
of the presupposed attack timeframe.

This technique is identified by
[MITRE ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/).

The `MACB` timestamps in the `$STANDARD_INFORMATION` attributes can be modified
by standard users while the `$FILENAME` attributes can only be modified by /
through the Windows kernel. The modification of a file `$STANDARD_INFORMATION`
attribute requires the rights to modify the file attributes (`FullControl`,
`Modify`, `Write`, `WriteAttributes`) which is granted by default to the file
owner.

Note that in addition to being the ones that can be easily modified, the
`MACB` timestamps from the `$STANDARD_INFORMATION` attribute are conveniently
the ones (generally) displayed by the `Windows Explorer`.

For more information on Windows timestamps, refer to the
`[DFIR] Windows - Artefacts - Timestamps` note.

### Timestomping detection

Most of timestomping detections below rely on information stored in the `$MFT`
file. Refer to the `[DFIR] Windows - MFT` note for more information on how to
parse the `$MFT` artefact.

###### MFT $STANDARD_INFORMATION vs $FILENAME

Timestomping can be detected by comparing the `$STANDARD_INFORMATION` and
`$FILENAME` timestamps of a given file in the `MFT`. Indeed, if the timestamps
from `$STANDARD_INFORMATION` (easily modifiable) are older than the `$FILENAME`
timestamps (not (easily) modifiable), the file timestamps may have been
timestomped.

****However, as the `$FILENAME` `MAB` timestamps are updated / copied from the
`$STANDARD_INFORMATION` `MAB` timestamps on file rename or volume-local file
move, `$FILENAME` timestamps can also be (undirectly) tampered.**

Additionally, This detection method is however prone to false-positives as some
applications or installers may modify the `$STANDARD_INFORMATION` timestamps.

`MFTECmd` can be used to parse the `MFT` of a `NTFS` volume and automatically
highlight the files having `$STANDARD_INFORMATION` timestamps older than their
`$FILENAME` timestamps.

###### UsnJrnl records

Data from the `UsnJrnl` artefact may reveal recent operations on timestomped
files. For instance, a `USN_REASON_FILE_CREATE` record logged in the `UsnJrnl`
for a seemingly older file could be an indicator of timestomping.

Additionally, an `USN_REASON_BASIC_INFO_CHANGE` (+ `USN_REASON_CLOSE`) record
would be logged in the `UsnJrnl` following the timestomping of a file. The
presence of such indicator is however not necessarily a strong indicator of
timestomping as many other attributes change would also trigger a similar
record to be logged in the `UsnJrnl`.

This detection method is however prone to false-negatives as the `UsnJrnl` has
usually limited historical data.

Refer to the `[DFIR] Windows - UsnJrnl` note for more information on how to
parse the `UsnJrnl` artefact.

###### MFT $STANDARD_INFORMATION timestamps precision

The timestomping tool used may have limitation on the time precision they
it for timestomped timestamps. For example, the tool may only allow precision
down to the second level, while the `$STANDARD_INFORMATION` timestamps are
precise down to the ten millionths of a second. In such case, the timestomped
timestamps will be padded with zeros in place of the actual milli-seconds:
`YYYY-MM-DD hh:mm:ss.0000000`.

This detection method is however prone to false-positives as some utilities or
file formats, such as file-archives, may truncate timestamps down the second
level.

###### MFT entry numbers

`$MFT` entry numbers grow sequentially, with older files generally having lower
entry numbers than more recent files. The `$MFT` entry numbers should thus grow
linearly with the `$STANDARD_INFORMATION` created / birth timestamp (with usual
exceptions in the days-range: files older by a few days may have slightly
higher entry numbers than relatively more recent files).

This detection method is however prone to false-positives as `$MFT` entry
numbers of deleted files may be re-used (especially for `NTFS` partitions on
SSDs).

--------------------------------------------------------------------------------

### References

https://dfir.ru/2021/01/10/standard_information-vs-file_name/

https://medium.com/@bromiley/a-journey-into-ntfs-part-4-f2865c39ac83

https://www.andreafortuna.org/2017/10/06/macb-times-in-windows-forensic-analysis/

https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/

https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html

https://alexsta-cybersecurity.com/how-to-detect-timestomping-on-a-windows-system/

https://www.sans.org/blog/ntfs-i30-index-attributes-evidence-of-deleted-and-overwritten-files/

https://www.youtube.com/watch?v=XzoYNOlJ37s
