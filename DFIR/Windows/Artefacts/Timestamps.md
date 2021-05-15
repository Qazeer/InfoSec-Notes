###### Convert UNIX time to human readable format

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
