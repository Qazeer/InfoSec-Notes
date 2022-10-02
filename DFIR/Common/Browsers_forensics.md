# DFIR - Browsers forensics

### Browsing history / download artefacts

The browsing and download history information for a number of browsers can be
found at the following location:

| Browser | Artefact description | Location | Associated tooling |
|--------|----------------------|----------|--------------------|
| `Google Chrome` | Navigation and download history. | Windows: <br> `%SystemDrive%:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data\Default\History` <br> If multiple profiles are configured: `%SystemDrive%:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data\Profile <1 \| X>\History` | `BrowsingHistoryView` |
| `Mozilla Firefox` | Navigation and download history. | Windows: <br> `%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite` | `BrowsingHistoryView` |
| `Microsoft Internet Explorer` | Navigation and download history. | Windows: <br> `%SystemDrive%:\Users\<USERNAME>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` | `BrowsingHistoryView` |
| `Microsoft Internet Explorer` | URLs types / entered in the navigation bar. | Windows: <br> `` | Registry viewer / parser (such as `RegistryExplorer`) |
| `Microsoft Edge` | Navigation and download history. | Windows: <br> `%SystemDrive%:\Users\<USERNAME>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` <br> `%SystemDrive%:\Users\<USERNAME>\AppData\Local\Microsoft\Edge\User Data\Default\History` | `BrowsingHistoryView` |

As stated,
[`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html)
utility (`NirSoft_BrowsingHistoryView` KAPE module) can be used to parse a
number of browsers artefacts to extract browsing history information.
`BrowsingHistoryView` can be used either as a graphical application or as a
command-line utility to export the parsing result (for instance in the CSV
format).

```
# /HistorySource 3: Load history from the specified profiles folder (specified using /HistorySourceFolder).
# /HistorySourceFolder <USER_PROFILES_FOLDER> example: "C:\Users" or "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users" (for shadow copy).
# /VisitTimeFilterType 1: Load history dating back to any time.
# /ShowTimeInGMT 1: Converts timestamps to UTC-0 (default to the local timezone).

browsinghistoryview.exe /HistorySource 3 /HistorySourceFolder "<USER_PROFILES_FOLDER>" /VisitTimeFilterType 1 /ShowTimeInGMT 1 /scomma <OUTPUT_CSV>
```

### Browsers cookies and saved credentials

### Browsers cache

### Browers bookmarks

--------------------------------------------------------------------------------

### References

https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts

https://www.nirsoft.net/utils/browsing_history_view.html

https://www.forensafe.com/blogs/typedurls.html
