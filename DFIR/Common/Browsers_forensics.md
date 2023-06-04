# DFIR - Browsers forensics

### Browsing history / download artefacts

###### Overview

The web browsers related artefacts can be split in the following categories:

  - User profile: web browsers, such as `Chronium`-based browsers and
    `Firefox`, implement a profile feature to store user's setttings, history,
    favourites, etc. The databases and files that store these information are
    usually stored under a user specific profile folder.

  - History: web browsing history and download history.

  - Cookies: web browsing cookies (session tokens).

  - Cache: cache of resources downloaded from accessed websites (images, text
    content, `HTML`, `CSS`, `Javascript` files, etc.).

  - Sessions: tabs and windows from a browsing session.

  - Settings: configuration settings.

These files are often stored under `%LocalAppData%`
(`%SystemDrive%:\Users\<USERNAME>\AppData\Local\`) and
`%AppData%` (`%SystemDrive%:\Users\<USERNAME>\AppData\Roaming\`).

###### Artefacts details

| Name | Type | Description | Information / interpretation | Location | Tool(s) |
|------|------|-------------|------------------------------|----------|---------|
| `NTUSER` <br> - <br> `TypedURLs` | Web browsers usage | `URL` entered (typed, pasted, or auto-completed) in the `Internet Explorer (IE)` web browser search bar. <br><br> Web searches do not generate entries, only typing of an `URL` will. <br><br> Entries are added / updated in near real-time. | The `URL` are stored as `url1` to `url[N]` in inversed chronological order. <br><br> The last write timestamp of the key is thus the timestamp of visit of the most recently visited `URL`. | File: `%SystemDrive%:\Users\<USERNAME>\NTUSER.dat` <br> Registry key: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs` |
| `Microsoft Internet Explorer` | Web browsers usage | `Microsoft Internet Explorer` artefacts. <br><br> For more information: [Browsers forensics note](../../Common/Browsers_forensics.md). | - | History, downloads, cache, and cookies metadata in a `ESE` database: <br> `%LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat` <br> > History: `History` table <br> > Downloads: `iedownload` table. <br> > Cache: `content` table <br> > Cookies metadata: `Cookies` table. <br><br> Local files access, not necessarily through the webbrowser, may also appear in the `WebCacheV01.dat` database with the `file` `URI` scheme (such as `file:///<DRIVE_LETTER>:/folder/file`). <br><br> Cookies: <br> ` %AppData%\Microsoft\Windows\Cookies` <br><br> Sessions: <br> `%LocalAppData%\Microsoft\Internet Explorer\Recovery\*.dat` | [`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html) |
| `Microsoft Edge` <br> (Legacy) | Web browsers usage | `Microsoft Edge` (legacy version) artefacts. <br><br> For more information: [Browsers forensics note](../../Common/Browsers_forensics.md). | - | User profile(s): <br> `%LocalAppData%\Packages\Microsoft.MicrosoftEdge_XXX\AC` <br><br> History, downloads, cache, and cookies (file shared with `Microsoft Internet Explorer`): <br> `%LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat` <br><br> Cache: <br> `%LocalAppData%\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache` <br><br> Sessions: <br> `%LocalAppData%\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active` <br><br> Settings: <br> `%LocalAppData%\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb` | [`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html) |
| `Microsoft Edge` <br> (`Chronium`-based) | Web browsers usage | `Microsoft Edge` (`Chronium`-based) artefacts. <br><br> Since Edge version `v79` (January 2020), `Microsoft Edge` uses a `Chronium` backend and shares similar artefacts to `Google Chrome`. <br><br> For more information: [Browsers forensics note](../../Common/Browsers_forensics.md). | - | User profile(s): <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\*` <br> *With `X` ranging from one to n.* <br><br> History: <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\History` <br><br> Cookies: <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\Network\Cookies` <br><br> Cache: <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\Cache` <br><br> Sessions: <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\Sessions` <br><br> Settings: <br> `%LocalAppData%\Microsoft\Edge\User Data\<Default \| Profile X>\Preferences` | [`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html) |
| `Google Chrome` | Web browsers usage | `Google Chrome` artefacts. <br><br> For more information: [Browsers forensics note](../../Common/Browsers_forensics.md). | - | User profile(s): <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\*` <br> *With `X` ranging from one to n.* <br><br> History: <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\History` <br><br> Cookies: <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\Network\Cookies` <br><br> Cache: <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\Cache` <br><br> Sessions: <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\Sessions` <br><br> Settings: <br> `%LocalAppData%\Google\Chrome\User Data\<Default \| Profile X>\Preferences` | [`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html) |
| `Mozilla Firefox` | Web browsers usage | `Mozilla Firefox` artefacts. <br><br> For more information: [Browsers forensics note](../../Common/Browsers_forensics.md). | - | User profile(s): <br> `%AppData%\Mozilla\Firefox\Profiles\<ID>.default-release\*` <br><br> History, downloads, and bookmarks in a `SQLite` database: <br> `%AppData%\Mozilla\Firefox\Profiles\<ID>.default-release\places.sqlite` <br><br> Cookies in a `SQLite` database: <br> `%AppData%\Mozilla\Firefox\Profiles\<ID>.default-release\cookies.sqlite` <br><br> Cache: <br> `%LocalAppData%\Mozilla\Firefox\Profiles\<ID>.default-release\cache2\*` <br><br> Sessions: <br> `%AppData%\Mozilla\Firefox\Profiles\<ID>.default-release\sessionstorebackups\*` <br><br> Settings: <br> `%AppData%\Mozilla\Firefox\Profiles\<ID>.default-release\prefs.js` | [`NirSoft's BrowsingHistoryView`](https://www.nirsoft.net/utils/browsing_history_view.html) |

### Parsing

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

-------------------------------------------------------------------------------

### References

https://www.13cubed.com/downloads/windows_browser_artifacts_cheat_sheet.pdf

https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts

https://www.nirsoft.net/utils/browsing_history_view.html

https://www.forensafe.com/blogs/typedurls.html
