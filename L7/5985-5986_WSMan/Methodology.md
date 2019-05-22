# WS-Management - Methodology

### Overview

Windows Remote Management (`WinRM`) is the Microsoft implementation of
WS-Management Protocol, a standard Simple Object Access Protocol (`SOAP`)-based,
protocol that allows hardware and operating systems, from different vendors, to
interoperate.

`WinRM` can be used to perform various management tasks remotely, including,
but not limited to, running batch and `PowerShell` commands or scripts.
Communication are performed over `HTTP`, port TCP 5985, or `HTTPS`, port TCP
5986.

`WinRM` supports multiples authentication mechanisms:

  - `Basic` / `Digest`: basic authentication for local Windows accounts.
  Credentials are base64 encoded and sent to the server ;
  - `Negotiate`: use negotiate authentication for both local and domain joined
  accounts, also known as Windows Integrated Authentication. By default, for
  local accounts, only the built-in Administrator account can connect.
  - `Client Certificate-based`: authentication is made using a client
  certificate mapped to a local Windows account on the server ;
  - `Kerberos`: use `Kerberos` authentication for domain joined accounts ;
  - `ntlm`: use `NTLM` authentication for both local and domain joined accounts ;
  - `credssp`: use `CredSSP` authentication mechanism for both local and domain
  joined accounts.

**`WinRM` presents a limited attack surface, with no publicly known
vulnerability to date (May-2019) and is subject to Windows anti brute
forcing mechanisms.
`WinRM` can thus be mostly used for lateral movement after an initial account
compromise.**

### Enumerate supported authentication mechanisms

The `Metasploit` module `auxiliary/scanner/winrm/winrm_auth_methods` can be
used to enumerate the authentication mechanisms, listed above, supported by the
remote `WinRM` service.

```
msf> use auxiliary/scanner/winrm/winrm_auth_methods
```

May returns false negatives on recent and up to date `WinRM` service.

### Credentials brute forcing

The `Metasploit` module `auxiliary/scanner/winrm/winrm_login` can be used to
conduct a brute force attack against a `WinRM` service.

Note that the account lockout policies for either local or domain joined account
will apply. Vertical brute forcing attack will thus most likely result in
account lockout. `WinRM` could however be used in passwords spraying attack,
for more information refer to the `Active Directory - Passwords spraying` note.   

```
msf> use auxiliary/scanner/winrm/winrm_login
```

### Remote commands execution

To execute commands through `WinRM` using known credentials, refer to the
`Active Directory - Credentials theft shuffle` note.
