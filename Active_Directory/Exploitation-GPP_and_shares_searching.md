# Active Directory - GPO and shares searching

### Overview

The `SYSVOL` folder, accessible on all Domain Controller to all authenticated
users, should be carefully reviewed for sensible information (notably the
`Group Policy Preferences (GPP)` data).
Some content may be accessible to unauthenticated users (`NULL session` or
`GUEST`) and can be a way to gain authenticated access to the Domain.

###### SMB

The `Server Message Block (SMB)` protocol, one version of which was also known
as `Common Internet File System (CIFS)`, is an application-layer network
protocol used for providing shared access to files, printers, and serial ports
and miscellaneous communications between nodes on a network. It also provides
an authenticated inter-process communication mechanism. Most usage of SMB
involves computers running Microsoft Windows.

###### Group Policy

`Group Policy` is a feature of the Microsoft `Windows NT` family of operating
systems that controls the working environment of user accounts and computer
accounts. `Group Policy` provides centralized management and configuration of
operating systems, applications, and users' settings in an Active Directory
environment. A version of `Group Policy` called `Local Group Policy` (`LGPO` or
`LocalGPO`) also allows `Group Policy Object (GPO)` management on standalone
and non-domain joined computers.

Two kinds of `Group Policy` exist : `Group Policy Object (GPO)` and `Group
Policy Preferences (GPP)`.
One of the most useful features of the `GPP` is the ability to store and use
credentials in several scenarios (local user creation, map drives, etc.). When
a new `GPP` is created, an associated `XML` file is created in the `SYSVOL`
share with the relevant configuration data and if a password is provided, it is
`AES-256` bit encrypted. Microsoft published the `AES` private key which can be
used to decrypt the password. Since authenticated users (any domain user or
users in a trusted domain) have read access to the `SYSVOL` share, anyone in
the domain can search the `SYSVOL` share for `XML` files containing a
`cpassword` field, which is the field that contains the `AES` encrypted
password. There are a few more differences between the two, for additional
details refer to the following article :
http://techgenix.com/policies-vs-preferences/.

###### SYSVOL

The `SYSVOL` is the domain-wide share in Active Directory to which all
authenticated users have read access. The `SYSVOL` contains logon scripts,
group policy data, and other domain-wide data which needs to be available
anywhere there is a Domain Controller (since the `SYSVOL` is automatically
synchronized and shared among all Domain Controllers).

In addition to the `GPP` data potentially containing password, more sensible
information can be stored in the `SYSVOL` share and its content should be
reviewed.

### Group Policy Preferences (GPP) password searching

As stated above, `GPP` may be used in the domain to manage and configure local
accounts on domain joined computers. The `GPP` defined may thus contain
passwords and the `SYSVOL` folder should be reviewed.

`PingCastle`'s `healthcheck` searches a Domain Controller's `SYSVOL` share for
any `XML` (`*.xml`)  files that may contain a `cpassword` field and
automatically decrypt any password found.

Additionally, the `Get-GPPPassword` cmdlet of the `PowerSploit` suite searches
a Domain Controller's `SYSVOL` share for `groups.xml`, `scheduledtasks.xml`,
`services.xml` and `datasources.xml` files and returns any (decrypted)
`cpassword` passwords:

```
Get-GPPPassword
Get-GPPPassword -Server <DC>
```

To manually search for `cpassword` field / passwords in `GPP`, the `Agent
Ransack` GUI or the `SauronEye` CLI tools can be used. Refer to the
`Distributed searching tools` section below for more information.

The Ruby `gpp-password` script can be used to decrypt a GPP password:

```
gpp-decrypt <ENC_PASSWORD>
```

### Distributed shares searching

###### Enumerate accessible shares

The `PingCastle`'s `share` module can be used to enumerate the machines joined
in the current, or specified, Active Directory domain and then retrieve the
exposed shares by each machines through direct `SMB` queries.

```
PingCastle.exe --scanner share
PingCastle.exe --server <DC_FQDN | DC_IP> --user "<DOMAIN>\<USERNAME>" --password "<PASSWORD>" --scanner share
```

From an unauthenticated perspective, `nmap` can be used to conduct a network
scan to enumerate exposed `SMB` services and to list the accessible shares on
the accessible services:

```
nmap --script smb-enum-shares.nse -p 445 <TARGETS>
nbtscan -r <RANGE>
```

For more practical information about shares listing and searching, refer to the
`[L7 SMB] - Methodology` note.

###### Distributed searching tools

The `Agent Ransack` GUI or `SauronEye` CLI files searching tool can be used to
search files in `SMB` shares for specified keywords or regex, such as
`pass*`, etc.

```
SauronEye.exe --directories <LOCAL_DIRECTORY | NETWORK_SHARE> <...> --filetypes <.FILE_EXTENSION> <...> --contents --keywords <KEYWORD | BASIC_REGEX>
```
