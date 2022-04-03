# Azure Active Directory / Office 365 - Tenant recon

### Unauthenticated reconnaissance

The PowerShell `AADInternals` module implements a number of techniques
that leverage publicly available Azure APIs to gather information on an
`Azure AD tenant` without authenticating.

The following APIs are publicly available, with corresponding cmdlets from
the `AADInternals` module:
  - TODO

The `Invoke-AADIntReconAsOutsider` PowerShell cmdlet aggregates the
aforementioned cmdlets of the `AADInternals` module.

```
Invoke-AADIntReconAsOutsider -DomainName <test.com | COMPANY_DOMAIN> | Format-Table
```

###### Azure Desktop SSO

If `Desktop SSO` is enabled for the tenant, valid users enumeration (oracle
type) is possible.

TODO

### Authenticated enumeration

###### o365recon

The [`o365recon`](https://github.com/nyxgeek/o365recon) PowerShell script can
be used to enumerate information from an `AzureAD` tenant.

The following information are gathered:
  - `O365` and `AzureAD` users
  - `O365` and `AzureAD` groups and group memberships
  - Admin group memberships
  - Device information and user / device mappings
  - Applications information and user / application mappings
  - Dangerous rights (such as the right to create applications or groups,
    access other users information, etc.).

```
# The script rely on the MSOnline and AzureAD PowerShell modules.
Install-Module MSOnline
Install-Module AzureAD

.\o365recon.ps1 -azure
```

###### AzureHound

[`AzureHound`](https://github.com/BloodHoundAD/AzureHound) is a collector for
[`BloodHound`](https://github.com/BloodHoundAD/BloodHound), used to
enumerate information on `Azure` and `Azure AD` environments. The collected
data can be ingested by `BloodHound` to determine possible compromise graphs.
If data about a linked `Active Directory` forest / domain has be been collected
(using `SharpHound`), `BloodHound` adds potential path to / from `Azure` to /
from the on-premise `Active Directory`.

```
# AzureHound relies on the Az and Azure AD PowerShell modules which require PowerShell version 5.1 and greater (retrievable with $PSVersionTable.PSVersion).
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module -Name Az -AllowClobber
Install-module -Name AzureADPreview -AllowClobber

# The modules can also be installed using AzureHound directly.
Invoke-AzureHound -Install

# Invoke-AzureHound may not properly process authentication from non joined computers.
# In such case, the authentication process can be done manually.
Connect-AzAccount [-Tenant '<TENANT_ID>']
Connect-AzureAD [-Tenant '<TENANT_ID>']

Invoke-AzureHound [-TenantID '<TENANT_ID>']
```
