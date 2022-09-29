# Azure

### Subscription-wide authenticated enumeration

###### ScoutSuite

[`ScoutSuite`](https://github.com/nccgroup/ScoutSuite) is a multi-cloud
Python audit tool that produce an `HTML` report based on a subscription-wide
enumeration and a number of configuration and security checks.

`ScoutSuite` notably includes enumeration / checks on:
  - Azure AD users, groups, service principals, and applications
  - Azure RBAC roles (details, associated permissions and users)
  - Various services, such as VMs, Databases, Key vaults, or Storage Accounts
  - Security configurations, on logging / monitoring or Security Center options
  - ...

```bash
virtualenv -p python3 venv
source venv/bin/activate
pip install scoutsuite

scout azure --tenant <TENANT> [--user-account-browser | --user-account]
```

### Manual Azure / AAD enumeration

The `AzureAD` and `Az` modules can be used to conduct authenticated enumeration
of an AAD tenant and / or Azure subscription.

```bash
# AzureAD module authentication.
Connect-AzureAD

# -- Pass-the-PRT-cookie.
Connect-AzureAD -TenantId "<AAD_TENANT_ID>" -AccountId "<ACCOUNT_ID>" -AadAccessToken "<ACCESS_TOKEN>"

# -- AzureRT's Connect-ARTAD for Azure AD access.
Connect-ARTAD -Username <String> -Password <String> [-ServicePrincipal] [-TenantId <String>]
Connect-ARTAD -Credential <PSCredential>
Connect-ARTAD [-AccessToken <String>] [-TokenFromAzCli]

# Az module authentication.
Connect-AzAccount

# -- AzureRT's Connect-ART for Azure access.
Connect-ART -Username <String> -Password <String> [-ServicePrincipal] [-TenantId <String>]
Connect-ART -Credential <PSCredential>
Connect-ART [-AccessToken <String>] [-GraphAccessToken <String>] [-KeyVaultAccessToken <String>] [-SubscriptionId <String>] [-TokenFromAzCli]
```

| Description | `AzureAD` module | `Az` module | `AzureRT` module |
|-------------|------------------|-------------|------------------|
| Tenant | `Get-AzureADTenantDetail` | `Get-AzTenant` |
| Current session | `Get-AzureADCurrentSessionInfo` | `Get-AzContext` | `Get-ARTWhoami` |
| Users | `Get-AzureADUser` | `Get-AzADUser` |
| User's memberships | `Get-AzureADUserMembership -All $True -ObjectId "<USER_ID>"` |
| User's owned registered devices | `Get-AzureADUserOwnedDevice -ObjectId "<USER_ID>"` |
| User's owned objects | `Get-AzureADUserOwnedObject -All $True -ObjectId "<USER_ID>"` |
| Applications | `Get-AzureADApplication` |
| Devices | `Get-AzureADDevice` |
| Service Principals | `Get-AzureADServicePrincipal` |
| AAD Roles | `Get-AzureADDirectoryRole` |
| AAD Roles associated members | `Get-AzureADDirectoryRoleMember -ObjectId "<ROLE_ID>"` |
| Groups | `Get-AzureADGroup` | `Get-AzADGroup` |
| Group's members | `Get-AzureADGroupMember -ObjectId "<GROUP_ID>"` | `Get-AzADGroupMember -GroupObjectId  "<GROUP_ID>"` |
| Group's owner | `Get-AzureADGroupOwner -ObjectId "<GROUP_ID>"`
| Azure resources accessible by the current user | | `Get-AzResource` | `Get-ARTAccess` |
| Azure RBAC roles (all or for the given object) | | `Get-AzRoleAssignment [-ObjectId <OBJECT_ID>]` |
| Azure AD objects accessible by the current user | | | `Get-ARTADAccess` |

### Credentials retrieval

###### Automated subscription-wide credentials retrieval with MicroBurst's Get-AzPasswords

[`Get-AzPasswords`] is a PowerShell cmdlet, part of the `MicroBurst` module,
attempts to retrieves credentials from a number of Azure services (depending on
the current user privileges), including:
  - Key Vaults
  - App Services Configurations
  - Automation Accounts

```bash
Import-Module .\MicroBurst.psm1

Login-AzAccount

Get-AzPasswords -Verbose
```

###### Primary Refresh Token post-exploitation on Azure-joined systems

Refer to the `[Windows] Post exploitation - Credentials dumping` note
(`Primary Refresh Token for Azure-joined devices` section) for more information
on how to retrieve and use a `PRT` from a compromised Azure AD joined or
hybrid-joined device.
