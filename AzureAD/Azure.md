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

# Azure CLI.
az login [--service-principal] [--tenant <TENANT_ID>] []--username <USERNAME> --password <PASSWORD>
az login [--tenant <TENANT_ID>] --use-device-code
```

| Description | `AzureAD` module | `Az` module | `AzureRT` module |
|-------------|------------------|-------------|------------------|
| Tenant | `Get-AzureADTenantDetail` | `Get-AzTenant` |
| Current session | `Get-AzureADCurrentSessionInfo` | `Get-AzContext` | `Get-ARTWhoami` |
| Users | `Get-AzureADUser` | `Get-AzADUser` |
| User's memberships | `Get-AzureADUserMembership -All $True -ObjectId "<USER_ID>"` |
| User's owned registered devices | `Get-AzureADUserOwnedDevice -ObjectId "<USER_ID>"` |
| User's owned objects | `Get-AzureADUserOwnedObject -All $True -ObjectId "<USER_ID>"` |
| Applications | `Get-AzureADApplication` | `Get-AzureADApplication` | |
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
| Azure Container Registry | | List repositories in a given `Azure Container Registry`: <br> `Get-AzContainerRegistryRepository -RegistryName "<REGISTRY_NAME>"` <br><br>  | List repositories in a given `Azure Container Registry`: <br> `az acr repository list --name "<REGISTRY_NAME>" --output table` <br><br> Get the attributes of a repository or image: <br> `az acr repository show --name "<REGISTRY_NAME>" [--image "<IMAGE_NAME>" \| --repository "<REPOSITORY_NAME>"` <br><br> Get the credentials for a given `Azure Container Registry`: `az acr credential show --name "<REPOSITORY_NAME>"` |

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

### Logic App

Source(s):

https://www.netspi.com/blog/technical/cloud-penetration-testing/illogical-apps-exploring-exploiting-azure-logic-apps/

###### Reader

As `Logic App` can take user specific inputs / arguments, credentials may be
retrievable with the `Logic App Operator` or `Reader` permissions.

The following PowerShell script, based on the `Az` module, can be used to
enumerate the `Logic Apps` the authenticated user has access to and retrieve
the inputs to actions or parameters provided to each `Logic App`.

```
$allLogicApps = Get-AzLogicApp

foreach($app in $allLogicApps){
    Write-Host "App name:" $app.Name.ToString()

    $actions = ($app.Definition.ToString() | ConvertFrom-Json | select actions).actions

    $noteProperties = Get-Member -InputObject $actions | Where-Object { $_.MemberType -eq "NoteProperty" }
    foreach($note in $noteProperties){
        Write-Host "Note name:" $note.Name
        Write-Host "Note raw:" $note
        $inputs = ($app.Definition.ToString() | ConvertFrom-Json | Select actions).actions.$noteName.inputs
        Write-Host "Note inputs:" $inputs
    }

    Write-Host "Note parameters:" $app.Definition.parameters
}
```

###### Contributor

`Contributor` permissions on `Logic App` can, in addition to allow eventual
secrets retrieval, be used to modify and run the `Logic App`, effectively
assuming the rights granted to the `Logic App`. For instance, a
system or user `managed identity` or `API Connections` can be associated with a
given `Logic App` to allow authenticated access to other cloud services.

The `Logic App` content can be accessed, modified, and run under
`Logic app designer` (`/designer`) under `Development Tools`.

Note that restrictions can be configured on calls to trigger a given
`Logic App`. For instance, triggers or calls to get input and output messages
from a `Logic App` can be limited to whitelisted `IP` ranges. These
restrictions are configured under `Settings->Workflow settings`
(`/workflowSettings`) and be modified with `Contributor` permissions.
