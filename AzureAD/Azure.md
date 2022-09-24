# Azure

### Subscription-wide authenticated enumeration

###### ScoutSuite

```bash
virtualenv -p python3 venv
source venv/bin/activate
pip install scoutsuite

scout azure --tenant <TENANT> [--user-account-browser | --user-account]
```

### Manual Azure / AAD enumeration

| Description | `AzureAD` module | `Az` module |
|-------------|------------------|-------------|
| Tenant | `Get-AzureADTenantDetail` | `Get-AzTenant` |
| Current session | `Get-AzureADCurrentSessionInfo` | `Get-AzContext` |
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
| Azure resources accessible by the current user | | `Get-AzResource` |
| Azure RBAC roles (all or for the given object) | | `Get-AzRoleAssignment [-ObjectId <OBJECT_ID>]` |

### Storage Accounts

### Credentials retrieval

###### Automated subscription-wide credentials retrieval with MicroBurst's Get-AzPasswords

```bash
Import-Module .\MicroBurst.psm1

Login-AzAccount

Get-AzPasswords -Verbose
```
