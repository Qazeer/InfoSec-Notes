# DFIR - Cloud - Azure

### Minimal required privileges to access logs / perform a security review

The following privileges / roles are required in the Azure AD tenant and
Exchange Online instance:
  - Azure AD tenant: `Global Reader` ("Lecteur Général") role.

  - Exchange Online environment: `View-Only Audit Logs` role
    ("Journaux d’audit en affichage seul") role. This role is by default
    granted to the `Compliance Management` and `Organization Management` role
    groups (for which members can be assigned). Members can be assigned to the
    aforementioned groups through the
    [Exchange administration portal](https://admin.exchange.microsoft.com/).

  - Azure subscription (for retrieving `Azure Activity logs` for the given
    subscription): `Log Analytics Reader` role.

  - Azure DevOps organization (for retrieving `Azure DevOps Activity logs` for
    the given Azure DevOps organization): `Auditing\View audit log` permission.

### Office365 security review

###### Licensing plans

The licensing plans in use will define the level of logs available.
For instance, `MailItemsAccessed` mail access events will only be available
for users with an E5 license.

```bash
# List the license plans in the tenant.
Get-MsolAccountSku

# Retrieves the license plans associated with the specified user.
Get-MsolUser -UserPrincipalName <EMAIL> | Select-Object DisplayName -ExpandProperty Licenses
```

The license plans in use, and their associated users, can also be visualized
from the [Microsoft 365 admin center](https://portal.office.com/Adminportal/Home/?#/licenses) (https://portal.office.com/Adminportal/Home/?#/licenses).

###### Mailbox auditing configuration

Mailbox auditing is on by default for the entire Office365 tenant, but can be
turned off. Turning off mailbox auditing will result mailbox actions no longer
being audited (even if auditing is enabled on at a mailbox level). Existing
mailbox audit records will however be retained until the audit log age limit
for the record expires.

The following logon types are used to classify the audited actions on a
mailbox:
  - `Owner`: The account that's associated with the mailbox.
  - `Delegate`: A user who's been assigned the `SendAs`, `SendOnBehalf`, or
    `FullAccess` permission to another mailbox.
  - `Admin`: The mailbox is searched with a `Microsoft eDiscovery` tool or
    is accessed with the `Microsoft Exchange Server MAPI Editor`.

While mailbox auditing cannot be disabled for a specific mailbox if mailbox
auditing is enabled tenant-wide, mailbox audit logging can still be bypassed by
defined users. In such circumstances, mailbox `Owner`, `Delegate`, or `Admin`
aren't logged.

```bash
Connect-ExchangeOnline

# Retrieves the mailbox auditing status at the Office365 tenant level.
Get-OrganizationConfig | Select-Object Identity,Name,AuditDisabled

# Retrieves the mailbox auditing bypass status for the specified mailbox.
Get-MailboxAuditBypassAssociation -Identity <EMAIL> | Select-Object Id,DistinguishedName,AuditBypassEnabled

# Retrieves mailbox auditing settings, including the operations logged for the specified mailbox.
Get-Mailbox -Identity <EMAIL> | Select-Object Identity,Name,AuditEnabled,DefaultAuditSet,AuditLogAgeLimit,AuditOwner,AuditDelegate,AuditAdmin | ConvertTo-Json
```

###### Emails forwarding

*Mailbox Email Forwarding*

Mailbox Email Forwarding can be configured by any user for their mailbox,
allowing forwarding to external (`ForwardingSmtpAddress`) or internal
(`ForwardingAddress`) email addresses.

```bash
# Lists all mailboxes with a forwarding address configured from Mailbox Settings.
Get-Mailbox -ResultSize Unlimited | Where-Object { ($Null -ne $_.ForwardingSmtpAddress) } | Select Identity,Name,PrimarySmtpAddress,ForwardingSmtpAddress
```

The email forwarding configured on a given mailbox can also be visualized
from the [Microsoft 365 admin center](https://portal.office.com/Adminportal/Home/?#/users) (https://portal.office.com/Adminportal/Home/?#/users).

*Mailbox Inbox rules*

Mailbox Inbox rules can be configured by any user for their mailbox, allowing
forwarding to external or internal email addresses as well as deletion of
received emails.

```bash
# List all mailboxes's Inbox rules for the given mailbox.

Get-InboxRule -Mailbox <EMAIL> | Select-Object Identity,Name,Enabled,Description | Format-List

# List all mailboxes's Inbox rules with ForwardTo, RedirectTo, ForwardAsAttachmentTo, or DeleteMessage actions.

$Mailboxes = Get-Mailbox
Foreach ($Mailbox in $Mailboxes) {
    Get-InboxRule -Mailbox $Mailbox.Name |
    Where-Object {($Null -ne $_.ForwardTo) -or ($Null -ne $_.RedirectTo) -or ($Null -ne $_.ForwardAsAttachmentTo) -or ($True -eq $_.DeleteMessage) } |
    Select-Object Identity,Name,PrimarySmtpAddress,Enabled,ForwardAsAttachmentTo,ForwardTo,RedirectTo
}
```

*Mailbox Mail Flow / Transport rules*

Mailbox Mail Flow / Transport rules can only be configured by `Exchange Admin`
users, and allow actions to be taken on in transit emails. For instance, a
blind copy (i.e with out disclosure to the sender or recipients) can be send to
external or internal email addresses.

```bash
# List all Mail Flow / Transport rules.
Get-TransportRule | Select-Object *

# List all Mail Flow / Transport rules that send a copy of received emails.
Get-TransportRule | Where-Object { ($Null -ne $_.BlindCopyTo) } | Select-Object *
```

###### Mailbox delegations

The following level / scope of delegations can be configured:
  - Mailbox permissions: to allow items viewing at the mails
    box level (but not the right to send emails).
  - Recipient `SendAs` permissions: to delegate the right to send emails from
    the mailbox (that transparently appear to come from the specified mailbox
    to the recipients).
  - Recipient `SendOnBehalf` permissions: to delegate the right to send emails
    on behalf of the mailbox (and will appear as such to the receiving
    recipients).
  - Folder-level permissions: to delegate the rights to interact with items at
    the mailbox's folder level.

*Mailbox access rights / permissions*

Mailboxes are securable objects with a set of possible access rights /
permissions.

The available access rights are:
  - `ChangeOwner`: change the owner of the mailbox.
  - `ChangePermission`: change the permissions on the mailbox.
  - `DeleteItem`: delete the mailbox.
  - `ExternalAccount`: indicates the account isn't in the same domain.
  - `FullAccess`: open the mailbox, access its contents, but can't send mail.
  - `ReadPermission`: read the permissions on the mailbox.

The permissions defined on that level allow for emails viewing at the mailbox
scope but do not allow sending emails (which is defined through the ).

```bash
# Retrieves the access rights defined on the given mailbox.
Get-MailboxPermission -Identity <EMAIL>

# Lists the mailbox permissions with Full Access, ChangeOwner, ChangePermission, or ExternalAccount access rights.
Get-Mailbox -Resultsize Unlimited | Get-MailboxPermission | Where-Object { ($_.Accessrights -like "FullAccess" -or $_.Accessrights -like "ChangeOwner" -or $_.Accessrights -like "ChangePermission" -or $_.Accessrights -like "ExternalAccount") } | Format-List
```

*Recipient (or `SendAs`) access right / permission*

Recipient, or `SendAs`, permission does not allow for emails viewing but
allow a user, or group members, to send messages that appear to come from the
specified mailbox. The email received from the mailbox owner or through a
`SendAs` delegation are indistinguishable by the receiving end-user.

Note that the `Get-EXORecipientPermission` / `Get-RecipientPermission` is not
included by default in the cmdlets allowed for the
`View-Only Organization Management` role group.

```bash
# Lists the mailboxes with the SendAs reciptient permission.
Get-Mailbox -Resultsize Unlimited | Get-EXORecipientPermission | Where-Object { ($_.Accessrights -like "SendAs") }
```

*Folder-level permissions*

Permissions / access rights can also be defined at the folder-level in
mailboxes, to grant delegate the rights to interact with items at the
mailbox's folder level.

The [following individual permissions are available](https://learn.microsoft.com/en-us/powershell/module/exchange/add-mailboxfolderpermission):
  - `None`: The user has no access to view or interact with the folder or its
    contents.
  - `CreateItems`: The user can create items within the specified folder.
  - `CreateSubfolders`: The user can create subfolders in the specified folder.
  - `DeleteAllItems`: The user can delete all items in the specified folder.
  - `DeleteOwnedItems`: The user can only delete items that they created from
    the specified folder.
  - `EditAllItems`: The user can edit all items in the specified folder.
  - `EditOwnedItems`: The user can only edit items that they created in the
    specified folder.
  - `FolderContact`: The user is the contact for the specified public folder.
  - `FolderOwner`: The user is the owner of the specified folder. The user can
    view the folder, move the folder and create subfolders. The user can't read
    items, edit items, delete items or create items.
  - `FolderVisible`: The user can view the specified folder, but can't read or
    edit items within the specified public folder.
  - `ReadItems`: The user can read items within the specified folder.

The following roles, that group individual permissions, are available:
  - `Author`: CreateItems, DeleteOwnedItems, EditOwnedItems, FolderVisible,
    ReadItems.
  - `Contributor`: CreateItems, FolderVisible.
  - `Editor`: CreateItems, DeleteAllItems, DeleteOwnedItems, EditAllItems,
    EditOwnedItems, FolderVisible, ReadItems.
  - `NonEditingAuthor`: CreateItems, DeleteOwnedItems, FolderVisible,
    ReadItems.
  - `Owner`: CreateItems, CreateSubfolders, DeleteAllItems, DeleteOwnedItems,
    EditAllItems, EditOwnedItems, FolderContact, FolderOwner, FolderVisible,
    ReadItems.
  - `PublishingAuthor`: CreateItems, CreateSubfolders, DeleteOwnedItems,
    EditOwnedItems, FolderVisible, ReadItems.
  - `PublishingEditor`: CreateItems, CreateSubfolders, DeleteAllItems,
    DeleteOwnedItems, EditAllItems, EditOwnedItems, FolderVisible, ReadItems.
  - `Reviewer`: FolderVisible, ReadItems.

```bash
# Retrieves the folder-level permission for the specified mailbox.
Get-Mailbox -Identity <EMAIL> | Get-MailboxFolderPermission | Select-Object *

# Enumerates, for all the mailboxes, the folder-level permission allowing access to Anonymous or Default.
$MailBoxes = Get-Mailbox -Resultsize Unlimited
ForEach ($MailBox in $MailBoxes) {
  $Permissions = Get-MailboxFolderPermission $MailBox |
  Where-Object { (($_.User -like 'Anonymous') -or ($_.User -like 'Default')) -and $_.AccessRights -ne 'None' }

  ForEach ($Permission in $Permissions) {
    [PSCustomObject]@{
      MailBoxIdentity = $MailBox.Identity
      MailBoxPrimarySmtpAddress = $MailBox.PrimarySmtpAddress
      FolderName = $Permission.FolderName
      DelegateUser = $Permission.User
      DelegateRights = $Permission.AccessRights
      DelegateIsValid = $Permission.IsValid
    }
  }
}
```

###### OAuth Permissions

`OAuth` is a protocol to delegate access and grant third party websites or
applications access to users data and perform operations on their behalf. With
`OAuth`, users don't have to reveal their credentials to the third party
service, as access is granted through the `Identity Provider (IdP)`
(`Azure AD` in `Azure` case). In an `OAuth` abuse attack, a victim authorizes
a malicious third-party application to access their account data.

Microsoft Graph supports two access types, delegated permissions and
application permissions. With delegated permissions, the application calls
Microsoft Graph on behalf of a signed-in user. With application permissions,
the application calls Microsoft Graph with its own identity, without a signed
in user.

The delegated and application permissions available are referenced in the
[Microsoft documentation](https://learn.microsoft.com/en-us/graph/permissions-reference).

[`Microsoft-Extractor-Suite`](https://github.com/invictus-ir/Microsoft-Extractor-Suite)'s
`Get-OAuthPermissions` PowerShell cmdlet can be used to enumerate delegated
permissions (`OAuth2PermissionGrants`) and application permissions
(`AppRoleAssignments`) for all accounts:


```bash
Get-OAuthPermissions
```

### Azure AD, Office365, and Azure logs overview

| Source | Description | History | Mechanism used |
|--------|-------------|---------|------------------|
| [`Office 365 Unified Audit Logs`](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance) | All Office 365 logs (including Azure AD logs with a more limited level of information). <br><br> Entries are stored in `UTC+0`. <br><br> There can be a delay of around 30min for logs to be available in UAL and up to 24 hours for AAD logs (and Power Automate, Power Apps, and Yammer logs). <br><br> As of October 2021, `Audit Logs` are by default turned on for newly created tenants. | 90 days (by default) <br><br> 1 year for users assigned a E5 license.	| `Exchange online PowerShell` |
| [`Mailbox Audit Log`](https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing) | Information about certain actions performed on mailboxes by mailbox owners, delegates, and admins. For instance, log entries can be generated upon mail data access, email deletion or sending, etc. <br><br> As of January 2019, `mailbox audit logs` should be turned on by default for newly created tenants. [As stated in the Microsoft documentation](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-mailboxes?view=o365-worldwide), the `mailbox audit logs` are reliably sent to the `Office 365 Unified Audit Logs` only for users with E5/A5/G5 licenses or mailboxes with `mailbox audit logs` explicitly enabled (even if `mailbox audit logs` is implicitly enabled by default for every mailboxes). Events for users with non E5 licenses or `mailbox audit logs` not explicitly enabled should generally be sent to the `Office 365 Unified Audit Logs` but may not depending on performance reason. <br><br> A predefined set of mailbox actions are audited by default for each logon type (`Admin`, `Delegate`, and `Owner`). The list of actions logged by default can be found in the [official Exchange documentation](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-mailboxes). Note that while mailbox auditing cannot be disabled for a specific mailbox if mailbox auditing is enabled tenant-wide, mailbox audit logging can still be bypassed by defined users. In such circumstances, mailbox `Owner` actions as well as `Delegate` (i.e on other users' mailboxes) and `Admin` actions performed by the bypassed users aren't logged. <br><br> Mailbox logon types: <br> - `Owner`: access by the mailbox owner. <br> - `Delegate`: access by another user being granted `SendAs`, `SendOnBehalf`, or `FullAccess` (access to everything but not the right to send mails) permission to the mailbox. <br> - `Admin`: mailbox is searched with a Microsoft eDiscovery tool or with the Microsoft Exchange Server MAPI Editor. <br><br> `MailItemsAccessed` mail access events will only be available with a `E5 license`. Unofficially, a single `E5 license` in the tenant is sufficient to generate the events for all users, even retroactively populating events for the retention period. | 90 days | `Exchange Online PowerShell` |
| [`Azure AD sign-ins logs`](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins) | Information about Azure AD sign-ins and resources usage. <br><br> Entries are stored in `UTC+0`. | 30 days | `MS Graph API` |
| [`Azure AD audit logs`](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs) | Information about changes applied to the Azure AD tenant, such as users or group management and updates. <br><br> Entries are stored in `UTC+0`. | 30 days | `MS Graph API` |
| [`Azure Activity logs`](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) | Information about activity in an Azure subscription, such as resource modification, virtual machine creation and start, etc. | 30 days | `Azure Monitor RESTAPI` |
| [`Azure DevOps Activity logs`](https://docs.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing) | Information about operations in the Azure DevOps organization(s), such as operations on resources, permissions changes, etc. | 90 days | `Azure DevOps services RESTAPI` |

Note that accessing Azure AD logs through the `MS Graph API` requires at least
**one user with an Azure `AD Premium P1` or `AD Premium P2` license**. These
license can be included in other license plans, such as
`Microsoft 365 E3 / E5 / F3`. The other to which is associated the license does
not matter.

### Azure AD, Office365, and Azure logs search and collection

Remark: if only a day is specified, as `StartDate` and `EndDate` for some
cmdlets for instance, PowerShell will initialize the corresponding `DateTime`
objects at 12:00 AM (midnight) in the system local timezone (whereas records in
the UAL are stored in `UTC`). The results retrieved, by
`Search-UnifiedAuditLog` for example, will thus be bound by the local system
timezone. Timestamps should thus be provided directly in `UTC` or with timezone
information.

###### [Office365] Unified audit and Mailbox Audit logs manual search

The `Search-UnifiedAuditLog` cmdlet of the `ExchangeOnlineManagement` module
can be used to search and export the Office365 `Unified Audit Logs`. The cmdlet
returns a maximum of 5000 results for direct queries, 50 000 (unsorted) results
for paged queries. Requests that would return a large number of events should
thus automated (for instance with `DFIR-O365RC` or `Microsoft-Extractor-Suite`).

```bash
# If necessary, install and / or import the ExchangeOnlineManagement module.
Install-Module ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement

# Connect to Office365.
Connect-ExchangeOnline

# Retrieves events for the specified timeframe and accounts.
Search-UnifiedAuditLog -ResultSize 5000 -StartDate <YYYY-MM-DDT00:00:00Z> -EndDate <YYYY-MM-DDT00:00:00Z> -UserIds '<EMAIL | EMAIL_1,...,EMAIL_N>'

# Retrieves events for the specified record type.
# Record types: https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
# Record type examples for the the Exchange workload: "ExchangeItem","ExchangeAdmin","ExchangeItemGroup","ExchangeSearch","ExchangeAggregatedOperation","ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange","MipAutoLabelExchangeItem"
# Record type examples for Azure AD: "AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon"
Search-UnifiedAuditLog -ResultSize 5000 -RecordType <RECORD_TYPES>

# Retrieves events for the specified operation(s).
# Operation examples for the Exchange workload: "MailboxLogin","MailItemsAccessed","FolderBind","Send","SendAs","SendOnBehalf","Set-Mailbox","New-InboxRule","Set-InboxRule","UpdateInboxRules","New-TransportRule","Set-TransportRule","Remove-InboxRule","Disable-InboxRule","Add-MailboxPermission","AddFolderPermissions","Add-RecipientPermission","Remove-MailboxPermission","RemoveFolderPermissions","Remove-RecipientPermission","Set-OwaMailboxPolicy","MoveToDeletedItems","SoftDelete","HardDelete","Hard Delete user","Set-CASMailbox","SearchCreated","SearchExported"
Search-UnifiedAuditLog -ResultSize 5000 -Operations <OPERATIONS>

# Retrieves all Azure AD sign-in logs.
Get-ADSignInLogs
# Retrieves Azure AD sign-in logs before and / or after the specified date(s) (no timestamp support, date with day precision only).
Get-ADSignInLogs -Before <YYYY-MM-DD> -After <YYYY-MM-DD>

# Retrieves all Azure AD Audit logs.
Get-ADAuditLogs
# Retrieves Azure AD Audit logs before and / or after the specified date(s) (no timestamp support, date with day precision only).
Get-ADAuditLogs -Before <YYYY-MM-DD> -After <YYYY-MM-DD>
```

###### [Azure AD, Office365, & Azure] Microsoft-Extractor-Suite

The [`Microsoft-Extractor-Suite`](https://github.com/invictus-ir/Microsoft-Extractor-Suite)
PowerShell module can be used to extract logs from Azure AD and Office365.

```bash
# If necessary, installs the required PowerShell modules.
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name AzureADPreview

# The AzureADPreview module MUST be imported (in place of the AzureAD module), as Get-AzureADAuditSignInLogs is updated to allow the retrieval of all events (instead of 1.000 entries with the AzureAD version).
Remove-Module -Name 'AzureAD' -Force
Import-Module -Name 'AzureADPreview' -Force

Import-Module .\Microsoft-Extractor-Suite.psd1

# Connects to Office 365 and / or Azure.
Connect-M365
Connect-Azure

# Retrieves the total number of records in the UAL per Record Type.
# By default retrieve data for the last 90 days for all users.
Get-UALStatistics
# For the specified user(s) and / or in the given timeframe.
Get-UALStatistics -UserIds "<EMAIL>" -StartDate <YYYY-MM-DDT00:00:00Z> -EndDate <YYYY-MM-DDT00:00:00Z>

# Retrieves all UAL data.
# By default retrieve data for the last 90 days for all users.
Get-UALAll [-Output JSON]
# For the specified user(s) and / or in the given timeframe.
Get-UALAll [-Output JSON] -UserIds "<EMAIL | EMAILS_LIST>" -StartDate <YYYY-MM-DDT00:00:00Z> -EndDate <YYYY-MM-DDT00:00:00Z>

# Retrieves MailBox audit logs for the specified or all mailboxes.
Get-MailboxAuditLog [-StartDate <YYYY-MM-DDT00:00:00Z>] [-EndDate <YYYY-MM-DDT00:00:00Z>]
Get-MailboxAuditLog -UserIds "<EMAIL | EMAILS_LIST>"

# Retrieves the Azure Active Directory sign-in log,
Get-ADSignInLogs
```

###### [Azure AD, Office365, & Azure] DFIR-O365RC collector

[`DFIR-O365RC`](https://github.com/ANSSI-FR/DFIR-O365RC) is a PowerShell module
that implement a number of cmdlets to retrieve Office 365 / Azure logs. As
`DFIR-O365RC` supports PowerShell Core, it can be used on both Windows or Linux
endpoints.

The logs are retrieved in `JSON` from the following sources of information:
  - `Office 365 Unified Audit Logs`
  - `Mailbox Audit Log`
  - `Azure AD sign-ins logs`
  - `Azure AD audit logs`
  - `Azure Activity logs`
  - `Azure DevOps Activity logs`

*Manual installation*

`DFIR-O365RC` depends on the [`MSAL.PS`](https://github.com/AzureAD/MSAL.PS)
and [`PoshRSJob`](https://github.com/proxb/PoshRSJob) modules, that must be
installed before usage.

```bash
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force

Install-Module -Name MSAL.PS -RequiredVersion '4.21.0.1'
Install-Module -Name PoshRSJob -RequiredVersion '1.7.4.4'
```

On PowerShell Core, the installation of the `WSMan` client may also be
required:

```bash
Install-Module PSWSMan
Install-WSMan
```

The `DFIR-O365RC` directory of the `DFIR-O365RC` project can then be placed in
in one of the system modules path (retrievable using `$env:PSModulePath`) and
imported with `Import-Module DFIR-O365RC`.

*DFIR-O365RC cmdlets*

Note that whenever using PowerShell Core, the `-DeviceCode:$true` parameter
must be specified for all `DFIR-O365RC` cmdlets in order to authenticate to the
Azure AD tenant. The authentication should be done using a web browser at the
`https://microsoft.com/devicelogin` URL and the device code obtained passed
to the executed `DFIR-O365RC` cmdlet.

```bash
$EndDate = (Get-Date).ToUniversalTime()
$StartDate30 = $EndDate.adddays(-31)
$StartDate90 = $EndDate.adddays(-91)

# Get a subset of Office 365 Unified audit logs (selection of operations of judged of interest).
# Files produced:
# - Get-O365Light.log
# - O365_unified_audit_logs\YYYY-MM-DD\UnifiedAuditLog_<FQDN>_<YYYY-MM-DD>.json
Get-O365Light -StartDate $StartDate90 -Enddate $EndDate [-Operationsset "AllbutAzureAD"]

# Get all Office 365 Unified audit logs.
# As performance are poor, usage should be limited on a small time period or on small tenant.
$StartDateLimited = $EndDate.adddays(-<DAYS>)
Get-O365Full -StartDate [$StartDate90 | $StartDateLimited] -Enddate $EndDate

# Get Defender for Office 365 logs, from Office 365 Unified audit logs.
# Defender logs require an E5 license or a license plan with Microsoft Defender for Office 365 / cloud app security.
Get-DefenderforO365 -StartDate $StartDate90 -Enddate $EndDate

# Search for activity related to a particular user, IP address or freetext query in the Office 365 Unified audit logs.

# To retrieve the default time zone of a given user's mailbox the ExchangeOnlineManagement PowerShell module can be used (in order to correlate the Mailbox logs with UTC+0).
# Install-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-MailboxRegionalConfiguration -Identity <USER_ID>

# If a user is specified, Mailbox Audit Log will also be retrieved for the given user.
# User ids example: "user.name1@domain.com", "user.name2@domain.com"
Search-O365 -StartDate $StartDate90 -Enddate $EndDate -UserIds <USER_ID | USER_IDS_COMMA_LIST>
Search-O365 -StartDate $StartDate90 -Enddate $EndDate -IPAddresses <IP_ADDRESS | IP_ADDRESSES_COMMA_LIST>
Search-O365 -StartDate $StartDate90 -Enddate $EndDate -Freetext "<TEXT>"

# Get tenant general information, plus all Azure sign-ins and audit logs.
Get-AADLogs	-StartDate $StartDate30 -Enddate $EndDate

# Get Azure audit logs related to Azure applications and service principals only.
Get-AADApps	-StartDate $StartDate30 -Enddate $EndDate

# Get Azure audit logs related to Azure AD joined or registered devices only.
Get-AADDevices -StartDate $StartDate30 -Enddate $EndDate

# Get all Azure activity logs available for the tenant or for the specified tenant.
Get-AzRMActivityLogs -StartDate $StartDate90 -Enddate $EndDate [-SelectSubscription:$true]

# Get all Azure DevOps activity logs available for all the DevOps organization(s) the account executing the cmdlet has access to or for the given DevOps organization.
Get-AzDevOpsActivityLogs -StartDate $StartDate90 -Enddate $EndDate [-SelectOrg:$true]
```

###### [Azure AD & Azure] Log Analytics workspace or storage account with Diagnostic settings

Through the `Diagnostic settings`, Azure logs at tenant, subscription(s), or
resource(s) level can be either:

  - Exported to json formatted files in a `storage account blob`. Logs exported
    to a blob will be in `PT1H.json` files, and can be downloaded using the
    `Azure Storage Explorer` utility (among others).

  - Send to a `Log Analytics workspace` to be processed directly in the Cloud
    with `KQL` queries.

Once a `storage account` or `Log Analytics workspace` has been created, the
procedure to export logs from different sources is as follow:

  - `AzureAD` tenant logs (sign-ins and audit logs) - P1 / P2 license required:

    ```
    Azure Active Directory portal
       => Diagnostic settings (left menu)
          => Add diagnostic setting
             => Check "AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs", "ADFSSignInLogs", "RiskyUsers", "UserRiskEvents"
             => Archive to a storage account / Send to Log Analytics workspace
    ```

  - Subscription activity logs:

    ```
    Monitor portal
       => Activity log (left menu)
          => Export Activity logs (top menu)
             => Add diagnostic setting
                => Check all categories
                => Archive to a storage account / Send to Log Analytics workspace
    ```

  - Resources logs:

    ```
    The given resource portal
       => Diagnostic settings
          => Add diagnostic setting
             => Check all or the relevant categories
             => Archive to a storage account / Send to Log Analytics workspace
    ```

If exported to a `storage account blob`, logs will be available in the
following folders:
  - Azure AD audit logs: `insights-logs-auditlogs`

  - Azure AD sign-ins logs:
    - `insights-logs-signinlogs`
    - `insights-logs-noninteractiveusersigninlogs`
    - `insights-logs-managedidentitysigninlogs`
    - `insights-logs-serviceprincipalsigninlogs`

  - Subscription: `insights-activity-logs`

  - Resources:
    - Storage accounts: `insights-logs-storageread`
    - Key vaults: `insights-logs-auditevent`
    - NSG flows: `insights-logs-networksecuritygroupflowevent`
    - ...

### Office 365 logs analysis

###### Exchange Online Services workload

The following operations are notable for the `Exchange` workload:

| Source | Operation | Description | Default Scope | Default |
|--------|-----------|-------------|---------------|---------|
| Mailbox audit logging | `MailItemsAccessed` | Access to mails in the mailbox. | `Owner`, `Delegate`, `Admin` | Yes, for user with an `E5` license. |
| Mailbox audit logging | `FolderBind` | Access to a mailbox folder. <br><br> Only One audit record is generated for individual folder access within a 24-hour period. | `Delegate`, `Admin` | No |
| Mailbox audit logging | `MessageBind` | Access to a mailbox item. | `Admin` | No |
| Mailbox audit logging | `Create` | Creation of an item in Calendar, Contacts, Notes, or Tasks folder. Email creation is not audited. | `Owner`, `Delegate`, `Admin` | Yes, for `Delegate` and `Admin`. |
| Mailbox audit logging | `Send` | Sending of an email. | `Owner`, `Admin` | Yes, for user with an `E5` license. |
| Mailbox audit logging | `SendAs` | Sending of an email using the `SendAs` permission. | `Delegate`, `Admin` | Yes |
| Mailbox audit logging | `SendOnBehalf` | Sending of an email using the `SendOnBehalf` permission. | `Delegate`, `Admin` | Yes |
| | `Set-Mailbox` | Change to the mailbox parameters. Can notably be used to forward emails using the `ForwardingSmtpAddress` parameter. |
| | `New-InboxRule` | Creation of a new inbox rule in the mailbox. |
| | `Set-InboxRule` | Modification of an existing inbox rule in the mailbox. |
| Mailbox audit logging | `UpdateInboxRules` | Creation or modification of a mailbox inbox rules, typically with the `Outlook Desktop` client using the `Exchange Web Services (EWS)` API. | `Owner`, `Delegate`, `Admin` | Yes |
| | `New-TransportRule` <br> `Set-TransportRule` <br><br> With the `BlindCopyTo` parameter. | Creation of a Transport / Mail Flow rule to send a copy of the mail to the defined address. |
| | `Remove-InboxRule` | Removal of a mailbox inbox rule. |
| | `Disable-InboxRule` | Disabling of a mailbox inbox rule. |
| | `Add-MailboxPermission` | Update of the permissions associated to the mailbox, such as `FullAccess` or `ChangePermission` permissions (in the `AccessRights` field). |
| | `Add-RecipientPermission` | Adding of the `SendAs` permission to user(s) for the mailbox. |
| | `Set-OwaMailboxPolicy` | Update to the OWA mailbox policies. |
| Mailbox audit logging | `MoveToDeletedItems` | Deletion of a message (moved to the `Deleted Items` folder). | `Owner`, `Delegate`, `Admin` | Yes |
| Mailbox audit logging | `SoftDelete` | Soft deletion of a message (deletion from the `Deleted Items` folder, but potentially recoverable from the `Recoverable Items` folder). | `Owner`, `Delegate`, `Admin` | Yes |
| Mailbox audit logging | `HardDelete` | Permanent deletion of a message (message won't be placed in the `Deleted Items` folder or recoverable from the `Recoverable Items` folder). | `Owner`, `Delegate`, `Admin` | Yes |

The list of actions logged (depending on the logon type) and information on
whether the action is logged by default, can be found in the
[official Exchange documentation](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-mailboxes).

TODO: Sync vs Bind

###### Microsoft Flow / Power Automate workload

| Operation | Description |
|-----------|-------------|
| `CreateFlow` | Creation of a new flow. Flows can be used to forward emails, automatically copy or download files, etc. <br><br> Emails forwarded through `Microsoft Flow` can be identified in "Send" operation of the `UAL` logs' "Exchange" workload, as the user agent associated with the event will be "Microsoft Power Automate" (and the client IP will be an IP belonging to Microsoft). |

###### SharePoint workload

Anonymous links

###### Azure applications in AAD audit logs

Can be used to maintain persistence in M365 as applications can access
applications in the subscription with out MFA

###### Others

Consent grant allows applications to access resources in the tenant.
Permissions that can be granted: Application, Delegated, and Effective
permissions.

### Azure logs analysis

###### Activity log key fields

The key fields in the subscription / activity log schema are:

  - `identity.claims`: nested JSON with information about the identity that
    performed the action and its authentication method.

     - `identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`:
       the `UPN` of the identity that performed the action.

     - `identity.claims.groups`: the AzureAD groups of which the identity is a
       member.

    - `identity.claims.ipaddr`: the IP address the identity authenticated from.

  - `callerIpAddress`: the IP address the action was performed from.

  - `resourceId`: the unique resource identifier of the resource. The
    `resourceId` follows the format:
    `/SUBSCRIPTIONS/<SUBSCRIPTION_ID>/RESOURCEGROUPS/<RESOURCEGROUP_NAME>/PROVIDERS/<PROVIDER>/<RESOURCE_NAME>`.

    The provider can for example be `/MICROSOFT.COMPUTE/VIRTUALMACHINES` or
    `MICROSOFT.STORAGE/STORAGEACCOUNTS`.

  - `operationName`: the name of the operation.

    Examples:
      - `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`
      - `MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE`
      - `MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION`
      - `MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE`
      - `MICROSOFT.COMPUTE/DISKS/WRITE`
      - `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`
      - ...

  - `resultType` and `resultSignature` (more verbose): the result of the operation.

  - `correlationId`: an unique identifier that can be used to map the different
    events associated with a single operation.

--------------------------------------------------------------------------------

### References

https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-mailboxes?view=o365-worldwide

https://www.real-sec.com/2020/07/obscured-by-clouds-insights-into-office-365-attacks-and-how-mandiantmanaged-defense-investigates/

Thirumalai Natarajan & Anurag Khanna - Threat Hunting in M365 Environment - DFIR Summit 2022

https://redcanary.com/blog/email-forwarding-rules/
