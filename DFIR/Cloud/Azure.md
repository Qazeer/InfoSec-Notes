# DFIR - Cloud - Azure

### Azure logs overview

| Source | Description | History | Mechanism used |
|--------|-------------|---------|------------------|
| [`Office 365 Unified Audit Logs`](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance) | All Office 365 logs (including Azure AD logs with a more limited level of information). <br><br> Entries are stored in `UTC+0`. <br><br> There can be a delay of around 30min for logs to be available in UAL and up to 24 hours for AAD logs (and Power Automate, Power Apps, and Yammer logs). <br><br> As of October 2021, `Audit Logs` are by default turned on for newly created tenants. | 90 days (by default) <br><br> 1 year with a E5 license.	| `Exchange online PowerShell` |
| [`Mailbox Audit Log`](https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing) | Information about certain actions performed on mailboxes by mailbox owners, delegates, and admins. For instance, log entries can be generated upon mail data access, email deletion or sending, etc. <br><br> As of January 2019, `Mailbox Audit Logs` should be turned on by default for newly created tenants. <br><br> A predefined set of mailbox actions are audited by default for each logon type (`Admin`, `Delegate`, and `Owner`). The list of actions logged by default can be found in the [official Exchange documentation](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-mailboxes). Note that while mailbox auditing cannot be disabled for a specific mailbox if mailbox auditing is enabled tenant-wide, mailbox audit logging can still be bypassed by defined users. In such circumstances, mailbox `Owner` actions as well as `Delegate` (i.e on other users' mailboxes) and `Admin` actions performed by the bypassed users aren't logged. <br><br> Mailbox logon types: <br> - `Owner`: access by the mailbox owner. <br> - `Delegate`: access by another user being granted `SendAs`, `SendOnBehalf`, or `FullAccess` (access to everything but not the right to send mails) permission to the mailbox. <br> - `Admin`: mailbox is searched with a Microsoft eDiscovery tool or with the Microsoft Exchange Server MAPI Editor. <br><br> `MailItemsAccessed` mail access events will only be available with a `E5 license`. Unofficially, a single `E5 license` in the tenant is sufficient to generate the events for all users, even retroactively populating events for the retention period. | 90 days | `Exchange Online PowerShell` |
| [`Azure AD sign-ins logs`](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins) | Information about Azure AD sign-ins and resources usage. <br><br> Entries are stored in `UTC+0`. | 30 days | `MS Graph API` |
| [`Azure AD audit logs`](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs) | Information about changes applied to the Azure AD tenant, such as users or group management and updates. <br><br> Entries are stored in `UTC+0`. | 30 days | `MS Graph API` |
| [`Azure Activity logs`](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) | Information about activity in an Azure subscription, such as resource modification, virtual machine creation and start, etc. | 30 days | `Azure Monitor RESTAPI` |
| [`Azure DevOps Activity logs`](https://docs.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing) | Information about operations in the Azure DevOps organization(s), such as operations on resources, permissions changes, etc. | 90 days | `Azure DevOps services RESTAPI` |

Note that accessing Azure AD logs through the `MS Graph API` requires at least
**one user with an Azure `AD Premium P1` or `AD Premium P2` license**. These
license can be included in other license plans, such as
`Microsoft 365 E3 / E5 / F3`. The other to which is associated the license does
not matter.

### Minimal required privileges to access logs

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

### DFIR-O365RC collector

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

###### Manual installation

`DFIR-O365RC` depends on the [`MSAL.PS`](https://github.com/AzureAD/MSAL.PS)
and [`PoshRSJob`](https://github.com/proxb/PoshRSJob) modules, that must be
installed before usage.

```
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force

Install-Module -Name MSAL.PS -RequiredVersion '4.21.0.1'
Install-Module -Name PoshRSJob -RequiredVersion '1.7.4.4'
```

On PowerShell Core, the installation of the `WSMan` client may also be
required:

```
Install-Module PSWSMan
Install-WSMan
```

The `DFIR-O365RC` directory of the `DFIR-O365RC` project can then be placed in
in one of the system modules path (retrievable using `$env:PSModulePath`) and
imported with `Import-Module DFIR-O365RC`.

###### DFIR-O365RC cmdlets

Note that whenever using PowerShell Core, the `-DeviceCode:$true` parameter
must be specified for all `DFIR-O365RC` cmdlets in order to authenticate to the
Azure AD tenant. The authentication should be done using a web browser at the
`https://microsoft.com/devicelogin` URL and the device code obtained passed
to the executed `DFIR-O365RC` cmdlet.

```
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

### TTPs analysis

###### Exchange Online Services workload

The following operations are notable for the `Exchange` workload:

| Operation | Description | Default Scope | Default |
|-----------|-------------|---------------|---------|
| `MailItemsAccessed` | Access to mails in the mailbox. | `Owner`, `Delegate`, `Admin` | Yes with `E5` license |
| `FolderBind` | Access to a mailbox folder. <br><br> Only One audit record is generated for individual folder access within a 24-hour period. | `Delegate`, `Admin` | No |
| `Send` | Sending of an email. | `Owner`, `Admin` | Yes with `E5` license |
| `SendAs` | Sending of an email using the `SendAs` permission. | `Delegate`, `Admin` | Yes |
| `SendOnBehalf` | Sending of an email using the `SendOnBehalf` permission. | `Delegate`, `Admin` | Yes |
| `Set-Mailbox` | Change to the mailbox parameters. Can notably be used to forward emails using the `ForwardingSmtpAddress` parameter. |
| `New-InboxRule` | Creation of a new inbox rule in the mailbox. |
| `Set-InboxRule` | Modification of an existing inbox rule in the mailbox. |
| `UpdateInboxRules` | Creation or modification of a mailbox inbox rules, typically with the `Outlook Desktop` client using the `Exchange Web Services (EWS)` API. | `Owner`, `Delegate`, `Admin` | Yes |
| `New-TransportRule` <br> `Set-TransportRule` <br><br> With the `BlindCopyTo` parameter. | Creation of a Transport / Mail Flow rule to send a copy of the mail to the defined address. |
| `Remove-InboxRule` | Removal of a mailbox inbox rule. |
| `Disable-InboxRule` | Disabling of a mailbox inbox rule. |
| `Add-MailboxPermission` | Update of the permissions associated to the mailbox, such as `FullAccess` or `ChangePermission` permissions (in the `AccessRights` field). |
| `Add-RecipientPermission` | Adding of the `SendAs` permission to user(s) for the mailbox. |
| `Set-OwaMailboxPolicy` | Update to the OWA mailbox policies. |
| `MoveToDeletedItems` | Deletion of a message (moved to the `Deleted Items` folder. |
| `SoftDelete` | Permanent deletion of a message (or deletion from the `Deleted Items` folder). | `Owner`, `Delegate`, `Admin` | Yes |

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
Permissions that can be granted: Application, Delegated, and Effective permissions.

### References

https://www.real-sec.com/2020/07/obscured-by-clouds-insights-into-office-365-attacks-and-how-mandiantmanaged-defense-investigates/

Thirumalai Natarajan & Anurag Khanna - Threat Hunting in M365 Environment - DFIR Summit 2022

https://redcanary.com/blog/email-forwarding-rules/
