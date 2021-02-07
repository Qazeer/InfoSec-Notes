# DFIR - Active Directory persistence

### Active Directory replication metadata

###### Overview

The Active Directory replication metadata hold information about change made
on an Active Directory object. Every object within Active Directory stores
replication metadata, in their `msDS-ReplAttributeMetaData` and
`msDS-ReplValueMetaData` attributes.  

The replication metadata is used by the Domain Controllers to replicate
modifications and, as so, only attributes that are replicated will be logged in
the replication metadata. As stated in the Microsoft documentation: "every
attribute in [the Active Directory] `Schema` has a flag called
`FLAG_ATTR_NOT_REPLICATED`. If this flag value is `True (1)`, that attribute is
not included in AD Replication. If the attribute value is `False (0)`, then
that attribute is replicated". Upon creation of an object, all replicated
attributes that are automatically populated will be logged in the replication
metadata.

The `msDS-ReplAttributeMetaData` attribute stores replication metadata for
regular replicated attributes, while the `msDS-ReplValueMetaData` attribute
stores replication metadata for `linked attributes`.

The replication metadata is stored in the `msDS-ReplAttributeMetaData`
attribute as a XML with the following notable fields:
  - `pszAttributeName`: the name of the attribute replicated.
  - `dwVersion`: a replication counter, incremented upon each modification of
    the associated attribute.
  - `ftimeLastOriginatingChange`: last change timestamp.
  - `pszLastOriginatingDsaDN`: Domain Controller from which originated the last
    change. More precisely, the distinguished name of the `NTDS Settings`
    (type `Domain Controller Settings`) of the Domain Controller.
  - `uuidLastOriginatingDsaInvocationID`: `invocationId` of the Domain
    Controller (stored in the Domain Controller 's `NTDS Settings`).

As stated, the `msDS-ReplValueMetaData` attribute hold replication metadata for
the `linked attributes`, which were introduced in Windows Server 2003
functional level to reduce replication data. `Linked attributes` are pairs of
two attributes, with the values of one attribute, denominated the `back link`,
being based on the values set on the other attribute, denominated the `forward
link`. Only the `forward link` attributes are replicated, which allow to reduce
replication metadata.

For instance, the groups's `member` attribute is the forward link for the
user and computer accounts' `memberOf` attribute. The `member` attribute of
group objects holds, in addition to the fields introduced above, information on
when the principal was added (`ftimeCreated` field) or deleted (`ftimeDeleted`
field) from the group.

###### Replication metadata enumeration and timelining

The attributes that are / are not replicated can be listed using the following
PowerShell queries (that make use of the `Remote Server Administration Tools
(RSAT)`'s PowerShell `ActiveDirectory` module):

```
# DOMAIN_ROOT = "DC=LAB,DC=AD" for example

# Lists the attributes which are replicated.
Get-ADObject -SearchBase 'CN=schema,CN=configuration,<DOMAIN_ROOT>' -LDAPFilter '(&(objectClass=attributeSchema)(!systemFlags:1.2.840.113556.1.4.803:=1))' | Select-Object -Expand name

# Lists the attributes which are NOT replicated.
Get-ADObject -SearchBase 'CN=schema,CN=configuration,<DOMAIN_ROOT>' -LDAPFilter '(&(objectClass=attributeSchema)(systemFlags:1.2.840.113556.1.4.803:=1))' | Select-Object -Expand name
```

The `repadmin` utility and the `Get-ADReplicationAttributeMetadata` PowerShell
cmdlet (introduced in `Windows Server 2012`) can be used to enumerate the
replication metadata of a specified object:

```
repadmin /showobjmeta /Linked <. | DC_HOSTNAME> "<DISTINGUISHED_NAME>"

Get-ADReplicationAttributeMetadata -Server <DC> -IncludeDeletedObjects –ShowAllLinkedValues "<DISTINGUISHED_NAME>"
```

The [ADTimeline](https://github.com/ANSSI-FR/ADTimeline) PowerShell script can
be used to automate the enumeration of the replication metadata and
consolidates the modifications in a timeline. Only the objects "considered of
interest" are listed (more details on the project GitHub repository).

In order to access the objects in the tombstone, the account used to execute
the script must be able to read the object placed  the `Deleted Objects
Container`. It is thus advised to execute the script with `Domain Admins`
privileges. Otherwise, only the replication metadata of existing objects will
be enumerated.

```
.\AD-timeline.ps1 -Server <GLOBAL_CATALOG_FQDN>

# Offline mode, with the NTDS database being mounted using dsamain (requires ADLDS and RSAT to be installed)

dsamain.exe -dbpath <NTDS_DIT_PATH> -ldapport 3266 -allownonadminaccess
.\AD-timeline.ps1 -server "127.0.0.1:3266"
```

###### Replication metadata of interest

The following replicated attribute (in a default configuration) could be of
interest for digital forensics and incident response purposes.

| Attribute | Object(s) | Description |
|-----------|-----------|-------------|
| `adminCount` | User accounts or groups. | If `adminCount` equal `1`, successful elevation of privileges, that is adding of the object in a group protected by the `AdminSDHolder` mechanism. <br><br> If `adminCount` is set to `0`, potential manual concealing of previously obtained privileges, after removal of the object from a privileged group protected by the `AdminSDHolder` mechanism. |
| `lastLogonTimestamp` | Security principals. | Refer to `lastLogon v. lastLogonTimestamp` below for more information. |
| `member` | Groups. | Information on when a given principal was added or removed from the group. <br><br> While the list of present principals is exhaustive, the replication metadata of removed principal will only persist for the `tombstone lifetime` of the Active Directory domain. |
| `msDS-AllowedToDelegateTo` <br><br> `msDS-AllowedToActOnBehalfOfOtherIdentity` | User or computer accounts. | Setting or modification of Kerberos `constrained delegation` or `resource-based constrained delegation (RBCD)`. |
| `nTSecurityDescriptor` | Any securable objects: <br> user or computer accounts, groups, `Organizational Unit (OU)`, `AdminSDHolder` container, etc. | Modification of the security descriptor of a securable object, linked to a potential change of ownership or `DACL` modification. |
| `primaryGroupID` | User or computer accounts. | Modification of an account `primaryGroupID` attribute, potentially linked to persistence purposes. |
| `scriptPath` | User accounts. | Modification of an user's logon script. |
| `servicePrincipalName` | User or computer accounts. | Setting or modification of an user or computer account's `Service Principal Name (SPN)`. |
| `sIDHistory` | Security principals. | Setting or modification of a security principal `SID History`, potentially for persistence or trusts hopping purposes. |
| `userPrincipalName` | User or computer accounts. | Setting or modification of an user or computer account's `userPrincipalName`, potentially related to certificate-authentication attacks.  |
| ... | ... | ... |

###### lastLogon v. lastLogonTimestamp

Every account in Active Directory, be it an user or computer account, has both
a `lastLogon` and a `lastLogonTimestamp` attributes.

The `lastLogon` attribute of an account is immediately updated upon a
successful authentication of the account. The `lastLogon` attribute is however
(by default) not replicated, and is thus only updated on the Domain Controller
that provided the authentication.

On the other hand, the `lastLogonTimestamp` attribute of an account is
replicated by default but will only be updated if the difference between the
previous value and new value is greater than the default naming context's
`ms-DS-Logon-Time-Sync-Interval` attribute. By default the value for this
attribute is not set, and takes default to 14 days.

Knowing precisely when the account last connected thus requires to enumerate
the account's `lastLogon` attribute on all the Domain Controllers of the
forest.

###### Convert timestamps to human readable format

Both the `lastLogon` and a `lastLogonTimestamp` attributes are stored as `UNIX
time`: 32-bit value containing the number of seconds elapsed since 1/1/1970.
Both attributes store time values in `Greenwich Mean Time (GMT)`.

The following one-liners can be used to convert an `UNIX time` to an human
readable format:

```
# Display both the time in GMT and in the local time zone of the system.
w32tm.exe /ntte <UNIX_TIMESTAMP>


```

### Active Directory events logs

TODO

The following events could be indicator of persistence on the system:

| Hive     | Event ID | Description |
|----------|----------|-------------|
| Security | 4720 | `A user account was created`. Logged both for local SAM accounts and domain accounts and includes the creator SID, domain, username and `Logon ID`. |
| Security | 4722 | `A user account enabled`, logged both for local SAM accounts and domain accounts and is always logged after a Security event `4720 - user account creation`. |
| Security | 4723 | `An attempt was made to change an account's password`. Logged both for local SAM accounts and domain accounts when an user attempts to change his/her own password. This event is logged only if the user entered his/her correct password and reported as a failure if his/her new password fails to meet the password policy. Includes the SID, domain, username and `Logon ID` of the user that performed the password change. |
| Security | 4724 | `An attempt was made to reset an accounts password`. Logged both for local SAM accounts and domain accounts when an user attempts to change another user password. This event is logged only if the user correct password is specified, the user attempting the password reset as the necessary permissions to do so, and reported as a failure if his/her new password fails to meet the password policy. Includes the SID, domain, username and `Logon ID` of the user that performed the password change. |
| Security | 4670 | `Permissions on an object were changed`. This event generates when the permissions for an object are changed
| Security | 4738 | `A user account was changed`. Logged both for local SAM accounts and domain accounts when an user object attributes are modified. The old and new value for the updated attribute is logged. If all attributes are marked as "-", an update on a attribute that is not listed in the event log or a modification on the user DACL object has occurred. The `AD - Exploiting DACL` note can be consulted for more information on exploitable DACL on user principal object.<br/> In addition to a potential modification on the user object DACL, this event can be used to detect the following persistence means:<br/>  - addition of SID in the `SID History` of an user<br/>  - disabling of Kerberos `Require Preauth` to make the account vulnerable to `ASREPRoast`.<br/>  |
| Security | 4732 | `A member was added to a security-enabled local group`. Logged on domain controllers for Active Directory domain local groups and member computer for local SAM groups. |
| System   | 7030 | `Basic Service Operations`. Occurs when a service is configured as an interactive, which is not supported since Windows Vista and Windows Server 2008 (du to security risks posed by interactive services). |
| System   | 7045,4697 | `A service was installed in the system`. |
| System   | 7035, 7036 | `The <SERVICE_NAME> service was successfully sent a <start/stop> control.` and `The <SERVICE_NAME> service entered the <running/stopped> state.` A run / stop signal is sent then the service is effectively started / stopped. |
| Security | 4697 | `A service was installed in the system` from Windows Server 2016 and Windows 10 |
| System   | 7040 | Service start type was changed |  
| System   | 1056 | DHCP server oddities |
| Security | 4688 | `A new process has been created`. Occurs when a process is created and include information about the process: creator subject (SID, account domain and name as well as the Logon ID), creator PID, token elevation type. etc. If enabled, the "process command line" field include the command line of the process. |


TODO 4670 and 4662 and 4728 and 4732 and 4756

Windows Security Log Event ID 4657: A registry value was modified
this event will only be logged if the key's audit policy is enabled for Set Value permission for the appropriate user or a group in the user is a member.
