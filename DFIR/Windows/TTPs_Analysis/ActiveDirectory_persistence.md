# DFIR - Active Directory persistence

### Active Directory persistence detection through events logs

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
