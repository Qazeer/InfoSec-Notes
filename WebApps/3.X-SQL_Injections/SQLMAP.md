# WebApps - SQL injection - SQLMAP

### Overview

`sqlmap` is an open source penetration testing tool that automates the process
of detecting and exploiting SQL injection flaws and taking over of database
servers.

It provides an efficient detection injection as well many features ranging from
fetching data from the database to accessing the underlying file system and
executing commands on the operating system.

`sqlmap` currently supports the following database management systems:
  - MySQL
  - Oracle
  - PostgreSQL
  - Microsoft SQL Server
  - Microsoft Access
  - IBM DB2
  - SQLite
  - Firebird
  - Sybase
  - SAP MaxDB
  - HSQLDB
  - Informix

For a more, and very, detailed usage guide of `sqlmap`, refer to the official
documentation: `https://github.com/sqlmapproject/sqlmap/wiki/Usage`.

### General options

###### Target specification

`sqlmap` offers multiples ways to specify one or multiples targets:
  - using an URL with the `-u <URL>` option ;
  - from an HTTP request file using the `-r <REQUEST_FILE>` option, which can
  be helpful for authenticated requests using multiples session cookies ;
  - using a direct connection string to the database with the
  `-d <CONNECTION_STRING>` option, which can be helpful to make use of `sqlmap`
  file system, command injections and passwords retriving queries ;
  - from a `Burp` or `WebScarab` proxy log file using the `-l <LOG_FILE>`
  option, which can be used to conduct an automated testing on all requests made
  after spidering and mapping the targeted web application.

One or multiples injection points can be specified in the URL or request file
by appending an `*` (*asterix*) to a parameter value. The `*` should not replace
the parameter value, as a valid value helps `sqlmap` in detecting the injection
technique to use.

###### Techniques

Option: `--technique=<TECH>`.

`sqlmap` supports the following techniques:
  - `B`: Boolean-based blind
  - `E`: Error-based
  - `U`: Union query-based
  - `S`: Stacked queries
  - `T`: Time-based blind
  - `Q`: Inline queries

By default `sqlmap` tests for all types/techniques it supports, i.e: `BEUSTQ`.
To specify one or more techniques, the `--technique` option can be used:

```
--technique=<B | E | U | S | T | Q | BE | ...>
```

###### Level and risk

Option: `--level=<1 - 5>`.

The `level` defines the depth of tests to perform, ranging from `level=1`, very
limited number of requests performed, to `level=5`, corresponding to a much
larger number of payloads and boundaries tested. The level also influence the
injections points tested:
  - `GET` and `POST` parameters are always tested ;
  - HTTP Cookie header values are tested from `level=2` ;
  - HTTP `User-Agent` / `Referer` headers' value is tested from `level=3`.

The default value is `level=1`. It is recommended to start with a `level=1`
test, to quickly iterate over all injection techniques and then conduct a
`level=5` testing if no injections were yet detected.

Option: `--risk=<1 - 3>`.

The `risk` defines the presumed risk of the payloads to use, ranging from
`risk=1`, innocuous for the majority of SQL injection points, to `risk=3`,
adding `OR`-based SQL injection tests which could lead to update of entries of
the database if the SQL injection is in an `UPDATE` or `DELETE` statement.  

The `risk=3` option should not be used against production databases, especially
if the injected query is presumed to modify the data of the database.

###### Tamper injection data

Option: `--tamper="<TAMPER_SCRIPTS>"`.

Note that `sqlmap` integrates an IPS / WAF detection mechanism, which can be
launched using the `--identify-waf` switch option.

`sqlmap` provides a way to tamper the payloads to bypass input validation
mechanism such as an IPS appliance or a web application firewall (WAF). The
option takes as parameter a comma-separated list of tamper scripts to use, for
example `--tamper=between,charencode,charunicodeencode`.

On a Linux default installation, the tamper scripts packaged with
`sqlmap` can be found in `/usr/share/sqlmap/tamper/`.

To start `sqlmap` with all the packaged tamper scripts, the following commands
can be used:

```
# General tampering
tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes

# MSSQL
tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes

# MySQL
tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest
```

###### Estimated time of arrival (ETA)

Switch: `--eta`.

`sqlmap` provides an option to calculate and show in real time the estimated
time of arrival to retrieve each query output.

### Databases dumping

Once identified, the DBMS can be specified with the `--dbms=<DBMS>` option.

###### Users, passwords and privileges

`sqlmap` includes queries to retrieve users, users' password and users'
privileges from known DBMS databases and tables:

| Option | Description |
|--------|-------------|
| `--current-user` | Retrieve DBMS current user |
| `--current-db` | Retrieve DBMS current database |
| `--hostname` | Retrieve DBMS server hostname |
| `--is-dba` | Detect if the DBMS current user is DBA |
| `--users` | Enumerate DBMS users |
| `--passwords` | Enumerate DBMS users password hashes |
| `--privileges` | Enumerate DBMS users privileges |
| `--roles` | Enumerate DBMS users roles |

###### Databases, tables, columns and data

The following options can be used to dump one or multiples databases content:

| Option | Description |
|--------|-------------|
| `--dbs` | Enumerate DBMS databases |
| `--tables` | Enumerate DBMS database tables |
| `--columns` | Enumerate DBMS database table columns |
| `--schema` | Enumerate DBMS schema |
| `--count` | Retrieve number of entries for table(s) |
| `--dump` | Dump DBMS database table entries |
| `--dump-all` | Dump all DBMS databases tables entries |
| `-D <DB>` | DBMS database to enumerate |
| `-T <TBL>` | DBMS database table(s) to enumerate |
| `-C <COL>` | DBMS database table column(s) to enumerate |
| `-X <EXCLUDE>` | DBMS database identifier(s) to not enumerate |
| `--exclude-sysdbs` | Exclude DBMS system databases when enumerating tables (master, msdb, model, etc.) |
| `--where=<DUMP_WHERE>` | Use WHERE condition while table dumping |
| `--start=<LIMIT_START>` | First dump table entry to retrieve |
| `--stop=<LIMIT_STOP>` | Last dump table entry to retrieve |

For intance, the following `sqlmap` commands can be used to enumerate the
databases content and retrive data:

```
# Retrieve all tables in all databases, excluding the DBMS system databases
sqlmap --eta --tables --exclude-sysdbs [...]

# Retrieve the Nth first rows of each tables in the DB database
sqlmap --eta --dump -D <DB> --stop=<LIMIT_STOP> [...]

# Retrieve everything except for the DBMS system databases content
sqlmap --eta --dump-all --exclude-sysdbs [...]
```

###### Search keyword(s) in databases, tables or columns names

Switch and options: `--search <[ -D <DB_NAME> | -T <TABLE_NAME> | -C <COLUMN_NAME> ]>`.

This functionaly can be used to identify tables or columns containing sensible
information such as application level usernames or passwords.

The `--search` switch option needs to be used in conjunction with one of the
following support options:
  - `-C` following a list of comma-separated column names to look for across
  the whole database management system.
  - `-T` following a list of comma-separated table names to look for across the
  whole database management system.
  - `-D` following a list of comma-separated database names to look for across
  the database management system

For example:

```
# Search in the database DB for columns containing the password keyword  
sqlmap --search -D <DB> -C "password" [...]
do you want sqlmap to consider provided column(s):
[1] as LIKE column names (default)
[2] as exact column names
1
```

###### Direct SQL query

Option: `--sql-query <QUERY>`

Switch: `--sql-shell`
`sqlmap` also provides an option to directly run arbitrary SQL query,
automatically dissecting the provided statement, determining which technique is
appropriate to use to inject it and how to pack the SQL payload accordingly.

In case of a non `SELECT` statement, `sqlmap` will execute the query through
the stacked query SQL injection technique `S` if stacked queries are supported
through the injection point.

The `--sql-query` option can be used to run the specified SQL statement while
the `--sql-shell` switch option will start an interactive SQL console connected
to the database management system.

### OS access

###### File system access

If the DBMS is either `MySQL`, `PostgreSQL` or `Microsoft SQL Server`, an SQL
injection can be leveraged to retrieve or upload files from / on the underlying
file system. The DBMS user session used to make the SQL queries needs to have
the sufficient privileges needed to use the DBMS specific functionalities.

| Option | Description |
|--------|-------------|
| `--file-read=<REMOTE_FILE_PATH>` | Read a file from the back-end DBMS file system |
| `--file-write=<LOCAL_FILE_PATH>` | Write a local file on the back-end DBMS file system |
| `--file-dest=<REMOTE_FILE_PATH>` | Back-end DBMS absolute filepath to write to |

The `--file-write` and `--file-dest` options must be used simultaneously to
specify the local file to upload and its destination path on the target system.

Note that, if the account responsible of the DBMS service has sufficient
privileges on the file system, an SQL injection could be used to upload a
webshell in an accessible website folder to achieve remote commands execution.
The website foder can either be guessed through a brute force attack or leaked
by verbose error messages on the web application.    

###### Commands execution

Option and switch: `--os-cmd <COMMAND>` and `--os-shell`.

An SQL injection can be leveraged to remotely execute commands on the
underlying operating system, given:
  - the DBMS is either `MySQL`, `PostgreSQL` or `Microsoft SQL Server` ;
  - the current DBMS user session has sufficient privileges to use the DBMS
  specific functionalities.

On MySQL and PostgreSQL, sqlmap uploads a shared library containing two
user-defined functions, `sys_exec()` and `sys_eval()`, then it creates these
two functions on the database and calls one of them to execute the specified
command, depending on user's choice to display the standard output or not.
On Microsoft SQL Server, sqlmap abuses the `xp_cmdshell` stored procedure: if
it is disabled (by default on Microsoft SQL Server >= 2005), sqlmap re-enables
it if possible; if it does not exist, sqlmap creates it from scratch.

The `--os-cmd` option can be used to run the specified command while the
`--os-shell` switch option will start an interactive command prompt.

###### Windows registry access

Switches: `--reg-read`, `--reg-add` and `--reg-del`.  
Auxiliary options: `--reg-key`, `--reg-value`, `--reg-data` and `--reg-type`.

An SQL injection can be leveraged to access Windows registries if the following
conditions are met:
  - the DBMS is either `MySQL`, `PostgreSQL` or `Microsoft SQL Server` ;
  - stacked queries are supported through the injection point ;
  - the current DBMS user session has sufficient privileges to use the DBMS
  specific functionalities ;
  - the Windows, local or domain, account responsible of the DBMS service has
  sufficient privileges to access the specified registries.  

| Option | Description |
|--------|-------------|
| `--reg-key` | Windows registry key path |
| `--reg-value` | Value item name inside provided key |
| `--reg-data` | Item value data |
| `--reg-type` | Type of the item value data |
