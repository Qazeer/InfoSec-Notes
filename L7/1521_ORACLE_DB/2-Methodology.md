# Oracle Database - Methodology

### Overview

Oracle Database (commonly referred to as Oracle RDBMS or simply as Oracle) is a
multi-model database management system produced and marketed by Oracle
Corporation.

The latest release version is Oracle Database 18c (February 2018), but many
10g and 11g are still in use.

###### SID vs Service Name

To connect to an Oracle database a SID or a Service Name is required.
The SID is an unique name of the instance (eg the oracle process running on the
server), while the Service Name is an alias to one or multiples instances.  

The main purpose of this system is to manage an unique Service Name for
multiples instances in a cluster of servers. Multiple services names can also be
specified for a same SID in order to distinguish among different uses of the
same database.

###### Oracle client installation

1. Download the last version of the Oracle Instant Client from the official
  Oracle website. As of December 2018, the last version is 18.3.0.0.0 and is
  backwards compatible with Oracle Database 11.2 or later.

  The following packages are required for some of the techniques and tools
  presented in the present note:

    - instantclient-basic-linux.\*.zip
    - instantclient-sqlplus-linux.\*.zip
    - instantclient-sdk-linux.\*.zip

2. Unzip the packages into a single directory such as /opt/oracle

  ```
  cd /opt && mkdir oracle
  unzip instantclient-*
  ```

3. Prior to version 18.3, create the appropriate links for the version of
   Instant Client. For example:

   ```
   cd /opt/oracle/instantclient_12_2
   ln -s libclntsh.so.12.1 libclntsh.so
   ln -s libocci.so.12.1 libocci.so
   ```

4. Install the libaio package. This is called libaio1 on some Linux
   distributions.

   ```
   # Kali Linux
   apt-get install libaio1
   ```

5. Configure the needed environment variables by adding the following definition
   to the appropriate configuration file (~/.bashrc, ~/.zshrc, etc.):

  ```
  export PATH=$PATH:/opt/oracle/instantclient_18_3
  export SQLPATH=/opt/oracle/instantclient_18_3
  export TNS_ADMIN=/opt/oracle/instantclient_18_3
  export LD_LIBRARY_PATH=/opt/oracle/instantclient_18_3
  export ORACLE_HOME=/opt/oracle/instantclient_18_3
  ```


### Network scan

Nmap can be used to scan the network for exposed Oracle databases.
Note that while the default port for an Oracle database instance is 1521, it is
common to find multiples instances on a server, running on various ports.

```
nmap -v -p 1521 -oA nmap_oracle_db <RANGE | CIDR>
```

### TNS listener version

Nmap and the Metasploit module *auxiliary/scanner/oracle/tnslsnr_version* can
be used to retrieve the version of the TNS listener in use:

```
nmap -v -p 1521 -A <HOST | IP>
msf> use auxiliary/scanner/oracle/tnslsnr_version
```

### SID and Service Name retrieval

The SID or Service Name of the database must be specified when trying to
authenticate to an Oracle database.

On some older version of TNS listeners, SID and Service Name can be directly
enumerated. Some third parties components may also be used to enumerate
SID and Service Name. A vulnerable web application or an access to the file
system may be leveraged to retrieve database SID or Service Name.

If none of the techniques described above apply, the TNS listener SID must be
brute forced.  

The Oscanner tool can be used on Linux to conduct basic SID enumeration as well
as default / common credentials brute forcing on retrieved SID:

```
oscanner -s <HOST | IP> -P <PORT>
```

More exhaustive SID retrieval techniques and tools:

| Component | Tool(s) | Description |
|-----------|---------|-------------|
| TNS < Oracle 9.2.0.8 | `auxiliary/scanner/oracle/sid_enum` | Direct query to the unprotected listener to enumerate SID. |
| Oracle Enterprise Manager Control <br/> *Default port 1158* | `http://<HOST>:1158/em/console` | Access to the /em/console page of the manager may contain a login form with the database Service Name value. |
| Oracle XML DB (XDB) <br/> *Default port 8080* | `auxiliary/scanner/oracle/xdb_sid` | If an Oracle XML DB (XDB) service is exposed on the server and credentials could be obtained (default are scott:tiger before Oracle 12.1.0.2), make authenticated request to retrieve the SID from the Oracle XML DB httpd server. |
| Oracle Application Server <br/> *Default port 5560* | `http://<HOST>:5560/servlets/Spy` <br/> `auxiliary/scanner/oracle/spy_sid` | The default servlet Spy may reveal a Service Name value. |
| * | `auxiliary/scanner/oracle/sid_brute` <br/> `python patator.py oracle_login host=<HOST> sid=FILE0 0=<WORDLIST_SID> -x ignore:code=ORA-12505` <br/> `python patator.py oracle_login host=<HOST> service_name=FILE0 0=<WORDLIST_SERVICE_NAMES> -x ignore:code=ORA-12514` <br/> `hydra -L <WORDLIST_SID> -s <PORT> <HOST> oracle-sid` | SID bruteforce if others methods are not available. Metasploit include a list of default / common SID. The hostname of the server, and variations of the hostname, should be tried as well. |
| SAP environment | `http://<HOST>:8000/sap/bc/gui/sap/its/webgui` <br/> `http://<HOST>:8000/sap/bc/gui/sap/its/DONOT_EXIST404` <br/> `rfcping ashost=<HOST> sysnr=00` <br/> Limited SID brute forcing | Multiple ways exist to enumerate an Oracle Database SID or Service Name integrated to a SAP environment. The SAP Web Application Server or the SAP RFC endpoint may leak SID or Service Name. Moreover, as Oracle SID integrated in a SAP environment are limited to Latin symbols and must be 3 or less symbols in length, a limited brute force can be conducted. |
| Vulnerable Web application | Web stack trace error messages | SQL error messages from invalid queries using the Web application may leak the database SID or Service Name. |
| File system access  | Web application LFI or directory listing <br/> FTP or SMB access <br/> ... | An access to the file system may be leveraged to retrive the Oracle service configuration file *tnsnames.ora* stored in the *$ORACLE-home/NETWORK/admin* folder. |

### Authentication brute force

The Oscanner tool can be used to conduct a default / common credentials brute
force:

```
oscanner -s <HOST | IP> -P <PORT>
```

The *oracle_login_password.txt* from the fuzzdb project is a combo file of
default / common usernames and passwords.  

The patator tool can be used to brute force credentials on the service:

```
# Using oracle_login_password combo file
patator.py oracle_login host=<HOST | IP> (sid=<SID> | service_name=<SERVICE_NAME>) user=COMBO00 password=COMBO01 0=oracle_login_password.txt -x ignore:code=ORA-01017

# Using two different wordlists
patator.py oracle_login host=<HOST | IP> (sid=<SID> | service_name=<SERVICE_NAME>) user=FILE0 password=FILE1 0=<WORDLIST_USERS> 1=<WORDLIST_PASSWORDS> -x ignore:code=ORA-01017
```

Error messages may be returned if the credentials tested are valid:

```
connection to sys should be as sysdba or sysope
Connections to this server version are no longer supported
```

### Database privilege escalation

Multiples Metasploit modules can be used to exploit Oracle vulnerabilities to
elevate privileges from a low privileged user to SYSDBA on outdated Oracle
Database Server.

```
# Oracle Database Server 10.1.0.5, 10.2.0.4, 11.1.0.7, and 11.2.0.1
msf> use auxiliary/sqli/oracle/dbms_cdc_publish3

# Up to Oracle Database Server 10.1.0.5.0
msf> use auxiliary/sqli/oracle/lt_findricset_cursor

# Older Oracle Database Server versions
msf> use auxiliary/sqli/oracle/*
```

### Query the database

The XXX CLI tool can be used to make queries to the database:

```
XXX
```

The **DBeaver** GUI tool can be used to simply access the database content without
knowing the proper MSSQL syntax.

### OS access and commands execution

```
msf> use auxiliary/sqli/oracle/jvm_os_code_11g
msf> use auxiliary/sqli/oracle/jvm_os_code_10g
