# Internal pentesting - Methodology

### Overview

Internal pentesting simulates an insider attack starting from a point within
the internal network.

The present note does not address Active Directory pentesting. While part of
the methodology detailed in this note can be applied for an Active Directory
security audit, specific tools and techniques make the overall approach
completely different.

After enumerating accessible hosts and their exposed services, the first step
in an internal penetration test is to look for the path of least resistance,
aka the low hanging fruits that can easily be detected and exploited (unpatched
systems, default or guessable passwords, etc.).

The following methodology makes use of several automated tools and is thus not
directly implacable to the OSCP exam.  

###### Notable tools used in this methodology

| Name | Description | Link |
|------|-------------|------|
| `Aquatone` | Tool to validates and screenshot websites written in `Go`. | https://github.com/michenriksen/aquatone |
| `ffuf` | Web fuzzer written in `Go` that can be used for directory bruteforcing. | https://github.com/ffuf/ffuf |
| `Interlace` | Python utility to use single threaded command line applications in parallel and with `CIDR` support. | https://github.com/codingo/Interlace |
| `masscan` | Fast asynchronous and stateless network port scanner written in `C`. | https://github.com/robertdavidgraham/masscan |
| `metasploit` | Offensive framework notably used for vulnerability detection and exploitation. | https://github.com/rapid7/metasploit-framework |
| `Nessus` | Proprietary automated vulnerabilities scanner. | https://www.tenable.com/products/nessus |
| `nmap` | Network ports and services scanner. | https://nmap.org/download.html |
| `nmap-parse-output` | Bash script to parse and extract information from `nmap` output. | https://github.com/ernw/nmap-parse-output |
| `NmaptoCSV` | Python script to convert `nmap` output to CSV. | https://github.com/maaaaz/nmaptocsv |
| `patator` | Python login brute-forcer ang fuzzer. | https://github.com/lanjelot/patator |
| `Remote Server Administration Tools (RSAT)` PowerShell `ActiveDirectory` module | PowerShell cmdlets to extract AD information if an account is provided. | https://www.microsoft.com/en-us/download/details.aspx?id=45520 |
| `RustScan` | Fast network port scanner written in `Rust`. | https://github.com/RustScan/RustScan |
| `SecLists` | Collection of multiple types of lists (directory wordlists, usernames and passwords wordlists, etc.). | https://github.com/danielmiessler/SecLists |
| `Sn1per Community Edition` | Opensource automated vulnerabilities scanner. | https://github.com/1N3/Sn1per |
| `sshUsernameEnumExploit.py` | Python script to enumerate local users through `OpenSSH` services vulnerable to the `CVE-2018-15473` vulnerability. | https://github.com/Rhynorater/CVE-2018-15473-Exploit |
| `testssl` <br><br> `sslscan2` | Tools to enumerate the supported ciphers and presence of cryptographic flaws of `SSL` / `TLS` services. | https://github.com/drwetter/testssl.sh <br><br> https://github.com/rbsec/sslscan |
| `WhatWeb` | Tool to identify technological components, including content management systems, of  web applications. | https://github.com/urbanadventurer/WhatWeb |

### 0. Hosts enumeration through Active Directory

###### AD enrolled systems enumeration

If an AD account is provided for the internal penetration test, AD queries
can be used to quickly enumerate th (most-likely Windows) systems.     

Note that the IP retrieved may not be up to date or may even correspond to an
non accessible IP form another network interface.

```
Get-ADComputer -Filter * -Property IPv4Address | Export-CSV <FILENAME>.csv -NoTypeInformation -Encoding UTF8

# Identify obsolete Windows operating systems in use.
Get-ADComputer -Filter {Enabled -eq "True"} -Properties OperatingSystem | ? { $_.OperatingSystem -Match "Windows NT|Windows 2000 Server|Windows Server 2003|Windows Server 2008|Windows XP|Windows 7"} | Sort OperatingSystem | Ft DNSHostName, OperatingSystem

# Identify servers if a certain naming convention is respected, for example servers name's starting with a "S" and computer with a "P".
Get-ADComputer -Filter "Name -like 'S*'" -Property IPv4Address

# Specific search for known services.
Get-ADComputer -Filter "Name -like '*MSSQL*'" -Property IPv4Address
Get-ADComputer -Filter "Name -like '*TOMCAT*'" -Property IPv4Address
```

###### DNS hostnames resolution from target file

To resolve a list of DNS hostnames the following commands can be used:  

```
hostnames=<HOSTNAMES_FILE>
nmap -T5 -sL -n -oN hostnames_resolved.nmap -iL $hostnames
cat hostnames_resolved.nmap | grep "scan report" | cut --output-delimiter=',' -d ' ' -f '5,6' | tr -d '()' > hosts.csv && rm hostnames_resolved.nmap
cut -d ',' -f 2 hosts.csv > IP.txt   
```

### 1. Ports and services scan

For more details on techniques and tools to conduct ports and services scan,
refer to the `[General] Ports scan` note.

Command that may require a long execution time, can be started using the
`nohup` utility. `nohup` will start a process that remain active even after
the user that launched it logged out: `nohup <COMMAND> &`.

###### Ping sweep

`nmap` can be used to identify live hosts through a "ping sweep":
  - `ARP` ping for hosts on the same local subnet.
  - `ICMP` `echo` requests and `TCP` probes on ports 80 and 443 otherwise.

While a "ping sweep" can be used to quickly identify live hosts, it will miss
any targets outside of the local subnet that do not answer to ping or do not
expose services on the `TCP` 80 / 443 ports.

```
nmap -v -sn -T4 -oG <OUTPUT_NMAP_GNMAP> [<RANGE | CIDR> | -iL <INPUT_FILE>]

grep "Status: Up" <OUTPUT_NMAP_GNMAP> | cut -f 2 -d ' ' > <OUTPUT_IP_FILE>
```

###### Asynchronous fast ports scan

`Masscan` or `RustScan` can be used to conduct fast asynchronous and stateless
ports scan on targets supporting high inbound network bandwidth. `masscan` /
`RustScan`'s ports scan speed can be combined with `nmap`'s services detection
probes to rapidly conduct a large network ports and services scan.

Note however that the trade-off for the speed achieved using `masscan` /
`RustScan` is less precision, and potentially missed open ports.

```
# From file
masscan -i <INTERFACE> --rate 10000 --open -p 1-65535 -iL <INPUT_IP_FILE> > <RAW_MASSCAN_OUTPUT>

# Using CIDR or IP range
masscan -i <INTERFACE> --rate 10000 --open -p 1-65535 <CIDR | RANGE> > <RAW_MASSCAN_OUTPUT>
```

###### Nmap limited ports scan

Against unresponsive hosts, or for better overall precision, `nmap` can be used
directly to scan for open ports. As `nmap` is significantly slower than the
aforementioned ports scanners, only a limited range of ports should be probed
(by default the `TCP` top 1000 ports).

```
# The ports scan can be mutualized with a service -sV and default script -sC scan.

nmap -v -Pn [-sT] [-sV -sC] --min-hostgroup 128 --host-timeout 3600s -oA <OUTPUT_FILES> -iL <INPUT_IP_FILE>
```

###### Nmap services scan

Once the open ports are enumerated, `nmap` can be used to conduct a services
scan to more precisely identify exposed services and conduct banner probing /
versions identification.

`nmap` does not currently provide a way to scan specific host/port
combinations, which grandly limit the chaining possibility between ports scan
outputs and services scans. A GitHub issue is open and an external patch is
being reviewed:
[GitHub issue](https://github.com/nmap/nmap/issues/1217) and
[Nmap Development mailing list](https://seclists.org/nmap-dev/2019/q2/2).

*Full ports and services scan from IPs / range / CIDR input file*

The following command will instruct `nmap` to conduct a full ports scan (`-p-`)
on every host, without first trying to detect live hosts using a probing
requests (`-Pn`).

```
nmap -v -Pn [-sT] -p- -sV -sC --min-hostgroup 64 --host-timeout 3600s -oA <OUTPUT_FILES> -iL <INPUT_IP_FILE>
```

*From masscan output*

The currently optimized approach is to conduct a service scan on all ports
identified as open on at least one host.

```
ports=$(cut -d ' ' -f 4 <RAW_MASSCAN_OUTPUT> | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')

# IP & range.
IP="<IP>" && SUB="<MASK>"
nmap -v -Pn -sV -sC -oA "$IP-$SUB-TCP" -p $ports "$IP/$SUB"

# From file.
nmap -v -Pn -sV -sC -oA "<OUTPUTNAME>" -p $ports -iL <FILENAME>
```

###### nmap output parsing

*NmaptoCSV*

The `NmaptoCSV` Python script can be used to convert `nmap` output to the `CSV`
format. The produced CSV file can be loaded in a graphical CSV reader (such as
`Excel`) for an easier analysis of `nmap` scan results.

```
nmaptocsv [-d ","] -i <NMAP_REGULAR_OUPUT | NMAP_GNMAP_OUTPUT> -o <CSV_OUTPUT>

nmaptocsv [-d ","] -x <NMAP_XML_OUPUT> -o <CSV_OUTPUT>
```

*nmap-parse-output*

The `nmap-parse-output` bash script can be used to parse and extract
information from `nmap` results (in the `xml` format). It will be used
extensively in this note to extract hosts exposing certain services.

```
# Extract hosts with the specified service exposed, in the following format: "<IP>:<PORT>".
nmap-parse-output <NMAP_XML_SCAN_RESULT> service <SERVICE_NAME>
```

*Sort file by IP order*

The following one-liner can be used to sort a list of IP addresses, or any file
in which each line starts by an IP:

```
sort -t . -k 3,3n -k 4,4n <INPUT_FILE>
```

### 2. Automated vulnerabilities discovery

###### Tenable Nessus

`Nessus` is a proprietary automated vulnerability scanner. It can be used to
scan for vulnerabilities, various misconfigurations, and empty / default
passwords on common services.    

Depending, on the number of hosts to scan, `Nessus` can be instructed to
conduct a full ports scan and / or limit its scan for vulnerabilities that
could result in remote code execution.

```
# Transforms a list of servers hostnames / IPs into a comma separated list.
sed ':a;N;$!ba;s/\n/ /g' <INPUT_FILE>

# Instructs Nessus to scan all 0-65535 ports.
Settings -> Discovery -> Scan type -> Port scan (all ports)

# Instructs Nessus to limit scan for RCE vulnerabilities.
Plugins -> Only keep "Backdoors", "Gain a shell remotely" and "Service detection" enabled.
```

###### Sn1per Community Edition

Alternatively or in addition, the `Sn1per Community Edition` automated scanner
can be used as well.

The `NUKE` mode will launch a full audit of multiple hosts specified in text
file including:
  - full ports scan.
  - sub-domains brute force and `DNS` zone transfers.
  - anonymous `FTP` / `LDAP` access, `SMB` NULL sessions and `SNMP` community
    strings.
  - Web scan using `WPScan`, `Arachni` and `Nikto` for all detected web
    services.

```
sniper --update
sniper -f <TARGETS_FILE> nuke
```

### 3. SMB services enumeration and analysis

Multiple known vulnerabilities affect the `SMB` protocol, that could allow if
unpatched unauthenticated remote code execution.

Additionally, `SMB` network shares could be accessible to unauthenticated
users (`Anonymous` or `Guest` access). If an Active Directory account was
provided, or could be compromised, refer to the `[ActiveDirectory] GPP and
shares searching` note for techniques and tools for authenticated shares
enumeration and searches.

###### SMB RCE vulnerabilities

`Nmap` and `metasploit` can be used to detect vulnerability on exposed `SMB`
services. It is recommended to combine both tools to minimize the number of
false-negatives.

For vulnerability exploitation, refer to the `[L7] SMB - Methodology` note.

```
# If necessary, extracts the hosts exposing a service on port 445 from a nmap's gnmap output.
grep -w '445/open' <NMAP_GNMAP_OUTPUT> | cut -d ' ' -f 2 | tee <OUTPUT_HOSTS_SMB>

nmap -v -Pn -n -sT -p 139,445 -sV --script=vuln -oA <OUTPUT_HOSTS_SMB_VULN> -iL <INPUT_HOSTS>

msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; [set SMBUser <USERNAME>; set SMBPass <PASSWORD>;] set RHOSTS file:<INPUT_HOSTS>; run"
```

###### Null session and guest access to shares

`smbmap` can be used to attempt to list the accessible shares on the hosts
exposing an `SMB` services. If any share is found to be accessible, refer to
the `[L7] SMB - Methodology` for techniques and tooling to search and retrieve
sensible content in the shares.

```
# Unauthenticated access attempt.
smbmap --host-file <INPUT_HOSTS>

# Access attempt using the built-in Guest account (RID 501).
smbmap -u "Guest" --host-file <INPUT_HOSTS>
smbmap -u "Invité" --host-file <INPUT_HOSTS>

# Access attempt using the given credentials.
smbmap [-d <WORKGROUP | DOMAIN>] -u <USERNAME>] [-p <PASSWORD | NTLM_HASH>]
```

###### Null session enumeration attempts

`enum4linux-ng` can be used to attempt in an unauthenticated manner to retrieve
information, in addition to exposed shares, such as local users, groups,
password policy information, etc. For more information, refer to the
`[L7] MSRPC` note.

`Interlace` is used in combination with `WhatWeb` to manage multi-threading and
parameterize output.

```
# Command to instruct interlace to execute enum4linux-ng, to place in a file.
enum4linux-ng -A -R _target_ > _output_/_cleantarget_-enum4linux-ng.txt

interlace -tL <INPUT_SMB_HOSTS> -o <OUTPUT_FOLDER> -cL <ENUM4LINUX_COMMAND_FILE>
```

--------------------------------------------------------------------------------

### X. HTTP / HTTPS services enumeration and analysis

###### URL extraction from nmap scan results

`nmap-parse-output` can extract hosts with an exposed http service from
`nmap`'s `XML` output, in the following format: `<http | https>://<IP>:<PORT>`.

The following services are identified as being http services: `http`, `https`,
`http-alt`, `https-alt`, `http-proxy`, `sip`, `rtsp`, `soap`, `vnc-http`, and
`caldav`.

```
nmap-parse-output <NMAP_XML_OUPUT> http-ports | tee <OUTPUT_HOSTS_HTTP>
```

###### URL validation and screenshotting

Using the extracted list of URLs as input, `aquatone` can be used to validate
the URL and screenshot the accessible web applications.

`Aquatone` produces a report in the `HTML` format that embeds the screenshots,
web page title, and headers enumerated. Web applications are grouped by
similarities for easier visualization and analysis.

```
cat <INPUT_URLS> | aquatone <OUTPUT_DIR>
```

###### Web technologies identification

`WhatWeb` can be used to identify the various technological components used
by the web applications exposed on the URL validated by `aquatone`.

`Interlace` is used in combination with `WhatWeb` to manage multi-threading and
parameterize output.

```
# Command to instruct interlace to execute WhatWeb, to place in a file.
whatweb --aggression=3 _target_ > _output_/_cleantarget_-whatweb.txt

interlace -tL <INPUT_HTTPS_URLS> -o <OUTPUT_FOLDER> -cL <WHATWEB_COMMAND_FILE>
```

###### Files / directory bruteforcing

`ffuf` can be used to directories and files names on URL validated by
`aquatone`. The files / directories wordlist size should be adapted to the
number of URL to bruteforce and the network responsiveness.

A combination of wordlists, picked based on the technological components
identified by `WhatWeb`, from `SecLists` may be used.

```
ffuf -w "<INPUT_URLS>:URLS" -w <DIRECTORY_WL> -u URLS/FUZZ -of csv -o <OUTPUT_FILE>
```

###### SSL / TLS configuration analysis

`testssl` and `sslscan2` can be used to review the `SSL` / `TLS` configuration
(supported protocols and cyphers, certificates audit, etc.) of `HTTPS`
services.

`Interlace` is used in combination with `sslscan` and `testssl` to introduce
multi-threading and parameterize outputs.

```
# Commands to instruct interlace to execute sslscan and testssl.sh, to place in a file.
sslscan _target_ > _output_/_cleantarget_-sslscan.txt
testssl.sh _target_ > _output_/_cleantarget_-testssl.txt

interlace -tL <INPUT_HTTPS_URLS> -o <OUTPUT_FOLDER> -cL <SSL_COMMANDS_FILE>
```

--------------------------------------------------------------------------------

### X. Credentials bruteforcing

###### Usernames and passwords wordlist

###### SSH user enumeration

The `sshUsernameEnumExploit.py` Python script can be used to enumerate local
users against `OpenSSH` services, under `OpenSSH 7.7`, which are vulnerable to
oracle username enumeration (`CVE-2018-15473`).

```
# Commands to instruct interlace to execute sshUsernameEnumExploit, to place in a file.
python3 sshUsernameEnumExploit.py [--username <USERNAME> | --userList <USERNAMES_FILE> _target_ > _output_/_cleantarget_-ssh-enum.txt

interlace -tL <INPUT_SSH_HOSTS> -o <OUTPUT_FOLDER> -cL <SSH_COMMANDS_FILE>
```

###### Common services login bruteforce

| Service | Default port | Specific username(s) | Specific password(s) | Command |
|---------|--------------|----------------------|----------------------|---------|
| `FTP` | TCP 21 | anonymous | |
| `SSH` | TCP 22 | | |  
| `rexec` <br><br> `rlogin` | TCP 512 <br><br> TCP 513 | | |
| `MSSQL` | TCP 1433 | sa | sa | `patator mssql_login host=FILE0 user=FILE1 password=FILE2 0="<INPUT_HOSTS>" 1=<WORDLIST_USER> 2=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'`
| `Tomcat` | NA | tomcat <br> manager <br> role <br> role1 | tomcat <br> changethis <br> s3cret | |
