# General - External reconnaissance

> [`recon-ng`](https://github.com/lanmaster53/recon-ng) is an open source
intelligence (OSINT) framework designed to provide "a powerful environment to
conduct open source [reconnaissance] quickly and thoroughly".
`recon-ng` provides a layer of abstraction for numerous `APIs` that can be
leveraged for external information gathering (domains and subdomains
enumeration, reverse `DNS` lookups, searches in services and vulnerabilities
datasets, etc.). <br><br>
`recon-ng` is built around modules, that will be referenced in the adequate
sections of the present note. <br>

```bash
# Sets the USER-AGENT sent by recon-ng (by default "Recon-ng/vX") for a more OPSEC friendly approach.

options set USER-AGENT "<USER_AGENT_STRING>"

--------------------------------------------------------------------------------

# Workspaces: projects that will hold the related domains, hosts, ports, etc..
# Each workspace will be stored as a SQLite database on the filesystem.

# Creates a "workspace".
workspaces create <WORKSPACE_NAME>

# List the existing workspaces.
workspaces list

# Switches to the specified workspace.
workspaces load <WORKSPACE_NAME>

# Removes the specified workspace.
workspaces remove <WORKSPACE_NAME>

--------------------------------------------------------------------------------

# API keys operations.
# Each module lists the API key(s) it requires.

# Adds the specified key.
# Key names examples: bing_api, github_api, google_api, ipinfodb_api, shodan_api, spyse_api virustotal_api, whoxy_api, etc.
keys add <KEY_NAME> <KEY_VALUE>

# Removes the specified key.
keys remove <KEY_NAME>

# List the configured keys.
keys list

--------------------------------------------------------------------------------

# Database operations (adding / removing targets, listing current results, etc.).
# Supported tables (as of recon-ng v5.1.2): companies, contacts, credentials domains, hosts, leaks, locations, netblocks, ports, profiles, pushpins, repositories, and vulnerabilities.
# "companies" table: name of the companies to target (for Whois / ASN research for instance).
# "domains" table: domains to be targeted.
# "hosts" table: hosts enumerated (hostname and IP address information notably).
# "ports" table: ports enumerated, including information on the host, the protocol / service, etc.

# Displays the schema of the current's workspace database.
db schema

# Lists the values stored in the specified table (including their rowid, needed for various operations).
show <domains | hosts | ports | TABLE_NAME>
db query SELECT rowid, * FROM <domains | hosts | ports | TABLE_NAME>;

# Adds the specified entry in the given table.
db insert companies <COMPANY_NAME>~ ~
db insert domains <DOMAIN>~
db insert netblocks <CIDR>~
[...]

# Removes the specified domain from the "domains" table.
db delete domains <ROWID>

# Removes all entries from the specified table.
db query DELETE FROM <TABLE>;

--------------------------------------------------------------------------------

# The modules of the recon-ng framework are not provisioned / installed by default but are made available from the "Recon-ng Marketplace" (https://github.com/lanmaster53/recon-ng-marketplace).

# Lists all the modules available.
marketplace search

# Searches among the available modules for the specified keyword(s).
marketplace search <KEYWORD(S)>

# Retrieves information about all or the specified module(s) (description, last update date, required API keys and dependencies, etc.).
marketplace info <all | MODULE_PATH>

# Install all or the specified module.
marketplace install <all | MODULE_PATH>

--------------------------------------------------------------------------------

# The modules will usually require a <SOURCE> input.
# By default the source will be all the data from a recon-ng's table, but can be specified to be a single element, a file, or an SQL query to extract specific data.

# Lists the modules currently installed.
modules search

# Searches among the installed modules for the specified keyword(s).
modules search <KEYWORD(S)>

# Loads the specified module.
modules load <MODULE_PATH>

# Displays the help of the current module.
[recon-ng][<WORKSPACE>][<MODULE>] > info

# If required, set the <SOURCE> input for the current module.
[recon-ng][<WORKSPACE>][<MODULE>] > options set SOURCE <SINGLE_ELEMENT | FILE | SQL_QUERY>

# Execute the current module.
[recon-ng][<WORKSPACE>][<MODULE>] > run

--------------------------------------------------------------------------------

# Specific modules are designed for the importing / exporting of results.
# Input modules: import/csv_file, import/list, import/masscan, and import/nmap.
# Notable exporting modules: reporting/csv, reporting/list, reporting/json, reporting/html, and reporting/xlsx.

# Import the data in the file in the specified table's column.
# For example, to import subdomains: <TABLE> = hosts & <COLUMN> = host.
modules load import/list
[recon-ng][<WORKSPACE>][list] > options set FILENAME <FILENAME>
[recon-ng][<WORKSPACE>][list] > options set TABLE <TABLE>
[recon-ng][<WORKSPACE>][list] > options set COLUMN <COLUMN>
[recon-ng][<WORKSPACE>][list] > run
```

### Domain enumeration

###### [Passive] Initial domain enumeration

Manual searches using search engines, such as `Google` or `Bing`, should first
be conducted to identify a list of domains linked to the targeted entity.

The goal of the research is to:

  - Gather an initial list of the domain directly linked to the targeted
    entity.

  - Identify the possible subsidiaries of the entity and gather information
    about their associated domains.

Once the main domain names are identified:

  - Queries to `Whois` records can be done to retrieve information about the
    `registrant` (registered holder of the domain) or the `registrar`
    (accredited organization that registers a domain on behalf of the
    `registrant`) of the domains.

    The `whois` Linux utility can be used to retrieve the `Whois` record of a
    specified domain:

    ```bash
    whois <DOMAIN>

    # Bash script to retrieve the Registrant of each domains (one by line) in the file given as input.

    #!/bin/bash
    while IFS= read -r domain; do
        registrant=$(whois $domain | grep "Registrant Organization" | cut -d ":" -f 2 | awk '{$1=$1};1')
        echo "\"$domain\",\"$registrant\""
    done < "$1"
    ```

    Additionally, the following online services can be used to make `Whois`
    queries:

    | Service | URL | Description |
    |---------|-----|-------------|
    | `who.is` | https://who.is/ | Free service through a web interface. |
    | `Whoxy` Whois Lookup | https://www.whoxy.com/ | Free `Whois` queries through the web interface and paid `API` (with a low pricing: 1,000 Domain `Whois` `API` queries for 2$). <br><br> `recon-ng`'s module (requires a `whoxy_api` `API` key): <br> `recon/domains-companies/whoxy_whois`. |
    | `DomainTools`'s Whois lookup | https://whois.domaintools.com/ | Free service through a web interface. |


  - The `IP` address(es) associated with the domains can be enumerated through
    `DNS` resolutions (using utilities such as `dig`, `host`, or `nslookup`) or
    using proprietary databases. Note that more than one `IP` can be associated
    with a domain name (through `DNS` `A` or `AAAA` records) and result may
    vary depending on client `GeoIP` data, etc.

    ```bash
    host <DOMAIN>

    # Bash script to resolve one IP of each domains (one by line) in the file given as input.

    #!/bin/bash
    while IFS= read -r domain; do
        IP=$(dig +short $domain | sed ':a;N;$!ba;s/\n/ /g')
        echo "$domain,$IP"
    done < "$1"
    ```

    The `recon-ng`'s `recon/hosts-hosts/resolve` module can be used to resolve
    domain names (for the `hosts` table by default) using the nameserver
    configured with-in the framework (`Google`'s `DNS` 8.8.8.8 by default).

    Refer to the `[L7] DNS - Methodology` note for more information on `DNS`
    resolution if needed.

###### [Passive] Reverse Whois search

Reverse research in `Whois` records consist of researching information related
to the `registrant` (name or email address for example) in proprietary `Whois`
records dataset. Such research can be used to enumerate the others domains
possibly registered by the same `registrant`.

A number of online services can be used to make reverse `Whois` queries.

| Service | URL | Description |
|---------|-----|-------------|
| `ViewDNS.info` | https://viewdns.info/reversewhois | Free web interface, allows search based on company / person names or email addresses. <br><br> `recon-ng`'s module: <br> `recon/companies-domains/viewdns_reverse_whois`. <br><br> If `403 Forbidden` errors are returned by the `API`, the `recon-ng`'s `User-Agent` should be set to a legitimate one. |
| `reversewhois.io` | https://www.reversewhois.io | Free web interface, allows search based on names or email addresses. |
| `drs.WhoisXMLAPI.com` | https://drs.whoisxmlapi.com/reverse-whois-search | Paid service, with limited `API` credit upon signup. |
| `DomainTools`'s reverse Whois lookup | https://reversewhois.domaintools.com/ | Paid service, with the most comprehensive results. The number of results returned by a query can be consulted freely but the retrieval of the domain names is subject to charge. |

###### [Passive] Reverse DNS lookup and IP sharing

Reverse `DNS` lookup consist of retrieving, in proprietary datasets,
the domain(s) (or subdomain(s)) associated to a given `IP` address. It can be
used to identify the domains or subdomains sharing a common `IP` address (and
possibly owned by the targeted entity).

A number of online services can be used to make reverse `DNS` lookup to
identify `IP` sharing.

| Service | URL | Description |
|---------|-----|-------------|
| `api.hackertarget.com` | https://api.hackertarget.com/reverseiplookup/?q=<IP> | Website and `API`, limited to 20 queries / day in the free tier (Python script provided below). <br><br> `recon-ng`'s module: <br> `recon/hosts-hosts/hackertarget_reverse`. |
| `host.io` | https://host.io/ip/<IP> | Free queries through the web interface with limited result. <br><br> Premium API, with a free plan: 1000 requests / month with max 5 results per page (i.e 500 results would require 100 requests). |
| `ThreatCrowd` | https://www.threatcrowd.org/ip.php?ip=<IP> | Free queries through a web interface and `API`. <br><br> The web interface displays results in the form of a graph, including additional results such as reverse `DNS` or `Whois` lookups. |
| `WhoisXMLAPI`'s Reverse `IP` / `DNS` lookup | https://reverse-ip.whoisxmlapi.com/lookup | Website and `API`, with 100 free `API` calls upon signup. |
| `Bing` search engine | Search queries using: <br><br> `ip:<IP>` <br> `ip:<IP> -site:<EXCLUDE_DOMAIN1> -site:<EXCLUDE_DOMAIN2> [...]` | **Web browsing** <br><br> Free and unlimited but requires manual and time-consuming browsing. Search requests are additionally limited to 1000 characters. <br><br> The following bash one-liner can be used to generate a exclude `-site:` string from a file contaning domain names: <br><br> `while IFS= read -r line; do echo -n "-site:$line "; done < "$1"` <br><br> **Bing API** <br><br> 1,000 requests free per month, with a Microsoft Azure account (requires credit card details). |

The following Python script leverage the `api.hackertarget.com` reverse `IP`
lookup `API` to retrieve the `DNS` records associated with each `IP` in the
specified `IP` ranges:

```Python
import ipaddress
import requests
import sys

API_URL = 'https://api.hackertarget.com/reverseiplookup/'

if (len(sys.argv) < 2):
  print("Usage: reverse_dns.py <IP_FILE>")
  exit(1)

IP_file = open(sys.argv[1], 'r')
IP_ranges = IP_file.read().splitlines()

for IP_range in IP_ranges:
  for IP in ipaddress.IPv4Network(IP_range):
  	r = requests.get(url = API_URL, params = {'q':IP})
  	if 'No DNS A records found' in r.text:
  	  continue
  	for record in r.text.splitlines():
  	  print(f'{IP},{record}')
```

###### [Passive] Leveraging Autonomous System Number

An `Autonomous System Number (ASN)` is a unique number assigned to an
`Autonomous System (AS)` by the `Internet Assigned Numbers Authority (IANA)`.
An `AS` consists of blocks of `IP` addresses which have a distinctly defined
policy for accessing external networks and are administered by a single
organization (which may not be the targeted entity but an operator having the
entity as a client).

*ASNRECON*

[`ASNRECON`](https://github.com/orlyjamie/asnrecon) is a Python script that:
  - retrieve the `ASN` of a given domain,
  - lookup the `IP` addresses / ranges part of the `ASN` (in the dataset
    downloaded from the [`pyasn`](https://github.com/hadiasghari/pyasn)
    project),
  - and finally attempt to access, for each enumerated `IP`, an `HTTPS` service
    (on port `TCP` 443) to extract the `subject` defined in the `SSL` / `TLS`
    certificate.

Note that result may not usable if the `ASN` is not managed by the targeted
entity.

```bash
# As asnrecon.py requires Python2 and a number of dependencies, it is recommended to use the Docker file provided in the repository to  build a Docker container.
docker build -f Dockerfile -t asnrecon .

# Either chose 1. to scan by domain name or 2. to only conduct the SSL / TLS subject name extraction on a given IP range.  
docker run -it asnrecon
```

*ASN Lookup*

The [`asn`](https://github.com/nitefood/asn) Bash script can be used, among
other features, to lookup `ASN` by `organization name` in order to retrieve the
`IP` ranges linked to an entity.

Reverse `DNS` lookups, `SSL` / `TLS` certificates grabbing, etc. can then be
performed on the enumerated `IPs` to retrieve additional domain names of the
entity.

```
asn -o "<ENTITY_NAME>"
```

### Subdomains enumeration

###### [Passive] Search engines and passive DNS proprietary dataset

Search engines, such as `Google`, `Bing`, etc., and proprietary databases (with
historical data) operated by services such as `DNSdumpster`, `VirusTotal`,
`DomainTools`, can be used to retrieve subdomains associated with a domain
name.

| Service | URL / query | Description |
|---------|-----|-------------|
| `Rapid7`'s `Project Sonar` | https://opendata.rapid7.com/sonar.fdns_v2/ | massive offline dataset (hundreds of GB uncompressed) of domains and subdomains. <br><br> Gathered using various sources and using direct `DNS` resolutions queries (`ANY`, `A`, `AAAA`, `CNAME`, and `TXT` record lookups). <br><br> Offline query example (without extraction to disk to save disk space but which require new extraction for each search): <br> `pigz -dc <SONAR_GZ> \| grep -F '<DOMAIN>"' \| jq` |
| `DNSdumpster` (web GUI) <br> / <br> `HackerTarget` (`API`) | https://dnsdumpster.com/ <br><br> https://hackertarget.com/find-dns-host-records/ | Passive `DNS` service (with historical data) accessible using a web interface or an `API` through, respectively, `DNSdumpster` and `HackerTarget`. <br><br> `recon-ng`'s module (for `HackerTarget`): <br> `recon/domains-hosts/hackertarget`. |
| `VirusTotal` | https://www.virustotal.com/gui/home/search | Initiated as an online scan engine relying on multiple anti-virus products, `VirusTotal` has a subdomains dataset (a priori based on historical lookups of files or URL submitted for scanning by users). <br><br> The free `API` is limited to 500 requests per day and a rate of 4 requests per minute. <br><br> `recon-ng`'s module (requires a `virustotal_api` `API` key): <br> `recon/hosts-hosts/virustotal`. |
| `SPYSE` | https://spyse.com/tools/subdomain-finder | Unlimited free search through the web interface with however heavy restrictions: up to 20 results and unexportable results. <br><br> `API` available in the free tier, limited to 100 requests each month (with a maximum of 100 results per request). <br><br> `recon-ng`'s module (requires a `spyse_api` `API` key): <br> `recon/domains-hosts/spyse_subdomains`. |
| `ThreatCrowd` | https://www.threatcrowd.org/domain.php?domain=<DOMAIN> | Free queries through a web interface and `API`. <br><br> The web interface displays results in the form of a graph, including additional results such as reverse `DNS` or `Whois` lookups. <br><br> `recon-ng`'s module: <br> `recon/domains-hosts/threatcrowd`. |
| `Google` search engine | Google dorks: <br><br> `site` <br> `site:<DOMAIN> -site:<EXCLUDED_SUBDOMAIN1> -site:<EXCLUDED_SUBDOMAIN2> [...]` | Free and unlimited (with eventual `reCAPTCHA` protection) but requires manual and time-consuming browsing. Search requests are additionally limited to 32 words. <br><br> `recon-ng`'s module (which may fail du to CAPTCHA): <br> `recon/domains-hosts/google_site_web`. |
| `Bing` search engine | Bing dorks: <br><br> `site` <br> `site:<DOMAIN> -site:<EXCLUDED_SUBDOMAIN1> -site:<EXCLUDED_SUBDOMAIN2> [...]` | Similar to `Google` dorks. <br> `API` available, with 1,000 requests free per month for authenticated users (Microsoft Azure account, which requires credit card details). <br><br> `recon-ng`'s module that scrape `Bing` search results (no `API` key requied): <br> `recon/domains-hosts/bing_domain_web`. <br><br> `recon-ng`'s module for the `Bing API` (requires a `bing_api` `API` key): <br> `recon/domains-hosts/bing_domain_api`. |

###### [Passive] SSL / TLS certificates passive search

https://crt.sh/
https://transparencyreport.google.com/https/certificates

`recon-ng`'s module `recon/domains-hosts/certificate_transparency`.

###### [Active] SSL / TLS certificates grabbing

nmap -v -sT -T 2 -Pn -p 443 -sV -sC -oA <OUTPUT_FILES> [-iL <INPUT_FILE> | <HOST | IP | CIDR | IP_RANGE>

###### [Active] Forward / reverse DNS brute force

Forward `DNS` lookup brute force consist of attempting to guess valid
subdomains through `DNS` resolution. In addition, if the `DNS` `PTR records`,
used for mail services, are configured for the domain, reverse lookup brute
force may possible. Both actions require direct interactions with the
`DNS` nameservers of the targeted entity.

Refer to the `[L7] DNS - Methodology` note for techniques and tooling to
conduct forward / reverse `DNS` brute forcing.

###### [Passive / Active] Automated enumeration tools

Multiple tools can be used to automate the process of passively enumerating
subdomains using public resources. While the tools introduced below generally
produce fairly similar results, slight differences may arise and executing each
tool can ensure a more comprehensive enumeration.

| Tool | Description |
|------|-------------|
| [`Amass`](https://github.com/OWASP/Amass) | Go project retrieving data from [numerous sources](https://github.com/OWASP/Amass/blob/master/README.md). |
| [`assetfinder`](https://github.com/tomnomnom/assetfinder) | Go project retrieving data from `crt.sh`, `Certspotter`, `HackerTarget`, `ThreatCrowd`, the Wayback Machine, and `dns.bufferover.run`, as well as `Facebook`, `VirusTotal`, and `SPYSE` if `API` keys are provided. |
| [`Sublist3r`](https://github.com/aboul3la/Sublist3r) | Python script retrieving data from: <br> - Search engines (`Google`, `Bing`, `Yahoo`, `Baidu`, `Ask`, and `Netcraft`). <br> - Proprietary `DNS` datasets (`DNSdumpster`, `VirusTotal`, and `ThreatCrowd`) <br> - `SSL` / `TLS` certificates using `crt.sh`. |

*Amass*

```
# Execution of Amass on a single domain.
amass enum -passive -d <DOMAIN>

# Uses of interlace to multi-thread the execution of Amass on multiples domain.
echo 'amass enum -passive -d _target_ > _output_/_cleantarget_-amass.txt' > Amass_cmd_file.txt
interlace -tL <INPUT_DOMAIN_FILE> -o <OUTPUT_FOLDER> -cL Amass_cmd_file.txt
```

*assetfinder*

```
# Execution of assetfinder on a single domain.
assetfinder <DOMAIN>

# Uses of interlace to multi-thread the execution of assetfinder on multiples domain.
echo 'assetfinder _target_ > _output_/_cleantarget_-assetfinder.txt' > assetfinder_cmd_file.txt
interlace -tL <INPUT_DOMAIN_FILE> -o <OUTPUT_FOLDER> -cL assetfinder_cmd_file.txt
```

*Sublist3r*

```
# Execution of Sublist3r on a single domain.
python sublist3r.py -d <DOMAIN>

# Uses of interlace to multi-thread the execution of Sublist3r on multiples domain.
echo 'python3 sublist3r.py -n -d _target_ | grep _target_ | grep -v "Enumerating subdomains now for" > _output_/_cleantarget_-sublist3r.txt' > Sublist3r_cmd_file.txt
interlace -tL <INPUT_DOMAIN_FILE> -o <OUTPUT_FOLDER> -cL Sublist3r_cmd_file.txt
```

### IPs and services exposure

###### Shodan

### Code repository enumeration and research

TODO

### Employees contacts gathering

TODO

### Leaked credentials

###### [Passive] Dehashed

[`dehashed.com`](https://dehashed.com/) is a website that indexes multiple
billions of credentials leaked in various data breaches and datasets. It
allows searches to be conducted by domain name, username, emails, name,
password, etc.

While leaked email entries can be consulted freely, `dehashed.com` requires a
paid subscription to view the password or hash associated with an entry.
Additional `API` credits are also required to programmatically retrieve
credentials. As of the end of 2021, the prices are:
  - 5.49$ for a one week access, 15.49$ monthly or 179.99$ annually.
  - 2.5$ for 100 API requests (with a maximum of 10 000 results by request).


The `API` request can be used to retrieve the entries with an email containing
the specified domain:

```bash
# Example of a valid <EMAIL_DOMAIN>: test.com.
# Searches can also be conducted using the username, password, name, ip_address keywords.

curl -o <OUTPUT_JSON_FILE> 'https://api.dehashed.com/search?query=email:<EMAIL_DOMAIN>&size=10000' \
-u <EMAIL>:<API_KEY>  \
-H 'Accept: application/json'
```

The following Python snippet convert the `JSON` file produced by the `API`
request above to a `CSV` file:

```python
import json
import csv

json_file = open(r'<JSON_INPUT_FILE>', encoding="utf8")
csv_file = open(r'<CSV_OUTPUT_FILE>', 'w', encoding="utf8", newline='')

dehashed = json.load(json_file)

csv_writer = csv.DictWriter(csv_file, quoting=csv.QUOTE_ALL, fieldnames = ["email", "password", "hashed_password", "username", "name", "database_name", "ip_address", "address", "phone", "vin", "id"])
csv_writer.writeheader()

for entry in dehashed['entries']:
    csv_writer.writerow(entry)

json_file.close()
csv_file.close()
```

--------------------------------------------------------------------------------

### References

https://github.com/appsecco/the-art-of-subdomain-enumeration
https://www.whatismyip.com/asn/
https://www.twelve21.io/getting-started-with-recon-ng/
