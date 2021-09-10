# Ports and services scanning - Methodology

--------------------------------------------------------------------------------

###### Single host fast ports and services scan using masscan and nmap

```
target="<HOSTNAME | IP>"

# TCP ports.
masscan --open -p1-65535 $target --rate=1000 > raw_masscan_output.txt
ports=$(cut -d ' ' -f 4 raw_masscan_output.txt | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -v -Pn -sV -sC -oA $target-TCP -p $ports $target

# UDP ports.
masscan --open -pU:1-65535 $target --rate=1000 > raw_masscan_output.txt
ports=$(cut -d ' ' -f 4 raw_masscan_output.txt | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -v -Pn -sV -sC -oA $target-UDP -p $ports $target
```
--------------------------------------------------------------------------------

### Basic ports scan

###### ping + netcat

The `ping` and `netcat` utilities can be used to quickly enumerate accessible
servers and their open ports from a compromised host. Both utilities can be
uploaded, if not already available on the compromised host, as standalone
binaries. Note that some statically linked version of `netcat` may be detected
as malicious agent by anti-viral solutions.

The following one-liners can be used to conduct an `ICMP` echo sweep using the
built-in `ping` utility:

```
# Linux.

# /16 IP range.
prefix="<X.X>" && for i in {0..254}; do echo $prefix.$i/24; for j in {1..254}; do sh -c "ping -c 1 $prefix.$i.$j | grep \"icmp\" &" ; done; done

# /24 IP range.
prefix="<X.X.X>" && for i in {0..254}; do sh -c "ping -c 1 $prefix.$i | grep \"icmp\" &" ; done
```

`netcat` can be used to conduct a basic `TCP` or `UDP` ports scan, with no
banner grabbing or version probing:

```
# TCP ports.
nc -znv -w 2 <HOSTNAME | IP> <PORT | PORT_RANGE>

# UDP ports.
nc -uznv -w 2 <HOSTNAME | IP> <PORT | PORT_RANGE>
```

Combining `ping` and `netcat`, the following bash one-liners can be used to do
a `ping` sweep followed by a basic port scan using `netcat` on the hosts
responding to the `ICMP` echo requests:

```
# The IP range shoudl be specified using the prefix and seq number variables.
# For example: specify prefix="10.10.10" and seq 255 to scan the range 10.10.10.0-255.

prefix="<X.X.X>" && for i in `seq <SUBNET | 255>`; do ping -c 1 $prefix.$i &> /dev/null && echo "Scan host: $prefix.$i" && nc -zvn -w 2 $prefix.$i <PORT | PORT_RANGE> 2>&1 | grep "open" ; done
```

###### PowerShell

PowerShell can be used to conduct a *very slow* and basic ports scan using the
`Net.Sockets.TcpClient` or `Test-Netconnection` built-ins.

Note that for each and every inaccessible ports `Test-NetConnection` will
perform an `ICMP` echo request (ping) to the targeted host, tremendously
slowing down the ports scanning process.

```
# Single host.
1..65355 | % { echo ((new-object Net.Sockets.TcpClient).Connect("<IP>",$_)) "[OPEN] Port $_" } 2>$null
$WarningPreference = 'SilentlyContinue'; foreach ($port in 1..65355) { Test-NetConnection -Port $port <IP> | Where { $_.TcpTestSucceeded -eq $True } | Ft RemoteAddress,RemotePort }

# Range /24.
1..255 | % { $ip = <X.X.X.$_>; 1..65355 | % { echo ((new-object Net.Sockets.TcpClient).Connect("$x",$_)) "[OPEN] Port $ip:$_"} 2>$null }
$WarningPreference = 'SilentlyContinue'; foreach ($sub in 1..255) { $ip = <X.X.X.$sub>; foreach ($port in 1..65355) { Test-NetConnection -Port $port $ip | Where { $_.TcpTestSucceeded -eq $True } | Ft RemoteAddress,RemotePort } }

# From a file.
Get-Content <FILE_PATH> | ForEach-Object { foreach ($port in 1..65355) { echo ((new-object Net.Sockets.TcpClient).Connect("$_",$port)) "[OPEN] Port $_ : $port"}} 2>$null
$WarningPreference = 'SilentlyContinue'; Get-Content <FILE_PATH> | ForEach-Object { foreach ($port in 1..65355) {  Test-NetConnection -Port $port $_ | Where { $_.TcpTestSucceeded -eq $True } | Ft RemoteAddress,RemotePort }}

# From an input comma separated list.
"<LIST_IP>".Split(",") | ForEach { foreach ($port in 1..65355) { echo ((new-object Net.Sockets.TcpClient).Connect("$_",$port)) "[OPEN] Port $_ : $port"}} 2>$null
```

The [`PowerSploit`'s `Invoke-Portscan` cmdlet](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1), supporting  `nmap`-like
arguments, can be used for a faster ports scan from a compromised host using
PowerShell:

```
Invoke-Portscan -TopPorts 1000 -Hosts "<IP> | <FQDN> | <CIDR> | <RANGE> | <COMMA_LIST_HOSTNAMES" -oA "<FILEOUT>"
Invoke-Portscan -p- -Hosts "<IP> | <FQDN> | <CIDR> | <RANGE> | <COMMA_LIST_HOSTNAMES" -oA "<FILEOUT>"
Invoke-Portscan -f -noProgressMeter -quiet -Pn -p- -iL "<HOSTNAMES_FILE | IP_FILE>" -oA "<FILEOUT>"

# AD enrolled computers into ports scan using Invoke-Portscan.
Get-NetComputer -ComputerName "*" | Out-File -Force -FilePath "<OUTFILE_HOSTNAMES>"
Invoke-Portscan -f -noProgressMeter -quiet -Pn -p "<COMMA_LIST_PORTS>" -iL "<OUTFILE_HOSTNAMES>" -oA "<FILEOUT>"
```

### Asynchronous and stateless ports scan

[`masscan`](https://github.com/robertdavidgraham/masscan) or
[`RustScan`](https://github.com/RustScan/RustScan) (or `Unicornscan`, `ZMap`,
etc.) can be used to conduct fast asynchronous and stateless ports scan on
targets supporting high inbound network bandwidth. `masscan` / `RustScan`'s
ports scan speed can be combined with `nmap`'s services detection probes to
rapidly conduct a large network ports and services scan.

Note however that the trade-off for the speed achieved using such tools is
less precision, and potentially missed open ports.

###### masscan

`masscan` uses a default rate of 100 packets/second and supports `nmap` like
options.

```
# Supports nmap's XML or grepable (gnmap) output file format.

masscan --rate <10000 | RATE> --open [-oL <FILENAME.mscan> | -oX <FILENAME.xml> | -oG <FILENAME.gmap>] -p <PORT | PORT_RANGE | 0-65535> <CIDR | RANGE>
```

###### RustScan

`rustscan` uses a default rate of 3000 packets/second, which may interfere with
the target host(s) operational activity, and scans all `TCP` 65535 ports.

```
rustscan [-p <PORT | PORT_RANGE | 0-65535>] -a <IP | HOST | LIST_HOSTS | CIDR | RANGE>

# Set the batch size to <BATCH_SIZE> and the timeout <TIMEOUT> milliseconds.
rustscan -b <BATCH_SIZE> -T <TIMEOUT> -a <IP | HOST | LIST_HOSTS | CIDR | RANGE>
```

### Ports and services scan with nmap

The [`nmap`](https://nmap.org/) ("Network Mapper") tool is the most popular,
versatile, and robust port scanners to date. It has been actively developed
for over a decade, and has numerous features beyond port scanning.

`nmap` uses raw IP packets to determine what hosts are available on the
network, what services (application name and version) those hosts are offering,
what operating systems (and OS versions) they are running, what type of packet
filters/firewalls are in use, and dozens of other characteristics.

In addition to the classic command-line `nmap` executable, the `nmap` suite
includes an advanced GUI and results viewer (`Zenmap`), a flexible data
transfer, redirection, and debugging tool (`Ncat`), a utility for comparing
scan results (`Ndiff`), and a packet generation and response analysis tool
(`Nping`).

###### Usage

```
nmap [<SCAN_TYPE>] [<SCAN_OPTIONS>] (<IP> | <FQDN> | <CIDR> | <RANGE>)
```

###### Single host scanning

Using `nmap` to scan a single host:

```
# TCP - all ports.
nmap -v -sS -Pn -A -p- <IP/FQDN>
nmap -v -sT -Pn -A -p- <IP/FQDN>
nmap -v -sS -Pn -A -oA nmap_<FILENAME> -p- <IP/FQDN>

# UDP - Top 1000.
nmap -v -sU -Pn -sV <IP/FQDN>
nmap -v -sU -Pn -sV -oA nmap_<FILENAME> <IP/FQDN>

# NSE Script engine.
# For more information about the nmap scripts to use for a given service refer to the service note (L7/<SERVICE>).

nmap -v -sT -Pn -p <SERVICE_PORT> --script=vuln <IP/FQDN>
```

###### Network scanning

*Host Discovery*

Generate a live hosts list through a `nmap` "ping sweep":
  - `ARP` ping for hosts on the same local subnet.
  - `ICMP` `echo` requests and `TCP` probes on ports 80 and 443 otherwise.

```
nmap -v -sn -T4 -oG <OUTPUT_GNMAP> [<RANGE | CIDR> -iL <INPUT_FILE>]

grep "Status: Up" <OUTPUT_GNMAP> | cut -f 2 -d ' ' > <OUTPUT_IP_FILE>
```

*Port Discovery*

```
# Most common top 100 ports.
nmap -sS -T4 -Pn -A -oG <TopTCP | OUTPUT_FILE> -iL <HOSTS_FILE>
nmap -sU -T4 -Pn -A -oN <TopUDP | OUTPUT_FILE> -iL <HOSTS_FILE>

# Full port scans (UDP scans are very slow).
nmap -sS -T4 -Pn -A -p- -oN <FullTCP | OUTPUT_FILE> -iL <HOSTS_FILE>
nmap -sU -T4 -Pn -A -p- -oN <FullUDP | OUTPUT_FILE> -iL <HOSTS_FILE>
```

*Print results*

```
grep "open" FullTCP | cut -f 1 -d ' ' | sort -nu | cut -f 1 -d '/' | xargs | sed 's/ /,/g'| awk '{print "T:"$0}'
grep "open" FullUDP | cut -f 1 -d ' ' | sort -nu | cut -f 1 -d '/' | xargs | sed 's/ /,/g'| awk '{print "U:"$0}'
```

*Specific service vulnerabilities*

```
nmap -v -sT -Pn -p <SERVICE_PORT> -oA <FILEOUT> --script=vuln <RANGE | CIDR>
nmap -v -sT -Pn -p <SERVICE_PORT> -oA <FILEOUT> --script=vuln -iL <HOSTS_FILE>
```

###### Scan Types

`-sS`: `TCP` `SYN` scan.

`A SYN` packet is sent. In response, a `SYN/ACK` indicates the port is
listening (open), while a `RST` (reset) packet is indicative of a non-listener.
No response or an `ICMP` unreachable error means the port is filtered.

`-sT`: `TCP` connect scan.

Does not require admin privilege. Instead of writing raw packets as most other
scan types do, `nmap` asks the underlying operating system to establish a
connection with the target machine. Works the same way as the `TCP` `SYN` scan,
only closing the `TCP` handshake.

`-sU`: `UDP` scan.

Can be combined with a `TCP` scan. A `UDP` packet is sent. Open and filtered
ports rarely send any response. If an `ICMP` port unreachable error
(type 3, code 3) is returned, the port is closed.

`-sN`, `-sF`, `-sX`: `TCP` `NULL`, `FIN`, and `Xmas` scans.

  - NULL scan: Does not set any bits (`TCP` flag header is 0).  
  - `FIN` scan: Sets just the `TCP` `FIN` bit.  
  - Xmas scan: Sets the `FIN`, `PSH`, and `URG` flags, "lighting the packet
    up like a Christmas tree."

If the system scanned is RFC compliant, a `RST` packet will be received if the
port is closed and no response at all if the port is open. The port is marked
filtered if an `ICMP` unreachable error (`type 3`, code 0, 1, 2, 3, 9, 10, or
13) is received. The key advantage to these scan types is that they might
sneak through certain non-stateful firewalls and packet filtering routers.

`-sI <REMOTE_ZOMBIE_HOST>`: idle / zombie scan.

Channel the ports scan through a non controlled remote host. Reference:
`https://nmap.org/book/idlescan.html`.

###### Target Specification

`nmap` supports multiple way to specify a target host, either as an input
command line parameter or through a file:
  - IP address or hostname (example: 192.168.15.15 / www.google.com).
  - IP range (example: 192.168.0.*).
  - CIDR-style subnet (example: 192.168.0.0/24).

###### Common options

  - `-p <PORT | PORTS | PORT_RANGE>`: scan specified ports.

  Individual port numbers, comma separated list of ports or hyphen separated
  range can be used.
  When scanning a combination of protocols, a particular protocol can be
  specified by preceding the port numbers by `T:` for `TCP`, `U:` for `UDP`.

  Example: `-p U:53,111,137, T:21-25,80,139,443,8080`
  <br>

  - `-sn`: no port scan (ping scan only).

  Instructs `nmap` not to do a port scan after host discovery, and only print
  out the available hosts that responded to the host discovery probes.
  <br>

  - `-Pn`: skip the host discovery phase and assume every hosts is up.

  By default, `nmap` use a ping scan to determine if the host is up before
  starting the specified scan. If specified, this flag tells `nmap` to skip the
  host discovery phase and directly start the specified scan.
  <br>

  - `-n`: skip `DNS` resolution.

  Instructs `nmap` to never do reverse `DNS` resolution on the active IP
  addresses it may find. Can reduce scanning times.
  <br>

  - `--dns-servers <NAMESERVER>`.

  Instructs `nmap` to use the specified nameserver for `DNS` resolution.
  <br>

  - `-PR`: `ARP` ping.

  Instructs `nmap` to use `ARP` requests to conduct host discovery on `LA-T4N`
  network.
  <br>

  -`-sV`: enables version probing.

 	Instructs `nmap` to try to determine the service protocol, the application
  name, the version number, hostname, device type and OS family of the target.
  <br>

  - `-O`: enables OS detection.

  Instructs `nmap` to try to determine the OS and OS details of the target.
  <br>

  -`-sC`: enables default script scanning.

  Instructs `nmap` to perform enumeration using its `NSE` script engine and a
  default set of scripts.
  <br>

  - `-A`: "aggressive" scan options (equivalent to `-sV`, `-O`, and `-sC`).

  Tells `nmap` to perform OS detection (`-O`), version scanning (`-sV`), script
  scanning (`-sC`) and traceroute (`--traceroute`).
  <br>

  - `-T <paranoid/0 | sneaky/1 | polite/2 | normal/3 | aggressive/4 | insane/5>`: timing template.

  Instructs `nmap` to use the specified scan / timing template:
    - `paranoid/0` and `sneaky/1` are for `IDS` evasion and are incredibly
      slow.
    - `polite/2` mode slows down the scan to use less bandwidth and resources
      from the targeted hosts. A `polite` scan may be 10 times slower than a
      `normal` scan.
    - `normal/3` mode is the default scan mode.  
    - `aggressive/4` mode speeds scans up by making the assumption that the
      scan is conducted on a reasonably fast and reliable network.
    - `insane/5` mode assumes that the scan is conducted on an extraordinarily
      fast network or sacrifices some accuracy for speed.  

###### nmap Scripting Engine (NSE)

`nmap`'s `NSE` scripts are categorized in a list of categories they belong to.
The following categories are currently defined:
 - `auth`
 - `broadcast`
 - `brute`
 - `default`
 - `discovery`
 - `dos`
 - `exploit`
 - `external`
 - `fuzzer`
 - `intrusive`
 - `malware`
 - `safe`
 - `version`
 - `vuln`

`nmap`'s `NSE` usage:

```
# Updates the script database (found in scripts/script.db).
nmap --script-updatedb

# Runs the specified script, comma-separated list of scripts, script category, or scripts in the specified directory.
nmap [...] --script <SCRIPT_NAME> | <SCRIPT_CATEGORY> | <DIRECTORY> | <EXPRESSION> | [,...]>

# Specifies arguments for the given script.
# Arguments are a comma-separated list of name=value pairs. Names and values may be strings not containing whitespace or the characters '{', '}', '=', or ','. To include one of these characters in a string, the string must be enclosed in single or double quotes.
nmap [...] --script <SCRIPT> --script-args <n1=<v1>,<n2>={<n3>=<v3>},<n4>={<v4>,<v5>}

# Loads the arguments from the specified file. Any arguments on the command line supersede ones in the file.
nmap [...] --script <SCRIPT> [--script-args <CLI_ARGUMENTS>] --script-args-file <FILE>

# Shows the help and usage for the specified scripts.
# The online NSE Documentation Portal at https://nmap.org/nsedoc/ lists as well the arguments that each script accepts, including any library arguments that may influence the script.
nmap --script-help <SCRIPT_NAME> | <SCRIPT_CATEGORY> | <DIRECTORY> | <EXPRESSION> | [,...]>

# Runs all scripts whose name starts with http-, such as http-auth and http-open-proxy.
nmap --script 'http-*'

# Runs every script except for those in the intrusive category.
nmap --script "not intrusive"

# Runs all scripts that are in the default category or the safe category.
# Equivalent to nmap --script "default,safe".
nmap --script "default or safe"
```

###### nmap output parsing

*nmap-parse-output*

The [`nmap-parse-output`](https://github.com/ernw/nmap-parse-output) utility
can be used to parse and extract information from `nmap` outputs (in the `xml`
format).  

```
# Extracts hosts that have at least one open port.
nmap-parse-output <NMAP_XML_SCAN_RESULT> hosts

# Extracts all open ports in the following format: "<IP>:<PORT> <TCP | UDP>".
nmap-parse-output <NMAP_XML_SCAN_RESULT> host-ports
nmap-parse-output <NMAP_XML_SCAN_RESULT> host-ports | cut -d " " -f 1

# Extract a list of uniquely filtered services identified.
nmap-parse-output <NMAP_XML_SCAN_RESULT> service-names

# Extract hosts with the specified service exposed, in the following format: "<IP>:<PORT>".
nmap-parse-output <NMAP_XML_SCAN_RESULT> service <SERVICE_NAME>

# Extract hosts with an exposed http service, in the following format: "<http | https>://<IP>:<PORT>".
# The following services are currently identified as being http services: http, https, http-alt, https-alt, http-proxy, sip, rtsp, soap, vnc-http, caldav.
nmap-parse-output <NMAP_XML_SCAN_RESULT> http-ports
```

*NmaptoCSV*

The [`NmaptoCSV`](https://github.com/maaaaz/nmaptocsv) Python script can be
used to convert `nmap` outputs (regular, `GNMAP`, or `XML` formats) to the
`CSV` format.

```
nmaptocsv [-d ","] -i <NMAP_REGULAR_OUPUT | NMAP_GNMAP_OUTPUT> -o <CSV_OUTPUT>

nmaptocsv [-d ","] -x <NMAP_XML_OUPUT> -o <CSV_OUTPUT>
```

### Pivot scans through compromised hosts

###### Netcat

As described above, `netcat` can be used to conduct a basic ports scan from a
compromised host.

###### Static nmap

Prebuild static and standalone binaries of `nmap` are available on the
following GitHub repository. `nmap` is compiled from the official GitHub
repository sources automatically with `GitHub Actions`.

```
https://github.com/ernw/static-toolbox
```

The
[`run-nmap.sh`](https://github.com/ernw/static-toolbox/blob/master/package/targets/nmap/run-nmap.ps1)
or [`run-nmap.ps1`](https://github.com/ernw/static-toolbox/blob/master/package/targets/nmap/run-nmap.sh)
scripts can be used to run the prebuild `nmap` on a compromised host without
external dependencies. Additionally, the binary comes with the various `NSE`
scripts and modules necessary to conduct version fingerprinting.

```
./run-nmap.sh <NMAP_OPTIONS>

.\run-nmap.ps1 <NMAP_OPTIONS>
```

###### Proychains

`Proxychains` (or [`ProxyChains-NG`](https://github.com/rofl0r/proxychains-ng))
can be used to conduct ports scans through a proxy (supported proxies types:
`http`, `socks4` and `socks5`).

Note that a few restrictions apply whenever conducting a ports scan through a
proxy:
  - `HTTP`/`socks4` can only be used to conduct `TCP` scan.

  - `ICMP` packets can not pass through the proxy (`nmap`'s `-Pn` option).

  - `RAW` packets cannot be redirected through `proxychains` as it is designed
    to relay full `TCP` connections only (`nmap`'s `-sT` option).

  - `DNS` resolutions should not be conducted through a proxy if confidentially
    is of importance and to reduce scan time (`nmap`'s `-n`).

  - OS fingerprinting based on features of the IP stack may not work properly.

For example, `nmap` can be used to conduct a ports scan and services discovery
through a proxy using `proxychains`:

```
The proxychains configuration file (/etc/proxychains.conf) should first be updated to specify the proxy to use.
<http | socks4 | socks5> <IP> <PORT>

# Start the scan using proxychains.
proxychains nmap -v -n -Pn -sT -sV [...]
```

###### Metasploit

The following [`Metasploit`](https://www.metasploit.com/) modules can be used
to conduct a ports scan:
  - `auxiliary/scanner/portscan/syn`
  - `auxiliary/scanner/portscan/tcp`
  - `auxiliary/scanner/portscan/ack`
  - `auxiliary/scanner/portscan/ftpbounce`
  - `auxiliary/scanner/portscan/xmas`

The port range default to `1-10000`. To scan all possible ports the `0-65535`
ports range should be specified (`set PORTS 0-65535`).

The modules can be used directly or through a `meterpreter` session
to use the compromised host as a pivot.

```
# Direct ports scan from the current host.
msf> use auxiliary/scanner/portscan/tcp

# Pivoting through a meterpreter session.
meterpreter> run auxiliary/scanner/portscan/syn RHOSTS=<IP | CIDR> [PORTS=<PORT | PORTS_RANGE>]
meterpreter> run auxiliary/scanner/portscan/tcp RHOSTS=<IP | CIDR> [PORTS=<PORT | PORTS_RANGE>]
```

### Local netstat execution trough remote code execution

A remote execution utility, such as a `PsExec`-like tool or
[`CrackMapExec`](https://github.com/byt3bl33d3r/CrackMapExec), can be used to
retrieve the locally exposed services on a target through `netstat` if valid
credentials could be obtained for remote code execution.

For more information about the tools usage refer to the
`[Windows] Lateral movements` note for more information.

```
# netstat's -b options requires local administrator privileges (which are also required by CrackMapExec for remote code execution over the SMB protocol).

crackmapexec [...] -x 'netstat -anob'
crackmapexec [...] -x 'netstat -anob | find "<PORT>"'
```

### Graphical ports scanning utilities

###### Advanced port scanner

[`Advanced port scanner`](https://www.advanced-port-scanner.com/fr/) is a
Windows GUI multithreaded ports and services scanner that can be both installed
and used in standalone mode.

The tool provides easy access to the main identified services (`HTTP`, `HTTPS`,
`SSH`, `RDP`, `SMB`, etc.) by starting the associated Windows built-ins.

###### netscan

[`SoftPerfect`'s `NetScan`](https://www.softperfect.com/products/networkscanner/)
is an advanced and lightweight Windows GUI network scanner utility, available
as a standalone binary. `NetScan` supports the `Windows 7` through
`Windows 10`, and `Windows Server 2008 R2` through `Windows Server 2019`
operating systems.

Note that the free edition of `NetScan` can only be used to display a maximum
of 10 devices.

In addition to IPv4 and IPv6 hosts discovery and ports scanning, `NetScan`
provides the following key features:
  - Discovery of network shares and integration with Windows built-in network
    share explorer and drive mapping functionalities.
  - Sending of `Wake-on-LAN (WoL)` messages.
  - Discovery of `Dynamic Host Configuration Protocol (DHCP)` servers.
  - Automatic discovery of network interface IP range.
  - Remote execution of `SSH`, `PowerShell` and `VBScript` command execution.

Cracked commercial editions of `NetScan` have been observed to be used in the
wild by malicious actors, notably in ransomware attack scenarios, with the
deployment of `NetScan` standalone binary on a compromised system to discover
and map remote `C$` network shares.
