# Internal pentesting - Methodology

Internal pentesting simulates an insider attack starting from a point within
the internal network.

The present note does not address Active Directory pentesting. While part of the
methodology detailed in this note can be applied for an Active Directory
pentesting, specific tools and techniques make the overall approach completely
different.

After enumerating accessible hosts and their exposed services, the first step in
an internal penetration test is to look for the path of least resistance, aka
the low hanging fruits that can easily be detected and exploited
(unpatched systems, default or guessable passwords, etc.).

The following methodology makes use of automated tools (Nessus, etc.) and is
thus not directly implicable to the OSCP exam.  

### Hosts enumeration

###### AD enrolled systems

In case an AD account is provided for the internal penetration test, AD queries
can be used to quickly enumerate the, most-likely Windows, systems.     

Note that the IP retrieved may not be up to date or may even correspond to an non
accessible IP form another network interface.

```
Get-ADComputer -Filter * -Property IPv4Address | Export-CSV <FILENAME>.csv -NoTypeInformation -Encoding UTF8

# identify servers if a certain naming convention is respected, for example
servers name's starting with a "S" and computer with a "P"
Get-ADComputer -Filter "Name -like 'S*'" -Property IPv4Address

# Specific search
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

### Ports and services scan

`masscan`'s ports scan speed can be combined with `nmap`'s services detection
probes to rapidly conduct a large network scan.

###### Ports scan

`MASSCAN` can be used to conduct an asynchrone and stateless ports scan.

```
# From file
masscan -i <INTERFACE> --rate 10000 --open -p 1-65535 -iL IP.txt > raw_masscan_output.txt

# Using CIDR or IP range
masscan -i <INTERFACE> --rate 10000 --open -oG ports.gmap -p 1-65535 <CIDR | RANGE> > raw_masscan_output.txt
```

###### Services scan

Once the open ports are enumerated, `nmap` can be used to conduct a services
scan.

`nmap` does not currently provide a way to scan specific host/port combination.
A GitHub issue is open and an external patch is being reviewed :
https://github.com/nmap/nmap/issues/1217
https://seclists.org/nmap-dev/2019/q2/2

The currently optimized approach is to conduct a service scan on all ports
detected open on at least one host.

```
ports=$(cut -d ' ' -f 4 raw_masscan_output.txt | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')

# IP & range
IP="<IP>" && SUB="<MASK>"
nmap -v -Pn -sV -sC -oA "$IP-$SUB-TCP" -p $ports "$IP/$SUB"

# From file
nmap -v -Pn -sV -sC -oA "<OUTPUTNAME>" -p $ports -iL <FILENAME>
```

3. Quick port scan with nmap

   ```
   nmap -v -sS -A -oA "quick_scan_tcp_$IP-$SUB" -iL "ping_sweep_$IP-$SUB.txt"
   ```

### Vulnerability discovery

  X. Nessus scan on all ports testing for RCE

     ```
     # Transfomr a list of servers hostnames / IP into a comma separated list
     sed ':a;N;$!ba;s/\n/ /g' <FILE>

     Advanced Scan
     # Scan all 0-65535 ports
     Settings -> Discovery -> Scan type -> Port scan (all ports)
     # Scan for RCE vulnerabilities
     Plugins -> Only keep "Backdoors", "Gain a shell remotely" and "Service detection" enabled
     ```

  x. Alternatively or in addition, the `Sn1per Community Edition` automated
  scanner can be used as well.

  The `NUKE` mode will launch a full audit of multiple hosts specified in text
  file including:
    - full ports scan
    - sub-domains brute force and `DNS` zone transfers
    - anonymous `FTP` / `LDAP` access, `SMB` NULL sessions and `SNMP` community
    strings
    - Web scan using `WPScan`, `Arachni` and `Nikto` for all detected web
    services

  ```
  sniper --update

  sniper -f <TARGETS_FILE> nuke
  ```

  X. SMB RCE vulnerabilities, notably EternalBlue & SambaCry, detection and
     exploitation

     ```
     grep -w '445' quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "SMB_$IP-$SUB.txt"
     nmap -v -p 139,445 --script=vuln -oG

     # MS17-010
     # Windows 7 and Server 2008 R2 (x64) All Service Packs
     msf> use exploit/windows/smb/ms17_010_eternalblue
     ```

  X. MSSQL default or guessable credentials

     ```
     grep -w '1433' quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "MSSQL_$IP-$SUB.txt"

     # Usernames: sa, Administrator, Administrateur
     # Passwords: blank, sa or Password123
     patator mssql_login host=FILE0 user=FILE1 password=FILE2 0="MSSQL_$IP-$SUB.txt" 1=<WORDLIST_USER> 2=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'
     ```  

  X. Exposed rlogin and rexec services without password

     ```
     grep -w "512\|513" quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "RLOGIN_$IP-$SUB.txt"
     ```

  X. Tomcat guessable credentials

     ```
     ```

  X. RDP BlueKeep

  X. Review Nessus RCE scan results
