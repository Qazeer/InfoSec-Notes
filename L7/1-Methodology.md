# Internal pentesting - Methodology

Internal pentesting simulates an insider attack starting from a point within
the internal network.

The present note does not address Active Directory pentesting. While part of the
methodology detailed in this note can be applied for an Active Directory
pentesting, specific tools and techniques make the overall approach completely
different.

### Low hanging fruits

The first step in an internal pentesting is to look for the path of least
resistance, the low hanging fruits that can easily be detected and exploited
(unpatched systems, default or guessable passwords, etc.).

The following steps represent my personnal methodology when starting an
internal penetration test:

  1. Nessus scan on all ports testing for RCE

     ```
     # Transfomr a list of servers hostnames / IP into a comma separated list
     sed ':a;N;$!ba;s/\n/ /g' <FILE>

     Advanced Scan
     # Scan all 0-65535 ports
     Settings -> Discovery -> Scan type -> Port scan (all ports)
     # Scan for RCE vulnerabilities
     Plugins -> Only keep "Backdoors", "Gain a shell remotely" and "Service detection" enabled
     ```

  2. Ping sweep with nmap

     ```
     # IP & range
     IP="<IP>" && SUB="<MASK>"
     nmap -v -sn -oG "ping_sweep_$IP-$SUB.gnmap" "$IP/$SUB"

     # From file
     nmap -v -sn -oG "<EXPORT_NAME>.gnmap" -iL <FILENAME>

     grep Up ping_sweep_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "ping_sweep_$IP-$SUB.txt"
     ```

  3. Quick port scan with nmap

     ```
     nmap -v -sS -A -oA "quick_scan_tcp_$IP-$SUB" -iL "ping_sweep_$IP-$SUB.txt"
     ```

  4. SMB RCE vulnerabilities, notably EternalBlue & SambaCry, detection and
     exploitation

     ```
     grep -w '445' quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "SMB_$IP-$SUB.txt"
     nmap -v -p 139,445 --script=vuln -oG

     # MS17-010
     # Windows 7 and Server 2008 R2 (x64) All Service Packs
     msf> use exploit/windows/smb/ms17_010_eternalblue
     ```

  5. MSSQL default or guessable credentials

     ```
     grep -w '1433' quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "MSSQL_$IP-$SUB.txt"

     # Usernames: sa, Administrator, Administrateur
     # Passwords: blank, sa or Password123
     patator mssql_login host=FILE0 user=FILE1 password=FILE2 0="MSSQL_$IP-$SUB.txt" 1=<WORDLIST_USER> 2=<WORDLIST_PASSWORD> -x ignore:fgrep='Login failed for user'
     ```  

  6. Exposed rlogin and rexec services without password

     ```
     grep -w "512\|513" quick_scan_tcp_$IP-$SUB.gnmap | cut -d ' ' -f 2 | tee "RLOGIN_$IP-$SUB.txt"
     ```

  7. Tomcat guessable credentials

     ```
     ```

  8. Review Nessus RCE scan results
