Linux - Priv Esc - sudo + init.d + cron
L7 - SNMP
L7 - Squid (HTB box)
L7 - Printers
L7 5985 - Windows Remote Management (WinRM)
AD - Dump ntds_dit + MS14-068
AD - (basic) https://hackingandsecurity.blogspot.com/2017/07/attack-methods-for-gaining-domain-admin.html
Android - Trad report into Note
L7 - Oracle DB to system commands
L7 - LDAP htb fulcrum
Windows - Priv esc https://labs.mwrinfosecurity.com/assets/1089/original/Windows_Services_-_All_roads_lead_to_SYSTEM-1.1-oct15.pdf
Windows - Post exploit mimikittenz
Windows - Post exploit https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1
Windows - Activate RDP
Windows - Integrate https://www.exploit-db.com/docs/english/26000-windows-meterpreterless-post-exploitation.pdf
Windows AD - Priv Esc + AD / Integrate https://fr.slideshare.net/rootedcon/carlos-garca-pentesting-active-directory
WebApps - Session
WebApps - Injection NoSQL NoSQLMap
WebApps - Injection SQL MySQL
WebApps - Injection SQL MSSQL https://www.exploit-db.com/papers/12975
WebApps - Injection SQL Oracle
WebApps - Injection SQL PSSQL
WebApps - Session modern vulnerabilities
Escape restricted shell - https://0xdf.gitlab.io/2018/12/15/htb-waldo.html
Format - replace -A by -sV -sC
Windows - https://github.com/M4ximuss/Powerless
Windows - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
Shells - Ebowla
Tunneling - https://github.com/sensepost/reGeorg
? - powershell.exe -win hidden -Ep ByPass $r = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('')); iex $r;
AD - Password spraying LDAP open / null bind to retrieve usernames list
L7 - Methodology better initial ports scan + integrate bruteforce tool
Windows Priv Esc - identify binaries
Get-ChildItem C:\ -recurse -file |ForEach-Object {if($_ -match '.+?exe$') {Get-AuthenticodeSignature $_.fullname}} | where {$_.IsOSBinary} |ForEach-Object { write-host $_ }
WebApps - XSS - https://rastating.github.io/xss-chef/
https://gist.github.com/HarmJ0y/fe676e3ceba74f22a28bd1b121182db7
Windows - Post Exploit - Bypass Windows Credentials Guard
AD - golden ticket mimikatz
AD - user session hunting
AD - trusts
AD - DCSync & DCShadow
AD - MS14-068
