# References

### AD

###### Credentials reuse

https://stackoverflow.com/questions/18113651/powershell-remoting-policy-does-not-allow-the-delegation-of-user-credentials
https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-1/
https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/

###### Kerberoasting

https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/

### File transfer

https://github.com/frizb/Windows-Privilege-Escalation

### WebApps

###### ColdFusion

http://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf
https://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html
http://www.pwnag3.com/2013/04/coldfusion-for-pentesters-part-2.html
https://waycool.tech/coldfusion-data-source-decryption/

###### WebApps - File upload

https://www.owasp.org/index.php/Unrestricted_File_Upload
https://fr.slideshare.net/HackIT-ukraine/15-technique-to-exploit-file-upload-pages-ebrahim-hegazy
http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html
https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf
https://labs.detectify.com/2014/05/20/the-lesser-known-pitfalls-of-allowing-file-uploads-on-your-website/

####### WebApps - SQLi

https://sqlwiki.netspi.com
https://www.slideshare.net/inquis/advanced-sql-injection-to-operating-system-full-control-whitepaper-4633857

*SQLite*

http://atta.cked.me/home/sqlite3injectioncheatsheet

*MSSQL*

https://www.gracefulsecurity.com/sql-injection-cheat-sheet-mssql/
https://www.asafety.fr/mssql-injection-cheat-sheet
http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet

*sqlmap*

https://github.com/sqlmapproject/sqlmap/wiki/Usage
https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423

###### WebApps - LFI

https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/
https://www.hackingarticles.in/smtp-log-poisioning-through-lfi-to-remote-code-exceution/
https://liberty-shell.com/sec/2018/05/19/poisoning/
https://medium.com/bugbountywriteup/bugbounty-journey-from-lfi-to-rce-how-a69afe5a0899
https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf

### NTLM relay

https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html
https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning
https://pen-testing.sans.org/blog/2013/04/25/smb-relay-demystified-and-ntlmv2-pwnage-with-python

### Windows

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

###### Services

https://docs.microsoft.com/fr-fr/windows/desktop/SecAuthZ/ace-strings
https://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/

###### Priv esc - WSL

http://www.alex-ionescu.com/publications/BlueHat/bluehat2016.pdf
https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Linux-Vulnerabilities_Windows-Exploits--Escalating-Privileges-with-WSL.pdf
https://resources.infosecinstitute.com/windows-subsystem-linux/#gref

### L7

###### memcached

https://lzone.de/cheat-sheet/memcached
https://stackoverflow.com/questions/19560150/get-all-keys-set-in-memcached

### Reverse

https://reverseengineering.stackexchange.com/questions/1935/how-to-handle-stripped-binaries-with-gdb-no-source-no-symbols-and-gdb-only-sho

### Passwords cracking

###### mRemoteNG

http://cosine-security.blogspot.com/2011/06/stealing-password-from-mremote.html
https://robszar.wordpress.com/2012/08/07/view-mremote-passwords-4/

###### MSSQL

https://hackingandsecurity.blogspot.com/2018/09/abusing-sql-server-trusts-in-windows.html
https://alamot.github.io/mssql_shell/
https://blog.netspi.com/get-sql-server-sysadmin-privileges-local-admin-powerupsql/
https://docs.microsoft.com/fr-fr/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-2017
https://docs.microsoft.com/fr-fr/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-2017
https://dba.stackexchange.com/questions/199440/why-securityadmin-does-not-have-enough-permission
https://blog.netspi.com/get-sql-server-sysadmin-privileges-local-admin-powerupsql/
https://docs.microsoft.com/fr-fr/dotnet/framework/data/adonet/sql/customizing-permissions-with-impersonation-in-sql-server
https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation/
https://sqlity.net/en/1701/the-trustworthy-database-property-explained-part-2/

### Linux

###### Priv Esc - groups

https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=299007

###### Priv Esc - Process

proc man page

###### Priv Esc - drivers mmap

https://unix.stackexchange.com/questions/47208/what-is-the-difference-between-kernel-drivers-and-kernel-modules

###### Post Exploit

https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing
https://xorl.wordpress.com/2018/02/04/ssh-hijacking-for-lateral-movement/
