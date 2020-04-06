# References

### AD

###### Credentials reuse

https://stackoverflow.com/questions/18113651/powershell-remoting-policy-does-not-allow-the-delegation-of-user-credentials
https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-1/
https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/
https://powersploit.readthedocs.io/en/latest/Recon/Find-DomainUserLocation/

###### Kerberoasting

https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/
https://github.com/GhostPack/Rubeus/blob/master/README.md

###### AS_REP roasting

https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
https://tools.ietf.org/html/rfc4120#page-60
https://beta.hackndo.com/kerberos-asrep-roasting/
https://adsecurity.org/?p=227

###### DACLs / ACEs exploit

https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
https://wald0.com/?p=112
https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
https://www.ssi.gouv.fr/uploads/IMG/pdf/Audit_des_permissions_en_environnement_Active_Directory_article.pdf
https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf
https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/
https://github.com/gdedrouas/Exchange-AD-Privesc

###### Passwords spraying

https://social.technet.microsoft.com/Forums/ie/en-US/79978325-549e-42b3-a532-1e26775982bf/how-to-reset-badpwdcount-value?forum=winserverDS

###### ACL

https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists

###### GPO users rights / GPO exploitation

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb457125(v=technet.10)?redirectedfrom=MSDN
https://adsecurity.org/?p=3658
https://wald0.com/?p=179
https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/
https://www.ssi.gouv.fr/uploads/IMG/pdf/Lucas_Bouillot_et_Emmanuel_Gras_-_Chemins_de_controle_Active_Directory.pdf
https://labs.f-secure.com/tools/sharpgpoabuse
https://blogs.technet.microsoft.com/musings_of_a_technical_tam/2012/02/15/group-policy-basics-part-2-understanding-which-gpos-to-apply/

###### BloodHound

https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf#page=45&zoom=100,92,390
https://beta.hackndo.com/bloodhound/
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
https://neo4j.com/docs/cypher-manual/current/clauses/match/

### File transfer

https://github.com/frizb/Windows-Privilege-Escalation

### WebApps

###### ColdFusion

http://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf
https://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html
http://www.pwnag3.com/2013/04/coldfusion-for-pentesters-part-2.html
https://waycool.tech/coldfusion-data-source-decryption/

###### WebApps - LDAP injections

http://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm
https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf

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

https://ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates
https://www.elastic.co/fr/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf

###### Services

https://docs.microsoft.com/fr-fr/windows/desktop/SecAuthZ/ace-strings
https://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/

###### Priv esc - WSL

http://www.alex-ionescu.com/publications/BlueHat/bluehat2016.pdf
https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Linux-Vulnerabilities_Windows-Exploits--Escalating-Privileges-with-WSL.pdf
https://resources.infosecinstitute.com/windows-subsystem-linux/#gref

### L7

###### DNS

https://medium.com/iocscan/how-dnssec-works-9c652257be0

###### LDAP

https://ldap.com/dit-and-the-ldap-root-dse/
https://ldapwiki.com/wiki/ANONYMOUS%20SASL%20Mechanism
https://ldap.com/the-ldap-search-operation/
https://docs.oracle.com/cd/E19476-01/821-0506/ldapsearch-examples.html

###### SMB

https://www.petri.com/how-to-get-ntfs-file-permissions-using-powershell

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

### DFIR

###### Windows event logs

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=*
https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-X.html
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738
https://repo.zenk-security.com/Forensic/A-forensic-analysis-of-apt-lateral-movement-in-windows-environment.pdf
https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

###### Processes

https://digital-forensics.sans.org/media/dfir_poster_2014.pdf

###### ASEP

http://www.fuzzysecurity.com/tutorials/19.html
https://digital-forensics.sans.org/blog/2019/04/29/offline-autoruns-revisited

###### Filesystem history

http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf
https://countuponsecurity.com/2017/05/25/digital-forensics-ntfs-change-journal/

###### Memory

https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
https://www.youtube.com/watch?v=BMFCdAGxVN4
https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=4
Learning Malware Analysis: Explore the concepts, tools, and techniques to analyze and investigate Windows malware (English Edition)
https://www.aldeid.com/wiki/
https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html
https://blog.scrt.ch/2010/11/22/manipulation-des-jetons-des-processus-sous-windows/

### Windows

###### Bypass AppLocker

http://docshare02.docshare.tips/files/17344/173447840.pdf
https://github.com/api0cradle/UltimateAppLockerByPassList
https://hinchley.net/articles/an-approach-for-managing-microsoft-applocker-policies/
https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

###### Lateral movements

https://ss64.com/nt/sc.html
https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe
https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
https://docs.microsoft.com/fr-fr/windows/win32/winrm/portal
https://docs.microsoft.com/fr-fr/windows/win32/wmisdk/wmi-start-page
https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

###### Post exploitation

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
https://blogs.technet.microsoft.com/ash/2016/03/02/windows-10-device-guard-and-credential-guard-demystified/
https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
https://yungchou.wordpress.com/2016/03/14/an-introduction-of-windows-10-credential-guard/
https://github.com/Hackndo/lsassy/wiki
