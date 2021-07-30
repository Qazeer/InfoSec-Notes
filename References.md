# References

### AD

###### Azure AD Connect

https://blog.xpnsec.com/azuread-connect-for-redteam/
https://www.synacktiv.com/publications/azure-ad-introduction-for-red-teamers.html
https://github.com/fox-it/adconnectdump
https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/
https://www.varonis.com/blog/azure-skeleton-key/
https://docs.microsoft.com/fr-fr/azure/active-directory/manage-apps/migrate-adfs-apps-to-azure
https://docs.microsoft.com/fr-fr/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization
https://docs.microsoft.com/fr-fr/azure/active-directory/hybrid/how-to-connect-pta

###### Credentials theft shuffling

https://stackoverflow.com/questions/18113651/powershell-remoting-policy-does-not-allow-the-delegation-of-user-credentials
https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-1/
https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/
https://powersploit.readthedocs.io/en/latest/Recon/Find-DomainUserLocation/
https://blog.cptjesus.com/posts/sharphoundtechnical
https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives
https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum
https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
https://docs.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-session_info_10

###### Kerberos

https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Article-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf
https://www.ssi.gouv.fr/uploads/IMG/pdf/Aurelien_Bordes_-_Secrets_d_authentification_episode_II_Kerberos_contre-attaque_--_planches.pdf
https://remivernier.com/index.php/2018/07/07/kerberos-exploration/
https://docs.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation

###### Kerberos tickets usage

https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It.pdf
https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html
https://gist.github.com/HarmJ0y/dc379107cfb4aa7ef5c3ecbac0133a02
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
https://github.com/GhostPack/Rubeus
https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/ConvertTo-KerberosKey.md
https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/ConvertTo-NTHash.md

###### Kerberoasting

https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/
https://github.com/GhostPack/Rubeus/blob/master/README.md

###### AS_REP roasting

https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
https://tools.ietf.org/html/rfc4120#page-60
https://beta.hackndo.com/kerberos-asrep-roasting/
https://adsecurity.org/?p=227

###### Kerberos golden and silver tickets

https://2014.rmll.info/slides/80/day_3-1010-Benjamin_Delpy-Mimikatz_a_short_journey_inside_the_memory_of_the_Windows_Security_service.pdf
https://adsecurity.org/?page_id=1821
TECHNIQUES DE PERSISTANCE ACTIVE DIRECTORY BASÉES SUR KERBEROS - MISC Hors-Série N°20
https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Silver_Ticket_Walkthrough.html

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

###### DACLs / ACEs exploit

https://www.microsoft.com/en-us/download/details.aspx?id=46899
https://blog.stealthbits.com/running-laps-in-the-race-to-security/
https://github.com/leoloobeek/LAPSToolkit

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

###### ntds.dit dumping

https://docs.microsoft.com/fr-fr/windows-server/storage/file-server/volume-shadow-copy-service
https://github.com/giuliano108/SeBackupPrivilege/blob/master/README.md
https://pure.security/dumping-windows-credentials/
https://cqureacademy.com/cqure-labs/cqlabs-dsinternals-powershell-module
https://www.dsinternals.com/en/dumping-ntds-dit-files-using-powershell/
https://wiki.samba.org/index.php/DRSUAPI
https://adsecurity.org/?p=1729
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410
https://blog.stealthbits.com/what-is-dcsync-an-introduction/

###### Kerberos_delegations

https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Article-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf
https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
https://adsecurity.org/?p=1667
https://www.synetis.com/risques-associes-a-la-delegation-kerberos/
https://blog.stealthbits.com/unconstrained-delegation-permissions/
https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/
https://docs.microsoft.com/fr-fr/dotnet/api/system.security.principal.wellknownsidtype?view=dotnet-plat-ext-3.1
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a
https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
https://beta.hackndo.com/unconstrained-delegation-attack/#rappels--unconstrained-delegation
https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
https://chryzsh.github.io/relaying-delegation/
https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
https://alsid.com/fr/node/143
https://alsid.com/fr/node/144
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
https://stackoverflow.com/questions/57171940/accessing-parsing-msds-allowedtoactonbehalfofotheridentity-ad-property-in-c-sh

###### Operators to Domain Admins

https://adsecurity.org/?p=3700
https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
https://adsecurity.org/?p=4064
https://www.youtube.com/watch?v=8KJebvmd1Fk
https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges
https://github.com/FuzzySecurity/Capcom-Rootkit
https://github.com/tandasat/ExploitCapcom

###### Active Directory trusts

https://docs.microsoft.com/fr-fr/azure/active-directory-domain-services/concepts-forest-trust
https://blogs.msmvps.com/acefekay/2016/11/02/active-directory-trusts/
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c9efe39c-f5f9-43e9-9479-941c20d0e590
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962
https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/
https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
https://www.ssi.gouv.fr/uploads/IMG/pdf/Aurelien_Bordes_-_Secrets_d_authentification_episode_II_Kerberos_contre-attaque_--_planches.pdf
https://github.com/wavestone-cdt/MISC-AD-trusts-relationships/SIDHistoryInjection
http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
https://support.microsoft.com/fr-fr/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server
https://github.com/vletoux/pingcastle/issues/9

###### AD persistence

https://adsecurity.org/?p=1714
https://adsecurity.org/?p=1785
https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#primary_group_id_1000
https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
https://www.alsid.com/2020/07/14/primary-group-id-attack/
https://www.youtube.com/watch?v=6thBskwsOss
http://www.labofapenetrationtester.com/2018/04/dcshadow.html
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1
https://stealthbits.com/blog/server-untrust-account/

### File transfer

https://lolbas-project.github.io/
https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
https://github.com/frizb/Windows-Privilege-Escalation
https://github.com/cube0x0/CVE-2021-1675
https://www.giac.org/paper/gcwn/22/limiting-anonymous-logon-network-access-named-pipes-shares/100328

### WebApps

###### ColdFusion

http://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf
https://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html
http://www.pwnag3.com/2013/04/coldfusion-for-pentesters-part-2.html
https://waycool.tech/coldfusion-data-source-decryption/

###### Jenkins

https://github.com/gquere/pwn_jenkins
https://codurance.com/2019/05/30/accessing-and-dumping-jenkins-credentials/
https://www.jenkins.io/doc/book/managing/security/
https://support.cloudbees.com/hc/en-us/articles/203802500-Injecting-Secrets-into-Jenkins-Build-Jobs
https://plugins.jenkins.io/mask-passwords/
https://www.jenkins.io/doc/book/architecting-for-scale/

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
https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
https://www.secureauth.com/blog/playing-relayed-credentials
https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc160954(v=msdn.10)?redirectedfrom=MSDN
https://github.com/NotMedic/NetNTLMtoSilverTicket

###### NTLM relay ADIDNS

https://blog.netspi.com/exploiting-adidns/#adidnszones
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-integrated-dns-zones

### L7

###### DNS

https://medium.com/iocscan/how-dnssec-works-9c652257be0

###### LDAP

https://ldap.com/dit-and-the-ldap-root-dse/
https://ldapwiki.com/wiki/ANONYMOUS%20SASL%20Mechanism
https://ldap.com/the-ldap-search-operation/
https://docs.oracle.com/cd/E19476-01/821-0506/ldapsearch-examples.html

###### RPC

https://pubs.opengroup.org/onlinepubs/9629399/chap2.htm
Network Security Assessment: Know Your Network
https://publications.opengroup.org/c706
https://book.hacktricks.xyz/pentesting/135-penstesting-wrpc
https://actes.sstic.org/SSTIC06/Dissection_RPC_Windows/SSTIC06-article-Pouvesle-Dissection_RPC_Windows.pdf
http://etutorials.org/Networking/network+security+assessment/Chapter+9.+Assessing+Windows+Networking+Services/9.2+Microsoft+RPC+Services/
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/cca27429-5689-4a16-b2b4-9325d93e4ba2
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15
https://tools.ietf.org/html/rfc1831
https://redmondmag.com/articles/2004/02/01/the-magic-of-rpc-over-http.aspx
https://www.windows-security.org/windows-service/rpc-endpoint-mapper
https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/96952411-1d17-4fe4-879c-d5b48a264314
https://kb.juniper.net/InfoCenter/index?page=content&id=KB12057&pmv=print&actp=&searchid=&type=currentpaging
https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/
https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
https://beta.hackndo.com/constrained-unconstrained-delegation/
https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol?redirectedfrom=MSDN

###### NetBIOS

https://www.itprotoday.com/compute-engines/knowing-angles-netbios-suffixes
https://www.itprotoday.com/compute-engines/what-are-netbios-suffixes-16th-character
Network Security Assessment: Know Your Network
Windows NT TCP/IP Network Administration

###### SMB

https://www.petri.com/how-to-get-ntfs-file-permissions-using-powershell

###### Java RMI

https://docs.oracle.com/javase/tutorial/rmi/overview.html
https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/codebase.html
https://docs.oracle.com/javase/7/docs/technotes/guides/rmi/enhancements-7.html
https://docs.oracle.com/javase/7/docs/api/java/rmi/server/RMIClassLoader.html
https://en.wikipedia.org/wiki/Java_remote_method_invocation
https://apiacoa.org/publications/teaching/distributed/rmi.pdf
http://www2.ift.ulaval.ca/IFT-Stage/ateliers/old/RMI/atelierRMI.pdf
https://www.jmdoudoux.fr/java/dej/chap-rmi.htm
https://www.clear.rice.edu/comp310/course/rmi/stub_passing.html
https://book.hacktricks.xyz/pentesting/1099-pentesting-java-rmi
https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d
https://null-byte.wonderhowto.com/how-to/exploit-java-remote-method-invocation-get-root-0187685/
https://docs.oracle.com/javase/7/docs/api/java/rmi/registry/Registry.html
https://docs.oracle.com/javase/7/docs/api/java/rmi/registry/LocateRegistry.html
http://www.docjar.com/docs/api/sun/rmi/registry/RegistryImpl.html
https://github.com/BishopFox/rmiscout
https://github.com/NickstaDB/BaRMIe
https://labs.bishopfox.com/tech-blog/rmiscout
https://labs.bishopfox.com/tech-blog/lessons-learned-on-brute-forcing-rmi-iiop-with-rmiscout
https://ctftime.org/writeup/6953
https://github.com/allesctf/writeups/tree/master/2018/RealWorldCTF2018_Finals/RMI

###### JDWP

https://docs.oracle.com/javase/7/docs/technotes/guides/jpda/jdwp-spec.html
https://ioactive.com/hacking-java-debug-wire-protocol-or-how/
https://book.hacktricks.xyz/pentesting/pentesting-jdwp-java-debug-wire-protocol
https://www.redteamsecure.com/research/exploitation-java-debug-wire-protocol

###### memcached

https://lzone.de/cheat-sheet/memcached
https://stackoverflow.com/questions/19560150/get-all-keys-set-in-memcached

### Reverse

https://reverseengineering.stackexchange.com/questions/1935/how-to-handle-stripped-binaries-with-gdb-no-source-no-symbols-and-gdb-only-sho

### Passwords cracking

###### kwprocessor

https://github.com/hashcat/kwprocessor

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
https://docs.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/ms189237(v=sql.105)
https://docs.microsoft.com/fr-fr/sql/ssms/agent/create-an-activex-script-job-step?view=sql-server-2016
https://www.mssqltips.com/sqlservertip/2014/replace-xpcmdshell-command-line-use-with-sql-server-agent/
https://docs.microsoft.com/fr-fr/sql/ssms/agent/clear-the-job-history-log?view=sql-server-ver15

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

https://blog.1234n6.com/2018/10/available-artifacts-evidence-of.html
https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf

###### Windows event logs

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=*
https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-X.html
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738
https://repo.zenk-security.com/Forensic/A-forensic-analysis-of-apt-lateral-movement-in-windows-environment.pdf
https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
https://docs.microsoft.com/fr-fr/windows/security/threat-protection/auditing/event-4624
https://docs.microsoft.com/fr-fr/windows/security/threat-protection/auditing/event-4688
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688
https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks.pdf
https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
http://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm
https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html
https://www.powershellmagazine.com/2014/07/16/investigating-powershell-attacks/
https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging
https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
https://www.eventtracker.com/EventTracker/media/EventTracker/Files/support-docs/Integration-Guide-Windows-PowerShell.pdf
https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf
https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
https://www.andreafortuna.org/2020/06/04/windows-forensic-analysis-some-thoughts-on-rdp-related-event-ids/
https://www.13cubed.com/downloads/rdp_flowchart.pdf
https://purerds.org/remote-desktop-security/auditing-remote-desktop-services-logon-failures-1/
https://dfironthemountain.wordpress.com/2019/02/15/rdp-event-log-dfir/
https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm
https://salt4n6.com/2019/09/22/event-id-1024/
https://nullsec.us/windows-rdp-related-event-logs-the-client-side-of-the-story/

###### Active Directory persistence

https://social.technet.microsoft.com/wiki/contents/articles/51185.active-directory-replication-metadata.aspx#:~:text=Replication%20Metadata%20is%20the%20data,in%20Active%20Directory%20(AD)
https://www.harmj0y.net/blog/defense/hunting-with-active-directory-replication-metadata/
https://social.technet.microsoft.com/wiki/contents/articles/25946.metadata-de-replication-et-analyse-forensic-active-directory-fr-fr.aspx
https://www.ssi.gouv.fr/uploads/2019/04/ad_timeline_first_tc.pdf

###### Active Directory lastLogon v. lastLogonTimestamp

https://social.technet.microsoft.com/wiki/contents/articles/22461.understanding-the-ad-account-attributes-lastlogon-lastlogontimestamp-and-lastlogondate.aspx

###### Programs execution

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

###### Timestomping

https://dfir.ru/2021/01/10/standard_information-vs-file_name/
https://medium.com/@bromiley/a-journey-into-ntfs-part-4-f2865c39ac83
https://www.andreafortuna.org/2017/10/06/macb-times-in-windows-forensic-analysis/
https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/
https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html
https://alexsta-cybersecurity.com/how-to-detect-timestomping-on-a-windows-system/
https://www.sans.org/blog/ntfs-i30-index-attributes-evidence-of-deleted-and-overwritten-files/
https://www.youtube.com/watch?v=XzoYNOlJ37s

###### ShellBags

https://www.sans.org/reading-room/whitepapers/forensics/windows-shellbag-forensics-in-depth-34545
https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags/
https://lifars.com/wp-content/uploads/2020/04/LIFARS-WhitePaper-Windows-ShellBags-Forensics-Investigative-Value-of-Windows-ShellBags.pdf

###### LNKFile / JumpLists

https://www.youtube.com/watch?v=wu4-nREmzGM
https://forensicswiki.xyz/page/LNK
https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/#:~:text=LNK%20files%20are%20a%20relatively,LNK%20extension

###### Shimcache

https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf
https://www.fireeye.com/blog/threat-research/2015/06/caching_out_the_val.html
http://www.alex-ionescu.com/?p=39
https://docs.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database
https://lifars.com/wp-content/uploads/2017/03/Technical_tool_Amcache_Shimcache.pdf
https://github.com/mandiant/ShimCacheParser

### Windows

###### LPE

https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates
https://www.elastic.co/fr/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
https://docs.microsoft.com/fr-fr/windows/desktop/SecAuthZ/ace-strings
https://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
http://www.alex-ionescu.com/publications/BlueHat/bluehat2016.pdf
https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Linux-Vulnerabilities_Windows-Exploits--Escalating-Privileges-with-WSL.pdf
https://resources.infosecinstitute.com/windows-subsystem-linux/#gref
https://mspscripts.com/get-installed-antivirus-information-2/
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/
https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/
https://itm4n.github.io/localservice-privileges/

###### Bypass AppLocker

http://docshare02.docshare.tips/files/17344/173447840.pdf
https://github.com/api0cradle/UltimateAppLockerByPassList
https://hinchley.net/articles/an-approach-for-managing-microsoft-applocker-policies/
https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

###### Bypass PowerShell ConstrainedLanguage mode

http://www.3nc0d3r.com/2016/12/pslockdownpolicy-and-ways-around-it.html
https://github.com/p3nt4/PowerShdll
https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/
https://decoder.cloud/2017/11/17/we-dont-need-powershell-exe-part-3/
https://github.com/padovah4ck/PSByPassCLM
https://www.sysadmins.lv/blog-en/powershell-50-and-applocker-when-security-doesnt-mean-security.aspx
https://github.com/stonepresto/CLMBypass

###### Lateral movements

https://ss64.com/nt/sc.html
https://support.microsoft.com/en-us/help/251192/how-to-create-a-windows-service-by-using-sc-exe
https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec
https://docs.microsoft.com/fr-fr/windows/win32/winrm/portal
https://docs.microsoft.com/fr-fr/windows/win32/wmisdk/wmi-start-page
https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
https://blog.cobaltstrike.com/2017/05/23/cobalt-strike-3-8-whos-your-daddy/
https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/
https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/
https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens
http://woshub.com/powershell-remoting-via-winrm-for-non-admin-users/
https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
https://www.cybereason.com/blog/dcom-lateral-movement-techniques
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/ba4c4d80-ef81-49b4-848f-9714d72b5c01
https://blog.varonis.fr/dcom-technologie-distributed-component-object-model/
https://gallery.technet.microsoft.com/scriptcenter/89a5e3c2-0a1c-4471-b78c-136606cafdfb
https://blog.f-secure.com/endpoint-detection-of-remote-service-creation-and-psexec/
Applied Incident Response, Steve Anson
https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd
https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf

###### Post exploitation

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
https://blogs.technet.microsoft.com/ash/2016/03/02/windows-10-device-guard-and-credential-guard-demystified/
https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
https://yungchou.wordpress.com/2016/03/14/an-introduction-of-windows-10-credential-guard/
https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
https://github.com/Hackndo/lsassy/wiki
http://blog.gentilkiwi.com/securite/mscache-v2-dcc2-iteration

###### Post exploitation - Local Security Authority Protection

https://aaltodoc.aalto.fi/bitstream/handle/123456789/38990/master_Aquilino_Broderick_2019.pdf?sequence=1&isAllowed=y
https://www.programmersought.com/article/3880644118/
https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html
https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/
https://docs.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
https://posts.specterops.io/mimidrv-in-depth-4d273d19e148
https://medium.com/@gorkemkaradeniz/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5
https://github.com/alxbrn/gdrv-loader

###### Post exploitation - DPAPI

https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials
https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi
https://onedrive.live.com/view.aspx?resid=A352EBC5934F0254!3104&ithint=file%2cxlsx&authkey=!ACGFg7R-U5xkTh4
https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf
https://rastamouse.me/2017/08/jumping-network-segregation-with-rdp/
https://ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++
https://docs.microsoft.com/fr-fr/windows/win32/api/wincred/ns-wincred-credentiala?redirectedfrom=MSDN
http://revertservice.com/10/wwansvc/
