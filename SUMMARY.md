# Summary

* [InfoSec Notes](README.md)

## General

* [Ports scan](General/Ports_scan.md)
* [Shells](General/Shells.md)
* [File transfer](General/File_Transfer.md)
* [Pivoting](General/Pivoting.md)
* [Data exfiltration](General/Data_exfiltration.md)
* [Passwords cracking](General/Passwords_cracking.md)

## Active Directory

* [Recon - Domain Recon](Active_Directory/Recon-Domain_Recon.md)
* [Recon - AD scanners](Active_Directory/Recon-AD_scanners.md)
* [Exploitation - NTLM capture and relay](Active_Directory/Exploitation-NTLM_capture_and_relay.md)
* [Exploitation - Password spraying](Active_Directory/Exploitation-Password_spraying.md)
* [Exploitation - Domain Controllers CVE](Active_Directory/Exploitation-DC_CVE.md)
* [Exploitation - Kerberos AS_REP roasting](Active_Directory/Exploitation-Kerberos_AS_REP_Roasting.md)
* [Exploitation - Credentials theft shuffling](Active_Directory/Exploitation-Credentials_theft_shuffling.md)
* [Exploitation - GPP and shares searching](Active_Directory/Exploitation-GPP_and_shares_searching.md)
* [Exploitation - Kerberos Kerberoasting](Active_Directory/Exploitation-Kerberos_Kerberoasting.md)
* [Exploitation - ACL exploiting](Active_Directory/Exploitation-ACL_exploiting.md)
* [Exploitation - GPO users rights](Active_Directory/Exploitation-GPO_users_rights.md)
* [Exploitation - Kerberos tickets usage](Active_Directory/Exploitation-Kerberos_tickets_usage.md)
* [Exploitation - Kerberos silver tickets](Active_Directory/Exploitation-Kerberos_Silver_Tickets.md)
* [Exploitation - Kerberos delegations](Active_Directory/Exploitation-Kerberos_delegations.md)
* [Exploitation - Azure AD Connect](Active_Directory/Exploitation-Azure_AD_Connect.md)
* [Exploitation - Operators to Domain Admins](Active_Directory/Exploitation-Operators_to_Domain_Admins.md)
* [Post Exploitation - ntds.dit dumping](Active_Directory/Post_Exploitation-ntds_dit_dumping.md)
* [Post Exploitation - Kerberos golden tickets](Active_Directory/Post_Exploitation-Kerberos_Golden_Tickets.md)
* [Post Exploitation - Trusts_hopping.md](Active_Directory/Post_Exploitation-Trusts_hopping.md)
* [Post Exploitation - Persistence](Active_Directory/Post_Exploitation-Persistence.md)

## L7

* [Methodology](L7/1-Methodology.md)
* [21 - FTP](L7/21_FTP/Methodology.md)
* [22 - SSH](L7/22_SSH/Methodology.md)
* [25 - SMTP](L7/25_SMTP/Methodology.md)
* [53 - DNS](L7/53_DNS/Methodology.md)
* [80 / 443 - HTTP/S ](L7/80-443_HTTP-S/Methodology.md)
* [111 / 2049 - NFS](L7/111-2049_NFS/Methodology.md)
* [113 - Ident](L7/113_Ident/Methodology.md)
* [135 - MSRPC](L7/135_MSRPC/Methodology.md)
* [137-139 - NetBIOS](L7/137-139_NetBIOS/Methodology.md)
* [161 - SNMP](L7/161_SNMP/Methodology.md)
* [389 / 3268 - LDAP](L7//Methodology.md)
* [445 - SMB](L7/445_SMB/Methodology.md)
* [512 / 513 - REXEC / RLOGIN](L7/512-513_REXEC-RLOGIN/Methodology.md)
* [554 - RTSP](L7/554_RTSP/Methodology.md)
* [1099 - JavaRMI](L7/1099_JavaRMI/Methodology.md)
* [1433 - MSSQL](L7/1433_MSSQL/Methodology.md)
* [1521 - ORACLE_DB](L7/1521_ORACLE_DB/Methodology.md)
* [3128 - Proxy](L7/3128_Proxy/Methodology.md)
* [3306 - MySQL](L7/3306_MySQL/Methodology.md)
* [3389 - RDP](L7/3389_RDP/Methodology.md)
* [5985 / 5986 - WSMan](L7/5985-5986_WSMan/Methodology.md)
* [8000 - JDWP](L7/8000_JDWP/Methodology.md)
* [9100 - Printers](L7/9100_Printers/Methodology.md)
* [11211 - memcached](L7/11211_memcached/Methodology.md)
* [27017 / 27018 - MongoDB](L7/27017-27018_MongoDB/Methodology.md)

## Windows

* [Lateral movements](Windows/Lateral_movements.md)
* [Local privilege escalation](Windows/Local_privilege_escalation.md)
* [Bypass AppLocker](Windows/Bypass_AppLocker.md)
* [Bypass PowerShell ConstrainedLanguageMode](Windows/Bypass_PS_ConstrainedLanguageMode.md)
* [Post exploitation](Windows/Post_exploitation.md)

## Linux

* [Local privilege escalation](Linux/Local_privilege_escalation.md)
* [Post exploitation](Linux/Post_exploitation.md)

## DFIR

* [Collectors](DFIR/Collectors/README.md)
  * [Velociraptor](DFIR/Collectors/Velociraptor.md)
* [Memory](DFIR/Memory.md)
* [Windows](DFIR/Windows/README.md)
  * [Artefacts overview](DFIR/Windows/Artefacts/_Artefacts_overview.md)
    * [KAPE](DFIR/Windows/Artefacts/_KAPE.md)
    * [Amcache](DFIR/Windows/Artefacts/Amcache.md)
    * [EVTX](DFIR/Windows/Artefacts/EVTX.md)
    * [Jumplist](DFIR/Windows/Artefacts/Jumplist.md)
    * [LNKFile](DFIR/Windows/Artefacts/LNKFile.md)
    * [MFT](DFIR/Windows/Artefacts/MFT.md)
    * [Outlook_files](DFIR/Windows/Artefacts/Outlook_files.md)
    * [Prefectch](DFIR/Windows/Artefacts/Prefectch.md)
    * [RecentFilecache](DFIR/Windows/Artefacts/RecentFilecache.md)
    * [RecycleBin](DFIR/Windows/Artefacts/RecycleBin.md)
    * [Shellbags](DFIR/Windows/Artefacts/Shellbags.md)
    * [Shimcache](DFIR/Windows/Artefacts/Shimcache.md)
    * [Timestamps](DFIR/Windows/Artefacts/Timestamps.md)
    * [UsnJrnl](DFIR/Windows/Artefacts/UsnJrnl.md)
  * [TTPs analysis](DFIR/Windows/TTPs_Analysis/README.md)
    * [Accounts usage](DFIR/Windows/TTPs_Analysis/Accounts_usage.md)
    * [Local persistence](DFIR/Windows/TTPs_Analysis/Local_persistence.md)
    * [ASEP](DFIR/Windows/TTPs_Analysis/ASEP.md)
    * [PowerShell activity](DFIR/Windows/TTPs_Analysis/PowerShell_activity.md)
    * [Program execution](DFIR/Windows/TTPs_Analysis/Program_execution.md)
    * [Timestomping](DFIR/Windows/TTPs_Analysis/Timestomping.md)
    * [EVTX integrity](DFIR/Windows/TTPs_Analysis/EVTX_integrity.md)
    * [ActiveDirectory replication metadata](DFIR/Windows/TTPs_Analysis/ActiveDirectory_replication_metadata.md)
    * [ActiveDirectory persistence](DFIR/Windows/TTPs_Analysis/ActiveDirectory_persistence.md)
* [Linux](DFIR/Linux/README.md)
  * [Timestomping](DFIR/Linux/Timestomping.md)
* [Web logs](DFIR/Web_logs.md)

## Phishing

* [Office Documents](Phishing/OfficeDocuments.md)

## Web applications

* [Recon - Server exposure](WebApps/Recon-Server_exposure.md)
* [Recon - Hostnames discovery](WebApps/Recon-Hostnames_discovery.md)
* [Recon - Application mapping](WebApps/Recon-Application_mapping.md)
* [Recon - Attack surface overview](WebApps/Recon-Attack_surface.md)
* [CMS & softwares](WebApps/CMS_and_softwares/README.md)
  * [ColdFusion](WebApps/CMS_and_softwares/ColdFusion.md)
  * [DotNetNuke](WebApps/CMS_and_softwares/DotNetNuke.md)
  * [Jenkins](WebApps/CMS_and_softwares/Jenkins.md)
  * [Jira](WebApps/CMS_and_softwares/Jira.md)
  * [Ovidentia](WebApps/CMS_and_softwares/Ovidentia.md)
  * [WordPress](WebApps/CMS_and_softwares/WordPress.md)
* [Exploitation - Overview](WebApps/Exploitation-Overview.md)
* [Exploitation - Authentication](WebApps/Exploitation-Authentication.md)
* [Exploitation - LDAP injections](WebApps/Exploitation-LDAP_injections.md)
* [Exploitation - Local and remote file inclusions](WebApps/Exploitation-Local_and_remote_file_inclusions.md)
* [Exploitation - File upload](WebApps/Exploitation-File_upload.md)
* [Exploitation - SQL injections](WebApps/Exploitation-SQL_injections/README.md)
  * [SQLMAP.md](WebApps/Exploitation-SQL_injections/SQLMAP.md)
  * [MSSQL.md](WebApps/Exploitation-SQL_injections/MSSQL.md)
  * [MySQL.md](WebApps/Exploitation-SQL_injections/MySQL.md)
  * [SQLite.md](WebApps/Exploitation-SQL_injections/SQLite.md)
* [Exploitation - NoSQL injections](WebApps/Exploitation-NoSQL_injections/README.md)
  * [NoSQLMap.md](WebApps/Exploitation-NoSQL_injections/NoSQLMap.md)
  * [mongoDB.md](WebApps/Exploitation-NoSQL_injections/mongoDB.md)
* [Exploitation - GraphQL](WebApps/Exploitation-GraphQL.md)

## Binary exploitation

* [Linux - ELF64 ROP leaks](BinExploit/Linux/ELF64_ROP_leaks.md)
* [(Very) Basic reverse](BinExploit/Reverse.md)

## Android

* [Static analysis](Android/Static_Analysis.md)
