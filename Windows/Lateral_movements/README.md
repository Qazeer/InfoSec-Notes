# Windows - Lateral movement

### Expired password renewal

Expired password of local or domain accounts can be renewed over `SMB`
(`MSRPC-SAMR`) using `impacket`'s `smbpasswd.py` Python script. `smbpasswd.py`
supports authentication using an account `NTLM` hash.

```
smbpasswd.py [-newpass '<NEW_PASSWORD>'] <USERNAME>[:<CURRENT_PASSWORD>]@<HOSTNAME | IP>
smbpasswd.py [-newpass '<NEW_PASSWORD>'] -hashes <CURRENT_NT_HASH> <USERNAME>@<HOSTNAME | IP>
```

The account's previous password can be restored using `mimikatz`'s
`lsadump::changentlm` function with only the knowledge of the previous `NTLM`
hash. Note that the minimum password age policy setting may prevent an
immediate password restoration.

```
mimikatz # privilege::debug
mimikatz # lsadump::changentlm /server:<DC_FQDN | HOSTNAME> /user:<USERNAME> [/oldpassword:<CURRENT_PASSWORD> | /old:<CURRENT_NT_HASH>] [/newpassword:<NEW_PASSWORD> | /new:<NEW_NT_HASH>]
```

### Lateral movements overview

Multiples techniques can be used to access computers remotely:

| Technique / Service | Port | Required privileges | Pass-the-Hash? |
|---------------------|------|------------|---------------|
| `PsExec` | `SMB`: TCP Port 445 <br> or <br> `SMB` over `NetBIOS`: TCP port 139 | If `User Account Control (UAC)` is disabled (`EnableLUA` set to `0x0`): <br> Any local and domain accounts members of the local `Administrators` group <br><br> If `UAC` is enabled (`EnableLUA` set to `0x1`) in default configuration (standard since `Windows Vista` / `Windows Server 2008`): <br> Local built-in `Administrator` (RID: `500`) <br> Domain accounts members of the local `Administrators` group (SID: `S-1-5-32-544`) <br><br> If `UAC` remote restrictions are disabled (`LocalAccountTokenFilterPolicy` set to `0x1`): <br> Any local (and domain) accounts members of the local `Administrators` group <br><br> If `UAC` is enforced for the local built-in `Administrator` account `RID` 500 (`FilterAdministratorToken` set to `0x1`): <br> Only domain accounts members of the local `Administrators` group | Network logon <br> -> Yes |
| `Remote Desktop Protocol (RDP)` | `Terminal Services`	TCP port 3389 | Any local and domain accounts members of the local `Administrators` (SID: `S-1-5-32-544`) or `Remote Desktop Users` (SID: `S-1-5-32-555`) groups | Yes, if `Restricted Admin` mode is enabled server-side  |
| `Windows Management Instrumentation (WMI)` | `RPC` TCP port 135 <br> `RPC` randomly allocated high TCP ports: <br> - TCP ports 1024 - 5000 (<= Windows 2003R2) <br> - TCP ports 49152 - 65535 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| `Windows Remote Management (WinRM)` | `WinRM 1.1 and earlier`: <br> `HTTP` port 80 <br> or <br> `HTTPS` port 443 <br><br> `WinRM 2.0`: <br> `HTTP` port 5985 <br> or <br> `HTTPS` port 5986 | Similar privileges to `PsExec` with the addition of membership to the `Remote Management Users` (SID: `S-1-5-32-580`) group | Network logon <br> -> Yes |
| `Distributed Component Object Model (DCOM)` | Same TCP ports as `WMI` | Similar privileges to `PsExec` with the addition of membership to the `Distributed COM Users` (SID: `S-1-5-32-562`) group depanding on the target host configuration | Network logon <br> -> Yes |
| Remote Windows services | TCP port 445 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| Remote scheduled tasks | TCP port 445 | Similar privileges to `PsExec` | Network logon <br> -> Yes |
| Third parties remote administration IT tools | `AnyDesk`: TCP port 7070 <br> `TeamViewer`: TCP / UDP ports 5938 <br> ... | Technology dependent | Likely not |

To quickly identity which servers or workstations in the domain are exposing
one of the service above from your network standpoint, AD queries and `nmap`
can be used in combination (refer to the `[Active Directory] Methodology -
Domain Recon` note).

Note that the `Impacket` Python scripts presented below are available as static
stand-alone binaries for both Windows and Linux x64 operating systems on the
following GitHub repository:

```
https://github.com/Qazeer/OffensivePythonPipeline

https://github.com/ropnop/impacket_static_binaries
```

**For the forensics artefacts induced by the different lateral movement
technics refer to the `[DFIR] Windows - Analysis - Lateral movement` note.**

--------------------------------------------------------------------------------

### References

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
