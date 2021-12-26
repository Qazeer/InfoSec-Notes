# Red Team - OpSec Operating systems

### Windows

###### Computer's hostname update (to match the environment / context)

It is recommended to update the hostname of the system that will connect to
the internal network, to help blend in normal traffic.

```bash
# Changes the hostname of the local computer.
WMIC ComputerSystem where Name="%COMPUTERNAME%" call Rename Name=<NEW_HOSTNAME>
Rename-Computer -NewName <NEW_HOSTNAME>

# Restarts the computer for the hostname to be effective.
shutdown.exe -r -t 0
Restart-Computer
```

###### Disabling LLMNR and NetBIOS protocols

It is recommended to disable the `LLMNR` and `NetBIOS` protocols that may leak
`Net-NTLM(v1|v2)` credentials on the local subnet.

```bash
# Disables the use of the LLMNR protocol.
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force

# Disables the use of the use of the NetBIOS protocol.
$RegKey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $RegKey | foreach { Set-ItemProperty -Path "$RegKey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
```

###### MAC address

It is recommenced to change the `MAC address` of the virtual machine, in order
to bypass simple `Network Access Control (NAC)` solutions and blend in the
usual network traffic. The `MAC` address of a virtual machine should be changed
through both the hypervisor and the guest operating system.

```
# Shows the network interfaces and their respective MAC address ("Physical Address").
ipconfig.exe /all

# Changes the MAC address through the Device manager (devmgmt.msc) graphical utility.
Device Manager -> Network adapters -> Right click on the network adapter of the network interface -> Properties
  -> Advanced -> Network Address -> Value: MAC address.
```

###### DNS servers

It is recommended to set the system-wide `DNS` nameservers to `localhost`, in
order to avoid leaking `DNS` requests (from Windows, Web browsers, or security
products) that may indicate an unusual traffic and generate alerts (from
solutions such as `DarkTrace` or `Vectra`).

```bash
# Shows the network interfaces settings. Can be used to retrieve the interface name and validate settings updates.
netsh interface ip show config

# Statically sets the primary DNS server for the given interface to the loopback address.
# The following error message may be returned with no incidence: "The configured DNS server is incorrect or does not exist".
netsh interface ip set dns "Ethernet 0 | <INTERFACE>" static 127.0.0.1

# ! Not working for some reason ! It is recommended to use tools that allow DNS nameservers specification.
Add-DnsClientNrptRule -Namespace ".google.com" -NameServers "8.8.8.8"
```

###### Disabling IPv6

If `IPv6` is not used in the target environment, it is recommended to disable
its support at a network interface level.

```
Set-NetAdapterBinding -Name "<INTERFACE>" -ComponentID ms_tcpip6 -Enabled $False
```

###### Windows Firewall

The Windows Firewall can be configured to block all inbound / outbound
connections that do not match a rule, which allow to stricly control the
network footprint of the system on the internal network.

The following `netsh` commands or PowerShell cmdlets can be used to enable the
Windows Firewall, and block all inbound / outbound traffic:

```bash
# Enables all Windows firewall profiles.
netsh advfirewall set allprofiles state on
Set-NetFirewallProfile -All -Enabled True

# Block all inbound and outbound traffic for all Windows firewall profiles.
# The firewall can be configured to block all inbound connections or only block inbound connections that do not match an inbound rule.
netsh advfirewall set allprofiles firewallpolicy [blockinboundalways | blockinbound],blockoutbound
Set-NetFirewallProfile –All [-AllowInboundRules False] –DefaultInboundAction Block –DefaultOutboundAction Block

# Delete every inbound and outbound rules currently defined.
netsh advfirewall firewall delete rule name=all
Remove-NetFirewallRule -All
```

The following commands can be used to allow inbound / outbound traffic on a
remote host or program basis:

```bash
# Allows inbound connections over the specified TCP port.
# Only effective if the firewall is configured to take into account inbound rules.
netsh advfirewall firewall add rule name="Open inbound port <PORT>" dir=in action=allow protocol=TCP localport=<PORT>
New-NetFirewallRule -DisplayName "Open inbound port <PORT>" -Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT>

# Allows outbound connections to the specified host(s).
# ! Make sure that traffic to internal DNS servers is not allowed if the DNS servers are configured system-wide. Otherwise Windows / browser / tools DNS requests will leak !
netsh advfirewall firewall add rule name="Open to hosts <XXX>" dir=out action=allow remoteip=<IPv4 | IPv6 | SUBNET (ex: 1.2.3.4/24 | 1.2.3.4/255.255.255.0) | RANGE (ex: 1.2.3.4-1.2.3.7)>
New-NetFirewallRule -DisplayName "Open to hosts <XXX>" -Direction Outbound -Action Allow -RemoteAddress <IPv4 | IPv6 | SUBNET (ex: 1.2.3.4/24 | 1.2.3.4/255.255.255.0) | RANGE (ex: 1.2.3.4-1.2.3.7)>

# Allows outbound connections of the specified program.
netsh advfirewall firewall add rule name="<APPLICATION> outbound" dir=out action=allow program="<BINARY_FULL_PATH>"
New-NetFirewallRule -DisplayName "<APPLICATION> outbound" -Direction Outbound -Action Allow -Program "<BINARY_FULL_PATH>"
```

The settings of the Windows Firewall can be restored to their default values:

```bash
netsh advfirewall reset
(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()
```

--------------------------------------------------------------------------------

### References

http://woshub.com/manage-windows-firewall-powershell/ <br>
https://infinitelogins.com/2020/11/23/disabling-llmnr-in-your-network/
