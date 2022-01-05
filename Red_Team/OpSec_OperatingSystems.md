# Red Team - OpSec Operating Systems

### Setup overview

The following setup is described in the present note:
  - An host Windows operating system using an `Hyper-V` hypervisor. the `IPv4`
    and `IPv6` connectivity is disabled for each network adapters on the host.

  - A Linux virtual machine (such as [`Kali Linux`](https://www.kali.org/)).
    The VM is configured with two network adapters: one bridged on the targeted
    network and the other as an internal / private adapter that can only be
    used by VMs on the host.

  - A `Windows 10` virtual machine
    (such as [`CommandoVM`](https://github.com/mandiant/commando-vm)). The VM is
    configured with only the internal / private adapter and network traffic
    from the VM is routed to the targeted network through the Linux VM.

In the aforementioned configuration:
  - The host operating system should not leak network traffic on the targeted
    network.
  - Only the Linux VM is bridged on the network, limiting to a single `MAC`
    address being used in the targated network. Switches might otherwise detect
    that multiple MAC addresses are used over a single physical port (such as
    through `DHCP` requests).

### Host configuration

###### Hyper-V virtual switches configuration

###### Disabling IPv4 and IPv6 connectivity

### Windows VM guest configuration

###### Updating the machine's hostname (to match the environment / context)

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

###### Updating the network interface MAC address

*Not required if the Windows VM is not bridged to the targeted network (as
described in the setup specified in this note).*

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

###### Disabling IPv6 connectivity (if not needed)

If `IPv6` is not used in the target environment, it is recommended to disable
its support at a network interface level.

```bash
Set-NetAdapterBinding -Name "<INTERFACE>" -ComponentID ms_tcpip6 -Enabled $False
```

###### Disabling the LLMNR and NetBIOS protocols

It is recommended to disable the `LLMNR` and `NetBIOS` protocols that may leak
broadcast requests (including `Net-NTLM(v1|v2)` credentials) on the local
subnet.

```bash
# Disables the use of the LLMNR protocol.
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force

# Disables the use of the use of the NetBIOS protocol.
$RegKey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $RegKey | foreach { Set-ItemProperty -Path "$RegKey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
```

###### Disabling the Web Proxy Auto Discovery protocol

It is recommended to disable the `Web Proxy Auto Discovery (WPAD)` protocol as
it may leak `DNS` and `LLMNR` requests (for `wpad*`) on the network. The `WPAD`
protocol can be disabled through the Windows settings or an `host` file entry
(advised to do both):

```
# Windows settings.
Settings -> Network & Internet -> Proxy -> Untoggle "Automatically detect settings" (-> Off)
Or Control Panel -> Network and Internet -> Internet Options -> Connections tab -> LAN settings > Uncheck "Automatically detect settings"

# host file entry
Edit %SystemRoot%\system32\drivers\etc\hosts -> Add "255.255.255.255 wpad."
```

###### Disabling 802.1x authentication

It is recommended to disable `802.1x` authentication (on a network interface /
adapter basis), as it may leak `Extensible Authentication Protocol (EAP)`
responses on the network:

```
Run (Win + R) -> type ncpa.cpl (-> OK) -> Right click on the adapter -> Properties -> Authentication tab -> Uncheck "Enable IEEE 802.1X authentication"
```

###### Disabling File and Printer Sharing & Link Layer Topology Discovery

The `Link Layer Topology Discovery (LLTD)` protocol is used to determine / map
a network's topology. The usage of the protocol is disabled by default for
"Domain" and "Public" networks. It is however recommended to disable the usage
of the protocol at a network adapter level to be certain that no `LLTD`
requests will be leaked.

It is also recommended to disable File and Printer Sharing at a adapter level.

```
Run (Win + R) -> type ncpa.cpl (-> OK) -> Right click on the adapter -> Properties -> Networking tab
  -> Uncheck "Link-Layer Topology Discovery Responder"
  -> Uncheck "Link-Layer Topology Discovery Mapper I/O Driver"
  -> Uncheck "File and Printer Sharing for Microsoft Networks"
```

###### Disabling the Simple Service Discovery Protocol

The `Simple Service Discovery Protocol (SSDP)` is used as the discovery
protocol in the `Universal Plug and Play (UPnP)` protocols suite and may result
in multicast `SSDP` alive messages being sent over the network.

It is recommended to disable the support of the `SSDP` protocol by stopping and
disabling the `SSDPSRV` Windows service:

```
# Using the sc.exe built-in CLI utility.
sc stop SSDPSRV
sc config "SSDPSRV" start=disabled

# Using the services.msc built-in graphical utility.
Run (Win + R) -> type services.msc (-> OK) -> Right click on the "SSDP Discovery" service
  -> Stop
  -> Properties -> Set "Startup type" to "Disabled"
```

###### Disabling the Internet Group Management Protocol

The `Internet Group Management Protocol (IGMP)` is used to establish multicast
group memberships on the local subnet and may result in multicast `IGMP`
membership requests / reports being sent over the network.

It is recommended to disable the support of the `IGMP` protocol and to add a
Firewall rule blocking all outbound `IGMP` traffic:

```bash
# Disables IGMP traffic by setting the IGMPLevel registry key to 0x0 (None).
netsh interface ipv4 set global mldlevel=none

# validates that the IGMPLevel registry was correctly set.
REG query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IGMPLevel

# Blocks the IGMP using the Windows Firewall.
netsh advfirewall firewall add rule name="Block outbound IGMP" dir=out action=block protocol=2
New-NetFirewallRule -DisplayName "Block outbound IGMP" -Direction Outbound -Action Block -Protocol 2
```

###### Avoiding DNS request leaks by setting DNS servers to localhost

It is recommended to set the system-wide `DNS` nameservers to `localhost`, in
order to avoid leaking `DNS` requests (from Windows, Web browsers, or security
products) that may indicate an unusual traffic and generate alerts (from
solutions such as `DarkTrace` or `Vectra`).

Then [`Name Resolution Policy Table (NRPT)`](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn593632(v=ws.11))
rules, `host` file entries, or tools that allow `DNS` nameservers
specification can be used to make controlled `DNS` requests.

```bash
# Shows the network interfaces settings. Can be used to retrieve the interface name and validate settings updates.
netsh interface ip show config

# Statically sets the primary DNS server for the given interface to the loopback address.
# The following error message may be returned with no incidence: "The configured DNS server is incorrect or does not exist".
netsh interface ip set dns "Ethernet 0 | <INTERFACE>" static 127.0.0.1

# Creates a NRPT rule so that any domains that match "*.<DOMAIN>" will be resolved using the specified nameserver(s).
# Example: Add-DnsClientNrptRule -Namespace "*.google.com" -NameServers "8.8.8.8"
Add-DnsClientNrptRule -Namespace "*.<DOMAIN>" -NameServers "<NAMESERVER_IP>"
```

###### Blocking inbound / outbound network traffic using the Windows Firewall

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

### Linux VM guest configuration

###### Updating the machine's hostname (to match the environment / context)

###### Updating the network interface MAC address

###### Avoiding DNS request leaks by setting DNS servers to localhost

###### Forwarding of network traffic from the Windows VM

--------------------------------------------------------------------------------

### References

http://woshub.com/manage-windows-firewall-powershell/

https://infinitelogins.com/2020/11/23/disabling-llmnr-in-your-network/

https://its.uiowa.edu/support/article/3576
