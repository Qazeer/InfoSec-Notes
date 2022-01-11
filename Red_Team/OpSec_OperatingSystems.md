# Red Team - OpSec Operating Systems

### Setup overview

The following setup is described in the present note:
  - An host Windows operating system using an `Hyper-V` hypervisor. the `IPv4`
    and `IPv6` connectivity is disabled on the host.

  - A Linux virtual machine (such as [`Kali Linux`](https://www.kali.org/)).
    The VM is configured with two network adapters: one bridged on the targeted
    network and the other as an internal / private adapter that can only be
    used by local VMs on the host.

  - A `Windows 10` virtual machine
    (such as [`CommandoVM`](https://github.com/mandiant/commando-vm)). The VM is
    configured with only the internal / private adapter and network traffic
    from the VM is routed to the targeted network through the Linux VM.

In the aforementioned configuration:
  - The host operating system should not leak network traffic on the targeted
    network.
  - Only the Linux VM is bridged on the network, limiting the use of a single
    `MAC` address in the targeted network. Switches might otherwise detect that
    multiple MAC addresses are used over a single physical port (such as
    through `DHCP` requests).

### Host configuration

###### Hyper-V virtual switches configuration

Two virtual `Hyper-V` switches should be configured for the setup: an
`External` virtual switch bridged on the host system network adapter
(`<HYPERV_EXTERNAL_BRIDGED>`), and a `Private` virtual switch
(`<HYPERV_PRIVATE>`), that will only be used by the local virtual machines.

The procedure to create virtual switches in `Hyper-V` using the
`Hyper-V Manager` graphical utility is as follow:

```
Right click on the Hyper-V server -> Virtual Switch Manager... -> Create Virtual Switch
  # Bridged switch.
  -> Name: <HYPERV_EXTERNAL_BRIDGED>
  -> Check "External network":
  -> Specify the network adapter.

  # Private switch
  -> Name: <HYPERV_PRIVATE>
  -> Check "Private network"
```

###### Disabling IPv4 and IPv6 connectivity

The connectivity of the host operating system to the targeted network should be
disabled, so that only the Linux VM is (directly) connected to the targeted
network. In order to do so, `IPv4` and `IPv6` support on both the physical
Ethernet network adapter and the `Hyper-V` bridged external virtual switch
`<HYPERV_EXTERNAL_BRIDGED>` should be disabled.

```
# Should be done for both the physical Ethernet and Hyper-V virtual <HYPERV_EXTERNAL_BRIDGED> network adapters.
Run (Win + R) -> ncpa.cpl (-> OK) -> Right click on the adapter -> Properties
-> Networking tab
  -> Uncheck "File and Printer Sharing for Microsoft Networks"
  -> Uncheck "Internet Protocol Version 4 (TCP/IPv4)"
  -> Uncheck "Internet Protocol Version 6 (TCP/IPv6)"
  -> Uncheck "Link-Layer Topology Discovery Responder"
  -> Uncheck "Link-Layer Topology Discovery Mapper I/O Driver"
```

It is also recommended to disable the `Wi-Fi` network adapter (on systems
having such network adapter):

```bash
# Disables the "Wi-Fi" network adapter.
Disable-NetAdapter -Name "Wi-Fi"

# Enables the "Wi-Fi" network adapter to restore Wi-Fi connectivity.
Enable-NetAdapter -Name "Wi-Fi"
```

### Linux VM guest configuration

As described in the setup above, the Linux VM will have two network interfaces:
  - `<ETH_EXTERNAL>` (example: `eth0`) that will be bridged to the targeted
    network.
  - `<ETH_INTERNAL>` (example: `eth1`) that will be internal / private to the
    host.

###### Updating the machine's hostname (to match the environment / context)

It is recommended to update the hostname of the system that will connect to the
internal network, to help blend in normal traffic.

The Linux VM hostname can be updated by editing the `/etc/hostname` file. The
system must be rebooted for the hostname change to be effective.

###### Updating the network interface MAC address

It is recommenced to change the `MAC address` associated with the
`<ETH_EXTERNAL>` network adapter, in order to bypass simple
`Network Access Control (NAC)` solutions and blend in the usual network
traffic. The `MAC` address of the `<ETH_EXTERNAL>` network adapter should be
changed through both the hypervisor and the guest operating system.

The `ifconfig` utility can be used to change the `MAC address` (on the Linux
VM):

```bash
ifconfig <ETH_EXTERNAL> hw ether <MAC_ADDRESS>
```

###### Disabling IPv6 connectivity (if not needed)

If `IPv6` is not used in the target environment, it is recommended to disable
its support at a system level. `IPv6` can be disabled from `grub` as the Linux
kernel has a boot option to disable `IPv6` from startup. The `grub`
configuration file should be modified to add the `ipv6.disable=1` boot option:

```
sudo vim /etc/default/grub

Replace the GRUB_CMDLINE_LINUX_DEFAULT="quiet" line by GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1 quiet"
```

Following the modification, `grub` should be updated using `sudo update-grub`
and the system rebooted.

###### Avoiding DNS request leaks

*Avoiding self-hostname DNS requests*

By default, the Linux operating system may try to retrieve the current machine
`IP`. In order to avoid leaking unwanted `DNS` requests on the targeted
network, an entry for the system's hostname should be added in the
`/etc/hosts` file:

```bash
echo '127.0.0.1 <HOSTNAME>' | sudo tee -a /etc/hosts
```

*Setting DNS nameservers to localhost*

It is recommended to set the system-wide `DNS` nameservers to `localhost`, in
order to avoid leaking `DNS` requests (from the operating system, Web browsers,
security products, ...) that may indicate an unusual traffic and generate
alerts (from solutions such as `DarkTrace` or `Vectra`).

Setting the `DNS nameservers` through the `/etc/resolv.conf` is not sufficient
as the file is indirectly managed by the `systemd-resolved` service as well as
the `networking.service` (for instance for updates made through the
`NetworkManager`).

The `reolvconf` utility can be used to permanently define the system's
`DNS nameservers` (and so even if no network adapters are configured at the of
configuration):

```bash
# Installs the reolvconf utility.
sudo apt update && sudo apt install resolvconf

# Enables and starts the resolvconf.service service.
sudo systemctl enable resolvconf.service
sudo systemctl start resolvconf.service

# Checks the status of the resolvconf.service service.
sudo systemctl status resolvconf.service

# Defines the system DNS nameservers.
mv /etc/resolvconf/resolv.conf.d/ /etc/resolvconf/resolv.conf.d_backup/
mkdir /etc/resolvconf/resolv.conf.d/ && echo 'nameserver 127.0.0.1' > /etc/resolvconf/resolv.conf.d/head

# Updates the resolv.conf file.
sudo resolvconf -u

# Validates that the DNS nameservers modification is effective.
cat /etc/resolv.conf
```

By default, `glibc` sends all `DNS` requests to the first `DNS nameserver`
specified in the `/etc/resolv.conf` file. Using the aforementioned command,
the `nameserver 127.0.0.1` entry should be defined at the top of the
`resolv.conf` file, superseding eventual other `DNS nameservers` (notably the
eventual `DNS nameservers` provided by the targeted network `DHCP` servers).

As the Linux operating system does natively not support the definition of
`DNS nameservers` for specific domains. A third-party utility such as `dnsmasq`
must thus be used to associate specific `DNS nameservers` with specific
domains.

The following configuration file restrict can be used as a template for
`/etc/dnsmasq.conf` that configure `127.0.0.1` as the default `DNS server`
while defining specific domain and `DNS` mappings as required.

```
# Never forward plain names (without a dot or domain part).
domain-needed

# Never forward addresses in the non-routed address spaces.
bogus-priv

# Use the nameservers define in its own configuration (rather than the /etc/resolv.conf file).
no-resolv

# Define localhost as the main DNS nameserver.
server=127.0.0.1

# Answer query for the specified domain (machine hostname) only from the /etc/hosts file or DHCP.
local=/<SYSTEM_HOSTNAME>/

# Associates a specific DNS nameserver for queries to a specific domain.
# Example for Internet domain: server=/google.com/1.1.1.1
# Example for Active Direcory name resolution: server=/domain.loc/<DC_IP>
server=/<DOMAIN>/<DNS_NAMESERVER_IP>
```

The `dnsmasq` service should then be enabled and started / restarted for the
configuration to be effective:

```
sudo systemctl enable dnsmasq

sudo systemctl start dnsmasq
sudo systemctl restart dnsmasq
```

###### Blocking inbound / outbound network traffic using UFW

The `Uncomplicated Firewall (UFW)` utility can be used to block all inbound /
outbound connections that do not match a rule, which allow to strictly control
the network footprint of the system on the targeted network. `UFW` translates
rules into an `iptables` chain, which follows the first-match policy.

`IPv6` support for `UFW` should first be enabled by adding `IPV6=yes` to the
`UFW` configuration file `/etc/default/ufw`:

```
echo 'IPV6=yes' | sudo tee -a /etc/default/ufw
```

The following commands can then be used as a template to configure blocking
inbound / outbound rules with rules to allow network traffic through the
`<ETH_INTERNAL>`.

```bash
# Disables UFW while setting rules.
ufw disable

# Resets all the current firewall rules.
ufw reset

# Deny rules.
# Place holder for deny rules that should supersede any allow rules.
# Blocks the Simple Service Discovery Protocol (SSDP) protocol that emit multicast SSDP messages.
ufw deny 1900

# Allow all inbound and outbound traffic on the the <ETH_INTERNAL> interface.
ufw allow in on <ETH_INTERNAL>
ufw allow out on <ETH_INTERNAL>

# Example rules to allow traffic to a specific DNS server.
# ufw allow out to <DNS_NAMESERVER_IP> port 53

# Example rule to allow inbound connections <REMOTE_IP> on the local specified port.
# ufw allow in from <REMOTE_IP> to any port <PORT>

# Example rule to outbound connections to the specified host.
# ufw allow out to <REMOTE_IP>

# Example rules to allow network traffic on private networks.
ufw allow out to 10.0.0.0/8
ufw allow in from 10.0.0.0/8
ufw allow out to 172.16.0.0/16
ufw allow in from 172.16.0.0/16
ufw allow out to 192.168.0.0/24
ufw allow in from 192.168.0.0/24

# Sets default rules: deny all incoming traffic, deny all outgoing traffic.
ufw default deny incoming
ufw default deny outgoing

# Enables UFW back.
ufw enable

# Lists all UFW rules.
ufw status verbose
```

###### Network configuration

The `<ETH_EXTERNAL>` adapter should be configured appropriately depending on
the context of the operation, and only after the Linux and Windows VMs are
configured. For instance, the `<ETH_EXTERNAL>` adapter could rely on the target
network `DHCP` servers to obtain an `IPv4` or a static `IPv4` could be
specified.

A static `IPv4` should be configured on the `<ETH_INTERNAL>` adapter. The
static `IP` can be assigned by modifying the `/etc/network/interfaces` file:

```
# Example configuration with <ETH_INTERNAL> being eth1.

# The settings for the loopback network interface should be left unchanged.

auto eth1
iface eth1 inet static
  address 192.168.125.1
  netmask 255.255.255.0
  gateway 192.168.125.254
  dns-nameservers 127.0.0.1
```

Following the modification of the `/etc/network/interfaces` file, the
`networking` service must be restarted for the change to be effective:
`sudo systemctl restart networking`.

Then `routes` should be configured to route all network traffic through
`<ETH_EXTERNAL>`, except for network traffic on the VMs private subnet. The
`ip` built-in utility can be used to this end. **The routes configured this way
will not persist across reboots.**

```bash
# Deletes the current default route(s).
ip route del default

# Adds a new default to route network traffic through <ETH_EXTERNAL>.
ip route add default via <ETH_EXTERNAL_GATEWAY> dev <ETH_EXTERNAL>

# Adds a specific route for network traffic between VMs.
# For the example above: ip route add 192.168.125.0/24 via 192.168.125.254 dev eth1
ip route add <ETH_INTERNAL_SUBNET> via <ETH_INTERNAL_GATEWAY> dev <ETH_INTERNAL>

# Displays the routes in effect.
netstat -rt
```

*Note: the Windows VM firewall may block inbound `ICMP` packets, thus `ping`
should not be used to determine if the VMs can communicate with each others.*

###### Forwarding of network traffic from the Windows VM

`IP Forwarding` should be enabled to allow the transfer of network packets
received from the Windows VM (on the `<ETH_INTERNAL>` network adapter) to the
targeted network (through the `<ETH_EXTERNAL>` network adapter):

```bash
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
```

Then `iptables` rules can be configured to route packets from `<ETH_INTERNAL>`
to `<ETH_EXTERNAL>`:

```bash
# Adds a masquerade rule so that the network packets received from the Windows VM are modified in real-time to appear to be originating from the Linux VM.
# By doing so, receiving hosts on the targeted network will be able to send back their responses to the Linux VM instead of attempting to join the inaccessible Windows VM.
# Example: iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o <ETH_INTERNAL> -j MASQUERADE

# Adds a forwarding rule so that the network packets associated with an existing connection received on the <ETH_EXTERNAL> interface are sent to the <ETH_INTERNAL> interface.
# By doing so, the responses from remote hosts on the targeted network received for requests emitted by the Windows VM will be able to be transferred back.
# Example: iptables -A FORWARD -i eth0 -o eth1 -mstate --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i <ETH_EXTERNAL> -o <ETH_INTERNAL> -mstate --state RELATED,ESTABLISHED -j ACCEPT

# Adds a forwarding rule so that all the network packets received on the  <ETH_INTERNAL> interface are sent to the <ETH_EXTERNAL> interface.
# By doing so, all network packets received on the <ETH_INTERNAL> interface will be sent through the <ETH_EXTERNAL> interface.
# Example: iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -i <ETH_INTERNAL> -o <ETH_EXTERNAL> -j ACCEPT
```

### Windows VM guest configuration

As described in the setup above, the Windows VM will only have a
`<ETH_INTERNAL>` network adapter internal / private to the host (example
`Ethernet 1`). The network traffic from the Windows VM will be routed to the
targeted network through the Linux VM.

###### Network configuration and routing traffic to the Linux VM

*Not required for standalone Windows VM configuration.*

The default gateway of the Windows VM should be configured to point the
the `IP` of the Linux VM (of the Linux VM's internal network interface).

```
Run (Win + R) -> ncpa.cpl (-> OK) -> Right click on the <ETH_INTERNAL> network adapter (identifiable by its description: "Hyper-V Virtual Ethernet Adapter") -> Properties
  -> Internet Protocol Version 4 (TCP/IPv4) -> Properties
    -> Set a static IPv4 address ("Use the following IP address:")
      # Example.
      -> IP address: 192.168.125.2
      -> Subnet mask: 255.255.255.0
      -> Default gateway: 192.168.125.1

    -> Advanced -> Default gateways... -> Add -> <LINUX_VM_IP> (example: 192.168.125.1)

    -> Check "Validate settings upon exit"
```

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

If the Windows VM is bridged to the targeted network, it is recommenced to
change the `MAC address` associated with the network adapter bridged to the
network, in order to bypass simple `Network Access Control (NAC)` solutions
and blend in the usual network traffic. The `MAC` address of the network
adapter should be changed through both the hypervisor and the guest operating
system.

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
# Lists the network interfaces.
ipconfig.exe

# Disables IPV6 on the specified network interface.
Set-NetAdapterBinding -Name "<ETH_INTERNAL>" -ComponentID ms_tcpip6 -Enabled $False
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
Add-Content '255.255.255.255 wpad.' -Path "$Env:SystemRoot\system32\drivers\etc\hosts"
```

###### Disabling 802.1x authentication (if supported by the network adapter)

It is recommended to disable `802.1x` authentication (on a network interface /
adapter basis), as it may leak `Extensible Authentication Protocol (EAP)`
responses on the network. If `802.1x` authentication is not supported by the
`<ETH_INTERNAL>` network adapter, the `Authentication` tab will not appear in
the adapter properties.

```
Run (Win + R) -> ncpa.cpl (-> OK) -> Right click on the <ETH_INTERNAL> network adapter -> Properties
  -> Authentication tab -> Uncheck "Enable IEEE 802.1X authentication"
```

###### Disabling File and Printer Sharing & Link Layer Topology Discovery

The `Link Layer Topology Discovery (LLTD)` protocol is used to determine / map
a network's topology. The usage of the protocol is disabled by default for
"Domain" and "Public" networks. It is however recommended to disable the usage
of the protocol at a network adapter level to be certain that no `LLTD`
requests will be leaked.

It is also recommended to disable File and Printer Sharing at a adapter level.

```
Run (Win + R) -> ncpa.cpl (-> OK) -> Right click on the <ETH_INTERNAL> network adapter -> Properties
  -> Networking tab
    -> Uncheck "File and Printer Sharing for Microsoft Networks"
    -> Uncheck "Link-Layer Topology Discovery Responder"
    -> Uncheck "Link-Layer Topology Discovery Mapper I/O Driver"
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

###### Avoiding DNS request leaks by setting DNS nameservers to localhost

It is recommended to set the system-wide `DNS nameservers` to `localhost`, in
order to avoid leaking `DNS` requests (from Windows, Web browsers, or security
products) that may indicate an unusual traffic and generate alerts (from
solutions such as `DarkTrace` or `Vectra`).

Then [`Name Resolution Policy Table (NRPT)`](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn593632(v=ws.11))
rules, `host` file entries, or tools that allow `DNS nameservers`
specification can be used to make controlled `DNS` requests.

```bash
# Shows the network interfaces settings. Can be used to retrieve the interface name and validate settings updates.
netsh interface ip show config

# Statically sets the primary DNS server for the given interface to the loopback address.
# The following error message may be returned with no incidence: "The configured DNS server is incorrect or does not exist".
netsh interface ip set dns "<ETH_INTERNAL>" static 127.0.0.1

# Creates a NRPT rule so that any domains that match "*.<DOMAIN>" will be resolved using the specified nameserver(s).
# Example: Add-DnsClientNrptRule -Namespace "*.google.com" -NameServers "8.8.8.8"
Add-DnsClientNrptRule -Namespace "*.<DOMAIN>" -NameServers "<NAMESERVER_IP>"
```

###### Blocking inbound / outbound network traffic using the Windows Firewall

The Windows Firewall can be configured to block all inbound / outbound
connections that do not match a rule, which allow to strictly control the
network footprint of the system on the targeted network.

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

https://www.tecmint.com/set-permanent-dns-nameservers-in-ubuntu-debian/

https://github.com/imp/dnsmasq/blob/master/dnsmasq.conf.example

https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-18-04

https://www.marmosetelectronics.com/computing/ufw-allow-outbound-connections/

http://woshub.com/manage-windows-firewall-powershell/

https://infinitelogins.com/2020/11/23/disabling-llmnr-in-your-network/

https://its.uiowa.edu/support/article/3576
