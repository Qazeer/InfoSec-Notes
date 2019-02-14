# Printers - Methodology

### Overview

Multi-Function Printers (MFP) incorporates the functionality of multiple
devices in one, typically some or all of the following devices: email, fax,
photocopier, printer, scanner. Some MFP also support more advanced features:
Active Directory integration, SNMP support, wireless connection, ...

The TCP Port 9100 is commonly used by printer manufacturers, and by CUPS and
the Windows printing architecture, as the TCP port to establish a bidirectional
channel to send and receive raw data. Indeed, the port 9100, also referred to as
JetDirect, AppSocket or PDL-datastream, is not used by a specific printing
protocol but to send data that will be directly processed by the printing
device.

MFP usually support one or all of the following printing languages:
  - Printer Command Language (PCL), used to encode printed documents. Considered
    to be the de facto industry standard with a wider adoption.
  - PostScript, similar to PCL and used to encode printed documents. The
    processing required printer side to use PostScript induce a higher
    implementation cost, reserved to high-end printers.    
  - Printer Job Language (PJL), conceived as an extension to PCL that adds
    job level controls, environment and file system commands, etc.

### Network scan

`nmap` can be used to scan the network for accessible printers (with port
9100 open):

```
nmap -v -p 9100 --open -A -oA nmap_printers <RANGE | CIDR>
```

### Unrestricted document printing

### SNMP

### Printer Exploitation Toolkit (PRET)

PRET is a tool for printer security testing that connects to a printer via
network through port 9100 or USB and exploits the features of a given printer
language.

PRET interfaces UNIX-like commands to the PostScript, Printer Job Language (PJL)
or Printer Command Language (PCL) languages which are supported by most laser
printers.

PRET can be used to:
  - capture or manipulate print jobs
  - access the printer's file system and memory
  - cause physical damage to the device
