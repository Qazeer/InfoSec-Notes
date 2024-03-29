# Simple Network Management Protocol (SNMP) - Methodology

### Overview

Simple Network Management Protocol (SNMP) is an Internet-standard protocol for
collecting and organizing information about managed devices on IP networks
and for modifying that information to change device behavior.

SNMP operates in the Application Layer of the Internet Protocol Suite
(Layer 7 of the OSI model).

Devices that typically support SNMP include cable modems, routers, switches,
servers, workstations, printers, and more.

SNMP exposes management data in the form of variables on the managed systems
organized in a management information base (MIB) which describe the system
status and configuration.   
These variables can then be remotely queried (and, in some circumstances,
manipulated) by managing applications.

An SNMP device has a lot different counters and string values inside them that
can be accessed using the SNMP protocol.

For example, a switch with 32 ports will have multiple counters for each port
that indication each port's name, its status, its bandwidth usage and more.
Many devices will keep counters indicating how many processes are running on
them including which ones are using how much CPU and memory they are using.

Three significant versions of SNMP have been developed and deployed SNMPv1 is
the original version of the protocol. More recent versions,
SNMPv2c and SNMPv3, feature improvements in performance, flexibility and
security.

###### Operation

In typical uses of SNMP, one or more administrative computers called managers
have the task of monitoring or managing a group of hosts or devices on a
computer network.  
Each managed system executes a software component called an agent which reports
 information via SNMP to the manager.

The SNMP agent receives requests on UDP port 161. The manager may send requests
from any available source port to port 161 in the agent. The agent response will
be sent back to the source port on the manager.

The manager receives notifications (Traps and InformRequests) on port 162. The
agent may generate notifications from any available port.

When used with Transport Layer Security or Datagram Transport Layer Security
requests are received on port 10161 and traps are sent to port 10162.

###### Protocol data units

SNMPv1 specifies five core protocol data units (PDUs). Two other PDUs,
GetBulkRequest and InformRequest were added in SNMPv2 and the Report PDU was
added in SNMPv3.

All SNMP PDUs are constructed as follows:

```
IP header | UDP header | version | community | PDU-type | request-id | error-status | error-index | variable bindings
```

The seven SNMP protocol data unit (PDU) types are as follows:

- GetRequest: A manager-to-agent request to retrieve the value of a variable or
list of variables. Desired variables are specified in variable bindings.
Retrieval of the specified variable values is to be done as an atomic operation
by the agent. A Response with current values is returned.

- SetRequest: A manager-to-agent request to change the value of a variable or
list of variables. Variable bindings are specified in the body of the request.
Changes to all specified variables are to be made as an atomic operation by the
agent. A Response with (current) new values for the variables is returned.

- GetNextRequest: A manager-to-agent request to discover available variables
and their values. Returns a Response with variable binding for the
lexicographically next variable in the MIB. The entire MIB of an agent can be
walked by iterative application of GetNextRequest starting at OID 0. Rows of a
table can be read by specifying column OIDs in the variable bindings of the
request.

- GetBulkRequest: Optimized version of GetNextRequest. A manager-to-agent
request for multiple iterations of GetNextRequest. Returns a Response with
multiple variable bindings walked from the variable binding or bindings in the
request. PDU specific non-repeaters and max-repetitions fields are used to
control response behavior. GetBulkRequest was introduced in SNMPv2.

- Response: Returns variable bindings and acknowledgement from agent to manager
for GetRequest, SetRequest, GetNextRequest, GetBulkRequest and InformRequest.
Error reporting is provided by error-status and error-index fields. Although
it was used as a response to both gets and sets, this PDU was called
GetResponse in SNMPv1.

- Trap: Asynchronous notification from agent to manager. SNMP traps enable an
agent to notify the management station of significant events by way of an
unsolicited SNMP message.

- InformRequest: Acknowledged asynchronous notification. This PDU was
introduced in SNMPv2 and was originally defined as manager to manager
communication. Later implementations have loosened the original definition to
allow agent to manager communications. As SNMP runs over UDP delivery of a Trap
are not guaranteed, InformRequest fixes this by sending back an acknowledgement
on receipt.

###### Community strings

The SNMP Community String is like a user id or password. It is sent along with
each SNMP and allows (or denies) access to the SNMP device.

There are three community strings for SNMPv1-v2c-speaking devices:

- SNMP Read-only community string: enables a remote device to retrieve
"read-only" information from a device. If the community string is correct,
the device responds with the requested information. If the community string is
incorrect, the device simply ignores the request and does not respond.

- SNMP Read-Write community string: used in requests for information from a
device and to modify settings on that device.

- SNMP Trap community string: included when a device sends SNMP Traps.

### Network scan

`nmap` can be used to scan the network for exposed SNMP services:

```
nmap -v -sU -p 161,162 -sV -sC -oA nmap_snmp <RANGE | CIDR>
```

### SNMPv1 & SNMPv2c community strings bruteforce

Note: SNMP Community strings are used only by devices which support SNMPv1 and
SNMPv2c protocol. SNMPv3 uses username/password authentication, along with an
encryption key.

```
onesixtyone
patator
```

### Community strings query

```
smbwalk
```

### SNMPv3 authentication bruteforce

```
patator
```
