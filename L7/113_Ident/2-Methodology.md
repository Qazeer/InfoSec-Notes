# Ident - Methodology

The Ident Protocol (Identification Protocol) is a protocol that helps identify
the user of a particular TCP service.  

The Ident service can be queried to retrieve the username of the user who runs
the program that uses the specified TCP port.  

An exposed Ident service can be useful to identity services running under high
privileges.

### Network scan

Nmap can be used to detect exposed Ident services:

```
nmap -v -p 113 -A <HOSTS>
```

### Ident query

The python script identi.py can be used to query the Ident service:

```
identi.py [-h] [-q QUERY_PORT [QUERY_PORT ...]] [-p PORT] [-a] [-v] <HOST>

# Specified ports
identi.py <HOST> -q <PORT1> <PORT2> ...

# All ports
identi.py -a <HOST>
```
