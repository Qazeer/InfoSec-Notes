# MongoDB - Methodology

### Overview

MongoDB is a cross-platform document-oriented database program developed by
MongoDB Inc and initialy released February 11, 2009.

Classified as a NoSQL database program, MongoDB uses JSON-like documents with
schemata.

### Network scan and basic recon

`nmap` can be used to scan the network for exposed MongoDB database services.

`nmap` includes the following default NSE scripts, triggered by usning `-sC`:
  - `mongodb-info`, which will attempts to get build info and server status
    (sysinfo, MongoDB version, current and max connections, etc.)

  - `mongodb-databases`, which will attempts to get a list of databases by using
    the listDatabases() function (by default, through an unauthenticated
    access).  

```
nmap -v -sV -sC -oA nmap_MongoDB -p 27017,27018 <HOST | RANGE | CIDR>
```

### HTTP interface

MongoDB provides a monitoring and administration HTTP interface. `mongod`
versions greater than 2.6 run by default with the http interface disabled and
the `--rest` option must be specified whenever starting the service.

The port used for the HTTP interface is 1000 more than the configured
mongod port thus being 28017 for a default installation.

An exposed HTTP interface could be leveraged to leak information about the
MongoDB components and databases.

### Authentication brute force

Starting from MongoDB version 3.0, MongoDB uses a challenge and response
mechanism: `SCRAM-SHA-1`. SCRAM-SHA-1 verifies supplied user credentials
against the user’s name, password and database. The user’s database is the
database where the user was created, and the user’s database and the user’s name
together serves to identify the user.

Brute forcing MongoDB service is thus quite diffuclt as, in addition to the
username and password, a correct database name has to be provided.

The `nmap` NSE script `mongodb-brute` and the `Metasploit` module
`auxiliary/scanner/mongodb/mongodb_login` can be used to brute force credentials
on the service:

```
# Include an empty line in the passwords wordlist to test for empty password
nmap -v -sV --script mongodb-brute --script-args "userdb=<USERNAMES_FILE>,passdb=<PASSWORDS_FILE>" -p 27017,27018 <HOST | RANGE | CIDR>

msf > use auxiliary/scanner/mongodb/mongodb_login
```

### Misconfigurations and known vulnerabilities

The `mongoaudit` python script can be used to detect misconfigurations and known
vulnerabilities.

As of December 2018, the following tests are conducted:

  - MongoDB listens on a port different to default one
  - Server only accepts connections from whitelisted hosts / networks
  - MongoDB HTTP status interface is not accessible on port 28017 (See
    "HTTP interface" above)
  - MongoDB is not exposing its version number
  - MongoDB version is newer than 2.4
  - TLS/SSL encryption is enabled
  - Authentication is enabled
  - SCRAM-SHA-1 authentication method is enabled
  - Server-side Javascript is forbidden *
  - Roles granted to the user only permit CRUD operations *
  - The user has permissions over a single database *
  - Security bug CVE-2015-7882
  - Security bug CVE-2015-2705
  - Security bug CVE-2014-8964
  - Security bug CVE-2015-1609
  - Security bug CVE-2014-3971
  - Security bug CVE-2014-2917
  - Security bug CVE-2013-4650
  - Security bug CVE-2013-3969
  - Security bug CVE-2012-6619
  - Security bug CVE-2013-1892
  - Security bug CVE-2013-2132

Once started from the command line, `mongoaudit` makes use of a terminal
graphical interface that can be used to start and follow the testing process.  

### Database access

The mongo CLI shell is an interactive JavaScript interface that can be used to
query and update data as well as perform administrative operations on MongoDB
databases.

```
# Specifying --password without the user’s password, will make the shell prompt for the password
mongo --username <USERNAME> --password --authenticationDatabase <DATABASE> --host <HOST> --port <PORT>

mongo mongodb://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>?authSource=<AUTH_DATABASE>
```

The supported mongo shell commands are:

  - `db` display the current database
  - `show dbs`, equivalent to `db.adminCommand( { listDatabases: 1 } )`, list
    the available databases, results conditionned by the authentication enforced
    and the current user access rights  
  - `use <DATABSE>` switch to the specified database
  - `db.getCollectionNames()`
  - `db.getCollection("<COLLECTION_NAME").find({}).limit(50)`
For more information about the MongoDB operations syntax, refer to the official
documentation: `https://docs.mongodb.com/manual/crud/`.

Multiple GUI tools can be used to access a MongoDB database with out the need to
know the mongo NoSQL syntax. The `Studio 3T` (previously known as `MongoChef`)
provides a complete and an intuitive user-friendly graphical interface through
a standalone executable.

### NoSQL injection

Applications using MongoDB could be vulnerable to NoSQL injections.

Note that since MongoDB version 2.4 (released in March 2013), the exploit
possibilities through a NoSQL injection are limited.

For a detailed methodology to conduct NoSQL injection against MongoDB, refer
to the `[WebApps] NoSQL injections - MongoDB` note.

### Compromised system to database access

If an access to the underlying operating system hosting the MongoDB service
could be obtained, it is possible to modify the MongoDB configuration to access
the database with out knowledge of the database users.

To add a superuser to the database:

  - Stop the MongoDB service `sudo service mongod stop`
  - Edit the MongoDB configuration file `mongodb.conf` 
