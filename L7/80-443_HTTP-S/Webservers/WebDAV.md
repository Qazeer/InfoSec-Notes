# Hypertext Transfer Protocol / Secure  - WebDAV - Methodology

### Overview

Web Distributed Authoring and Versioning (WebDAV) is an extension of the
Hypertext Transfer Protocol (HTTP) that allows clients to perform remote Web
content authoring operations. WebDAV is defined in RFC 4918 by a working group
of the Internet Engineering Task Force.

The WebDAV protocol provides a framework for users to create, change and move
documents on a server.

###### WebDAV verbs

WebDAV extends the set of standard HTTP verbs and headers allowed for request
methods.

The added verbs include:

  - COPY: copy a resource from one URI to another
  - LOCK: put a lock on a resource. WebDAV supports both shared and exclusive
    locks.
  - MKCOL: create collections (a.k.a. a directory)
  - MOVE: move a resource from one URI to another
  - PROPFIND: retrieve properties, stored as XML, from a web resource. It is
    also overloaded to allow one to retrieve the collection structure
    (also known as directory hierarchy) of a remote system.
  - PROPPATCH: change and delete multiple properties on a resource in a single
    atomic act
  - UNLOCK: remove a lock from a resource

### Network scan and basic recon

`nmap` can be used to scan the network for exposed HTTP WebDAV services.

`nmap` includes the following default NSE script, triggered by usning `-sC`:
  - `http-webdav-scan`, which will detect and attempt to retrieve information
  about a WebDAV installation, notably the allowed verbs.

```
nmap -v -sV -sC -oA nmap_WebDAV -p 80,443  <HOST | RANGE | CIDR>
```

### WebDAV client

The `DAV Explorer` utility (`dave` on Linux systems) can be used to interact
with a WebDAV service through Linux like commands interfaced with the WebDAV
HTTP verbs.

The supported commands are:

  - **cat**        shows the contents of a remote file
  - **cd**         changes directories
  - **copy**       copies one remote resource to another
  - **delete**     deletes a remote resource
  - **edit**       edits the contents of a remote file
  - **get**        downloads the file or directory at URL
  - **help**       prints list of commands or help for CMD
  - **lcd**        changes local directory
  - **lls**        lists local directory contents
  - **lock**       locks a resource
  - **ls**         lists remote directory contents or file props
  - **mkcol**      make a remote collection (directory)
  - **move**       moves a remote resource to another
  - **open**       connects to the WebDAV-enabled server at URL
  - **option**     show the HTTP methods allowed for a URL
  - **propfind**   show the properties of a resource
  - **put**        uploads a local file or directory to URL
  - **pwd**        prints the currently opened URL (working directory)
  - **quit**       exits dave
  - **set**        sets a custom property on a resource
  - **sh**         executes a local command (alias !)
  - **showlocks**  show my locks on a resource
  - **steal**      remove ANY locks on a resource
  - **unlock**     unlocks a resource
  - **unset**      unsets a property from a resource

Usage:

```
dave <URL>
dave -u <USERNAME> -p <PASSWORD> <URL>
```

### Automated files upload tests with davtest

The `davtest` Perl script can be used to automatically detect if files of
various types can be upload on a WebDAV server.

The script attempts to:

   - PUT test files of various programming languages
   - PUT files with .txt extension then MOVE them to executable file types      

`davtest` can also be used to upload a specific file on a WebDAV server.

Usage:

```
davtest -url <URL>
davtest -url <URL> -directory <UPLOAD_DIR> -uploadfile <LOCAL_FILE_PATH> --uploadloc <REMOTE_FILE_NAME>                                
```

# Windows 2k3 R2
