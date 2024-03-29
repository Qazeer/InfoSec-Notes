# Real Time Streaming Protocol - Methodology

### Overview

The Real Time Streaming Protocol (RTSP) is a non-stateless network control
protocol designed for media streaming between endpoints.

RTSP defines a number of commands for controlling multimedia playback, which can
be send both way, from client to server or vice versa.

The connection to a RTSP service is made using an RTSP URL of the following
format: `rtsp://<HOSTNAME | IP>:<PORT>/<STREAM_ROUTE>`.

### Network scan

`nmap` can be used to scan the network for `RTSP` services:

```
nmap -v -p 554 -sV -sC -oA nmap_smb <RANGE | CIDR>
```

The `Cameradar` GO tool can be used to scan the network for RTSP services and
conduct automated dictionary attacks on the stream route and username/password
of the retrieved services.  

```
# sudo service docker start

docker pull ullaakut/cameradar

# Scan ports 554, 5554, 8554
docker run ullaakut/cameradar -t <HOSTNAME | IP | CIDR | RANGE | FILE>

docker run <FILES_DIR_PATH>:/tmp/dictionaries ullaakut/cameradar -t <HOSTNAME | IP | CIDR | RANGE | FILE> -p "1-65535"-r <FILE_STREAM_ROUTES> -c <FILE_CREDENTIALS_JSON>
```

### RTSP stream access

The utility `VLC Media Player` can be used to access the video stream using
`Open Network Stream` / `Ctrl + N` and specifying the RTSP URL in the following
format:

```
rtsp://<HOSTNAME | IP>:<PORT>/<STREAM_ROUTE>
rtsp://<USERNAME>:<PASSWORD>@<HOSTNAME | IP>:<PORT>/<STREAM_ROUTE>
```
