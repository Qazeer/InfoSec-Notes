# Proxy services - Methodology

### Overview

The `TCP` port 3128 is commonly used by web proxy servers, such as `Squid`. A
proxy server is simply a component that acts as an intermediary relay for
clients accessing network resources. Instead of connecting directly to the
resource, the client makes requests to the proxy server that fulfill, or not,
the requests and transmit the result back to the client.

Web proxies, also known as HTTP proxies, forward `HTTP` requests or `TCP`
sessions. The later are tunneled using the `CONNECT` `HTTP` verb.   
As stated in the `Squid` documentation for `CONNECT` tunnel: "the proxy
establishes a `TCP` connection to the specified server, responds with an `HTTP
200` (Connection Established) response, and then shovels packets back and forth
between the client and the server, without understanding or interpreting the
tunneled traffic".

###### Open proxies

An open proxy is a proxy server that will forward unauthenticated client's
requests, which may be leveraged to access services exposed on the proxy
server's loopback interface or network resources otherwise inaccessible.   

### Network enumeration

`nmap` can be used to scan the network for exposed Proxy services:

```
nmap -v -p 3128 -sV -sC -oA nmap_proxy <RANGE | CIDR>
```

### Open proxies detection

Multiple techniques may be used to detect open web proxies, each one having
its own advantages and disadvantages. The usage of some of the tools associated
with each techniques is detailed below.

| Description | Pros | Cons | Possible tool(s) |
|-------------|------|------|------------------|
| Attempt to access a well known website through the proxy. | Only requires a single request. | Requires the proxy server to have Internet access. <br><br> Forwarding of internal traffic may be authorized while sending of Internet going traffic restricted. | `nmap`'s `NSE` script `http-open-proxy`. <br> By default the script will attempt to access `www.google.com`. <br><br> `masscan` + `Masscan-Proxies-Tester`. <br> By default the script will attempt to access `http://perdu.com`. <br><br> *Detailed in the "Access attempt to a well known website" section below.* |
| Attempt to access localhost services (of the proxy server) through the proxy. | Requires a maximum of 65535 requests to exhaustively attempt to access every possible localhost `TCP` services. | Forwarding to remote hosts may be authorized while access to the loopback interface restricted. | `proxychains` + `nmap` full `TCP` connect scan. <br><br> `Metasploit`. <br><br> *Detailed in the "HTTP(S) proxy usage" section below.* |
| Attempt to access well known ports / services (or all ports) of remote internal hosts. | The more ports / hosts are scanned, the more thorough the approach will be. | May requires a tremendous amount of time depending on the number of ports / hosts scanned. | `proxychains` + `nmap` full `TCP` connect scan. <br><br> *Detailed in the "HTTP(S) proxy usage" section below.* |

###### Access attempt to a well known website

The `nmap`'s `NSE` script `http-open-proxy` or `masscan` followed by
`Masscan-Proxies-Tester` Python script can be used to detect open proxy servers
that can reach the Internet. `Masscan-Proxies-Tester` takes as input a
`masscan` scan output in the `List` format.

```
# Masscan-Proxies-Tester
masscan <IP | RANGE | CIDR | RANGES | etc.> -p <3128,8080,5555,8000 | PORTS> -oL <MASSCAN_OUTPUT_FILE>
# Parameters default: 10 threads, queue size of 10000, 6s timeout.
process.py [--thread=<THREAD_NUMBER>] -m <MASSCAN_OUTPUT_FILE>

# nmap's http-open-proxy.nse
nmap -v -sT -p <3128,8080,5555,8000 | PORTS> --script http-open-proxy.nse <IP | RANGE | CIDR | RANGES | etc.>
```

### HTTP(S) proxy usage

Tools may natively support the specification of a proxy to channel `HTTP` /
`HTTPS` requests or `TCP` sessions through a web proxy server. For tools that
do not offer such mechanism natively (such as `nmap`), `proxychains` can be
used to force the `TCP` connections made by the given application to pass
through the specified proxy.

Note that a number of restrictions apply when conducting ports scan through a
proxy (usage of full `TCP` connections, no forwarding of `ICMP` requests,
etc.). Refer to the `[General] Ports scan` note for more information on how to
conduct a ports scan through a Proxy server.

In additions to `HTTP(S)` proxies, `proxychains` also supports `SOCKS4` /
`SOCKS5` and `TOR` proxies. For more information on `SOCKS` proxies, refer to
the `[General] Pivoting` note.

```
# Specification of the HTTP/HTTPS proxy address in /etc/proxychains.conf or passed as argument to proxychains using the CLI "-f" option.
[ProxyList]
<http | https> <PROXY_IP> <PROXY_PORT>

# Execution of commands through proxychains.
proxychains [...]
```

The `Metasploit`'s `auxiliary/scanner/http/squid_pivot_scanning` module can
also be used to directly conduct network scan through an exposed `Squid`
proxy:

```
msf> use auxiliary/scanner/http/squid_pivot_scanning
```
