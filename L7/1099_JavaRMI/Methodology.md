# Java Remote Method Invocation - Methodology

### Overview

`Java Remote Method Invocation (Java RMI)` is a set of Java APIs that allows
Java objects running on separate `Java Virtual Machines (JVM)` to communicate.
In some regards, it can be considered the Java object-oriented equivalent of
`Remote Procedure Calls (RPC)`, with the support of transfer of serialized
Java classes and a distributed garbage collector.

As stated in the official Java documentation regarding `Java RMI` applications:
"A typical server program creates some remote objects, makes references to
these objects accessible, and waits for clients to invoke methods on these
objects. A typical client program obtains a remote reference to one or more
remote objects on a server and then invokes methods on them".

The original implementation of `Java RMI` relied on the `Java Remote Method
Protocol (JRMP)` protocol (over `TCP` / `IP`). The `JRMP` protocol is specific
to Java and can only be used to make calls from a `JVM` to another. An
implementation based on the `Common Object Request Broker Architecture (CORBA)`
standard was later implemented to support communications between non-`JVM`
components. This implementation rely on the `RMI over Internet Inter-Orb
Protocol (RMI-IIOP)` protocol. While older, the `RMI-JRMP` implementation is
still actively maintained, more integrated into Java and easier to use than
the more complicated `RMI-IIOP` implementation.

The official `TCP` port linked to the `JRMP` protocol (more precisely to the
`RMI registry` component used by the protocol) is **1099** while the TCP port
usually linked to the `RMI-IIOP` protocol is **1050**.

**While `Java RMI` shouldn't be used in modern applications (and replaced by
REST or SOAP web services for inter-process communications), it can still be
encountered in legacy or enterprise internal applications.**

###### Stub and Skeleton classes

In `Java RMI`, the client side object, usually simply referred to as the client,
communicate through `Stub` classes to server side objects on the `Java RMI`
server. The `Stub` classes act as client-side gateway for all requests to
remote objects. The remote object's stub instance is what the client will use
to make remote method calls to the remote object.

Before `Java Standard Edition (Java SE)` 5, stub classes had to be
pre-generated from the compiled code (`.class`) of the server-side class that
would be called. This step is no longer required, as the stub classes can now
be directly retrieved from the `Java RMI` server.

The `Skeleton` class used to be the server-side equivalent of the `Stub`
classes to process all incoming clients requests. Skeletons are deprecated
since `J2SE 1.2` (1998).

###### RMI registry and invocation process

The `Java RMI registry` is a naming service that hold information about the
remote objects registered by `Java RMI` servers.  

The `Java RMI` servers call the `Java RMI registry` to register (remote)
object(s) and  associate a name with each registered object, an operation known
as `binding`. When `Java RMI` clients request a reference to a named remote
object, a `lookup` to the `RMI registry` is first performed by the clients to
retrieve the remote object associated to the given name. The `Java RMI
registry` returns a reference, which correspond to the remote object's `stub`
instance, to the client.

The reference / remote object's `stub` instance is then used to call the
methods of the remote object. More precisely, each stub contains an instance of
the `RemoteRef` interface, used to carry out remote `RMI calls` on the remote
object for which it is a reference. As stated in the official Java
documentation: "the [methods of the `RemoteRef` interface] delegate method
invocation to the `stub`'s (object) remote reference and allows the reference
to take care of setting up the connection to the remote host, marshaling some
representation for the method and parameters then communicating the method
invocation to the remote host".

The `RMI calls` are conducted using different methods depending of the `Java`
version in use:
  - Since `Java 2 SDK, Standard Edition, v1.2`, using the (new)
    `invoke(Remote obj, Method method, Object[] params, long opnum)` method.
    The `opnum` parameter is a 64-bit (long) integer that represent a hash of
    the method signature.
  - using the (now deprecated) `newCall(RemoteObject obj, Operation[] op, int
    opnum, long hash)`, `invoke(RemoteCall call)`, and
    `done(RemoteCall call)` methods. The `hash` parameter is an equivalent to
    the `opnum` parameter of the new `invoke` method.

The method signatures correspond to a value calculated from the method
prototypes (method names, return and parameters' types, and number of
parameters).

**In both cases, the signatures of the methods must be known to call the
methods as they are not disclosed by the `RMI registry`.**

###### Remote class loading

As stated, `Java RMI` supports the transfer of serialized objects over the
network. In order to deserialize any serialized object received (that is
transform back the serialized objects to object instances), the `JVM` must
have access to the bytecode of the class of the object being deserialized.

Under certain circumstances, remote classes can be loaded by the `JVM` upon
reception of a serialized object (as an argument or return value) to a `Java
RMI` call, **thus resulting in code execution from the sending `JVM`**. As some
methods of `Java RMI` servers can be called by default by unauthenticated
users, remote class loading would allow unauthenticated remote code execution
on the server hosting the `Java RMI` service, under the security context and
privileges of the `JVM`.

The following conditions must be met for remote class loading to be enabled:
  - The class to load should not exist locally, that is should not be present
    in the `CLASSPATH` of the local `JVM`.

  - The `SecurityManager` should be enabled on the receiving `JVM`.

  - The receiving `JVM`'s `java.rmi.server.useCodebaseOnly` property should be
    be set to `false`. Since `JDK 7u21` (released in 2013), the
    `java.rmi.server.useCodebaseOnly` property is set to `true` by default
    (and was set to `false` in prior releases).

If the conditions for remote class loading are met, the loader will use, when
marshalling objects, the codebase `URL` specified in the `annotation` of the
object's class to download the definition of the class.

### Network scan

`nmap` can be used to scan the network for `Java RMI` services:

```
# The rmi-dumpregistry and rmi-vuln-classloader NSE scripts are introduced below.
# Only rmi-dumpregistry is included in the default scripts.

nmap -v -p <1050,1098,1099 | PORT(S)> -sV [--script "rmi-dumpregistry or rmi-vuln-classloader"] -oA nmap_javarmi <IP | RANGE | CIDR>
```

### Remote class loading

###### Detection

The `nmap` `NSE` script `rmi-vuln-classloader` and the `Metasploit` module
`auxiliary/scanner/misc/java_rmi_server` can be used to check if `Java RMI`
servers allow remote class loading.

Note however that the aforementioned tooling are, as of March 2021, [prone to
false-positives](https://github.com/rapid7/metasploit-framework/issues/10090)
likely due to the original exploit code dating back to before the `JDK 7u21`
default configuration hardening.  

```
nmap -v -p <PORT> -sV --script rmi-vuln-classloader <IP | RANGE | CIDR>

msf > use auxiliary/scanner/misc/java_rmi_server
```

###### Exploitation

The `Metasploit` module `exploit/multi/misc/java_rmi_server` can be used to
exploit `Java RMI` server allowing remote class loading to execute system
commands.

In order to be successful, the exploitation requires:
  - that the attacking machine can be reached by the `Java RMI` server (to
    retrieve the class on a webserver hosted by `Metasploit`)
  - the `Runtime.getRuntime().exec()` method can be called

Note that `Runtime.getRuntime().exec()` does make use of a shell (such as
`/bin/sh`) to deport arguments parsing. Instead it splits the command line in
an array of words, with the first word being executed and the others words used
as arguments. **In result, shell metacharacters** (| ; & > < etc.) **are not
supported by `Runtime.getRuntime().exec()`.**

```
msf > use exploit/multi/misc/java_rmi_server
```

### Enumeration of Java RMI registry bound objects

The remote objects bound in a `Java RMI registry` may be enumerated using the
`list()` method of the (deprecated) `java/rmi/registry/RegistryImpl_Stub` class
(as implemented by `Metasploit` and `nmap`) or
`java.rmi.registry.LocateRegistry` class (as implemented by `rmiscout` and
`BaRMIe`).

Note that restrictions may be implemented by the `Java RMI` server to limit the
listing of the bound objects (for example to limit listing to calls
originating from the local host).

The `nmap` `NSE` script `rmi-dumpregistry`, the `Metasploit` module
`auxiliary/gather/java_rmi_registry`, `rmiscout`, and `BaRMIe` can be used to
attempt to list the objects bound in a `Java RMI registry`.

The aforementioned tools may return different level of information, with
`nmap` and `BaRMIe` attempting to retrieve more data about the remote objects.

```
nmap -v -p <PORT> -sV --script rmi-dumpregistry <IP | RANGE | CIDR>

msf > use auxiliary/gather/java_rmi_registry

java -jar rmiscout.jar <IP> <PORT>

java -jar BaRMIe_v1.01.jar -enum <IP> <PORT>
```

The following Java code snippet can be used as a template to implement a very
simple enumerator of `Java RMI` registry bound objects. Usage of the tools above
is recommended for a better implementation of error handling.

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.RemoteException;
import static java.lang.System.out;

public class SimpleRMIClient {
    public static void main(String[] args) {
        Registry registry;
        try {
            registry = LocateRegistry.getRegistry("<HOST | IP>", 1000);
        } catch(RemoteException re) {
            throw new RuntimeException("Could not connect to remote Java RMI server.");
        }

        System.out.println("Retrieved the registry...");

        try {
            String[] objNames = registry.list();

            for (String objName: objNames) {
                System.out.println(objName);
            }
        } catch(Exception re) {
            throw new RuntimeException("An error occurred will attempting to list the bound objects.");
        }
    }
}
```

### Enumeration of available methods

###### Publicly documented classes

If publicly documented classes are enumerated, the documentation could contain
information about dangerous methods that, for example, could lead to filesystem
access or system command execution.

`BaRMIe_v1.01.jar`'s `enum` checks for the presence of some `AxiomSL`'s
methods allowing access to the underlying filesystem.

###### Method's prototypes or signatures bruteforce

`rmiscout` can be used to bruteforce methods, either by using a wordlist of
method prototypes or a permutation of possible method names, return and
parameters' types, and number of parameters. The computing method signatures
are automatically calculated from the given method prototype.

These bruteforce techniques, while not covering all possible method signatures
(2^64 possibilities), will still give a good probability of findings methods
(according to statistical analysis of 15,000+ method signatures by `rmiscout`'s
author ([@theBumbleSec](https://twitter.com/theBumbleSec)).

In order to check if a method signature is valid with out actually invoking the
method, `rmiscout` will deliberately mismatch parameters types to trigger
`RemoteExceptions`. The original supplied parameter types will be used but the
parameters will have for value a serialized instance of a non existing class
(random name). This technique cannot be used for methods which do not take
parameters.

**In `RMI-JRMP`, it is thus possible to safely bruteforce methods that take
parameters without invoking the methods. On the contrary, bruteforcing
methods that do not take input parameters requires to actually invoke the
methods, which may induce undesirable effects.**  

Enumeration of method signatures for `RMI-IIOP` services while following the
same overall principle works a bit differently. More information on the
bruteforcing process and differences can be found in the following blog post:
`https://labs.bishopfox.com/tech-blog/lessons-learned-on-brute-forcing-rmi-iiop-with-rmiscout`.

```
# Method names and prototypes can be found in the rmiscout GitHub repository: https://github.com/BishopFox/rmiscout/tree/master/lists
# --allow-unsafe: bruteforce methods that do not take parameters by invoking them.

# Bruteforce using the specified method prototypes wordlist.
java -jar rmiscout.jar wordlist [--allow-unsafe] [-n <REGISTRY_NAME>] -i <METHOD_PROTOTYPES_WORDLIST> <IP> <PORT>

# Bruteforce using the permutations of the given parameters.
# RETURN_TYPES / PARAMETER_TYPES example: String,void,int,long,boolean
# PARAMETER_LENGTH example: 1,5
java -jar rmiscout.jar bruteforce [--allow-unsafe] [-n <REGISTRY_NAME>] -i <METHOD_NAMES_WORDLIST> -r <RETURN_TYPES> -p <PARAMETER_TYPES> -l <PARAMETER_LENGTH_MIN,PARAMETER_LENGTH_MAX> <IP> <PORT>
```

### Java RMI method invocation

With knowledge of their prototypes, methods of remote objects can be invoked.
If a `SecurityManager` / (deprecated) `RMISecurityManager` is implemented, the
client must have the necessary permissions, as dicted by the `security policy`
to conduct the call. Otherwise a `SecurityException` is thrown by the service.

`rmiscout` can be used as a `Java RMI` client to invoke arbitrary methods:

```
# METHOD_PROTOTYPE example: int add(int a, int b)
# Parameters example: -p 2 -p 2
# Parameters array example: -p "a,b,c"

java -jar rmiscout.jar invoke [-n <REGISTRY_NAME>] -s '<METHOD_PROTOTYPE>' [-p <PARAM1_VALUE> [-p <PARAM2_VALUE> ...]] <IP> <PORT>
```

The following Java code snippet can be used as a template to implement a very
simple `Java RMI` client to invoke methods of remote objects. While the code
below illustrate a remote object method invocation, the use of `rmiscout`
should generally be preferred.

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.RemoteException;
import static java.lang.System.out;

public class SimpleRMIClient {
    public static void main(String[] args) {
        Registry registry;
        try {
            registry = LocateRegistry.getRegistry("<HOST | IP>", 1000);
        } catch(RemoteException re) {
            throw new RuntimeException("Could not connect to remote Java RMI server.");
        }

        System.out.println("Retrieved the registry...");

        try {
            <CLASS> objInstance = (<CLASS>) registry.lookup("<REMOTE_OBJECT_NAME>");
            System.out.println(objInstance.<METHOD>(<METHOD_PARAMETERS));
        } catch(Exception re) {
            throw new RuntimeException("An error occurred will attempting to invoke the method.");
        }
    }
}
```

###### Probe

### Java deserialization

https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/

--------------------------------------------------------------------------------

### References

https://docs.oracle.com/javase/tutorial/rmi/overview.html
https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/codebase.html
https://docs.oracle.com/javase/7/docs/technotes/guides/rmi/enhancements-7.html
https://docs.oracle.com/javase/7/docs/api/java/rmi/server/RMIClassLoader.html
https://en.wikipedia.org/wiki/Java_remote_method_invocation
https://apiacoa.org/publications/teaching/distributed/rmi.pdf
http://www2.ift.ulaval.ca/IFT-Stage/ateliers/old/RMI/atelierRMI.pdf
https://www.jmdoudoux.fr/java/dej/chap-rmi.htm
https://www.clear.rice.edu/comp310/course/rmi/stub_passing.html
https://book.hacktricks.xyz/pentesting/1099-pentesting-java-rmi
https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d
https://null-byte.wonderhowto.com/how-to/exploit-java-remote-method-invocation-get-root-0187685/
https://docs.oracle.com/javase/7/docs/api/java/rmi/registry/Registry.html
https://docs.oracle.com/javase/7/docs/api/java/rmi/registry/LocateRegistry.html
http://www.docjar.com/docs/api/sun/rmi/registry/RegistryImpl.html
https://github.com/BishopFox/rmiscout
https://github.com/NickstaDB/BaRMIe
https://labs.bishopfox.com/tech-blog/rmiscout
https://labs.bishopfox.com/tech-blog/lessons-learned-on-brute-forcing-rmi-iiop-with-rmiscout
https://ctftime.org/writeup/6953
https://github.com/allesctf/writeups/tree/master/2018/RealWorldCTF2018_Finals/RMI
