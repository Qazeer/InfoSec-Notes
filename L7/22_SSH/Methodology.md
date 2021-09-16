# SSH - Methodology

### Network scan

[`nmap`](https://nmap.org/) can be used to scan the network for `SSH` services:

```
nmap -v -p 22 -A -oA nmap_smb <IP | RANGE | CIDR>
```

### User enumeration (CVE-2018-15473)

The `OpenSSH` service for all versions < `7.7` are vulnerable to oracle
username enumeration.

The Python script
[`sshUsernameEnumExploit`](https://github.com/Rhynorater/CVE-2018-15473-Exploit)
as well as the `Metasploit` module `auxiliary/scanner/ssh/ssh_enumusers` can
be used to validate the presence of a system user:

```
# [--threads <THREADS>] - Default to 5. If more than 10 are used, the OpenSSH service often gets overwhelmed
# [--outputFile <OUTPUTFILE>] [--outputFormat <{list,json,csv}>]
sshUsernameEnumExploit.py [--port PORT]  (--username <USERNAME> | --userList <USERLIST>) <HOST>

msf> use auxiliary/scanner/ssh/ssh_enumusers
```

### Supported authentication methods

A verbose connection attempt will display the authentication methods supported
by the server (under `debug1: Authentications that can continue:`):

```
ssh -v <HOST>
```

###### Authentication methods available

The following authentication methods are possible:

  - `password authentication`: simple request for a single password with no
    specific prompt.

  - `keyboard interactive`: more complex request for arbitrary number of pieces
    of information. Can be hooked to two-factor (or multi-factor)
    authentications (PAM, Kerberos, etc.).  

  - `public key authentication`: clients must provide a public key in the list
    of allowed keys on the server and encrypts a certain data packet using the
    private key. The public key authentication method is the only method that
    both client and server software are required to implement.

  - `host-based authentication`: host-based authentication is used to
    restrict client access only to certain hosts. This method is similar to
    public key authentication; however, the server additionally maintains a
    list of hosts mapped to their public keys and will only accept connection
    with the keys from the pre recorded host.

###### Legacy DSA public key authentication

To connect to a server using `DSA` keys with a modern `OpenSSH` client, the
`PubkeyAcceptedKeyTypes +ssh-dss` option must be added to the client config:

```
echo 'PubkeyAcceptedKeyTypes +ssh-dss' > ~/.ssh/config
```

If the client is not correctly configured, the following debug error message
will be returned during the authentication process:

```
debug1: Skipping ssh-dss key ... - not in PubkeyAcceptedKeyTypes
```

### Authentication brute force

###### Password & keyboard interactive authentication

The [`patator`](https://github.com/lanjelot/patator) multi-purpose brute-forcer
or the `auxiliary/scanner/ssh/ssh_login` `metasploit` module can be used to
brute force credentials through the `password` and `keyboard interactive`
authentication methods:

```
# auth_type: auth type to use <password|keyboard-interactive>
patator ssh_login host=<HOST> user=<USERNAME> password=<PASSWORD> -x ignore:mesg='Authentication failed.'
patator ssh_login host=<HOST> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:mesg='Authentication failed.'

msf> auxiliary/scanner/ssh/ssh_login
```

###### publickey authentication spraying

The `Metasploit`'s `auxiliary/scanner/ssh/ssh_login_pubkey` module and the
Python script [`crowbar`](https://github.com/galkan/crowbar) can be used to
brute force `SSH` keys.

While an exhaustive attack is not possible, the key based brute force can be
used for lateral movement once a private key could be compromised.

```
msf5 > use auxiliary/scanner/ssh/ssh_login_pubkey

python crowbar.py -b sshkey (-u <USERNAME> | -U USERNAME_FILE) -k <KEY_FILE | KEY_FOLDER> -s <CIDR>
```

A repository of static authorized SSH keys "hardcoded" into software and
hardware products is available in the
[`ssh-badkeys` GitHub repository](https://github.com/rapid7/ssh-badkeys).

### Known vulnerabilities

###### OpenSSL Predictable PRNG (CVE-2008-0166)

Due to a default of implementation of the seeding process in the `OpenSSL`
package, all `SSL` and `SSH` keys generated on Debian-based systems (Ubuntu,
Kubuntu, etc) between September 2006 and May 13th, 2008 are cryptographically
weak.

All possible combination of public / private RSA (2048 and 4096 bits) and DSA
(1024 bits) keys can be downloaded here:

```
https://github.com/g0tmi1k/debian-ssh/tree/master/common_keys
https://github.com/g0tmi1k/debian-ssh/tree/master/uncommon_keys
```

To retrieve a private key if its public counterpart could somehow be extracted
from the server (`/root/.ssh/authorized_keys` or
`/home/<USERNAME>/.ssh/authorized_keys` through LFI or file system disclosure,
etc.):

```
# Only take the base64 content of the public key in format PEM
grep -rl <KEY> <FOLDER_RSA|FOLDER_DSA>
```

### SSH clients

###### [Windows] PuTTY

[`PuTTY`](https://www.putty.org/) is a simple `SSH`, as well as `telnet`,
`rlogin` and `serial`, GUI client for Microsoft Windows, available as an
installed program and a standalone binary.

###### [Linux] parallel-ssh

The [`parallel-ssh` / `pssh`](https://github.com/ParallelSSH/parallel-ssh)
command-line utility can be used to execute operating system commands through
`ssh` on multiple hosts. The utility will return for each host the
`return code` of the provided command.

The option `-x '-q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null'` can be provided to bypass the verification of
the target host key and prevent the saving of the host key.

```
# apt install pssh

# -i: displays the standard output and standard error of each SSH execution. By default, the outputs are not displayed.
# --inline-stdout: displays (only) the standard output of each SSH execution.
# -o <OUTPUT_DIR>: outputs the standard output of each SSH execution in a dedicated file (format: [<USERNAME@>]<HOSTNAME | IP>[:<PORT>][.num]) in the specified folder.
# -A: prompts for the user password (once for all of the specified hosts). By default, a authentication through SSH keys will be conducted.
# -t <0 | NUMBER_SECONDS>: allowed execution timeout in seconds prevent timeout of the execution, which can be necessary for
parallel-ssh [-i | --inline-stdout] [-o <OUTPUT_DIR>] [-A] -l "<USERNAME>" [-h <HOSTFILE> | -H "<HOSTNAME | IP>[:<PORT>] [<HOSTNAME | IP>[:<PORT>]]"] <COMMAND>
parallel-ssh [-i | --inline-stdout] [-o <OUTPUT_DIR>] [-A] [-h <HOST_FILE> | -H "[<USERNAME>@]<HOSTNAME | IP>[:<PORT>] [[<USERNAME>@]<HOSTNAME | IP>[:<PORT>]]"] <COMMAND>

# Bypass host keys verification and prevents the saving of the hosts keys.
parallel-ssh -x '-q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null' [...]

# Execute the specified with elevated rights through sudo using the provided password.
# The first option is more secure as it does not leave any trace of the password on either the local or remote host but operational problems may arise.
stty -echo; printf "sudo password: "; read PASS; stty echo; echo "${PASS}" | parallel-ssh [...] "sudo -S <COMMAND>"
parallel-ssh [...] "echo <SUDO_PASSWORD> | sudo -S <COMMAND>"
```
