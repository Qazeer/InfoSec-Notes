# SSH - Methodology

### Network scan

Nmap can be used to scan the network for SSH services:

```
nmap -v -p 22 -A -oA nmap_smb <RANGE/CIDR>
```

### User enumeration (CVE-2018-15473)

The OpenSSH service for all versions < 7.7 is vulnerable to username
enumeration.

```
# [--threads THREADS] - Default to 5. If more than 10 are used, the OpenSSH service often gets overwhelmed
# [--outputFile OUTPUTFILE] [--outputFormat {list,json,csv}]
sshUsernameEnumExploit.py [--port PORT]  (--username <USERNAME> | --userList <USERLIST>) <HOST>
```

### Supported authentication methods

A verbose connection attempt will display the authentication methods supported
by the server:

```
ssh -v <HOST>
debug1: Authentications that can continue:
```

###### Authentication methods available

The following authentication methods are possible:

  - *password authentication*: Simple request for a single password with no
  specific prompt

  - *keyboard interactive*: More complex request for arbitrary number of pieces
  of information. Can be hooked to two-factor (or multi-factor) authentications
  (PAM, Kerberos, etc.)  

  - *public key authentication*: Clients must provide a public key in the list
  of allowed keys on the server and encrypts a certain data packet using the
  private key. The public key authentication method is the only method that
  both client and server software are required to implement.

  - *host-based authentication*: Host-based authentication is used to
  restrict client access only to certain hosts. This method is similar to
  public key authentication; however, the server additionally maintains a list
  of hosts mapped to their public keys and will only accept connection with the
  keys from the pre recorded host.

###### Legacy DSA public key authentication

To connect to a server using DSA keys with a modern OpenSSH client, the
*PubkeyAcceptedKeyTypes +ssh-dss* option must be added to the client config:

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

The patator Python script can be used to brute force credentials through the
password and keyboard interactive authentication methods:

```
# auth_type: auth type to use <password|keyboard-interactive>
patator ssh_login host=<HOST> user=<USERNAME> password=<PASSWORD> -x ignore:mesg='Authentication failed.'
patator ssh_login host=<HOST> user=FILE0 password=FILE1 0=<WORDLIST_USER> 1=<WORDLIST_PASSWORD> -x ignore:mesg='Authentication failed.'
```

###### Public keys authentication

The crowbar Python Script can be used to brute force SSH keys.  

While an exhaustive attack is not possible, the key based brute force can be
used for lateral movement once a private key could be compromised.

```
python crowbar.py -b sshkey (-u <USERNAME> | -U USERNAME_FILE) -k <KEY_FILE | KEY_FOLDER> -s <CIDR>
```

A repository of static authorized SSH keys "hardcoded" into software and
hardware products is available:

```
https://github.com/rapid7/ssh-badkeys
```

### Known vulnerabilities

###### OpenSSL Predictable PRNG (CVE-2008-0166)

Due to a default of implementation of the seeding process in the OpenSSL
package, all SSL and SSH keys generated on Debian-based systems (Ubuntu,
Kubuntu, etc) between September 2006 and May 13th, 2008 are cryptographically
weak.

All possible combination of public / private RSA (2048 and 4096 bits) and DSA
(1024 bits) keys can be downloaded here:

```
https://github.com/g0tmi1k/debian-ssh/tree/master/common_keys
https://github.com/g0tmi1k/debian-ssh/tree/master/uncommon_keys
```

To retrieve a private key if its public counterpart could somehow be extracted
from the server (/home/user/.ssh/authorized_keys through LFI or file system
disclosure, etc.):

```
# Only take the base64 content of the public key in format PEM
grep -rl <KEY> <FOLDER_RSA|FOLDER_DSA>
```
