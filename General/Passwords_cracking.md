# Passwords cracking

Password cracking is the process of recovering passwords from data that have
been stored in or transmitted in a hashed form by a computer system.  

Passwords cracking can be attempted using a:
  - Brute-force attack, in which all possible passwords are exhaustively
    tried. Past a certain password length and complexity, brute force attack
    become ineffective
  - Dictionary attack rely on a wordlist to guess passwords
  - Rainbow table attack use a precomputed table of hashes reducing the
    computer processing time required

The time to crack a password is related to the password strength and the
hashing function used.

### Wordlist

The following word list can be used for passwords cracking:

| Name | Entry count | Description |
|------|-------------|-------------|
| darkweb2017-top | 10/100/1000/10000 | Top X passwords |
| rockyou.txt | 14 millions | Enough for any CTF purpose |
| CrackStation’s 15GB | 1.5 billion | The most complete list to date |  

### Hash types

To identity the hash type being faced, the list from the hashcat organization
can be used:

```
https://hashcat.net/wiki/doku.php?id=example_hashes
```

### Passwords cracking tools

It is recommended to use the cracking tools on the native operating system,
as opposed to a virtual system, as the performance can greatly improve.

John should be used for quick passwords cracking attempts while hashcat allows
for better performance and more complex attacks for serious needs.

###### John-the-Ripper & magnumripper John-the-Ripper

John, also abbreviated JrT, is a password cracking tool, available notably on
Linux and Windows and supporting a wide range of hashes type.

The Jumbo version of John the Ripper is a community-enhanced version of John and
can be found on the magnumripper GitHub repository. It noatably supports more
hash types.

John will try to automatically detect the hash type of the provided hashes.

John stores the cracked passwords in a "pot" file, located in
`~/.john/john.pot`.

John-the-Ripper usage:

```
john [OPTIONS] [HASH_FILE]

# Supported hash types
john --list=formats

# Show cracked passwords
john --show <HASH_FILE>
cat ~/.john/john.pot

john --wordlist=<WORDLIST> --format=<HASH_FORMAT> <HASH_FILE>
```

###### Hashcat

Hashcat is an advanced cracking tool that generally offer better performance
than john and is considered to be the world's fastest password cracking tool.

Multi-OS (Windows, Linux, etc.) and multi-platforms (CPU, GPU, etc.), hashcat
supports more than 200 different hash types.

Moreover, hashcat introduced rule-based attack, which is one of the most
complicated of all the passwords cracking attack modes. The rule-based attack
is like a programming language designed for password candidate generation. It
has functions to modify, cut or extend words and has conditional operators.

The "OneRuleToRuleThemAll" rule aggregate multiples rule sets with the aim of
maximizing efficiency (success rates vs number of total candidates).

The following attack modes can be used, specified by the -a / --attack-mode
option:
  - 0: dictionary attack
  - 1: combinator attack, concatenating words from multiple wordlists
  - 3: mask attack, trying all combinations from a given keyspace, defined
    using a mask
  - 6/7: hybrid attack, combining wordlists+masks (mode 6) and masks+wordlists
    (mode 7)

Hashcat usage:

```
# Supported hash types, with a hash example
# -m 500 for md5crypt
hashcat --example-hashes

hashcat [options] <HASH | HASH_FILE> [<WORDLIST | MASK>]

# Dictionary attack
hashcat -m <HASH_TYPE> -a 0 -r <RULE_FILE> -o <OUTPUT_FILE> <HASH | HASH_FILE> <WORDLIST>

# Mask attack
# A mask is a string that configures the keyspace of the password candidate
# Built-in mask charsets
    ?l = abcdefghijklmnopqrstuvwxyz
    ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
    ?d = 0123456789
    ?h = 0123456789abcdef
    ?H = 0123456789ABCDEF
    ?s = «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    ?a = ?l?u?d?s
    ?b = 0x00 - 0xff

hashcat -m <HASH_TYPE> -a 3 --increment -o <OUTPUT_FILE> <HASH | HASH_FILE> "?a?a?a?a?a?a?a?a"
hashcat -m <HASH_TYPE> -a 3 --increment --increment-min=4 -o <OUTPUT_FILE> <HASH | HASH_FILE> "?a?a?a?a?a?a?a?a"
```

### Misc

###### Firefox / Thunderbird stored passwords

Firefox and Thunderbird save the password registered by the user in the user
profile:

```bash
~/.mozilla/firefox/$profile$.default/
~/.thunderbird/$profile$.default/
```

The passwords are stored in the following files:

```bash
Key3.db
signons.sqlite3 / logins.json
```

A master password can be set in either program and this affects key3.db. By
default no password is set.

John-the-Ripper can be used to crack the master password:

```bash
# First extract the master password hash
python mozilla2john.py key3.db > john_key3.hash

# Crack it with john
john --show john_key3.hash
```

The passwords can then be extracted from the Firefox / Thunderbird profile:

```bash
python firefox_decrypt/firefox_decrypt.py <PATH_TO_PROFILE>
```

###### ZIP and RAR protected archives

The Linux utilities `zip2john` and `rar2john`, packaged with the `John the
Ripper Jumbo` community version, can be used to extract the hash of the
password protecting the archive.

```
zip2john <ZIP_FILE> > <ZIP_HASH_FILE>
rar2john <RAR_FILE> > <RAR_HASH_FILE>
```

`Jumbo john` can then be used to crack the extracted hash.

```
# Detected hash type should be "PKZIP [32/64]"
john --wordlist=<WORDLIST> <ZIP_HASH_FILE>
john --wordlist=<WORDLIST> <RAR_HASH_FILE>
```

The Linux utility `fcrackzip` may be used as well and works directly on the ZIP
archive.

```
# -u (–use-unzip): use unzip to weed out wrong passwords
# -D and -p: use dictionary with the specified wordlist
fcrackzip -u -D -p <WORDLIST> <ZIP_FILE>
```

###### Password protected PDF

The Linux utility `pdfcrack` can be used to crack password protecting PDF files.

```
pdfcrack -w <WORDLIST> -f <PDF_FILE>
```

###### Linux Unified Key Setup (LUKS)

`hashcat` and `bruteforce-luks` can be used to crack LUKS encrypted disks:

```
dd if=<DISK | FILE> of=tmp_luks_header bs=512 count=4097
# dd if=<DISK | FILE> of=tmp_luks_header bs=1M count=10
hashcat --force -m 14600 -a 0 -w 3 tmp_luks_header <WORDLIST>
bruteforce-luks -t 4 -f <WORDLIST> tmp_luks_header
```

Once the password is retrieved, the Linux utility `cryptsetup` can be used to
create a device that can be mounted:

```
cryptsetup  open --type luks <LUKS_FILE> <DEVICE_NAME>
mount /dev/mapper/<DEVICE_NAME> /mnt
```
