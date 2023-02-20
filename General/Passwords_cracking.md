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
| `darkweb2017-top` | 10/100/1000/10000 | Top X passwords. |
| `rockyou.txt` | 14 millions | Usually considered sufficient for any CTF purpose, coupled if necessary with cracking rules. |
| `CrackStation`’s 15GB | 1.5 billion | The publicly available most complete password wordlist to date. |

###### kwprocessor

`kwprocessor` is a keyboard-walk generator utility, with configurable
basechars, keymap and routes. Keyboard-walk sequences correspond to a sequence
of juxtaposed keyboard keys, such as "qwerty" or "azerty" for example.

The `basechars` characters list consist of every characters that will be used
as a starting point for the keyboard-walking sequences. The `tiny.base` list
includes very limited, `QWERTY` keyboard based, starting points: `1q!Q`. The
`full.base` file provides a more comprehensive `basechars` list and its use is
recommended.

The `keymap` correspond to a keyboard layout, representing the physical
disposition of the keyboard keys. A `keymap` file should consist of 12 lines:
4 complete physical keyboard lines, represented as of (`azertyuiop^$`), and
if pressed in combination with the modifier keys `Shift` (`AZERTYUIOP¨£`) and
`AltGr` (`€¤`). Various keymaps (`en-us`, `en-gb`, `fr`, `es`, `de`, `ru`,
etc.) are provided on the `kwprocessor` GitHub.

The `route` corresponds to the patterns used to generate the keyboard-walking
sequences. A `route` is composed of a sequence of number(s), each number
representing the number of pressed keys in the same geographical directions
(north, south, west and east by default, extendable to north-west, north-east,
south-west, south-east and repeat in place). For example, the route `1`, for
the `h` key starting point and with the default `kwprocessor` configuration,
would generate the following words: `hn`, `hg`, `hj` and `hy`.<br/>
For more information and explanation on `route`, refer to the `kwprocessor`
GitHub documentation: `https://github.com/hashcat/kwprocessor`

```
# -s: include characters reachable by holding Shift. Default to false.
# -a: include characters reachable by holding AltGr. Default to false.
# -n: minimum allowed distance between keys. Default to 1.
# -x: maximum allowed distance between keys. Default to 1.    
# --keywalk-all: enable all --keywalk-* directions (keywalk-north, keywalk-south, keywalk-west, keywalk-east, keywalk-north-west, keywalk-north-east, keywalk-south-west, keywalk-south-east and keywalk-repeat).
# Default keywalk routes are the cardinal geographic directions: north, south, west and east, with out repetition.

kwp -s 1 -a 1 ./basechars/full.base <KEYBOARD_LAYOUT_FILE> <ROUTES> > <OUTPUT_FILE>
```

### Hash types

The `hashid` Python utility can be used to determine the hash type and its
corresponding `hashcat` and `john` modules:

```
hashid -m -j "<HASH | HASH_FILE>"
```

Additionally, the `hashcat` documentation may be directly used as well in order
to identify the hash type and its corresponding `hashcat` mode:

```
https://hashcat.net/wiki/doku.php?id=example_hashes
```

### Passwords cracking tools

It is recommended to use the cracking tools on the native operating system,
as opposed to a virtual system, as the performance can greatly improve.

John should be used for quick passwords cracking attempts while hashcat allows
for better performance and more complex attacks for serious needs.

###### John-the-Ripper & magnumripper John-the-Ripper

`John`, also abbreviated `JrT`, is a password cracking tool, available notably
on Linux and Windows and supporting a wide range of hashes type.

The `Jumbo` version of `John the Ripper` is a community-enhanced version of
`John` that can be found on the `magnumripper` `GitHub` repository. It notably
supports more hash types.

`John` will try to automatically detect the hash type of the provided hashes.
John stores the cracked passwords in a "pot" file, located in
`~/.john/john.pot`.

`John-the-Ripper` usage:

```
john [OPTIONS] [HASH_FILE]

# Supported hash types
john --list=formats

# Show cracked passwords
john --show <HASH_FILE>
cat ~/.john/john.pot

# With out the --format option, John will automatically attempt to determine the hash type.
john --wordlist=<WORDLIST> <HASH_FILE>
john --wordlist=<WORDLIST> --format=<HASH_FORMAT> <HASH_FILE>

# Default rules.
john --wordlist=<WORDLIST> --rules --format=<HASH_FORMAT> <HASH_FILE>

# Specified rule.
john --wordlist=<WORDLIST> --rules=<Jumbo | KoreLogic | All | RULE_NAME> --format=<HASH_FORMAT> <HASH_FILE>
```

###### hashcat

`hashcat` is an advanced cracking tool that generally offer better performance
than `John` and is considered to be among the world's fastest password cracking
tool.

Multi-OS (Windows, Linux, etc.) and multi-platforms (CPU, GPU, etc.), `hashcat`
supports more than 200 different hash types.

Moreover, `hashcat` introduced rule-based attack, which is one of the most
complicated of all the passwords cracking attack modes. The rule-based attack
is like a programming language designed for password candidate generation. It
has functions to modify, cut or extend words and has conditional operators.

The `OneRuleToRuleThemAll` rule aggregate multiples rule sets with the aim of
maximizing efficiency (success rates versus number of total candidates).

The following attack modes can be used, specified by the `-a` / `--attack-mode`
option:
  - 0: dictionary attack
  - 1: combinator attack, concatenating words from multiple wordlists
  - 3: mask attack, trying all combinations from a given keyspace, defined
    using a mask
  - 6/7: hybrid attack, combining wordlists+masks (mode 6) and masks+wordlists
    (mode 7)

`hashcat` usage:

```
# Supported hash types, with a hash example
# -m 500 for md5crypt
# https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat --example-hashes

# -w: Sets workload profile, with may have significant performance and power consumption impacts. 1 = Low, 2 = Default, 3 = High, and 4 = Nightmare.
# --hwmon-temp-abort <TEMP_DEGRE_CELSIUS>: Defines a maximum temperature in place of the default 90° celsius.
hashcat [options] <HASH | HASH_FILE> [<WORDLIST | MASK>]

# Dictionary attack
hashcat -w 3 -m <HASH_TYPE> -a 0 -o <OUTPUT_FILE> <HASH | HASH_FILE> <WORDLIST>
hashcat -w 3 -m <HASH_TYPE> -a 0 -r <best64.rule | OneRuleToRuleThemAll.rule | RULE_FILE> -o <OUTPUT_FILE> <HASH | HASH_FILE> <WORDLIST>

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

hashcat -w 3 -m <HASH_TYPE> -a 3 --increment -o <OUTPUT_FILE> <HASH | HASH_FILE> "?a?a?a?a?a?a?a?a"
hashcat -w 3 -m <HASH_TYPE> -a 3 --increment --increment-min=4 -o <OUTPUT_FILE> <HASH | HASH_FILE> "?a?a?a?a?a?a?a?a"
```

### Misc

###### Firefox / Thunderbird stored passwords

`Firefox` and `Thunderbird` save the password registered by the user in the
user profile:

```bash
~/.mozilla/firefox/$profile$.default/
~/.thunderbird/$profile$.default/
```

The passwords are stored in the following files:

```bash
Key3.db
signons.sqlite3 / logins.json
```

A master password can be set in either program and this affects `key3.db`. By
default no password is set.

`John-the-Ripper` can be used to crack the master password:

```bash
# First extract the master password hash
python mozilla2john.py key3.db > john_key3.hash

# Crack it with john
john --show john_key3.hash
```

The passwords can then be extracted from the `Firefox` / `Thunderbird` profile:

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

###### Encrypted SSH private keys

The Linux utilities `ssh2john`, packaged with the `John the Ripper Jumbo`
community version, can be used to convert an encrypted SSH private key to a
crackable hash by `john`.

```
ssh2john <SSH_PRIVKEY_ENC_FILE> > <SSH_HASH_FILE>
```

`Jumbo john` can then be used to crack the extracted hash.

```
john --wordlist=<WORDLIST> <SSH_HASH_FILE>
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

###### PKCS#12 certificate

The Linux utilities `pfx2john`, packaged with the `John the Ripper Jumbo`
community version, can be used to convert a password protected `PKCS12`
certificate to a hash crackable by `john`.

```
pfx2john <PKCS12_CERTIFICATE> > <PKCS12_HASH_FILE>

john --wordlist=<WORDLIST> <PKCS12_HASH_FILE>
```

###### mRemoteNG

`mRemoteNG` is an open source multi-protocol remote connections manager. The
connections information, including usernames and passwords, are stored
encrypted in `confCons.xml` files.

On older versions of `mRemoteNG`, the passwords were encrypted in AES-128-CBC
using the md5 of `mR3m` as the secret key and storing the IV in the 16 first
bytes of the passwords hash.

The clear-text passwords can be retrieved on all `mRemoteNG` versions directly
through the GUI application by creating an external tool:

```
Tools -> External Tools -> New External Tool
  Display Name: Print password
  Filename: cmd
  Arguments: /k echo %password%

After the confCons.xml is loaded, the created external tool can be used to retrieve the passwords
Connections -> <CONNECTION> -> External Tools -> Print pasword
```

--------------------------------------------------------------------------------

### References

https://github.com/hashcat/kwprocessor
http://cosine-security.blogspot.com/2011/06/stealing-password-from-mremote.html
https://robszar.wordpress.com/2012/08/07/view-mremote-passwords-4/
