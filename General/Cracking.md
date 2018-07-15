# Cracking

### Firefox / Thunderbird

Files to crack:

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
