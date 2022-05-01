# Miscellaneous - Regular expressions 101

### Online resources

Online resources for regular expressions:

| Website | Description |
|---------|-------------|
| https://regex101.com/ | Online testing of regex, supporting different regex types / languages. <br><br> Detailed explanation of the different regex parts. |

### Regex basic cheatsheet

| keyword | Description |
|---------|-------------|
| `a` | Matches the character a. |
| `a\|b` | Matches either the character a or b. |
| `a?` | Matches zero or one a. |
| `a*` | Matches zero or more a. |
| `a+` | Matches one or more a, as many times as possible, giving back as needed (greedy). |
| `a+?` | Matches one or more a, as few times as possible, expanding as needed (lazy). |
| `a{5}` | Matches exactly 5 consecutive a. |
| `a{5-10}` | Matches between 5 to 10 (inclusive) consecutive a. |
| `a{5,}` | Matches 5 or more consecutive a. |
| `.` | Matches any single character. |
| `\s` | Matches any single space, tab or newline character. |
| `\S` | Matches any single character that is not a space, tab or newline. |
| `\d`  <br><br> `[0-9]` | Matches any single digit character. |
| `\D`  <br><br> `[^0-9]` | Matches any single character that is not a digit. |
| `\w` <br><br> `[a-zA-Z0-9_]` | Matches any single letter, digit, or underscore. |
| `\W` <br><br> `[^a-zA-Z0-9_]` | Matches any single any single character that is not a letter, digit, or underscore. |
| `^` | Matches the start of the string. |
| `^abc` | Matches a string starting by abc. |
| `$` | Matches the end of the string. |
| `xyz$` | Matches a string ending by xyz. |
| `[xyz]` | Matches a single character among x, y, or z. |
| `[^xyz]` | Matches any character except for x, y or z. |
| `[a-z]` | Matches a single character in the range a to z. |
| `[a-zA-Z]` | Matches a single character in the range a to z or A to Z. |
| `[^a-z]` | Matches any character except those in the a to z range. |

### Regex examples

| Regex | Description |
|---------|-------------|
| `((25[0-5]\|2[0-4][0-9]\|1?[0-9][0-9]?)\\.){3}(25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)(:[1-65535]\D)?` | Matches an IPv4 address, with an eventual port number. |
