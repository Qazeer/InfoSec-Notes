# DFIR - Web logs analysis

### Webservers logs format

Webservers, such as `Apache` or `nginx`, usually follow known / standard log
formats by default.

The following standard log formats are notably in use:

| Name | Template | Example | Remarks |
|------|----------|---------|-------------|
| `Common Log Format (CLF)` | `%h %l %u %t "%r" %>s %b` <br><br> `<REMOTE_HOST> <- \| IDENTITY> <USER> <TIMESTAMP> "<REQUEST>" <STATUS_CODE> <RETURN_SIZE>` | `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326` | A `-` indicates that the information is not present. <br><br> The `<IDENTITY>` field is not reliable and will often not be logged. <br><br> The `<USER>` field may not be indicated (`-`) even if the request was identified at a higher level. For instance, `CMS`, such as `WordPress`, may not rely on webserver authentication and can identify users at the application level. In such case, the webserver log, such as `Apache`, will not contain user information while the request was however dully authentified. |
| `NCSA Combined Log Format` | `%h %l %u %t "%r" %>s %b "%{Referer}" "%{User-agent}"` <br><br> `<REMOTE_HOST> <- \| IDENTITY> <USER> <TIMESTAMP> "<REQUEST>" <STATUS_CODE> <RETURN_SIZE> "<REFERER>" "<USER_AGENT>"` | `127.0.0.1 - frank [10/Oct/2022:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"` | Identical to the `Common Log Format (CLF)` format, with the addition of the `Referer` and `User-agent` fields. |
| `IIS Log File Format` | | | |
| `W3C Extended Log File Format` | | | |

### Graphical web logs parsers / viewer

###### GoAccess

[`GoAccess`](https://goaccess.io/) is a C program that can be used to parse
webserver logs to get a first level of statistics for the given logs: total
requests, unique visitors, operating systems and browsers stats (if user-agent
information is available), accessed endpoints, etc. `GoAccess` supports many
web log formats (Apache, Nginx, Amazon S3, Elastic Load Balancing, CloudFront,
etc.) and can outputs reports in `JSON`, `CSV` or `HTML`.

Statistics linked to specifics IPs require to first filter the log files.

```bash
# Generate a static HTLM report with statistics for the given input log file(s).
goaccess <ACCESS_LOG_FILE | ACCESS_LOG_FILES> -o <REPORT_CSV_FILE | REPORT_JSON_FILE | REPORT_HTML_FILE>

# Filters the given log files on the specified IPs to generate a targeted statistics report.
grep -i "IP1\|...\|IPn" <ACCESS_LOG_FILE | ACCESS_LOG_FILES> | goaccess -o <REPORT_CSV_FILE | REPORT_JSON_FILE | REPORT_HTML_FILE>
```

###### HTTP logs viewer

The [`http Logs Viewer`](https://www.apacheviewer.com/) application, formerly
`Apache Logs Viewer`, supports various webservers logs (Apache, IIS, nginx,
etc.) and allows filtering based on various fields.

Only limited functionalities are however available in the free version and
some key features require the paid version (20$ for individuals, 70$ for
corporations as of 2022-08).

### Automated attack patterns detection

###### Apache access logs

The `Scalp!` Python script can be used in combination with the `PHPIDS`
project's regular expression filters to automatically detect common attacks
(`SQL` injection, `cross-site scripting (XSS)`, local and remote file
inclusion, etc.). The `PHPIDS` project's `default_filter.xml` defines 78
optimized and tested regex.

`Scalp!` parses the specified `Apache` logs files and leverages the
`PHPIDS` project's regular expressions to detect the matching attack patterns.

```
# nanopony GitHub repository
--exhaustive: Will not stop at the first type of attacks detected
--tough: Will attempt to decode potential attack vectors. Increases the analysis time but can greatly reduce false-positives

python3 scalp.py --exhaustive --tough -l <LOG_FILE_PATH> -f <default_filter.xml | FILTER_FILE_PATH> -o <OUTPUT_DIR>
```

The analysis of 10 000 lines of logs takes around 90 seconds (on a
`i7-4700MQ` CPU), and while `Scalp!` implements a time frame filter, the
functionnality does not seem to be functionnal.

For larger `Apache` log files, the files can be splited in multiple parts and
the analysis multi-threaded, to the maximun processing power, using the Linux
`xargs` utility. Doing so, the analysis time of 100 000 lines of logs is
reduced to around 200 seconds (on a `i7-4700MQ` CPU).

```
FILE_NAME=<FILE_NAME>
OUTPUT_FOLDER=<OUTPUT_DIR>
SCALP_PATH=<SCALP_PYTHON_PATH>
FILTER_PATH=<default_filter.xml | FILTER_FILE_PATH>
NUMBER_LINES=10000

split -d -l $NUMBER_LINES $FILE_NAME "$PWD/$OUTPUT_FOLDER/$FILE_NAME"
find "$PWD/$OUTPUT_FOLDER" -maxdepth 1 -type f | xargs -P0 -I {} python3 $SCALP_PATH --exhaustive --tough -l {} -f $FILTER_PATH -o "$PWD/$OUTPUT_FOLDER"
```

--------------------------------------------------------------------------------

### References

https://httpd.apache.org/docs/current/logs.html
