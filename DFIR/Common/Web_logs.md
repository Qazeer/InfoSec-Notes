# DFIR - Web logs analysis

### Apache access logs

###### Automated attack patterns detection

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
