# DFIR - Tools - Splunk

### Quick deployment with Splunk docker container

For the quick deployment of a Splunk instance, the
[Splunk docker image](https://hub.docker.com/r/splunk/splunk/) (by Splunk)
can be used.

```
docker pull splunk/splunk:latest

# Port 8000: Splunk web interface.
# Port 8088: Splunk HTTP event collectors service.
docker run -p [<IP>:]8000:8000 -p [<IP>:]8088:8088 -e "SPLUNK_PASSWORD=<PASSWORD>" -e "SPLUNK_START_ARGS=--accept-license" splunk/splunk:latest
```

### Splunk search Cheat Sheet

###### Search commands

| Command | Description | Example |
|---------|-------------|---------|
| `dedup <FIELD>` <br><br> `dedup <FIELD1> <FIELDN>` | Removes events containing an identical value(s) for the specified field(s). | `dedup index` |
| `\| eventcount [index=<* \| INDEX>]` | Returns the number of events in the specified indexes. | |
| `fields [+\|-] <FIELD>` <br><br> `fields <FIELD1> <FIELDN>` | Keeps or removes the specified fields. <br><br> Default to keeping fields (`+`). | |
| `iplocation allfields=true <FIELD>` | Extracts location information (city, country, continent, ...) for the IP address <FIELD> by using a local copy of the `ip-to-city-lite.mmdb` IP geolocation database file |
| `rare [limit=<INT>] <FIELD>` <br><br> `rare <FIELD1> <FIELDN>` <br><br> `rare <FIELD> by <FIELD_GROUP_BY> [<FIELD_GROUP_BYN>]` | Displays the least common value of the specified field or the least common combination of values of the specified fields. <br><br> With the `group by` close, rare field(s) for each field(s) in the given grouped by fields are returned. | `... \| rare Process_Command_Line` <br> Returns the rare `Process_Command_Line` fields. <br><br> `... \| rare Process_Command_Line Account_Name` <br> Returns the rare combination of `Process_Command_Line` and `Account_Name` fields. <br><br> `... \| rare Process_Command_Line by Account_Name` <br> Returns the rare `Process_Command_Line` fields for each different `Account_Name`. |
| `rename <FIELD_NAME> AS <NEW_FIELD_NAME>` | Renames the specified field. <br><br> Can be used in a nested `search` query to rename the pivoting field. | Rename `FIELD` to `NEW_FIELD` to filter on `NEW_FIELD=FIELD_VALUE` in the main search: <br> `index=* [search index=* \| dedup FIELD \| rename FIELD AS NEW_FIELD`] <br><br> Rename `FIELD` to the `search` keyword to use `FIELD_VALUE` as a plain text filter in the main search: <br> `index=* [search index=* \| dedup FIELD \| rename FIELD AS search`] |
| `reverse` | Reverses the order in which events are displayed (more recent to oldest by default). | |
| `sort [limit=<LIMIT_INT>] [+ \| -] <FIELD>` <br><br> `sort [+ \| -] <FIELD1> <FIELDN>` | Sorts results by the specified field(s). The top 10 000 events are returned by default. <br><br> The `+` (default) and `-` sign can be used to sort respectively by ascending or descending order. <br><br> Cast functions (`nums`, `str`, etc.) can be applied to each fields if necessary. | `... \| sort -num(size)` <br> Sorts results by size in descending order. |
| `stats count by <FIELD>` <br><br> `stats count by <FIELD1> <FIELDN>` | Counts the number of events by field or for a combination of the specified fields. | |
| `timeformat="%Y-%m-%d %H:%M:%S" earliest="<YY-MM-DD HH:MM:SS>" latest="<YY-MM-DD HH:MM:SS>"`| Filters results in the specified timeframe (with `earliest` and / or `latest`). | `timeformat="%Y-%m-%d %H:%M:%S" earliest="2023-01-13 11:12:13" latest="2023-02-01 21:00:00"` |
| `where <CONDITION>` | Filters results based on the specified condition(s) |
| `<SELECTION> \| stats earliest(_time) AS Earliest, latest(_time) AS Latest \| convert ctime(Earliest) ctime(Latest)` | Displays the timestamps of first and last events from the selection |
| `eval match=if(match(<FIELD_1>,<FIELD_2>), 1, 0) \| search match=<0 \| 1>` | Filters events if `FIELD_1` and `FIELD_2` match (`match=1`) / do not match (`match=0`). |
| `eval <NEW_FIELD>=mvindex(<FIELD>,<0 \| INDEX_START>,<0 \| INDEX_END>)` | Extracts a subset - `INDEX_START` to `INDEX_END` - from the multivalue field `<FIELD>` into `NEW_FIELD` |

###### Example / useful search queries

| Query | Description |
|-------|-------------|
| `\| eventcount index=* summarize=false \| dedup index \| fields index` | Lists available (non-internal) indexes. |
| `index=* sourcetype=wineventlog EventCode=4688 \| rare limit=100 Process_Command_Line` | Returns the 100th rarest process execution command line (from non-default Windows Security logs). |
| `index=* sourcetype=xmlwineventlog EventCode=3 DestinationHostname=*<DOMAIN> \| stats count by DestinationHostname, Image` | Counts the number of hits on each subdomains of `<DOMAIN>` by Image (from Sysmon logs). |
| `\| tstats min(_time) as latest max(_time) as earliest WHERE index="<* \| INDEX>" by index, source \| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(earliest) ctime(latest)` | Retrieves the earliest and latest events of each given types for the specified or all index. |
| `index="<INDEX>" operationName="Sign-in activity" resultType=0` <br> `[search index="<INDEX>" operationName="Sign-in activity" resultType IN (50074, 50126, 50140) \| dedup properties.userPrincipalName,resultType,properties.ipAddress \| fields properties.ipAddress]`<br>`\| dedup properties.userPrincipalName \| table properties.userPrincipalName,resultType,properties.ipAddress` |
| `<SEARCH> \| regex _raw=".*\*.*"` | Searching for the literal character `*`. |
| `<SEARCH>` <br> `\| eval time_epoch=strptime(<TIMESTAMP_FIELD>, "[%Y-%m-%dT%T \| TIMESTAMP_FORMAT>")` <br> `\| eval time_diff=now() - time_epoch` <br> `\| search time_diff <= 2592000` <br> `\| sort 0 - time_epoch` | Sort events using another timestamp (`TIMESTAMP_FIELD`) of `TIMESTAMP_FORMAT` format, only keeping events newer than 30 days (30d * 24h * 3600s). |
| `rex field=<FIELD_TO_EXTRACT_FROM> "(?<<NEW_FIELD>>\\d+\.\\d+\.\\d+\.\\d+)"` | `rex` command to extract an IPv4 from the specified field to the new field using an (dirty) regex. |
| `<SELECTION> \| eventstats count AS Count by host \| eventstats earliest(_time) AS Earliest, latest(_time) AS Latest by host \| sort Earliest \| convert ctime(Earliest) ctime(Latest) \| table host,Earliest,Latest,Count` | Displays the timestamps of first and last events as well as the count of total events from the selection	by `host`. The `host` field can be replaced by any field(s). |

```
# Retrieve the first and last occurrence of an event (exemple: user,src,dst,dstname,dstport) as well as the total bytes sent and received across all events.
# Add a formatted message resuming the event in an human readable message.

index=* [...]
| eventstats sum(sent) as total_sent by user,src,dst,dstname,dstport
| eventstats sum(rcvd) as total_rcvd by user,src,dst,dstname,dstport
| stats earliest(_time) AS earliest, latest(_time) AS latest by user,src,dst,dstname,dstport,total_sent,total_rcvd
| sort earliest
| eval earliest = strftime(earliest, "%y-%m-%d %H:%M:%S")
| eval latest = strftime(latest, "%y-%m-%d %H:%M:%S")
| eval message="First access to " + dstname + " (IP: " + dst + ") from " + src + " for user " + user + ".-newline-Last access: " + latest + ".-newline-Total bytes sent: " + total_sent + " and received: " + total_rcvd + "."
| rex mode=sed field=message "s/-newline-/\n/g"
| table earliest,latest,user,src,dst,dstname,dstport,total_sent,total_rcvd
```

### Splunk apps

###### olafhartong's ThreatHunting

The [`ThreatHunting`](https://github.com/olafhartong/ThreatHunting) `Splunk`
application contains multiple dashboards, relying on telemetry from `Sysmon`
and mapped on the [`MITRE ATT&CK framework`](https://attack.mitre.org/).

The following `Splunk` applications must be installed for `ThreatHunting` to
work:
  - [`Punchcard Visualization`](https://splunkbase.splunk.com/app/3129/)
  - [`Force Directed App For Splunk`](https://splunkbase.splunk.com/app/3767/)
  - [`Splunk Sankey Diagram - Custom Visualization`](https://splunkbase.splunk.com/app/3112/)
  - [`Lookup File Editor`](https://splunkbase.splunk.com/app/1724/)

The [`Threathunting` application](https://splunkbase.splunk.com/app/4305/) can
then be installed. and will index should be configured on the indexers.

--------------------------------------------------------------------------------

### References

https://docs.splunk.com/Documentation/SplunkCloud/9.0.2208/SearchReference/ListOfSearchCommands
