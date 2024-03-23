###### Logs integrity

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

The following events occurs whenever the associated logs are cleared:

  - Event: `1102: The audit log was cleared`. <br/>
    Location: victim `Security` hive.
    Includes the SID, domain, username and `Logon ID` of the user that cleared
    the logs.

  - Event: `104: The System log file was cleared`. <br/>
    Location: victim `System` hive.
    Includes the domain and username of the user that cleared the logs.

Additionally, every event of a given event log hive has an `EventRecordID`
field representing an index number, sequentially incremented, of the event in
that particular hive. Any disparity in record ids may reflect a deletion of
event(s) in the hive.
