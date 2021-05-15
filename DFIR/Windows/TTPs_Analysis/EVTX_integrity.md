###### Logs integrity

Event: `1102: The audit log was cleared`.<br/>
Location: victim `Security` hive.

This event  occurs whenever the `Security` audit log is cleared. This event
includes the SID, domain, username and `Logon ID` of the user that cleared the
logs.

Additionally, every event of a given event log hive has an `EventRecordID`
field representing an index number, sequentially incremented, of the event in
that particular hive. Any disparity in record ids may reflect a deletion of
event(s) in the hive.  
