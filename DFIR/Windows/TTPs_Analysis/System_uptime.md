# DFIR - Windows - System uptime

**Windows DFIR notes are no longer maintained on InfoSec-Notes. Updated versions can be found on: [artefacts.help](https://artefacts.help/).**

### EVTX

| File | Event source | Description |
|------|------------|-------------|
| `System.evtx` | `User32` | Event `1074: The process <PROCESS_EXE> has initiated the xxx of computer <HOSTNAME> on behalf of user <USERNAME> for the following reason: <SHUTDOWN_REASON_TEXT>` |
| `System.evtx` | `EventLog` | Event `6005: The Event log service was started` |
| `System.evtx` | `EventLog` | Event `6006: The Event log service was stopped` |
| `System.evtx` | `Microsoft-Windows-Kernel-General` | Event `12: The operating system started at system time <TIME>` |
| `System.evtx` | `Microsoft-Windows-Kernel-General` | Event `13: The operating system is shutting down at system time <TIME>` |
| `System.evtx` | `Microsoft-Windows-Kernel-Power` | Event `109: The kernel power manager has initiated a shutdown transition. Shutdown Reason: <SHUTDOWN_REASON_INT>` |
| `System.evtx` | `Microsoft-Windows-Kernel-Power` | Event `41: The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly` |
| `System.evtx` | `Microsoft-Windows-Kernel-Power` | Event `42: The system is entering sleep` |
| `System.evtx` | `Microsoft-Windows-Power-Troubleshooter` | Event `1: The system has resumed from sleep` |
| `System.evtx` | `EventLog` | Event: `6013: The system uptime is <INT> seconds.` |

The
[`TurnedOnTimesView`](https://www.nirsoft.net/utils/computer_turned_on_times.html)
utility can be used to parse `System.evtx` files and determine the time ranges
that a system was turned on (by looking as a set of the aforementioned events).

--------------------------------------------------------------------------------

### References

https://www.nirsoft.net/utils/computer_turned_on_times.html
