# Forensics - Windows - Artifacts collectors

### DFIR Outil de recherche de compromission (ORC)

Collected artifacts:
  - running processes
  - Windows events logs
  - Windows registries hives
  - autorunsC CSV output
  - Prefetch and Amcache

Missing:
  - $MFT and UsnJrnl
  - Shimcache

### PowerShell PowerForensics Get-ForensicTimeline

The PowerShell cmdlet `Get-ForensicTimeline` of the `PowerForensics` suite
creates a forensic timeline for the selected volume or logical drive.
