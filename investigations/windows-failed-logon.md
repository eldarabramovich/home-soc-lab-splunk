# Windows Failed Logon Investigation

## Objective
Investigate multiple failed Windows login attempts and determine whether the activity may indicate brute-force behavior or normal user error.

## Data Source
Windows Security Event Logs ingested into Splunk.

## Relevant Event IDs
- 4625: Failed logon
- 4624: Successful logon
- 4740: Account lockout

## Investigation Steps
1. Search for failed logon events.
2. Identify affected usernames.
3. Check source IP addresses.
4. Review logon types.
5. Compare failed logons with successful logons.
6. Determine whether the pattern looks suspicious.

## Splunk Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, src_ip, Logon_Type
| sort - count