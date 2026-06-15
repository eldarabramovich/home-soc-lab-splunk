# Windows Failed Logon Investigation

## Objective

Investigate multiple failed Windows login attempts and determine whether the activity may indicate user error, misconfigured credentials, or possible brute-force behavior.

## Data Source

Simulated Windows Security Event logs were uploaded to Splunk for analysis.

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Index      | `main`                               |
| Sourcetype | `windows_auth_sample`                |
| Host       | `WIN-ENDPOINT-01`                    |
| Source     | `windows-security-events-sample.txt` |

## Relevant Windows Event Codes

| Event Code | Meaning            |
| ---------- | ------------------ |
| 4625       | Failed Logon       |
| 4624       | Successful Logon   |
| 4740       | Account Locked Out |

## Initial Search

```spl
index=main sourcetype=windows_auth_sample
```

### Purpose

This search was used to confirm that the uploaded Windows authentication sample logs were successfully indexed in Splunk.

### Result

Splunk returned 15 events from the uploaded sample log file.

## Failed Logon Search

```spl
index=main sourcetype=windows_auth_sample EventCode=4625
| stats count by Account_Name, Source_IP, Logon_Type
| sort - count
```

### Purpose

This search was used to identify which accounts had failed login attempts, how many failed attempts were detected, and which source IP addresses were involved.

## Findings

The search identified multiple failed login attempts targeting the `admin` account from source IP `192.168.1.80`.

The `admin` account had the highest number of failed login attempts in the reviewed logs. The activity used `Logon_Type=10`, which may indicate a remote interactive logon attempt.

Another account, `eldar`, also had failed login attempts from source IP `192.168.1.25`, but the `admin` activity is more suspicious because it targeted an administrative account.

## Timeline Review

```spl
index=main sourcetype=windows_auth_sample (EventCode=4625 OR EventCode=4624 OR EventCode=4740)
| table _time, EventCode, Account_Name, Source_IP, Logon_Type, Status
| sort _time
```

### Purpose

This search was used to review the authentication timeline and check whether the failed login attempts were followed by a successful login or an account lockout event.

## Analysis

The logs show repeated failed login attempts against the `admin` account from the same source IP address: `192.168.1.80`.

The activity was followed by an account lockout event, represented by `EventCode=4740`.

No successful login for the `admin` account was observed in the reviewed logs.

## SOC Tier 1 Conclusion

This activity should be treated as suspicious because it involves repeated failed login attempts against an administrative account from the same source IP address, followed by an account lockout event.

Possible explanations include:

* Brute-force attempt
* Repeated incorrect credentials
* Misconfigured service or scheduled task
* Unauthorized access attempt

## Recommended Next Steps

If this activity occurred in a real production environment, a SOC Tier 1 analyst should:

1. Verify whether the source IP address is internal or external.
2. Check whether the activity was expected or authorized.
3. Contact the user or system owner if needed.
4. Review related endpoint, VPN, and network logs.
5. Check whether any successful login occurred after the failed attempts.
6. Escalate to Tier 2 if the activity is unexplained, repeated, or related to a privileged account.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Reason                                                                         |
| ------------ | -------------- | ------------------------------------------------------------------------------ |
| T1110        | Brute Force    | Multiple failed authentication attempts were observed against the same account |

## Evidence to Include

Screenshots related to this investigation:

* `screenshots/windows-failed-logon-search.png`
* `screenshots/windows-failed-logon-timeline.png`
