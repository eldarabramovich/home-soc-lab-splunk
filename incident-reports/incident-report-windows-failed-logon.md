# Incident Report: Windows Failed Logon Activity

## Incident Summary

Multiple failed Windows login attempts were detected for the `admin` account from source IP `192.168.1.80`.

The activity was followed by an account lockout event, which may indicate brute-force behavior, repeated incorrect credentials, a misconfigured service, or an unauthorized access attempt.

## Severity

Medium

## Status

Investigated

## Affected Asset

| Field      | Value                 |
| ---------- | --------------------- |
| Host       | `WIN-ENDPOINT-01`     |
| Index      | `main`                |
| Sourcetype | `windows_auth_sample` |

## Affected Account

| Field      | Value          |
| ---------- | -------------- |
| Account    | `admin`        |
| Source IP  | `192.168.1.80` |
| Logon Type | `10`           |

## Evidence

| Evidence Type       | Details                                        |
| ------------------- | ---------------------------------------------- |
| Failed logon events | Multiple `EventCode=4625` events were observed |
| Account lockout     | `EventCode=4740` was observed                  |
| Repeated source IP  | The failed attempts came from `192.168.1.80`   |
| Targeted account    | The activity targeted the `admin` account      |

## Splunk Queries Used

### Failed Logon Summary

```spl
index=main sourcetype=windows_auth_sample EventCode=4625
| stats count by Account_Name, Source_IP, Logon_Type
| sort - count
```

### Authentication Timeline

```spl
index=main sourcetype=windows_auth_sample (EventCode=4625 OR EventCode=4624 OR EventCode=4740)
| table _time, EventCode, Account_Name, Source_IP, Logon_Type, Status
| sort _time
```

## Analysis

The logs show repeated failed login attempts against the `admin` account from the same source IP address.

The account was later locked out, which increases the suspicion level because the activity targeted a privileged account and triggered a security-relevant event.

No successful login for the `admin` account was observed in the reviewed logs.

## Possible Causes

* Brute-force attempt
* Repeated incorrect credentials
* Misconfigured service or scheduled task
* Unauthorized access attempt

## Recommended Actions

1. Verify whether the source IP `192.168.1.80` is internal or external.
2. Confirm whether the login attempts were expected.
3. Check whether the `admin` account should allow remote logon.
4. Review related endpoint, VPN, and network logs.
5. Monitor for additional failed login attempts.
6. Escalate to Tier 2 if the activity is unexplained or continues.

## Final SOC Tier 1 Assessment

Suspicious authentication activity was identified. In a real production environment, this event should be reviewed further because it involved repeated failed login attempts against an administrative account followed by account lockout.
