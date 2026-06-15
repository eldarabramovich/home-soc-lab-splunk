# Linux SSH Brute Force Investigation

## Objective

Investigate repeated failed SSH login attempts on a Linux server and determine whether the activity may indicate brute-force behavior, credential guessing, or normal user error.

## Data Source

Simulated Linux authentication logs were uploaded to Splunk for analysis.

| Field      | Value                       |
| ---------- | --------------------------- |
| Index      | `main`                      |
| Sourcetype | `linux_auth_sample`         |
| Host       | `UBUNTU-SERVER-01`          |
| Source     | `linux-auth-log-sample.txt` |

## Relevant Log Events

| Log Pattern         | Meaning                                   |
| ------------------- | ----------------------------------------- |
| `Failed password`   | Failed SSH login attempt                  |
| `Accepted password` | Successful SSH login                      |
| `invalid user`      | Login attempt against a non-existing user |
| `sudo`              | Privileged command execution              |

## Initial Search

```spl
index=main sourcetype=linux_auth_sample
```

### Purpose

This search was used to confirm that the uploaded Linux authentication logs were successfully indexed in Splunk.

## Failed SSH Login Search

```spl
index=main sourcetype=linux_auth_sample "Failed password"
| rex "from (?<Source_IP>\d+\.\d+\.\d+\.\d+)"
| stats count by Source_IP
| sort - count
```

### Purpose

This search was used to identify which source IP addresses generated the highest number of failed SSH login attempts.

## Failed SSH Login by Account and Source IP

```spl
index=main sourcetype=linux_auth_sample "Failed password"
| rex "Failed password for (invalid user )?(?<Account_Name>\w+) from (?<Source_IP>\d+\.\d+\.\d+\.\d+)"
| stats count by Account_Name, Source_IP
| sort - count
```

### Purpose

This search was used to identify which accounts were targeted and which source IP addresses were involved.

## Findings

The source IP `192.168.1.90` generated the highest number of failed SSH login attempts.

The failed attempts targeted the `admin` and `root` accounts. This is suspicious because both account names are commonly targeted in SSH brute-force or credential guessing attempts.

Another source IP, `192.168.1.55`, generated failed login attempts against the `backup` account and later had a successful login. This should be reviewed separately to determine whether it was expected behavior.

## Timeline Review

```spl
index=main sourcetype=linux_auth_sample ("Failed password" OR "Accepted password")
| rex "for (invalid user )?(?<Account_Name>\w+) from (?<Source_IP>\d+\.\d+\.\d+\.\d+)"
| table _time, Account_Name, Source_IP, _raw
| sort _time
```

### Purpose

This search was used to review the SSH authentication timeline and check whether failed login attempts were followed by successful logins.

## Analysis

The logs show repeated failed SSH login attempts from `192.168.1.90` against the `admin` and `root` accounts.

No successful login from `192.168.1.90` was observed in the reviewed logs.

The activity from `192.168.1.90` may indicate brute-force behavior or credential guessing.

The `backup` account had failed login attempts from `192.168.1.55` followed by a successful login. In a real environment, this would require validation to determine whether the activity was expected.

## SOC Tier 1 Conclusion

The activity from `192.168.1.90` should be treated as suspicious because it involved repeated failed SSH login attempts against sensitive account names such as `admin` and `root`.

No successful login from the suspicious source IP was observed.

## Recommended Next Steps

If this activity occurred in a real production environment, a SOC Tier 1 analyst should:

1. Verify whether `192.168.1.90` is an internal or external IP address.
2. Check whether SSH access from this source is expected.
3. Review whether root SSH login is disabled.
4. Check firewall, VPN, and endpoint logs for related activity.
5. Validate whether the `backup` login from `192.168.1.55` was expected.
6. Escalate if the suspicious IP is unknown, external, or continues attempting authentication.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name    | Reason                                                                       |
| ------------ | ----------------- | ---------------------------------------------------------------------------- |
| T1110        | Brute Force       | Multiple failed SSH authentication attempts were observed                    |
| T1110.001    | Password Guessing | Repeated login attempts targeted common usernames such as `admin` and `root` |

## Evidence

Screenshots related to this investigation:

* `screenshots/linux-ssh-bruteforce-search.png`
* `screenshots/linux-ssh-bruteforce-timeline.png`
