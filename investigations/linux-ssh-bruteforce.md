# Linux SSH Brute Force Investigation

## Objective

Investigate repeated failed SSH login attempts on a Linux server and determine whether the activity may indicate brute-force behavior, credential guessing, or normal user error.

## Data Source

Simulated Linux authentication logs were uploaded to Splunk for analysis.

| Field | Value |
|---|---|
| Index | `main` |
| Sourcetype | `linux_auth_sample` |
| Host | `UBUNTU-SERVER-01` |
| Source | `linux-auth-log-sample.txt` |

## Relevant Log Events

| Log Pattern | Meaning |
|---|---|
| `Failed password` | Failed SSH login attempt |
| `Accepted password` | Successful SSH login |
| `invalid user` | Login attempt against a non-existing user |
| `sudo` | Privileged command execution |

## Initial Search

```spl
index=main sourcetype=linux_auth_sample