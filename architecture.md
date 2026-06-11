# Lab Architecture

## Components

- Windows endpoint: Generates Windows Security and PowerShell logs
- Linux endpoint: Generates SSH and authentication logs
- Splunk: Used as the SIEM platform for log ingestion, searching, and investigation
- Analyst workstation: Used to perform searches, document findings, and create incident reports

## Data Sources

- Windows Security Events
- Windows PowerShell Logs
- Linux `/var/log/auth.log`
- Simulated authentication activity