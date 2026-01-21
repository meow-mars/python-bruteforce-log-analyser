# Security Log Analyser (Python)

The **Python Brute-Force Log Analyser** is a command-line tool that analyses authentication log files to detect potential brute-force login attempts. It identifies suspicious behaviour based on a configurable failed-login threshold and time window.

Using CLI flags, users can customise detection parameters to suit different environments. This tool helps security analysts identify brute-force attacks early, before accounts or systems are compromised.

---

## Features
- Parses authentication log files
- Tracks failed login attempts per user and IP address
- Detects brute-force attempts (default: 3+ failures within 5 minutes)
- Generates real-time console alerts
- Exports alerts to a persistent log file

---

## Example Alert
2026-01-12 22:47:20 | ALERT | USER: john | IP address: 10.0.0.5 | Attempts: 3 | Window: 5 minutes | IP Type: PRIVATE | Severity: HIGH
2026-01-12 22:57:23 | ALERT | USER: john | IP address: 12.0.0.6 | Attempts: 3 | Window: 5 minutes | IP Type: PUBLIC | Severity: MEDIUM

## Skills Demonstrated
- Python dictionaries & list comprehension
- datetime & timedelta usage
- Security event detection logic
- Log analysis fundamentals

## Alert Severity (RFC1918 IP ranges)
- HIGH: Internal (private) IP brute-force attempts
- MEDIUM: External (public) IP brute-force attempts
