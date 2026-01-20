# Security Log Analyser (Python)

A Python-based security log analyser that detects suspicious login behaviour
using time-window analysis.

## Features
- Parses authentication logs
- Tracks failed login attempts per user and IP
- Detects brute-force attempts (3+ failures within 5 minutes)
- Generates real-time alerts
- Exports alerts to a persistent log file

## Example Alert
2026-01-12 22:47:20 | ALERT | user=john | ip=10.0.0.5 | attempts=3 | window=5m

## Skills Demonstrated
- Python dictionaries & list comprehension
- datetime & timedelta usage
- Security event detection logic
- Log analysis fundamentals
