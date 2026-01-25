# Shell Command Auditing Guide

## Overview
Techniques for auditing and logging shell commands.

## Capture Methods

### Bash History
- HISTFILE configuration
- HISTTIMEFORMAT
- HISTCONTROL settings
- Append mode

### System Logging
- auditd rules
- PAM configuration
- Syslog integration
- rsyslog forwarding

### Process Accounting
- psacct/acct
- Process creation events
- Command arguments
- User attribution

## Audit Points

### User Sessions
- Login/logout events
- TTY allocation
- Session duration
- Source IP

### Command Execution
- Full command line
- Working directory
- Environment variables
- Exit codes

### Privilege Changes
- sudo usage
- su commands
- setuid execution
- capability changes

## Detection Rules

### Suspicious Commands
- Enumeration tools
- Download utilities
- Encoding/decoding
- Persistence mechanisms

### Data Exfiltration
- curl/wget usage
- nc/ncat commands
- Base64 operations
- Archive creation

## Analysis Techniques
- Timeline correlation
- Pattern matching
- Anomaly detection
- Session reconstruction

## Legal Notice
For authorized security monitoring.
