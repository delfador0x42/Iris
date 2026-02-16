import Foundation

/// Static threat intelligence tables for LOLBin detection
extension LOLBinDetector {

    /// macOS LOLBins — legitimate binaries commonly abused by attackers
    /// Keyed by binary name, value is the MITRE ATT&CK technique
    static let lolBins: [String: String] = [
        // Scripting / execution
        "osascript": "T1059.002",     // AppleScript execution
        "bash": "T1059.004",          // Unix shell
        "zsh": "T1059.004",
        "sh": "T1059.004",
        "python": "T1059.006",        // Python execution
        "python3": "T1059.006",
        "ruby": "T1059.005",          // Ruby execution
        "perl": "T1059.006",          // Script execution
        "swift": "T1059",             // On-the-fly compilation
        "swiftc": "T1027.004",        // Compile after delivery
        "tclsh": "T1059",
        "expect": "T1059",
        "awk": "T1059.004",
        "sed": "T1059.004",
        "osacompile": "T1059.002",    // Compile AppleScript to app
        "jxa": "T1059.007",           // JavaScript for Automation
        // Network / transfer
        "curl": "T1105",              // Ingress tool transfer
        "wget": "T1105",              // Ingress tool transfer
        "nscurl": "T1105",            // Network transfer
        "scp": "T1048",               // Exfiltration over SSH
        "sftp": "T1048",
        "nc": "T1095",                // Non-application layer protocol
        "ncat": "T1095",
        "networksetup": "T1090",      // Proxy config
        "scutil": "T1016",            // System network config
        "dns-sd": "T1016",            // DNS service discovery
        // Credential / data access
        "sqlite3": "T1555.001",       // Credential access / TCC
        "security": "T1555.001",      // Keychain dumping
        "screencapture": "T1113",     // Screen capture
        "pbcopy": "T1115",            // Clipboard data
        "pbpaste": "T1115",
        // Execution / evasion
        "open": "T1204.002",          // User execution
        "xattr": "T1553.001",         // Remove quarantine
        "hdiutil": "T1553.001",       // Mount disk images
        "codesign": "T1553.002",      // Subvert trust controls
        "spctl": "T1553.002",
        "installer": "T1218",         // Proxy execution via installer
        "pkgutil": "T1218",           // Package inspection / install
        "softwareupdate": "T1218",    // Masquerade as update
        // Archiving / staging
        "ditto": "T1560.001",         // Archive collection
        "zip": "T1560.001",
        "tar": "T1560.001",
        // Persistence / config
        "launchctl": "T1569.001",     // Service execution
        "defaults": "T1547.011",      // Plist modification
        "plutil": "T1547.011",
        "profiles": "T1176",          // MDM profile install
        "csrutil": "T1562.001",       // Disable SIP
        "kextload": "T1547.006",      // Kernel module loading
        "kextutil": "T1547.006",      // Kernel module loading
        // System manipulation
        "caffeinate": "T1497.001",    // Anti-sleep (keep C2 alive)
        "pmset": "T1529",             // Power management
        "killall": "T1489",           // Service stop
        "pkill": "T1489",
        "diskutil": "T1561",          // Disk manipulation
        "say": "T1059",               // Audio output (uncommon)
        "textutil": "T1005",          // Convert/read documents
        "mdm": "T1176",              // MDM enrollment
        "log": "T1070.002",           // Clear/read system logs
        "tmutil": "T1490",            // Time Machine manipulation
    ]

    /// Suspicious parent→child relationships.
    static let suspiciousLineages: [String: Set<String>] = [
        "Safari": ["osascript", "curl", "python3", "bash", "sh", "security"],
        "Mail": ["osascript", "curl", "python3", "bash", "sh", "security"],
        "Messages": ["osascript", "curl", "python3", "bash", "sh"],
        "Preview": ["osascript", "curl", "bash", "sh"],
        "TextEdit": ["osascript", "curl", "bash", "sh", "python3"],
        "QuickLookUIService": ["osascript", "curl", "bash", "python3"],
        "Finder": ["curl", "python3", "sqlite3", "security", "nc"],
        "mds": ["bash", "sh", "curl", "python3"],
        "mdworker": ["bash", "sh", "curl", "python3"],
        "IMTransferAgent": ["osascript", "curl", "bash"],
        "com.apple.WebKit": ["osascript", "curl", "bash", "python3"],
    ]

    /// Paths where LOLBin execution is always suspicious
    static let suspiciousExecDirs: [String] = [
        "/tmp/", "/private/tmp/", "/var/tmp/",
        "/Users/Shared/", "/Library/Caches/",
        "/dev/shm/",
    ]
}
