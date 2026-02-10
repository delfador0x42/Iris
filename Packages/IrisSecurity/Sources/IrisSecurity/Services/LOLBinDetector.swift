import Foundation
import os.log

/// Detects Living-off-the-Land Binary abuse and suspicious process genealogy.
/// An APT won't drop a custom binary — they use osascript, curl, python,
/// sqlite3, security CLI, and other system tools. We catch them by analyzing
/// WHO spawned WHAT and whether that lineage makes sense.
public actor LOLBinDetector {
    public static let shared = LOLBinDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "LOLBinDetector")

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

    /// Suspicious parent→child relationships. If the parent spawns this child,
    /// it's likely an attack chain. Key = parent name, Value = suspicious children.
    static let suspiciousLineages: [String: Set<String>] = [
        "Safari": ["osascript", "curl", "python3", "bash", "sh", "security"],
        "Mail": ["osascript", "curl", "python3", "bash", "sh", "security"],
        "Messages": ["osascript", "curl", "python3", "bash", "sh"],
        "Preview": ["osascript", "curl", "bash", "sh"],
        "TextEdit": ["osascript", "curl", "bash", "sh", "python3"],
        "QuickLookUIService": ["osascript", "curl", "bash", "python3"],
        "Finder": ["curl", "python3", "sqlite3", "security", "nc"],
        "mds": ["bash", "sh", "curl", "python3"],        // Spotlight
        "mdworker": ["bash", "sh", "curl", "python3"],
        "IMTransferAgent": ["osascript", "curl", "bash"], // iMessage
        "com.apple.WebKit": ["osascript", "curl", "bash", "python3"],
    ]

    /// Paths where LOLBin execution is always suspicious
    static let suspiciousExecDirs: [String] = [
        "/tmp/", "/private/tmp/", "/var/tmp/",
        "/Users/Shared/", "/Library/Caches/",
        "/dev/shm/",
    ]

    private static let maxAncestryDepth = 8

    /// Walk process ancestry up to maxAncestryDepth, return (names, pids) from child to root
    private func getAncestry(_ pid: pid_t, snapshot: ProcessSnapshot) -> [(name: String, pid: pid_t)] {
        var chain: [(name: String, pid: pid_t)] = []
        var current = pid
        var seen = Set<pid_t>()
        for _ in 0..<Self.maxAncestryDepth {
            let ppid = snapshot.parent(of: current)
            guard ppid > 0, ppid != current, !seen.contains(ppid) else { break }
            seen.insert(ppid)
            chain.append((name: snapshot.name(for: ppid), pid: ppid))
            current = ppid
        }
        return chain
    }

    /// Analyze all running processes for LOLBin abuse
    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        for pid in snap.pids {
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            // Get parent info
            let ppid = snap.parent(of: pid)
            let parentPath = snap.path(for: ppid)
            let parentName = parentPath.isEmpty ? "unknown" :
                URL(fileURLWithPath: parentPath).lastPathComponent

            // Check 1: Is this a LOLBin?
            if let mitreID = Self.lolBins[name] {
                // Walk ancestry to find suspicious lineage at any depth
                let ancestry = getAncestry(pid, snapshot: snap)
                for ancestor in ancestry {
                    if let suspChildren = Self.suspiciousLineages[ancestor.name],
                       suspChildren.contains(name) {
                        let chain = ancestry.reversed().map(\.name).joined(separator: " → ") + " → \(name)"
                        anomalies.append(ProcessAnomaly(
                            pid: pid, processName: name, processPath: path,
                            parentPID: ppid, parentName: parentName,
                            technique: "Suspicious Process Lineage",
                            description: "\(ancestor.name) spawned \(name) (chain: \(chain)). \(ancestor.name) should not normally lead to \(name).",
                            severity: .high, mitreID: mitreID
                        ))
                        break
                    }
                }

                // Check LOLBin executing from temp/suspicious directory
                let cwd = getProcessCWD(pid)
                for dir in Self.suspiciousExecDirs {
                    if cwd.hasPrefix(dir) || path.hasPrefix(dir) {
                        anomalies.append(ProcessAnomaly(
                            pid: pid, processName: name, processPath: path,
                            parentPID: ppid, parentName: parentName,
                            technique: "LOLBin in Suspicious Directory",
                            description: "\(name) running from \(cwd.isEmpty ? path : cwd). System tools should not execute from temp directories.",
                            severity: .high, mitreID: mitreID
                        ))
                        break
                    }
                }
            }

            // Check 2: Process running from /tmp or hidden path
            if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") ||
               path.contains("/.") {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "Execution from Suspicious Path",
                    description: "Binary executing from temporary or hidden directory: \(path)",
                    severity: .critical, mitreID: "T1059"
                ))
            }

            // Check 3: Deleted binary (process running but binary removed from disk)
            if !path.isEmpty && !FileManager.default.fileExists(atPath: path) && pid > 1 {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "Deleted Binary Still Running",
                    description: "Process \(name) (PID \(pid)) is running but its binary no longer exists on disk. Possible fileless malware.",
                    severity: .critical, mitreID: "T1620"
                ))
            }

            // Check 4: xattr removing quarantine
            if name == "xattr" {
                let args = getProcessArgs(pid)
                if args.contains("-d") && args.contains("com.apple.quarantine") {
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: ppid, parentName: parentName,
                        technique: "Gatekeeper Bypass",
                        description: "xattr removing quarantine attribute — bypassing Gatekeeper.",
                        severity: .high, mitreID: "T1553.001"
                    ))
                }
            }

            // Check 5: sqlite3 accessing sensitive databases
            if name == "sqlite3" {
                let args = getProcessArgs(pid)
                let argStr = args.joined(separator: " ")
                if argStr.contains("TCC.db") {
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: ppid, parentName: parentName,
                        technique: "TCC Database Access",
                        description: "sqlite3 accessing TCC.db — possible permission grant manipulation.",
                        severity: .critical, mitreID: "T1548"
                    ))
                }
                if argStr.contains("Cookies") || argStr.contains("Login Data") {
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: ppid, parentName: parentName,
                        technique: "Browser Credential Theft",
                        description: "sqlite3 accessing browser data — possible credential extraction.",
                        severity: .high, mitreID: "T1555.003"
                    ))
                }
            }

            // Check 6: security CLI keychain access
            if name == "security" {
                let args = getProcessArgs(pid)
                if args.contains("dump-keychain") || args.contains("find-generic-password") ||
                   args.contains("find-internet-password") {
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: ppid, parentName: parentName,
                        technique: "Keychain Credential Dump",
                        description: "security CLI extracting keychain credentials.",
                        severity: .critical, mitreID: "T1555.001"
                    ))
                }
            }
        }

        return anomalies.sorted { $0.severity > $1.severity }
    }

    // MARK: - Unique Helpers (CWD, Args — not shared)

    private func getProcessCWD(_ pid: pid_t) -> String {
        var vinfo = proc_vnodepathinfo()
        let size = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vinfo, Int32(MemoryLayout<proc_vnodepathinfo>.size))
        guard size > 0 else { return "" }
        return withUnsafePointer(to: vinfo.pvi_cdir.vip_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
    }

    private func getProcessArgs(_ pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }
        guard size > MemoryLayout<Int32>.size else { return [] }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var offset = MemoryLayout<Int32>.size

        // Skip exec path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Read args
        var args: [String] = []
        var current = ""
        while args.count < argc && offset < size {
            if buffer[offset] == 0 {
                if !current.isEmpty { args.append(current) }
                current = ""
            } else {
                current.append(Character(UnicodeScalar(buffer[offset])))
            }
            offset += 1
        }
        if !current.isEmpty { args.append(current) }
        return args
    }
}
