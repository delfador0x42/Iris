import Foundation

/// Argument-based checks: xattr quarantine bypass, sqlite3 data access, keychain theft
extension LOLBinDetector {

    /// Check specific binaries for malicious argument patterns
    func checkArgumentAbuse(pid: pid_t, name: String, path: String,
                            ppid: pid_t, parentName: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        if name == "xattr" {
            let args = ProcessEnumeration.getProcessArguments(pid)
            if args.contains("-d") && args.contains("com.apple.quarantine") {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "Gatekeeper Bypass",
                    description: "xattr removing quarantine attribute — bypassing Gatekeeper.",
                    severity: .high, mitreID: "T1553.001",
                    scannerId: "lolbin",
                    enumMethod: "sysctl(KERN_PROCARGS2) argument inspection",
                    evidence: [
                        "pid: \(pid)",
                        "command: xattr -d com.apple.quarantine",
                        "parent: \(parentName) (pid \(ppid))",
                    ]
                ))
            }
        }

        if name == "sqlite3" {
            anomalies += checkSqliteAccess(pid: pid, name: name, path: path,
                                           ppid: ppid, parentName: parentName)
        }

        if name == "security" {
            let args = ProcessEnumeration.getProcessArguments(pid)
            if args.contains("dump-keychain") || args.contains("find-generic-password") ||
               args.contains("find-internet-password") {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "Keychain Credential Dump",
                    description: "security CLI extracting keychain credentials.",
                    severity: .critical, mitreID: "T1555.001",
                    scannerId: "lolbin",
                    enumMethod: "sysctl(KERN_PROCARGS2) argument inspection",
                    evidence: [
                        "pid: \(pid)",
                        "command: security \(args.prefix(4).joined(separator: " "))",
                        "parent: \(parentName) (pid \(ppid))",
                    ]
                ))
            }
        }

        return anomalies
    }

    private func checkSqliteAccess(pid: pid_t, name: String, path: String,
                                   ppid: pid_t, parentName: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let args = ProcessEnumeration.getProcessArguments(pid)
        let argStr = args.joined(separator: " ")

        if argStr.contains("TCC.db") {
            anomalies.append(ProcessAnomaly(
                pid: pid, processName: name, processPath: path,
                parentPID: ppid, parentName: parentName,
                technique: "TCC Database Access",
                description: "sqlite3 accessing TCC.db — possible permission grant manipulation.",
                severity: .critical, mitreID: "T1548",
                scannerId: "lolbin",
                enumMethod: "sysctl(KERN_PROCARGS2) argument inspection",
                evidence: [
                    "pid: \(pid)",
                    "command: sqlite3 targeting TCC.db",
                    "args: \(argStr.prefix(200))",
                ]
            ))
        }
        if argStr.contains("Cookies") || argStr.contains("Login Data") {
            anomalies.append(ProcessAnomaly(
                pid: pid, processName: name, processPath: path,
                parentPID: ppid, parentName: parentName,
                technique: "Browser Credential Theft",
                description: "sqlite3 accessing browser data — possible credential extraction.",
                severity: .high, mitreID: "T1555.003",
                scannerId: "lolbin",
                enumMethod: "sysctl(KERN_PROCARGS2) argument inspection",
                evidence: [
                    "pid: \(pid)",
                    "command: sqlite3 targeting browser data",
                    "args: \(argStr.prefix(200))",
                ]
            ))
        }

        return anomalies
    }
}
