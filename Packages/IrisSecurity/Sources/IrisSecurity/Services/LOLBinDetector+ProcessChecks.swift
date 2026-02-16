import Foundation

/// Process-level checks: lineage, suspicious paths, deleted binaries
extension LOLBinDetector {

    /// Check ancestry for suspicious parent→child lineage
    func checkLineage(pid: pid_t, name: String, path: String, ppid: pid_t,
                      parentName: String, mitreID: String,
                      snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        let ancestry = getAncestry(pid, snapshot: snapshot)
        for ancestor in ancestry {
            if let suspChildren = Self.suspiciousLineages[ancestor.name],
               suspChildren.contains(name) {
                let chain = ancestry.reversed().map(\.name).joined(separator: " → ") + " → \(name)"
                return [ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "Suspicious Process Lineage",
                    description: "\(ancestor.name) spawned \(name) (chain: \(chain)). \(ancestor.name) should not normally lead to \(name).",
                    severity: .high, mitreID: mitreID,
                    scannerId: "lolbin",
                    enumMethod: "sysctl(KERN_PROCARGS2) + proc_pidinfo(PROC_PIDTASKALLINFO) ancestry walk",
                    evidence: [
                        "child: \(name) (pid \(pid))",
                        "ancestor: \(ancestor.name) (pid \(ancestor.pid))",
                        "chain: \(chain)",
                    ]
                )]
            }
        }
        return []
    }

    /// Check if LOLBin is running from a suspicious directory
    func checkSuspiciousExecDir(pid: pid_t, name: String, path: String, ppid: pid_t,
                                parentName: String, mitreID: String) -> [ProcessAnomaly] {
        let cwd = getProcessCWD(pid)
        for dir in Self.suspiciousExecDirs {
            if cwd.hasPrefix(dir) || path.hasPrefix(dir) {
                return [ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: ppid, parentName: parentName,
                    technique: "LOLBin in Suspicious Directory",
                    description: "\(name) running from \(cwd.isEmpty ? path : cwd). System tools should not execute from temp directories.",
                    severity: .high, mitreID: mitreID,
                    scannerId: "lolbin",
                    enumMethod: "proc_pidinfo(PROC_PIDVNODEPATHINFO) cwd + sysctl(KERN_PROCARGS2) path",
                    evidence: [
                        "binary: \(name)",
                        "cwd: \(cwd)",
                        "exec_path: \(path)",
                        "suspicious_dir: \(dir)",
                    ]
                )]
            }
        }
        return []
    }

    /// Check if process is running from /tmp or hidden path
    func checkSuspiciousPath(pid: pid_t, name: String, path: String,
                             ppid: pid_t, parentName: String) -> [ProcessAnomaly] {
        guard path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") ||
              path.contains("/.") else { return [] }
        return [ProcessAnomaly(
            pid: pid, processName: name, processPath: path,
            parentPID: ppid, parentName: parentName,
            technique: "Execution from Suspicious Path",
            description: "Binary executing from temporary or hidden directory: \(path)",
            severity: .critical, mitreID: "T1059",
            scannerId: "lolbin",
            enumMethod: "sysctl(KERN_PROCARGS2) path prefix check",
            evidence: [
                "pid: \(pid)",
                "binary: \(name)",
                "path: \(path)",
            ]
        )]
    }

    /// Check if process binary was deleted from disk while still running
    func checkDeletedBinary(pid: pid_t, name: String, path: String,
                            ppid: pid_t, parentName: String) -> [ProcessAnomaly] {
        guard !path.isEmpty, !FileManager.default.fileExists(atPath: path), pid > 1 else {
            return []
        }
        return [ProcessAnomaly(
            pid: pid, processName: name, processPath: path,
            parentPID: ppid, parentName: parentName,
            technique: "Deleted Binary Still Running",
            description: "Process \(name) (PID \(pid)) is running but its binary no longer exists on disk. Possible fileless malware.",
            severity: .critical, mitreID: "T1620",
            scannerId: "lolbin",
            enumMethod: "sysctl(KERN_PROCARGS2) path + FileManager.fileExists",
            evidence: [
                "pid: \(pid)",
                "binary: \(name)",
                "original_path: \(path)",
                "on_disk: false",
            ]
        )]
    }
}
