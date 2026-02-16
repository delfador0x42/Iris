import Foundation
import os.log

/// Detects hidden processes by cross-referencing enumeration methods.
/// If a PID exists (responds to kill(0)) but isn't in the process list,
/// it may be hidden by a rootkit. Covers hunt scripts: hidden_processes, pid_bruteforce.
public actor HiddenProcessDetector {
    public static let shared = HiddenProcessDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "HiddenProcess")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let knownPids = Set(snapshot.pids)

        // Brute-force PID range looking for hidden processes
        let maxPid = pidMax()
        var pid: pid_t = 1
        while pid < maxPid {
            if !knownPids.contains(pid) && processExists(pid) {
                // PID responds to signal 0 but isn't in our snapshot
                let name = procName(pid) ?? "unknown"
                // Skip kernel-only PIDs (they're expected to be invisible)
                if name != "kernel_task" && name != "launchd" {
                    let pathStr = procPath(pid) ?? ""
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: pathStr,
                        technique: "Hidden Process",
                        description: "PID \(pid) (\(name)) exists but not visible in process list. Possible rootkit.",
                        severity: .critical, mitreID: "T1014",
                        scannerId: "hidden_process",
                        enumMethod: "kill(pid,0) brute-force PID scan [1..\(maxPid)]",
                        evidence: [
                            "detection: kill(\(pid), 0) → \(kill(pid, 0) == 0 ? "success" : "EPERM (exists, no perms)")",
                            "not_in: sysctl(KERN_PROC_ALL) snapshot (\(knownPids.count) PIDs)",
                            "proc_path: \(pathStr.isEmpty ? "(empty — no binary on disk?)" : pathStr)",
                        ]
                    ))
                }
            }
            pid += 1
        }

        // Also check for duplicate system process names (masquerading)
        anomalies.append(contentsOf: checkDuplicateSystemProcesses(snapshot: snapshot))
        return anomalies
    }

    private func checkDuplicateSystemProcesses(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let singletons = ["WindowServer", "loginwindow", "Dock", "Finder",
                          "SystemUIServer", "launchd"]

        for name in singletons {
            let pids = snapshot.pids.filter { snapshot.name(for: $0) == name }
            if pids.count > 1 {
                for pid in pids {
                    let path = snapshot.path(for: pid)
                    if !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") {
                        result.append(.forProcess(
                            pid: pid, name: name, path: path,
                            technique: "Duplicate System Process",
                            description: "Multiple '\(name)' processes. PID \(pid) at non-system path: \(path)",
                            severity: .critical, mitreID: "T1036.004",
                            scannerId: "hidden_process",
                            enumMethod: "sysctl(KERN_PROC_ALL) name dedup",
                            evidence: [
                                "expected_singleton: \(name)",
                                "instance_count: \(pids.count)",
                                "pids: \(pids.map(String.init).joined(separator: ", "))",
                                "non_system_path: \(path)",
                            ]
                        ))
                    }
                }
            }
        }
        return result
    }

    private func processExists(_ pid: pid_t) -> Bool {
        kill(pid, 0) == 0 || errno == EPERM
    }

    private func pidMax() -> pid_t {
        var val: Int32 = 0; var size = MemoryLayout<Int32>.size
        sysctlbyname("kern.maxproc", &val, &size, nil, 0)
        return min(val, 99999) // cap for performance
    }

    private func procName(_ pid: pid_t) -> String? {
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return nil }
        return withUnsafeBytes(of: info.pbi_name) { buf in
            String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
    }

    private func procPath(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let r = proc_pidpath(pid, &buf, UInt32(MAXPATHLEN))
        guard r > 0 else { return nil }
        return String(cString: buf)
    }
}
