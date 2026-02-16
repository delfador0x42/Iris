import Foundation
import os.log

/// Detects hidden processes by cross-referencing THREE enumeration methods:
/// 1. sysctl(KERN_PROC_ALL) — standard process list (ProcessSnapshot)
/// 2. kill(pid, 0) brute-force — finds PIDs that respond but aren't listed
/// 3. processor_set_tasks() — Mach kernel task port walk (deepest, requires root)
/// Any PID found by one method but not another is suspicious.
public actor HiddenProcessDetector {
    public static let shared = HiddenProcessDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "HiddenProcess")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let sysctlPids = Set(snapshot.pids)

        // Layer 1: kill(0) brute-force vs sysctl
        let maxPid = pidMax()
        var killPids = Set<pid_t>()
        var pid: pid_t = 1
        while pid < maxPid {
            if processExists(pid) { killPids.insert(pid) }
            pid += 1
        }
        let hiddenFromSysctl = killPids.subtracting(sysctlPids)
        for hidden in hiddenFromSysctl {
            let name = procName(hidden) ?? "unknown"
            // Only skip kernel_task at PID 0, launchd at PID 1 — by PID, never by name alone
            if hidden == 0 || hidden == 1 { continue }
            let pathStr = procPath(hidden) ?? ""
            anomalies.append(.forProcess(
                pid: hidden, name: name, path: pathStr,
                technique: "Hidden Process (kill brute-force)",
                description: "PID \(hidden) (\(name)) responds to kill(0) but missing from sysctl. Possible rootkit.",
                severity: .critical, mitreID: "T1014",
                scannerId: "hidden_process",
                enumMethod: "kill(pid,0) brute-force [1..\(maxPid)] vs sysctl(KERN_PROC_ALL)",
                evidence: [
                    "detection: kill(\(hidden), 0) success",
                    "not_in: sysctl snapshot (\(sysctlPids.count) PIDs)",
                    "proc_path: \(pathStr.isEmpty ? "(no binary on disk)" : pathStr)",
                ]
            ))
        }

        // Layer 2: Mach processor_set_tasks() vs sysctl (deepest)
        let machTasks = MachTaskEnumerator.enumerateAll()
        let machPids = Set(machTasks.map(\.pid))

        // PIDs in Mach but not in sysctl — hidden from userland
        let machOnly = machPids.subtracting(sysctlPids)
        for machPid in machOnly {
            // Only skip by PID, never by name (a rootkit can name itself "kernel_task")
            if machPid == 0 || machPid == 1 { continue }
            let task = machTasks.first { $0.pid == machPid }
            let name = task?.name ?? "unknown"
            let pathStr = task?.path ?? ""
            // Don't double-report if already found by kill brute-force
            if hiddenFromSysctl.contains(machPid) { continue }
            anomalies.append(.forProcess(
                pid: machPid, name: name, path: pathStr,
                technique: "Hidden Process (Mach task walk)",
                description: "PID \(machPid) (\(name)) found via processor_set_tasks() but not in sysctl. Deep rootkit.",
                severity: .critical, mitreID: "T1014",
                scannerId: "hidden_process",
                enumMethod: "processor_set_tasks() vs sysctl(KERN_PROC_ALL)",
                evidence: [
                    "detection: processor_set_tasks() → pid_for_task()",
                    "not_in: sysctl snapshot (\(sysctlPids.count) PIDs)",
                    "mach_total: \(machTasks.count) tasks",
                    "proc_path: \(pathStr.isEmpty ? "(no binary on disk)" : pathStr)",
                ]
            ))
        }

        // PIDs in sysctl but not in Mach — possible DKOM (task list manipulation)
        let sysctlOnly = sysctlPids.subtracting(machPids)
        for sPid in sysctlOnly where sPid > 0 {
            let name = snapshot.name(for: sPid)
            let path = snapshot.path(for: sPid)
            anomalies.append(.forProcess(
                pid: sPid, name: name, path: path,
                technique: "Ghost Process (DKOM suspected)",
                description: "PID \(sPid) (\(name)) in sysctl but not in Mach task list. Possible DKOM.",
                severity: .high, mitreID: "T1014",
                scannerId: "hidden_process",
                enumMethod: "sysctl(KERN_PROC_ALL) vs processor_set_tasks()",
                evidence: [
                    "in_sysctl: true",
                    "in_mach: false",
                    "sysctl_count: \(sysctlPids.count)",
                    "mach_count: \(machTasks.count)",
                ]
            ))
        }

        // Layer 3: Duplicate system process names (masquerading)
        anomalies.append(contentsOf: checkDuplicateSystemProcesses(snapshot: snapshot))

        logger.info("Scan complete: sysctl=\(sysctlPids.count), kill=\(killPids.count), mach=\(machTasks.count), findings=\(anomalies.count)")
        return anomalies
    }

    private func checkDuplicateSystemProcesses(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let singletons = ["WindowServer", "loginwindow", "Dock", "Finder",
                          "SystemUIServer", "launchd"]

        for name in singletons {
            let pids = snapshot.pids.filter { snapshot.name(for: $0) == name }
            if pids.count > 1 {
                // Flag ALL instances — even system-path duplicates are suspicious.
                // A rootkit can plant in /System/ if SIP is bypassed.
                for pid in pids {
                    let path = snapshot.path(for: pid)
                    let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/")
                    result.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "Duplicate System Process",
                        description: "Multiple '\(name)' processes. PID \(pid) at \(path)\(isSystem ? " [system path — verify]" : " [non-system path]")",
                        severity: .critical, mitreID: "T1036.004",
                        scannerId: "hidden_process",
                        enumMethod: "sysctl(KERN_PROC_ALL) name dedup",
                        evidence: [
                            "expected_singleton: \(name)",
                            "instance_count: \(pids.count)",
                            "pids: \(pids.map(String.init).joined(separator: ", "))",
                            "path: \(path)",
                            "is_system_path: \(isSystem)",
                        ]
                    ))
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
        return min(val, 99999)
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
