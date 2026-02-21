import Foundation
import os.log

/// Multi-source process census — catches hidden processes by cross-referencing
/// three independent enumeration methods that MUST agree.
///
/// Source 1: sysctl(KERN_PROC_ALL) — standard BSD process list
/// Source 2: proc_listallpids() — libproc enumeration
/// Source 3: processor_set_tasks() — Mach kernel task walk (via MachTaskEnumerator)
///
/// A process hidden from ANY source but visible in others = rootkit.
/// All three returning the same set = system is consistent (not necessarily clean,
/// but at least not lying to us about what's running).
public actor ProcessCensusProbe {
    public static let shared = ProcessCensusProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessCensus")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // ── Source 1: sysctl KERN_PROC_ALL ────────────────────
        let sysctlPids = enumerateViaSysctl()

        // ── Source 2: proc_listallpids() ──────────────────────
        let procPids = enumerateViaProcList()

        // ── Source 3: Mach processor_set_tasks ────────────────
        let machTasks = MachTaskEnumerator.enumerateAll()
        let machPids = Set(machTasks.map(\.pid))

        let allPids = sysctlPids.union(procPids).union(machPids)

        logger.info("Census: sysctl=\(sysctlPids.count) proc=\(procPids.count) mach=\(machPids.count) union=\(allPids.count)")

        // ── Cross-reference: find disagreements ───────────────

        for pid in allPids {
            let inSysctl = sysctlPids.contains(pid)
            let inProc = procPids.contains(pid)
            let inMach = machPids.contains(pid)

            // Skip PID 0 (kernel_task) — may not appear in all sources
            if pid == 0 { continue }

            let sources = (inSysctl ? 1 : 0) + (inProc ? 1 : 0) + (inMach ? 1 : 0)

            if sources < 3 && sources > 0 {
                // DISAGREEMENT — at least one source can't see this PID
                let name = processName(for: pid)
                let path = processPath(for: pid)
                let missing = [
                    inSysctl ? nil : "sysctl",
                    inProc ? nil : "proc_listallpids",
                    inMach ? nil : "processor_set_tasks",
                ].compactMap { $0 }
                let visible = [
                    inSysctl ? "sysctl" : nil,
                    inProc ? "proc_listallpids" : nil,
                    inMach ? "processor_set_tasks" : nil,
                ].compactMap { $0 }

                // Hidden from Mach but visible elsewhere = DKOM (most serious)
                // Hidden from sysctl/proc but visible in Mach = userspace rootkit
                let severity: AnomalySeverity = !inMach ? .critical : .high
                let technique = !inMach ? "DKOM Hidden Process" : "Process Hiding"

                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: technique,
                    description: "PID \(pid) (\(name)) visible in [\(visible.joined(separator: ", "))] but HIDDEN from [\(missing.joined(separator: ", "))]. Cross-source disagreement indicates rootkit.",
                    severity: severity, mitreID: "T1014",
                    scannerId: "process_census",
                    enumMethod: "3-source cross-reference: sysctl vs proc_listallpids vs processor_set_tasks",
                    evidence: [
                        "pid: \(pid)",
                        "name: \(name)",
                        "path: \(path)",
                        "in_sysctl: \(inSysctl)",
                        "in_proc_listallpids: \(inProc)",
                        "in_mach_tasks: \(inMach)",
                        "missing_from: \(missing.joined(separator: ", "))",
                    ]))
                logger.warning("CENSUS MISMATCH: PID \(pid) (\(name)) missing from \(missing)")
            }
        }

        return anomalies
    }

    // MARK: - Enumeration Sources

    private func enumerateViaSysctl() -> Set<pid_t> {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var bufferSize = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &bufferSize, nil, 0) == 0 else { return [] }

        let entryCount = bufferSize / MemoryLayout<kinfo_proc>.stride
        let procList = UnsafeMutablePointer<kinfo_proc>.allocate(capacity: entryCount)
        defer { procList.deallocate() }

        guard sysctl(&mib, UInt32(mib.count), procList, &bufferSize, nil, 0) == 0 else { return [] }

        let actualCount = bufferSize / MemoryLayout<kinfo_proc>.stride
        var pids = Set<pid_t>()
        for i in 0..<actualCount {
            pids.insert(procList[i].kp_proc.p_pid)
        }
        return pids
    }

    private func enumerateViaProcList() -> Set<pid_t> {
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return [] }

        let capacity = estimated * 2
        let buffer = UnsafeMutablePointer<pid_t>.allocate(capacity: Int(capacity))
        defer { buffer.deallocate() }

        let actual = proc_listallpids(buffer, capacity * Int32(MemoryLayout<pid_t>.size))
        guard actual > 0 else { return [] }

        var pids = Set<pid_t>()
        for i in 0..<Int(actual) {
            pids.insert(buffer[i])
        }
        return pids
    }

    // MARK: - Process Info Helpers

    private func processName(for pid: pid_t) -> String {
        var name = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
        proc_name(pid, &name, UInt32(name.count))
        let s = String(cString: name)
        return s.isEmpty ? "unknown" : s
    }

    private func processPath(for pid: pid_t) -> String {
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        proc_pidpath(pid, &path, UInt32(path.count))
        let s = String(cString: path)
        return s.isEmpty ? "unknown" : s
    }
}
