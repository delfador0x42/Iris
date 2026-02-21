import Foundation
import os.log

/// Multi-source process census — catches hidden processes by cross-referencing
/// three independent enumeration methods that MUST agree.
///
/// Source 1: sysctl(KERN_PROC_ALL) — standard BSD process list
/// Source 2: proc_listallpids() — libproc enumeration
/// Source 3: processor_set_tasks() — Mach kernel task walk
///
/// A process hidden from ANY source but visible in others = rootkit.
public actor ProcessCensusProbe2: ContradictionProbe {
    public static let shared = ProcessCensusProbe2()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessCensus2")

    public nonisolated let id = "process-census"
    public nonisolated let name = "Process Census"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "All running processes appear in standard enumeration APIs",
        groundTruth: "Three independent sources: sysctl(KERN_PROC_ALL), proc_listallpids(), processor_set_tasks() via Mach",
        adversaryCost: "Must hook all three enumeration APIs simultaneously — sysctl, libproc, AND Mach processor_set_tasks",
        positiveDetection: "Shows each hidden PID with which sources see it and which don't",
        falsePositiveRate: "Low — transient PIDs may appear/disappear between enumerations, but persistent disagreement is suspicious"
    )

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let sysctlPids = enumerateViaSysctl()
        let procPids = enumerateViaProcList()
        let machTasks = MachTaskEnumerator.enumerateAll()
        let machPids = Set(machTasks.map(\.pid))

        let allPids = sysctlPids.union(procPids).union(machPids)

        logger.info("Census: sysctl=\(sysctlPids.count) proc=\(procPids.count) mach=\(machPids.count) union=\(allPids.count)")

        // Overall count comparison
        comparisons.append(SourceComparison(
            label: "process count: sysctl vs proc_listallpids",
            sourceA: SourceValue("sysctl(KERN_PROC_ALL)", "\(sysctlPids.count) PIDs"),
            sourceB: SourceValue("proc_listallpids()", "\(procPids.count) PIDs"),
            matches: sysctlPids.count == procPids.count))

        comparisons.append(SourceComparison(
            label: "process count: sysctl vs processor_set_tasks",
            sourceA: SourceValue("sysctl(KERN_PROC_ALL)", "\(sysctlPids.count) PIDs"),
            sourceB: SourceValue("processor_set_tasks()", "\(machPids.count) PIDs"),
            matches: sysctlPids.count == machPids.count))

        // Per-PID disagreements
        for pid in allPids {
            if pid == 0 { continue }  // kernel_task — may not appear in all sources

            let inSysctl = sysctlPids.contains(pid)
            let inProc = procPids.contains(pid)
            let inMach = machPids.contains(pid)

            let sources = (inSysctl ? 1 : 0) + (inProc ? 1 : 0) + (inMach ? 1 : 0)

            if sources < 3 && sources > 0 {
                hasContradiction = true
                let name = processName(for: pid)
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

                comparisons.append(SourceComparison(
                    label: "PID \(pid) (\(name)): visible vs hidden",
                    sourceA: SourceValue("visible in", visible.joined(separator: ", ")),
                    sourceB: SourceValue("hidden from", missing.joined(separator: ", ")),
                    matches: false))

                logger.warning("CENSUS MISMATCH: PID \(pid) (\(name)) missing from \(missing)")
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if hasContradiction {
            let hidden = comparisons.filter { !$0.matches && $0.label.hasPrefix("PID") }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(hidden) process(es) hidden from at least one enumeration source"
        } else {
            verdict = .consistent
            message = "All 3 sources agree on \(allPids.count) processes"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
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
        for i in 0..<actualCount { pids.insert(procList[i].kp_proc.p_pid) }
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
        for i in 0..<Int(actual) { pids.insert(buffer[i]) }
        return pids
    }

    private func processName(for pid: pid_t) -> String {
        var name = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
        proc_name(pid, &name, UInt32(name.count))
        let s = String(cString: name)
        return s.isEmpty ? "unknown" : s
    }
}
