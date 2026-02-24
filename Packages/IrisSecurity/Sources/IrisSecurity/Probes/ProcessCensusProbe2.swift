import Foundation
import os.log

/// Multi-source process census — catches hidden processes by cross-referencing
/// four independent enumeration methods that MUST agree.
///
/// Source 1: sysctl(KERN_PROC_ALL) — standard BSD process list
/// Source 2: proc_listallpids() — libproc enumeration
/// Source 3: processor_set_tasks() — Mach kernel task walk
/// Source 4: proc_listcoalitions() — kernel coalition membership (task count)
///
/// A process hidden from ANY source but visible in others = rootkit.
public actor ProcessCensusProbe2: ContradictionProbe {
    public static let shared = ProcessCensusProbe2()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProcessCensus2")

    @_silgen_name("proc_listcoalitions")
    private static func proc_listcoalitions(
        _ type: UInt32, _ typeorder: UInt32,
        _ buffer: UnsafeMutableRawPointer?, _ buffersize: Int32
    ) -> Int32

    public nonisolated let id = "process-census"
    public nonisolated let name = "Process Census"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "All running processes appear in standard enumeration APIs",
        groundTruth: "Four independent sources: sysctl(KERN_PROC_ALL), proc_listallpids(), processor_set_tasks() via Mach, proc_listcoalitions() kernel coalitions",
        adversaryCost: "Must hook all four enumeration APIs simultaneously — sysctl, libproc, Mach processor_set_tasks, AND kernel coalitions",
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
        let coalitionTaskCount = readCoalitionTaskCount()

        // A source that FAILS (returns empty) is excluded from comparison.
        // "No data" ≠ "0 processes found." processor_set_tasks requires root.
        let machAvailable = !machPids.isEmpty
        var activeSources = 2  // sysctl + proc always available
        if machAvailable { activeSources += 1 }

        // Union only includes sources that returned data
        var allPids = sysctlPids.union(procPids)
        if machAvailable { allPids = allPids.union(machPids) }

        logger.info("Census: sysctl=\(sysctlPids.count) proc=\(procPids.count) mach=\(machPids.count)\(machAvailable ? "" : "(unavail)") coalitions=\(coalitionTaskCount ?? -1) union=\(allPids.count)")

        // Source 1 vs 2: sysctl vs proc_listallpids (always available)
        // Allow ±3 for race conditions (processes spawning/dying between calls)
        let countDiff12 = abs(sysctlPids.count - procPids.count)
        comparisons.append(SourceComparison(
            label: "process count: sysctl vs proc_listallpids",
            sourceA: SourceValue("sysctl(KERN_PROC_ALL)", "\(sysctlPids.count) PIDs"),
            sourceB: SourceValue("proc_listallpids()", "\(procPids.count) PIDs"),
            matches: countDiff12 <= 3))
        if countDiff12 > 3 { hasContradiction = true }

        // Source 3: processor_set_tasks — requires root.
        // If unavailable, record as degraded info, NOT as contradiction.
        if machAvailable {
            let countDiff13 = abs(sysctlPids.count - machPids.count)
            comparisons.append(SourceComparison(
                label: "process count: sysctl vs processor_set_tasks",
                sourceA: SourceValue("sysctl(KERN_PROC_ALL)", "\(sysctlPids.count) PIDs"),
                sourceB: SourceValue("processor_set_tasks()", "\(machPids.count) PIDs"),
                matches: countDiff13 <= 3))
            if countDiff13 > 3 { hasContradiction = true }
        } else {
            comparisons.append(SourceComparison(
                label: "processor_set_tasks availability",
                sourceA: SourceValue("processor_set_tasks()", "unavailable — requires root"),
                sourceB: SourceValue("expected", "host_processor_set_priv needs root"),
                matches: true))  // Degraded, not contradicted
        }

        // Source 4: Coalition count cross-reference.
        // Each coalition = one app/process group. Multiple PIDs per coalition.
        // Coalition count should be LESS than PID count. If MORE, something is wrong.
        if let coalitionCount = coalitionTaskCount {
            let maxPids = allPids.count
            // Coalitions should be fewer than PIDs (typically 20-40% of PID count).
            // If coalition count exceeds PID count, either parsing is wrong or
            // there are coalitions for hidden processes.
            let suspicious = coalitionCount > maxPids
            if suspicious { hasContradiction = true }
            comparisons.append(SourceComparison(
                label: "coalition count vs visible processes",
                sourceA: SourceValue("proc_listcoalitions(JETSAM)", "\(coalitionCount) coalitions"),
                sourceB: SourceValue("union of \(activeSources) sources", "\(maxPids) PIDs"),
                matches: !suspicious))
        }

        // Per-PID disagreements — only between AVAILABLE sources.
        // Collect all mismatches, then decide if it's a real contradiction.
        var hiddenPids: [(pid: pid_t, name: String, visible: [String], missing: [String])] = []
        for pid in allPids {
            if pid == 0 { continue }  // kernel_task

            let inSysctl = sysctlPids.contains(pid)
            let inProc = procPids.contains(pid)
            // If mach unavailable, don't count it as missing
            let inMach = machAvailable ? machPids.contains(pid) : true

            var visible: [String] = []
            var missing: [String] = []
            if inSysctl { visible.append("sysctl") } else { missing.append("sysctl") }
            if inProc { visible.append("proc_listallpids") } else { missing.append("proc_listallpids") }
            if machAvailable {
                if inMach { visible.append("processor_set_tasks") } else { missing.append("processor_set_tasks") }
            }

            if !missing.isEmpty && !visible.isEmpty {
                hiddenPids.append((pid, processName(for: pid), visible, missing))
            }
        }

        // ≤3 transient mismatches = race condition (processes spawn/die between calls).
        // >3 persistent mismatches = something is hiding processes.
        let raceThreshold = 3
        if hiddenPids.count > raceThreshold { hasContradiction = true }

        for entry in hiddenPids.prefix(10) {
            let withinRace = hiddenPids.count <= raceThreshold
            comparisons.append(SourceComparison(
                label: "PID \(entry.pid) (\(entry.name)): visibility",
                sourceA: SourceValue("visible in", entry.visible.joined(separator: ", ")),
                sourceB: SourceValue("hidden from", entry.missing.joined(separator: ", ")),
                matches: withinRace))
            if !withinRace {
                logger.warning("CENSUS: PID \(entry.pid) (\(entry.name)) hidden from \(entry.missing)")
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if hasContradiction {
            verdict = .contradiction
            message = "CONTRADICTION: \(hiddenPids.count) process(es) hidden from enumeration source(s)"
        } else if !machAvailable {
            verdict = .consistent
            message = "\(activeSources)/4 sources agree on \(allPids.count) processes (Mach requires root)"
        } else {
            verdict = .consistent
            message = "All \(activeSources) sources agree on \(allPids.count) processes"
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

    /// Read coalition count from jetsam coalitions.
    /// Returns the number of active coalitions — each roughly maps to an app/process group.
    ///
    /// NOTE: procinfo_coalinfo struct layout varies by macOS version:
    ///   - 80 bytes on older macOS
    ///   - 104 bytes on arm64 macOS 15.x+
    /// We do NOT parse internal fields (the offsets are unreliable).
    /// Instead, use entry COUNT only — derived from (buffer size / entry size).
    private func readCoalitionTaskCount() -> Int? {
        let bufSize = Self.proc_listcoalitions(1, 0, nil, 0)
        guard bufSize > 0 else {
            logger.debug("proc_listcoalitions size query returned \(bufSize)")
            return nil
        }
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: Int(bufSize), alignment: 8)
        defer { buffer.deallocate() }
        let actual = Self.proc_listcoalitions(1, 0, buffer, bufSize)
        guard actual > 0 else { return nil }

        // Determine entry size: try known sizes that divide evenly
        let knownSizes = [104, 80, 88, 96, 112, 120, 128]
        let entrySize = knownSizes.first { Int(actual) % $0 == 0 } ?? 104
        return Int(actual) / entrySize
    }

    private func processName(for pid: pid_t) -> String {
        var name = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
        proc_name(pid, &name, UInt32(name.count))
        let s = String(cString: name)
        return s.isEmpty ? "unknown" : s
    }
}
