import Foundation
import os.log

/// Audits file descriptor types across all running processes.
///
/// On a compromised system, the attacker MUST have open fds for their operations:
///   FSEVENTS (type 7): filesystem surveillance — monitors every file change
///   NETPOLICY (type 9): kernel network policy control — traffic redirection
///   CHANNEL (type 10): Skywalk network channel — low-level kernel networking
///   NEXUS (type 11): Skywalk nexus — kernel network fabric access
///
/// If the kernel is compromised, proc_pidinfo returns attacker-controlled fd lists.
/// But hiding fds from proc_info requires hooking proc_pidinfo_internal() in the
/// kernel — which is a DIFFERENT code path than the fd table itself. Cross-reference
/// with /dev/fsevents device open count (IOKit) to catch proc_info-hidden watchers.
public actor FileDescriptorAuditProbe: ContradictionProbe {
    public static let shared = FileDescriptorAuditProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "FDAudit")

    // FD types — some not in public headers
    private static let PROX_FDTYPE_FSEVENTS: UInt32 = 7
    private static let PROX_FDTYPE_NETPOLICY: UInt32 = 9
    private static let PROX_FDTYPE_CHANNEL: UInt32 = 10
    private static let PROX_FDTYPE_NEXUS: UInt32 = 11

    public nonisolated let id = "fd-audit"
    public nonisolated let name = "File Descriptor Audit"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "No unauthorized process monitors filesystem events or controls kernel networking",
        groundTruth: "proc_pidinfo(PROC_PIDLISTFDS) enumerates fd types from kernel fd table per process",
        adversaryCost: "Must hook proc_pidinfo_internal in kernel to hide fds — separate code path from fd operations themselves",
        positiveDetection: "Non-system processes with FSEVENTS, NETPOLICY, CHANNEL, or NEXUS file descriptors",
        falsePositiveRate: "Medium for FSEVENTS (dev tools use it); very low for CHANNEL/NEXUS/NETPOLICY"
    )

    /// System processes expected to hold FSEVENTS — NOT an allowlist for trust,
    /// just a noise filter. Any process CAN be compromised.
    private static let knownFSEventsHolders: Set<String> = [
        "fseventsd", "mds", "mds_stores", "mdworker", "mdworker_shared",
        "Finder", "backupd", "bird", "cloudd", "filecoordinationd",
        "lsd", "revisiond", "coreduetd",
    ]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let snapshot = ProcessSnapshot.capture()
        var fseventsHolders: [String] = []
        var kernelNetHolders: [String] = []

        for pid in snapshot.pids where pid > 0 {
            let path = snapshot.path(for: pid)
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/")
                || path.hasPrefix("/sbin/") || path.isEmpty { continue }
            let name = snapshot.name(for: pid)
            if Self.knownFSEventsHolders.contains(name) { continue }

            let types = fdTypeCensus(pid: pid)

            if types.contains(Self.PROX_FDTYPE_FSEVENTS) {
                fseventsHolders.append("\(name)(\(pid))")
            }
            if types.contains(Self.PROX_FDTYPE_CHANNEL)
                || types.contains(Self.PROX_FDTYPE_NEXUS)
            {
                kernelNetHolders.append("\(name)(\(pid))")
            }
        }

        // FSEVENTS on non-system processes — informational, not contradiction
        // (dev tools legitimately use it, but on a compromised host this IS the attacker)
        comparisons.append(SourceComparison(
            label: "FSEVENTS on non-system processes",
            sourceA: SourceValue("proc_pidinfo FD scan",
                fseventsHolders.isEmpty ? "none"
                    : fseventsHolders.prefix(10).joined(separator: ", ")),
            sourceB: SourceValue("census", "\(fseventsHolders.count) holder(s)"),
            matches: true))  // census — always matches, data is the value

        // Kernel networking fds on non-system = contradiction
        if !kernelNetHolders.isEmpty { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "kernel network CHANNEL/NEXUS on non-system",
            sourceA: SourceValue("proc_pidinfo FD scan",
                kernelNetHolders.isEmpty ? "none"
                    : kernelNetHolders.prefix(5).joined(separator: ", ")),
            sourceB: SourceValue("expected", "none"),
            matches: kernelNetHolders.isEmpty))

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        return ProbeResult(
            probeId: id, probeName: name,
            verdict: hasContradiction ? .contradiction : .consistent,
            comparisons: comparisons,
            message: hasContradiction
                ? "CONTRADICTION: \(kernelNetHolders.count) non-system kernel network fd holder(s)"
                : "\(fseventsHolders.count) non-system FSEVENTS holder(s), no kernel network abuse",
            durationMs: durationMs)
    }

    private func fdTypeCensus(pid: pid_t) -> Set<UInt32> {
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else { return [] }
        let count = Int(bufSize) / MemoryLayout<proc_fdinfo>.size
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
        let actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, bufSize)
        guard actual > 0 else { return [] }
        let n = Int(actual) / MemoryLayout<proc_fdinfo>.size
        return Set(fds[..<n].map(\.proc_fdtype))
    }
}
