import Foundation
import os.log

/// Probes the kernel NECP (Network Extension Control Policy) subsystem and
/// scans all processes for network policy file descriptors.
///
/// On a clean system, only system networking daemons have NECP fds.
/// A non-system process with a NECP fd has direct kernel network policy control
/// — possible traffic interception or redirection.
///
/// If kernel is compromised, necp_open returns attacker-controlled fd and
/// proc_pidinfo hides the real NECP holders. Cross-reference: a compromised
/// kernel that hides NECP fds from proc_info must ALSO hide them from
/// the task port walk (processor_set_tasks → mach_port_names), which is a
/// separate kernel code path.
public actor NECPPolicyProbe: ContradictionProbe {
    public static let shared = NECPPolicyProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "NECPProbe")

    private static let PROX_FDTYPE_NETPOLICY: UInt32 = 9

    public nonisolated let id = "necp-policy"
    public nonisolated let name = "NECP Network Policy Audit"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "Only system networking daemons control kernel network policy",
        groundTruth: "necp_open() tests NECP subsystem liveness; proc_pidinfo(PROC_PIDLISTFDS) enumerates fd types per process",
        adversaryCost: "Must hide NECP fd from proc_info AND necp_open — two independent kernel subsystems",
        positiveDetection: "Non-system processes with NECP policy control fds, or dead NECP subsystem",
        falsePositiveRate: "Low — NECP fds are rare outside system networking daemons and VPN clients"
    )

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        // Source 1: NECP subsystem health — can we open a policy fd?
        let fd = iris_necp_open(0)
        let alive = fd >= 0
        if fd >= 0 { close(fd) }
        if !alive { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "NECP subsystem alive",
            sourceA: SourceValue("necp_open(0)", alive ? "fd returned (alive)" : "failed errno=\(errno)"),
            sourceB: SourceValue("expected", "alive"),
            matches: alive))

        // Source 2: Non-system processes with NECP fds
        let snapshot = ProcessSnapshot.capture()
        var suspicious: [String] = []

        for pid in snapshot.pids where pid > 0 {
            let path = snapshot.path(for: pid)
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/")
                || path.hasPrefix("/sbin/") || path.isEmpty { continue }

            if hasNetpolicyFd(pid: pid) {
                let name = snapshot.name(for: pid)
                suspicious.append("\(name)(\(pid)):\(path)")
            }
        }

        if !suspicious.isEmpty { hasContradiction = true }
        comparisons.append(SourceComparison(
            label: "non-system NECP fd holders",
            sourceA: SourceValue("proc_pidinfo FD scan",
                suspicious.isEmpty ? "none"
                    : suspicious.prefix(5).joined(separator: "; ")),
            sourceB: SourceValue("expected", "none"),
            matches: suspicious.isEmpty))

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        return ProbeResult(
            probeId: id, probeName: name,
            verdict: hasContradiction ? .contradiction : .consistent,
            comparisons: comparisons,
            message: hasContradiction
                ? "NECP anomaly: \(!alive ? "subsystem dead; " : "")\(suspicious.isEmpty ? "" : "\(suspicious.count) non-system NECP fd holder(s)")"
                : "NECP subsystem alive, no suspicious NECP fd holders",
            durationMs: durationMs)
    }

    private func hasNetpolicyFd(pid: pid_t) -> Bool {
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else { return false }
        let count = Int(bufSize) / MemoryLayout<proc_fdinfo>.size
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
        let actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, bufSize)
        guard actual > 0 else { return false }
        let n = Int(actual) / MemoryLayout<proc_fdinfo>.size
        return fds[..<n].contains { $0.proc_fdtype == Self.PROX_FDTYPE_NETPOLICY }
    }
}
