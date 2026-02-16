import Foundation

/// Point-in-time capture of all running processes.
/// Created once per scan cycle, shared across all scanners.
/// Eliminates ~4000 redundant syscalls per full scan.
public struct ProcessSnapshot: Sendable {
    public let pids: [pid_t]
    public let paths: [pid_t: String]
    public let parents: [pid_t: pid_t]
    public let timestamp: Date

    /// Capture current process state in one pass
    public static func capture() -> ProcessSnapshot {
        let pids = ProcessEnumeration.getRunningPIDs()
        var paths: [pid_t: String] = [:]
        var parents: [pid_t: pid_t] = [:]
        paths.reserveCapacity(pids.count)
        parents.reserveCapacity(pids.count)
        for pid in pids {
            paths[pid] = ProcessEnumeration.getProcessPath(pid)
            parents[pid] = ProcessEnumeration.getParentPID(pid)
        }
        return ProcessSnapshot(
            pids: pids, paths: paths,
            parents: parents, timestamp: Date()
        )
    }

    public func path(for pid: pid_t) -> String {
        paths[pid] ?? ""
    }

    public func parent(of pid: pid_t) -> pid_t {
        parents[pid] ?? 0
    }

    public func name(for pid: pid_t) -> String {
        let p = path(for: pid)
        guard !p.isEmpty else { return "unknown" }
        return URL(fileURLWithPath: p).lastPathComponent
    }

    /// Walk the parent chain up to maxDepth. Returns [pid, parent, grandparent, ...]
    public func ancestry(of pid: pid_t, maxDepth: Int = 8) -> [pid_t] {
        var chain: [pid_t] = []
        var current = pid
        for _ in 0..<maxDepth {
            let p = parent(of: current)
            guard p > 1, p != current else { break }
            chain.append(p)
            current = p
        }
        return chain
    }

    /// Walk the parent chain and return process names
    public func ancestryNames(of pid: pid_t, maxDepth: Int = 8) -> [String] {
        ancestry(of: pid, maxDepth: maxDepth).map { name(for: $0) }
    }
}
