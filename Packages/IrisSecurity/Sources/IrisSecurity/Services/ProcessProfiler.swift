import Foundation

/// Builds a complete profile for a process — identity, description, parent chain.
/// Combines ProcessSnapshot data with ProcessKnowledgeBase for "why is this running" context.
public enum ProcessProfiler {

    public struct Profile: Sendable {
        public let pid: pid_t
        public let name: String
        public let path: String
        public let description: String?
        public let category: ProcessKnowledgeBase.Category
        public let subsystem: String?
        public let genealogy: [Ancestor]
    }

    public struct Ancestor: Sendable {
        public let pid: pid_t
        public let name: String
        public let path: String
    }

    /// Build a profile for a single process using snapshot data.
    public static func profile(pid: pid_t, snapshot: ProcessSnapshot) -> Profile {
        let path = snapshot.path(for: pid)
        let name = snapshot.name(for: pid)
        let info = ProcessKnowledgeBase.lookup(name)
        let chain = traceGenealogy(pid: pid, snapshot: snapshot)

        return Profile(
            pid: pid, name: name, path: path,
            description: info?.description,
            category: info?.category ?? .unknown,
            subsystem: info?.subsystem,
            genealogy: chain
        )
    }

    /// Trace parent chain back to launchd (PID 1) or kernel (PID 0).
    public static func traceGenealogy(pid: pid_t, snapshot: ProcessSnapshot) -> [Ancestor] {
        var chain: [Ancestor] = []
        var current = pid
        var seen = Set<pid_t>([pid])

        while true {
            let parent = snapshot.parent(of: current)
            guard parent >= 0, !seen.contains(parent) else { break }
            seen.insert(parent)
            let parentPath = snapshot.path(for: parent)
            let parentName = parentPath.isEmpty ? (parent == 0 ? "kernel" : "unknown")
                                                : snapshot.name(for: parent)
            chain.append(Ancestor(pid: parent, name: parentName, path: parentPath))
            if parent <= 1 { break } // reached launchd or kernel
            current = parent
        }

        return chain
    }

    /// Trace parent chain using live syscalls (no snapshot needed).
    /// 2-5 syscalls vs 800 for full snapshot — ideal for on-demand view display.
    public static func traceGenealogyLive(pid: pid_t) -> [Ancestor] {
        var chain: [Ancestor] = []
        var current = pid
        var seen = Set<pid_t>([pid])

        while true {
            let parent = ProcessEnumeration.getParentPID(current)
            guard parent > 0, !seen.contains(parent) else { break }
            seen.insert(parent)
            let path = ProcessEnumeration.getProcessPath(parent)
            let name = path.isEmpty ? (parent == 0 ? "kernel" : "unknown")
                                    : URL(fileURLWithPath: path).lastPathComponent
            chain.append(Ancestor(pid: parent, name: name, path: path))
            if parent <= 1 { break }
            current = parent
        }
        return chain
    }

    /// Format genealogy as a readable chain: "launchd → Brave Browser → Helper"
    public static func genealogyString(for profile: Profile) -> String {
        let ancestors = profile.genealogy.reversed().map(\.name)
        let chain = ancestors + [profile.name]
        return chain.joined(separator: " → ")
    }

    /// Format ancestor chain as a readable string.
    public static func chainString(ancestors: [Ancestor], processName: String) -> String {
        let names = ancestors.reversed().map(\.name)
        return (names + [processName]).joined(separator: " → ")
    }
}
