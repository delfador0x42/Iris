import Foundation
import os.log

/// Detects Living-off-the-Land Binary abuse and suspicious process genealogy.
/// An APT won't drop a custom binary — they use osascript, curl, python,
/// sqlite3, security CLI, and other system tools. We catch them by analyzing
/// WHO spawned WHAT and whether that lineage makes sense.
public actor LOLBinDetector {
    public static let shared = LOLBinDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "LOLBinDetector")

    private static let maxAncestryDepth = 8

    /// Walk process ancestry up to maxAncestryDepth, return (names, pids) from child to root
    func getAncestry(_ pid: pid_t, snapshot: ProcessSnapshot) -> [(name: String, pid: pid_t)] {
        var chain: [(name: String, pid: pid_t)] = []
        var current = pid
        var seen = Set<pid_t>()
        for _ in 0..<Self.maxAncestryDepth {
            let ppid = snapshot.parent(of: current)
            guard ppid > 0, ppid != current, !seen.contains(ppid) else { break }
            seen.insert(ppid)
            chain.append((name: snapshot.name(for: ppid), pid: ppid))
            current = ppid
        }
        return chain
    }

    /// Analyze all running processes for LOLBin abuse
    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        for pid in snap.pids {
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            let ppid = snap.parent(of: pid)
            let parentPath = snap.path(for: ppid)
            let parentName = parentPath.isEmpty ? "unknown" :
                URL(fileURLWithPath: parentPath).lastPathComponent

            if let mitreID = Self.lolBins[name] {
                anomalies += checkLineage(pid: pid, name: name, path: path,
                    ppid: ppid, parentName: parentName, mitreID: mitreID, snapshot: snap)
                anomalies += checkSuspiciousExecDir(pid: pid, name: name, path: path,
                    ppid: ppid, parentName: parentName, mitreID: mitreID)
            }

            anomalies += checkSuspiciousPath(pid: pid, name: name, path: path,
                ppid: ppid, parentName: parentName)
            anomalies += checkDeletedBinary(pid: pid, name: name, path: path,
                ppid: ppid, parentName: parentName)
            anomalies += checkArgumentAbuse(pid: pid, name: name, path: path,
                ppid: ppid, parentName: parentName)
        }

        return anomalies.sorted { $0.severity > $1.severity }
    }

    // MARK: - Helpers

    func getProcessCWD(_ pid: pid_t) -> String {
        var vinfo = proc_vnodepathinfo()
        let size = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vinfo, Int32(MemoryLayout<proc_vnodepathinfo>.size))
        guard size > 0 else { return "" }
        return withUnsafePointer(to: vinfo.pvi_cdir.vip_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
    }
}
