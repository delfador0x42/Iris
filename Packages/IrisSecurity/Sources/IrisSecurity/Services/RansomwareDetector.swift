import Foundation
import os.log

/// Monitors file system events for ransomware-like behavior.
/// Detects rapid encryption of files by a single process.
public actor RansomwareDetector {
    public static let shared = RansomwareDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "RansomwareDetector")

    /// Thresholds
    private let encryptionCountThreshold = 3
    private let timeWindowSeconds: TimeInterval = 5.0
    private let maxAlerts = 100

    /// Per-process tracking of encrypted file modifications
    private var processEncryptionMap: [pid_t: [(path: String, time: Date)]] = [:]
    private var alerts: [RansomwareAlert] = []
    private var reportedPIDs: Set<pid_t> = []

    /// Process a file modification event — call from ES or FSEvents handler
    public func processFileEvent(pid: pid_t, path: String) async {
        // Skip small files or known safe formats (entropy analyzer handles this)
        guard let result = EntropyAnalyzer.analyze(path: path),
              result.isEncrypted else {
            return
        }

        let now = Date()

        // Add to tracking
        var entries = processEncryptionMap[pid, default: []]
        entries.append((path: path, time: now))

        // Prune entries outside the time window
        entries = entries.filter { now.timeIntervalSince($0.time) < timeWindowSeconds }
        processEncryptionMap[pid] = entries

        // Check threshold
        if entries.count >= encryptionCountThreshold && !reportedPIDs.contains(pid) {
            reportedPIDs.insert(pid)
            let processPath = Self.getProcessPath(pid)
            let processName = URL(fileURLWithPath: processPath).lastPathComponent

            let alert = RansomwareAlert(
                processID: pid,
                processName: processName,
                processPath: processPath,
                encryptedFiles: entries.map(\.path),
                entropy: result.entropy
            )
            alerts.insert(alert, at: 0)
            if alerts.count > maxAlerts { alerts.removeLast() }

            logger.critical("RANSOMWARE DETECTED: PID \(pid) (\(processName)) encrypted \(entries.count) files in \(self.timeWindowSeconds)s")
        }
    }

    /// Get all alerts
    public func getAlerts() -> [RansomwareAlert] {
        alerts
    }

    /// Reset tracking for a process (e.g., user approved it)
    public func clearProcess(_ pid: pid_t) {
        processEncryptionMap.removeValue(forKey: pid)
        reportedPIDs.remove(pid)
    }

    /// Prune stale tracking data
    public func pruneStale() {
        let now = Date()
        for (pid, entries) in processEncryptionMap {
            let fresh = entries.filter { now.timeIntervalSince($0.time) < timeWindowSeconds * 2 }
            if fresh.isEmpty {
                processEncryptionMap.removeValue(forKey: pid)
            } else {
                processEncryptionMap[pid] = fresh
            }
        }
    }

    /// Scan a directory for already-encrypted files (post-incident forensics)
    public func scanDirectoryForEncryptedFiles(_ dir: String) async -> [(path: String, entropy: Double)] {
        var results: [(path: String, entropy: Double)] = []
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dir) else { return results }

        while let file = enumerator.nextObject() as? String {
            let path = "\(dir)/\(file)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
                continue
            }
            if let result = EntropyAnalyzer.analyze(path: path), result.isEncrypted {
                results.append((path: path, entropy: result.entropy))
            }
        }
        return results
    }

    private static func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "unknown" }
        return String(cString: buf)
    }
}
