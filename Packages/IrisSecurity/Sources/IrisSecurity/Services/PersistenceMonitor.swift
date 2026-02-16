import Foundation
import os.log

/// Monitors persistence locations for changes (BlockBlock-inspired).
/// In ES mode: receives file events and matches against persistence paths.
/// In polling mode: snapshots persistence state and diffs for changes.
/// Uses SHA256 hashes to detect actual content changes (not just mtime bumps).
public actor PersistenceMonitor {
    public static let shared = PersistenceMonitor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "PersistenceMonitor")

    /// Regex patterns for persistence locations (from BlockBlock)
    static let persistencePatterns: [(pattern: String, type: PersistenceType)] = [
        // LaunchDaemons and LaunchAgents
        (#"^(/System|/Users/[^/]+|)/Library/(LaunchDaemons|LaunchAgents)/.+\.plist$"#, .launchDaemon),
        // Kernel extensions
        (#"^(/System|)/Library/Extensions/[^/]+\.kext$"#, .kernelExtension),
        // Login items (BTM file)
        (#"^(/Users/[^/]+|)/Library/Application Support/com\.apple\.backgroundtaskmanagementagent/backgrounditems\.btm$"#, .loginItem),
        // Cron jobs
        (#"^/private/var/at/tabs/.+"#, .cronJob),
        // Shell configs
        (#"^(/Users/[^/]+/|/etc/)\.(zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|profile)$"#, .shellConfig),
        // Authorization plugins
        (#"^/Library/Security/SecurityAgentPlugins/.+"#, .authorizationPlugin),
        // Periodic scripts
        (#"^/etc/periodic/(daily|weekly|monthly)/.+"#, .periodicScript),
        // Startup scripts
        (#"^/etc/(rc\.|launchd\.conf).+"#, .startupScript),
        // Login hooks (loginwindow plist)
        (#"^(/Library|/Users/[^/]+/Library)/Preferences/com\.apple\.loginwindow\.plist$"#, .loginHook),
    ]

    private var compiledPatterns: [(regex: NSRegularExpression, type: PersistenceType)] = []
    private var previousSnapshot: [String: FileSnapshot] = [:]
    private var changeLog: [PersistenceChange] = []
    private let maxChanges = 500

    /// File state captured during snapshot
    struct FileSnapshot {
        let modDate: Date
        let hash: String?  // SHA256, nil if unreadable
        let size: UInt64
    }

    init() {
        compiledPatterns = Self.persistencePatterns.compactMap { entry in
            guard let regex = try? NSRegularExpression(pattern: entry.pattern) else { return nil }
            return (regex: regex, type: entry.type)
        }
    }

    /// Check if a file path matches a persistence location
    public func matchesPersistenceLocation(_ path: String) -> PersistenceType? {
        let range = NSRange(path.startIndex..<path.endIndex, in: path)
        for (regex, type) in compiledPatterns {
            if regex.firstMatch(in: path, range: range) != nil {
                return type
            }
        }
        return nil
    }

    /// Process a file event from ES framework or FSEvents
    public func processFileEvent(
        path: String,
        eventType: FileEventType,
        pid: pid_t,
        processPath: String
    ) {
        guard let persistenceType = matchesPersistenceLocation(path) else { return }

        let change = PersistenceChange(
            path: path,
            persistenceType: persistenceType,
            eventType: eventType,
            pid: pid,
            processName: URL(fileURLWithPath: processPath).lastPathComponent,
            processPath: processPath
        )

        changeLog.insert(change, at: 0)
        if changeLog.count > maxChanges { changeLog.removeLast() }

        logger.warning("Persistence change: \(eventType.rawValue) \(path) by PID \(pid) (\(processPath))")
    }

    /// Get recent persistence changes
    public func getRecentChanges() -> [PersistenceChange] {
        changeLog
    }

    /// Snapshot current persistence file timestamps and hashes for later diffing.
    /// SHA256 hashes detect actual content changes (mtime alone is spoofable).
    public func takeSnapshot() async {
        let scanner = PersistenceScanner.shared
        let items = await scanner.scanAll()
        let fm = FileManager.default
        previousSnapshot = Dictionary(
            uniqueKeysWithValues: items.compactMap { item in
                guard let attrs = try? fm.attributesOfItem(atPath: item.path),
                      let modDate = attrs[.modificationDate] as? Date else { return nil }
                let size = (attrs[.size] as? UInt64) ?? 0
                let hash = hashFile(item.path)
                return (item.path, FileSnapshot(modDate: modDate, hash: hash, size: size))
            }
        )
        logger.info("Persistence snapshot captured: \(self.previousSnapshot.count) items")
    }

    /// Diff current state against last snapshot.
    /// Uses SHA256 to verify actual content changes (not just mtime bumps).
    public func diffAgainstSnapshot() async -> [PersistenceChange] {
        var changes: [PersistenceChange] = []
        let scanner = PersistenceScanner.shared
        let currentItems = await scanner.scanAll()
        let fm = FileManager.default

        for item in currentItems {
            guard let attrs = try? fm.attributesOfItem(atPath: item.path),
                  let modDate = attrs[.modificationDate] as? Date else { continue }

            if let prev = previousSnapshot[item.path] {
                // Only flag if content actually changed (hash mismatch), not just mtime
                let currentHash = hashFile(item.path)
                let contentChanged = (currentHash != nil && prev.hash != nil && currentHash != prev.hash)
                    || (modDate > prev.modDate && prev.hash == nil)  // can't verify, trust mtime
                if contentChanged {
                    changes.append(PersistenceChange(
                        path: item.path,
                        persistenceType: item.type,
                        eventType: .modified,
                        pid: 0,
                        processName: "unknown",
                        processPath: ""
                    ))
                }
            } else {
                changes.append(PersistenceChange(
                    path: item.path,
                    persistenceType: item.type,
                    eventType: .created,
                    pid: 0,
                    processName: "unknown",
                    processPath: ""
                ))
            }
        }

        // Check for deleted items
        let currentPaths = Set(currentItems.map(\.path))
        for (path, _) in previousSnapshot where !currentPaths.contains(path) {
            if let type = matchesPersistenceLocation(path) {
                changes.append(PersistenceChange(
                    path: path,
                    persistenceType: type,
                    eventType: .deleted,
                    pid: 0,
                    processName: "unknown",
                    processPath: ""
                ))
            }
        }

        return changes
    }

    /// SHA256 hash via Rust FFI (streaming, no full-file memory load).
    private nonisolated func hashFile(_ path: String) -> String? {
        RustBatchOps.sha256(path: path)
    }
}

/// Type of file event
public enum FileEventType: String, Sendable, Codable {
    case created
    case modified
    case deleted
    case renamed
}

/// A detected change to a persistence location
public struct PersistenceChange: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let path: String
    public let persistenceType: PersistenceType
    public let eventType: FileEventType
    public let pid: pid_t
    public let processName: String
    public let processPath: String
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        path: String,
        persistenceType: PersistenceType,
        eventType: FileEventType,
        pid: pid_t,
        processName: String,
        processPath: String,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.path = path
        self.persistenceType = persistenceType
        self.eventType = eventType
        self.pid = pid
        self.processName = processName
        self.processPath = processPath
        self.timestamp = timestamp
    }
}
