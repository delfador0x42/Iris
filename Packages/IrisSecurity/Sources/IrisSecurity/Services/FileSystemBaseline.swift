import Foundation
import os.log
import CryptoKit

/// Filesystem integrity baseline engine.
/// Hashes critical system files and directories, stores the baseline,
/// and diffs against it to detect unauthorized modifications.
/// Inspired by: IPSW filesystem diffing, AIDE, Tripwire, Wazuh FIM.
public actor FileSystemBaseline {
    public static let shared = FileSystemBaseline()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "FSBaseline")

    /// Directories to monitor for integrity
    static let criticalPaths: [(path: String, description: String)] = [
        ("/usr/bin", "System binaries"),
        ("/usr/sbin", "System admin binaries"),
        ("/usr/lib", "System libraries"),
        ("/usr/local/bin", "Local binaries"),
        ("/etc", "System configuration"),
        ("/Library/LaunchDaemons", "Launch daemons"),
        ("/Library/LaunchAgents", "Launch agents"),
        ("/Library/Security", "Security plugins"),
        ("/Library/Extensions", "Kernel extensions"),
        ("/Library/SystemExtensions", "System extensions"),
        ("/Library/Frameworks", "Third-party frameworks"),
        ("/System/Library/LaunchDaemons", "System launch daemons"),
        ("/System/Library/LaunchAgents", "System launch agents"),
    ]

    /// A snapshot of file hashes
    struct Baseline: Codable {
        let timestamp: Date
        let entries: [String: FileEntry]
    }

    struct FileEntry: Codable, Equatable {
        let hash: String
        let size: UInt64
        let permissions: UInt16
        let modificationDate: Date
        let isExecutable: Bool
    }

    private var currentBaseline: Baseline?
    private let baselinePath: String = {
        let support = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/com.wudan.iris")
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        return support.appendingPathComponent("fs_baseline.json").path
    }()

    /// Take a baseline snapshot of all critical paths
    public func takeBaseline() async -> Int {
        logger.info("Taking filesystem baseline...")
        var entries: [String: FileEntry] = [:]

        for (path, _) in Self.criticalPaths {
            let dirEntries = await hashDirectory(path)
            entries.merge(dirEntries) { _, new in new }
        }

        // Also hash user-level persistence locations
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let userPaths = [
            "\(home)/Library/LaunchAgents",
            "\(home)/.ssh",
            "\(home)/.zshrc", "\(home)/.zshenv", "\(home)/.bash_profile",
        ]
        for path in userPaths {
            if FileManager.default.fileExists(atPath: path) {
                var isDir: ObjCBool = false
                FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
                if isDir.boolValue {
                    let dirEntries = await hashDirectory(path)
                    entries.merge(dirEntries) { _, new in new }
                } else {
                    if let entry = Self.hashFile(path) {
                        entries[path] = entry
                    }
                }
            }
        }

        currentBaseline = Baseline(timestamp: Date(), entries: entries)
        saveBaseline()
        logger.info("Baseline captured: \(entries.count) files")
        return entries.count
    }

    /// Diff current filesystem against baseline
    public func diff() async -> [FileSystemChange] {
        guard let baseline = currentBaseline ?? loadBaseline() else {
            logger.warning("No baseline available. Take a baseline first.")
            return []
        }

        var changes: [FileSystemChange] = []

        for (path, baseEntry) in baseline.entries {
            let fm = FileManager.default

            if !fm.fileExists(atPath: path) {
                // File was deleted
                changes.append(FileSystemChange(
                    path: path,
                    changeType: .deleted,
                    severity: path.hasPrefix("/System") || path.hasPrefix("/usr") ? .critical : .high,
                    details: "File deleted since baseline"
                ))
                continue
            }

            guard let currentEntry = Self.hashFile(path) else { continue }

            if currentEntry.hash != baseEntry.hash {
                // Content changed
                let severity: AnomalySeverity
                if path.hasPrefix("/System") || path.hasPrefix("/usr/bin") ||
                   path.hasPrefix("/usr/sbin") {
                    severity = .critical
                } else if path.hasPrefix("/etc") || path.contains("LaunchDaemons") ||
                          path.contains("LaunchAgents") {
                    severity = .high
                } else {
                    severity = .medium
                }

                changes.append(FileSystemChange(
                    path: path,
                    changeType: .modified,
                    severity: severity,
                    details: "Hash changed: \(baseEntry.hash.prefix(16))... → \(currentEntry.hash.prefix(16))...",
                    oldHash: baseEntry.hash,
                    newHash: currentEntry.hash
                ))
            }

            if currentEntry.permissions != baseEntry.permissions {
                changes.append(FileSystemChange(
                    path: path,
                    changeType: .permissionsChanged,
                    severity: (currentEntry.permissions & 0o4000 != 0) ? .critical : .medium,
                    details: "Permissions changed: \(String(baseEntry.permissions, radix: 8)) → \(String(currentEntry.permissions, radix: 8))"
                ))
            }
        }

        // Check for new files in critical directories
        for (dirPath, _) in Self.criticalPaths {
            let currentFiles = await hashDirectory(dirPath)
            for (path, _) in currentFiles {
                if baseline.entries[path] == nil {
                    changes.append(FileSystemChange(
                        path: path,
                        changeType: .created,
                        severity: path.hasPrefix("/System") ? .critical : .high,
                        details: "New file not in baseline"
                    ))
                }
            }
        }

        return changes.sorted { $0.severity > $1.severity }
    }

    /// Hash all files in a directory — collects paths first, then hashes in parallel
    private func hashDirectory(_ dirPath: String) async -> [String: FileEntry] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dirPath) else { return [:] }

        // 1. Collect all file paths (fast, sequential)
        var paths: [String] = []
        while let file = enumerator.nextObject() as? String {
            let fullPath = "\(dirPath)/\(file)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: fullPath, isDirectory: &isDir),
                  !isDir.boolValue else { continue }
            if let attrs = try? fm.attributesOfItem(atPath: fullPath),
               let size = attrs[.size] as? UInt64, size > 50_000_000 { continue }
            paths.append(fullPath)
        }

        // 2. Hash in parallel (8 concurrent tasks)
        var entries: [String: FileEntry] = [:]
        entries.reserveCapacity(paths.count)

        await withTaskGroup(of: (String, FileEntry?).self) { group in
            var inflight = 0
            for path in paths {
                if inflight >= 8 {
                    if let (p, entry) = await group.next() {
                        if let e = entry { entries[p] = e }
                        inflight -= 1
                    }
                }
                group.addTask { (path, Self.hashFile(path)) }
                inflight += 1
            }
            for await (p, entry) in group {
                if let e = entry { entries[p] = e }
            }
        }

        return entries
    }

    /// Hash a single file — static so it can run off-actor in TaskGroup
    private static func hashFile(_ path: String) -> FileEntry? {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path) else { return nil }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }

        let digest = SHA256.hash(data: data)
        let hash = digest.map { String(format: "%02x", $0) }.joined()

        let size = attrs[.size] as? UInt64 ?? 0
        let perms = attrs[.posixPermissions] as? UInt16 ?? 0
        let modDate = attrs[.modificationDate] as? Date ?? Date.distantPast
        let isExec = fm.isExecutableFile(atPath: path)

        return FileEntry(
            hash: hash,
            size: size,
            permissions: perms,
            modificationDate: modDate,
            isExecutable: isExec
        )
    }

    private func saveBaseline() {
        guard let baseline = currentBaseline else { return }
        if let data = try? JSONEncoder().encode(baseline) {
            try? data.write(to: URL(fileURLWithPath: baselinePath))
        }
    }

    private func loadBaseline() -> Baseline? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: baselinePath)) else {
            return nil
        }
        return try? JSONDecoder().decode(Baseline.self, from: data)
    }
}

/// A detected change to the filesystem
public struct FileSystemChange: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let path: String
    public let changeType: ChangeType
    public let severity: AnomalySeverity
    public let details: String
    public let oldHash: String?
    public let newHash: String?
    public let timestamp: Date

    public enum ChangeType: String, Sendable, Codable {
        case created = "Created"
        case modified = "Modified"
        case deleted = "Deleted"
        case permissionsChanged = "Permissions Changed"
    }

    public init(
        id: UUID = UUID(),
        path: String,
        changeType: ChangeType,
        severity: AnomalySeverity,
        details: String,
        oldHash: String? = nil,
        newHash: String? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.path = path
        self.changeType = changeType
        self.severity = severity
        self.details = details
        self.oldHash = oldHash
        self.newHash = newHash
        self.timestamp = timestamp
    }
}
