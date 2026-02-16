import Foundation
import os.log
import CryptoKit

/// Filesystem integrity baseline engine.
/// Hashes critical system files and directories, stores the baseline,
/// and diffs against it to detect unauthorized modifications.
/// Inspired by: IPSW filesystem diffing, AIDE, Tripwire, Wazuh FIM.
public actor FileSystemBaseline {
    public static let shared = FileSystemBaseline()
    let logger = Logger(subsystem: "com.wudan.iris", category: "FSBaseline")

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

    var currentBaseline: Baseline?
    let baselinePath: String = {
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
}
