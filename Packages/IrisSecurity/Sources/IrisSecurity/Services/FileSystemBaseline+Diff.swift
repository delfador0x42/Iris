import Foundation
import os.log

/// Filesystem diffing against stored baseline
extension FileSystemBaseline {

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
}
