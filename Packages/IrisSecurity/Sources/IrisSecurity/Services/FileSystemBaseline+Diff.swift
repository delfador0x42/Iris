import Foundation
import os.log

/// Filesystem diffing against stored baseline
extension FileSystemBaseline {

    /// Fast diff: only re-hashes files whose mtime or size changed since baseline.
    /// Skips the expensive "new files" directory walk — use takeBaseline() for that.
    public func diff() async -> [FileSystemChange] {
        guard let baseline = currentBaseline ?? loadBaseline() else {
            return []
        }

        var changes: [FileSystemChange] = []
        let fm = FileManager.default

        for (path, baseEntry) in baseline.entries {
            if !fm.fileExists(atPath: path) {
                changes.append(FileSystemChange(
                    path: path,
                    changeType: .deleted,
                    severity: path.hasPrefix("/System") || path.hasPrefix("/usr") ? .critical : .high,
                    details: "File deleted since baseline"
                ))
                continue
            }

            guard let attrs = try? fm.attributesOfItem(atPath: path) else { continue }
            let modDate = attrs[.modificationDate] as? Date ?? .distantPast
            let size = attrs[.size] as? UInt64 ?? 0
            let perms = attrs[.posixPermissions] as? UInt16 ?? 0

            // Fast path: if mtime + size match, content hasn't changed. Skip hash.
            let needsHash = (modDate != baseEntry.modificationDate || size != baseEntry.size)

            if needsHash {
                guard let hash = RustBatchOps.sha256(path: path), !hash.isEmpty else { continue }
                if hash != baseEntry.hash {
                    let severity: AnomalySeverity
                    if path.hasPrefix("/System") || path.hasPrefix("/usr/bin")
                        || path.hasPrefix("/usr/sbin") {
                        severity = .critical
                    } else if path.hasPrefix("/etc") || path.contains("LaunchDaemons")
                        || path.contains("LaunchAgents") {
                        severity = .high
                    } else {
                        severity = .medium
                    }
                    changes.append(FileSystemChange(
                        path: path, changeType: .modified, severity: severity,
                        details: "Hash changed: \(baseEntry.hash.prefix(16))... → \(hash.prefix(16))...",
                        oldHash: baseEntry.hash, newHash: hash
                    ))
                }
            }

            if perms != baseEntry.permissions {
                changes.append(FileSystemChange(
                    path: path, changeType: .permissionsChanged,
                    severity: (perms & 0o4000 != 0) ? .critical : .medium,
                    details: "Permissions: \(String(baseEntry.permissions, radix: 8)) → \(String(perms, radix: 8))"
                ))
            }
        }

        return changes.sorted { $0.severity > $1.severity }
    }
}
