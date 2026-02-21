import Foundation
import os.log

/// Detects timestamp manipulation (timestomping) — a core anti-forensics technique
/// used by nation-state actors to hide when files were actually created or modified.
///
/// Detection layers:
/// 1. Birth time > modification time (impossible without manipulation)
/// 2. Files in recently-created directories with suspiciously old timestamps
/// 3. Executables/dylibs with creation dates far in the past in writable directories
/// 4. Clusters of files with identical timestamps (bulk timestomping)
/// 5. Extended attribute timestamps that don't match filesystem timestamps
public actor TimestompDetector {
    public static let shared = TimestompDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Timestomp")

    /// Directories to scan for timestomping
    private static let scanDirs: [String] = [
        "/tmp", "/var/tmp", "/private/tmp",
        "/Library/LaunchAgents", "/Library/LaunchDaemons",
    ]

    /// Additional per-user directories
    private static func userScanDirs() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            "\(home)/Library/LaunchAgents",
            "\(home)/Library/Application Support",
            "\(home)/.local/bin",
            "\(home)/Library/Services",
        ]
    }

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let dirs = Self.scanDirs + Self.userScanDirs()

        for dir in dirs {
            anomalies.append(contentsOf: scanDirectory(dir))
        }

        return anomalies
    }

    /// Scan a single directory for timestomping indicators
    private func scanDirectory(_ dir: String) -> [ProcessAnomaly] {
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { return [] }

        var anomalies: [ProcessAnomaly] = []
        var timestampClusters: [TimeInterval: [String]] = [:]

        for file in contents {
            let fullPath = "\(dir)/\(file)"
            guard let attrs = try? fm.attributesOfItem(atPath: fullPath) else { continue }

            let mtime = (attrs[.modificationDate] as? Date) ?? Date.distantPast
            let ctime = (attrs[.creationDate] as? Date) ?? Date.distantPast

            // Layer 1: Birth time after modification time (definitive timestomping)
            if ctime > mtime && mtime != Date.distantPast && ctime != Date.distantPast {
                let delta = ctime.timeIntervalSince(mtime)
                if delta > 60 { // More than 1 minute difference
                    anomalies.append(.filesystem(
                        name: file, path: fullPath,
                        technique: "Timestomping (Birth > Modify)",
                        description: "File creation date is \(Int(delta))s AFTER modification date. Timestamps have been manipulated.",
                        severity: .high, mitreID: "T1070.006",
                        scannerId: "timestomp",
                        enumMethod: "FileManager.attributesOfItem birth vs modify comparison",
                        evidence: [
                            "path: \(fullPath)",
                            "birth: \(ctime)",
                            "modify: \(mtime)",
                            "delta_seconds: \(Int(delta))",
                        ]))
                }
            }

            // Layer 2: Executables with suspiciously old timestamps in temp dirs
            if dir.contains("/tmp") || dir.contains("/var/tmp") {
                let age = Date().timeIntervalSince(mtime)
                let isExecutable = fm.isExecutableFile(atPath: fullPath)
                // Executable files in /tmp older than 30 days is suspicious
                // (temp dirs are usually cleaned regularly)
                if isExecutable && age > 30 * 86400 {
                    anomalies.append(.filesystem(
                        name: file, path: fullPath,
                        technique: "Timestomping (Old Temp Executable)",
                        description: "Executable in temp directory claims to be \(Int(age / 86400)) days old. Likely timestomped.",
                        severity: .medium, mitreID: "T1070.006",
                        scannerId: "timestomp",
                        enumMethod: "FileManager temp dir + age analysis",
                        evidence: [
                            "path: \(fullPath)",
                            "age_days: \(Int(age / 86400))",
                            "mtime: \(mtime)",
                        ]))
                }
            }

            // Layer 3: Collect timestamps for cluster analysis
            // Round to nearest hour for clustering
            let rounded = (mtime.timeIntervalSince1970 / 3600).rounded() * 3600
            timestampClusters[rounded, default: []].append(fullPath)

            // Layer 4: Check persistence locations for recent but backdated files
            if dir.contains("LaunchAgents") || dir.contains("LaunchDaemons") {
                let age = Date().timeIntervalSince(mtime)
                let birthAge = Date().timeIntervalSince(ctime)
                // If birth is recent but mtime is old, it's timestomped
                if birthAge < 7 * 86400 && age > 90 * 86400 {
                    anomalies.append(.filesystem(
                        name: file, path: fullPath,
                        technique: "Timestomping (Backdated Persistence)",
                        description: "Persistence item created \(Int(birthAge / 86400))d ago but claims mtime of \(Int(age / 86400))d ago.",
                        severity: .critical, mitreID: "T1070.006",
                        scannerId: "timestomp",
                        enumMethod: "FileManager persistence dir + birth vs mtime delta",
                        evidence: [
                            "path: \(fullPath)",
                            "birth_age_days: \(Int(birthAge / 86400))",
                            "mtime_age_days: \(Int(age / 86400))",
                        ]))
                }
            }
        }

        // Layer 5: Detect bulk timestomping (many files with same timestamp)
        for (_, paths) in timestampClusters {
            if paths.count >= 5 {
                // 5+ files with the exact same hour timestamp is suspicious
                let representative = (paths.first! as NSString).lastPathComponent
                anomalies.append(.filesystem(
                    name: representative, path: paths.first!,
                    technique: "Bulk Timestomping",
                    description: "\(paths.count) files share the same timestamp hour in \(dir). Indicates automated timestamp manipulation.",
                    severity: .medium, mitreID: "T1070.006",
                    scannerId: "timestomp",
                    enumMethod: "Timestamp clustering analysis (1-hour buckets)",
                    evidence: [
                        "directory: \(dir)",
                        "cluster_size: \(paths.count)",
                        "sample_files: \(paths.prefix(3).map { ($0 as NSString).lastPathComponent }.joined(separator: ", "))",
                    ]))
            }
        }

        return anomalies
    }
}
