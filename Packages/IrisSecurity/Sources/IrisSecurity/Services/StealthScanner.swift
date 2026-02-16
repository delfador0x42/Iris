import Foundation
import os.log

/// Scans for stealth persistence and APT artifacts that other tools miss.
/// Looks for: hidden LaunchAgents, modified system files, emond rules,
/// PAM modules, sudoers modifications, SSH authorized_keys, at jobs,
/// and files with suspicious extended attributes.
public actor StealthScanner {
    public static let shared = StealthScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "StealthScanner")

    /// Run all stealth scans
    public func scanAll(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        async let hidden = scanHiddenLaunchAgents()
        async let emond = scanEmondRules()
        async let pam = scanPAMModules()
        async let sudoers = scanSudoersModifications()
        async let ssh = scanSSHKeys()
        async let atJobs = scanAtJobs()
        async let envVars = scanDYLDEnvironment(snapshot: snap)
        async let quarantine = scanMissingQuarantine()
        async let suidBinaries = scanSUIDBinaries()

        let all = await [hidden, emond, pam, sudoers, ssh, atJobs, envVars,
                         quarantine, suidBinaries]
        return all.flatMap { $0 }
    }

    /// Hidden LaunchAgents — dot-prefixed plists that don't show in Finder
    func scanHiddenLaunchAgents() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = [
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "\(home)/Library/LaunchAgents"
        ]

        for dir in dirs {
            guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
                continue
            }
            for file in contents where file.hasPrefix(".") && file.hasSuffix(".plist") {
                anomalies.append(.filesystem(
                    name: file, path: "\(dir)/\(file)",
                    technique: "Hidden LaunchAgent/Daemon",
                    description: "Dot-prefixed plist hidden from Finder: \(dir)/\(file). This is a common APT technique.",
                    severity: .critical, mitreID: "T1564.001",
                    scannerId: "stealth",
                    enumMethod: "FileManager.contentsOfDirectory → dot-prefix filter",
                    evidence: [
                        "plist: \(dir)/\(file)",
                        "hidden: dot-prefixed (invisible in Finder)",
                        "directory: \(dir)",
                    ]
                ))
            }
        }
        return anomalies
    }

    // MARK: - Helpers

    func hasExtendedAttribute(_ path: String, name: String) -> Bool {
        let size = getxattr(path, name, nil, 0, 0, 0)
        return size >= 0
    }
}
