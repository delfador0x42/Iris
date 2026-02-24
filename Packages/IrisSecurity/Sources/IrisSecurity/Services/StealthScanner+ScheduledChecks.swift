import Foundation

/// Emond rules, at jobs — deprecated/rare persistence mechanisms
extension StealthScanner {

    /// Emond rules — deprecated since macOS 10.11 but still checked.
    /// If emond rules exist on a modern system, that's EXTRA suspicious.
    func scanEmondRules() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let emondDir = "/etc/emond.d/rules"

        guard let files = try? FileManager.default.contentsOfDirectory(atPath: emondDir) else {
            return anomalies
        }

        for file in files where file.hasSuffix(".plist") {
            let path = "\(emondDir)/\(file)"
            anomalies.append(.filesystem(
                name: file, path: path,
                technique: "Emond Rule Persistence",
                description: "Event Monitor daemon rule found. Emond is deprecated since macOS 10.11 — any rules present are highly suspicious.",
                severity: .critical, mitreID: "T1546.014"
            ))
        }
        return anomalies
    }

    /// At jobs — only actual scheduled jobs in /private/var/at/jobs/.
    /// Contradiction-based: at.deny and at.allow in /usr/lib/cron/ are stock macOS
    /// config files (they control who can USE `at`), not scheduled jobs.
    /// Only flag files in the actual jobs spool directory.
    func scanAtJobs() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let jobsDir = "/private/var/at/jobs"
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: jobsDir) else {
            return anomalies
        }
        for file in files {
            anomalies.append(.filesystem(
                name: file, path: "\(jobsDir)/\(file)",
                technique: "At Job Persistence",
                description: "Scheduled at job found: \(jobsDir)/\(file). Rarely used legitimately on macOS.",
                severity: .high, mitreID: "T1053.002"
            ))
        }
        return anomalies
    }
}
