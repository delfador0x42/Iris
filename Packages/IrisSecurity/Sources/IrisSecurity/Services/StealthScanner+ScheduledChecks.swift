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

    /// At jobs — /usr/lib/cron/at.* and /private/var/at/jobs/
    func scanAtJobs() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let dirs = ["/private/var/at/jobs", "/usr/lib/cron"]

        for dir in dirs {
            guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
                continue
            }
            for file in files where file.hasPrefix("a") || file.hasPrefix("at.") {
                anomalies.append(.filesystem(
                    name: file, path: "\(dir)/\(file)",
                    technique: "At Job Persistence",
                    description: "Scheduled at job found: \(dir)/\(file). Rarely used legitimately on macOS.",
                    severity: .high, mitreID: "T1053.002"
                ))
            }
        }
        return anomalies
    }
}
