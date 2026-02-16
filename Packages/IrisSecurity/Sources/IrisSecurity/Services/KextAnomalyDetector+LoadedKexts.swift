import Foundation

/// Query currently loaded kernel extensions via kextstat
extension KextAnomalyDetector {

    func getLoadedKexts() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        let output = await runCommand("/usr/sbin/kextstat", args: ["-l"])
        let lines = output.split(separator: "\n").dropFirst() // Skip header

        for line in lines {
            let cols = line.split(separator: " ", maxSplits: 6).map(String.init)
            guard cols.count >= 6 else { continue }

            let bundleID = cols[5]
            if bundleID.hasPrefix("com.apple.") { continue }

            let lower = bundleID.lowercased()
            let isKnownMalicious = Self.knownMaliciousPatterns.contains { lower.contains($0) }

            let severity: AnomalySeverity = isKnownMalicious ? .critical : .medium
            let description = isKnownMalicious
                ? "Loaded kernel extension \(bundleID) matches known rootkit pattern."
                : "Third-party kernel extension loaded: \(bundleID). Non-Apple kexts can intercept system calls, hide processes, and bypass security."

            anomalies.append(.filesystem(
                name: bundleID, path: "",
                technique: "Loaded Kernel Extension",
                description: description,
                severity: severity, mitreID: "T1547.006",
                scannerId: "kext",
                enumMethod: "kextstat -l",
                evidence: [
                    "bundle_id: \(bundleID)",
                    "known_malicious: \(isKnownMalicious)",
                ]
            ))
        }

        return anomalies
    }
}
