import Foundation

extension SupplyChainAuditor {

    /// Audit pip packages for known-compromised or typosquatting patterns.
    func auditPipPackages() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []

        let output = await runCommand("/usr/bin/python3", args: ["-m", "pip", "list", "--format=json"])
        guard let data = output.data(using: .utf8),
              let packages = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return findings
        }

        let suspiciousPatterns = [
            "python3-", "py-", "python-",  // Typosquatting prefixes
            "-python", "-py",               // Typosquatting suffixes
        ]

        for pkg in packages {
            guard let name = pkg["name"] as? String else { continue }
            let lower = name.lowercased()

            for pattern in suspiciousPatterns {
                if lower.hasPrefix(pattern) || lower.hasSuffix(pattern) {
                    let baseName = lower
                        .replacingOccurrences(of: pattern, with: "")
                        .trimmingCharacters(in: CharacterSet(charactersIn: "-_"))

                    if !baseName.isEmpty && baseName.count > 2 {
                        findings.append(SupplyChainFinding(
                            source: .pip, packageName: name,
                            finding: "Possible typosquatting package",
                            details: "Package '\(name)' matches typosquatting pattern. Verify this is the intended package.",
                            severity: .low
                        ))
                    }
                }
            }
        }

        return findings
    }
}
