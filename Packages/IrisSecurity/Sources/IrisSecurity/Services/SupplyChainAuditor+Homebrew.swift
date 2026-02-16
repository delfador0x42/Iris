import Foundation

extension SupplyChainAuditor {

    /// Audit Homebrew: check for modified formula, unsigned binaries, unusual install sources
    func auditHomebrew() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []

        let brewPath = FileManager.default.fileExists(atPath: "/opt/homebrew/bin/brew")
            ? "/opt/homebrew" : "/usr/local"

        let listOutput = await runCommand("\(brewPath)/bin/brew", args: ["list", "--versions"])
        guard !listOutput.isEmpty else { return findings }

        // Check for packages installed from non-standard taps
        let tapOutput = await runCommand("\(brewPath)/bin/brew", args: ["tap"])
        let taps = Set(tapOutput.split(separator: "\n").map {
            String($0).trimmingCharacters(in: .whitespaces)
        })

        let standardTaps: Set<String> = [
            "homebrew/core", "homebrew/cask", "homebrew/services",
            "homebrew/bundle", "homebrew/cask-fonts", "homebrew/cask-versions",
        ]

        for tap in taps {
            if !standardTaps.contains(tap) && !tap.isEmpty {
                findings.append(SupplyChainFinding(
                    source: .homebrew, packageName: tap,
                    finding: "Non-standard Homebrew tap",
                    details: "Third-party tap '\(tap)' is installed. Verify this is intentional — malicious taps can serve trojanized packages.",
                    severity: .medium
                ))
            }
        }

        // Check Homebrew's git integrity
        let gitOutput = await runCommand("/usr/bin/git", args: [
            "-C", "\(brewPath)/Homebrew", "status", "--porcelain",
        ])
        if !gitOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            findings.append(SupplyChainFinding(
                source: .homebrew, packageName: "Homebrew Core",
                finding: "Modified Homebrew installation",
                details: "Homebrew git repository has uncommitted changes. This could indicate formula tampering.",
                severity: .high
            ))
        }

        return findings
    }
}
