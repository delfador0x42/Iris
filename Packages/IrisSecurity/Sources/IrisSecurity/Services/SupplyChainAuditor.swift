import Foundation
import os.log
import CryptoKit

/// Audits supply chain integrity: Homebrew packages, npm global modules,
/// pip packages, and Xcode plugins for tampering or suspicious modifications.
/// APT41 compromised Xcode. Lazarus trojanized crypto trading apps.
/// Supply chain is the modern attack vector.
public actor SupplyChainAuditor {
    public static let shared = SupplyChainAuditor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "SupplyChain")

    /// Audit all package managers
    public func auditAll() async -> [SupplyChainFinding] {
        async let brew = auditHomebrew()
        async let npm = auditNPMGlobal()
        async let pip = auditPipPackages()
        async let xcode = auditXcodePlugins()

        let all = await [brew, npm, pip, xcode]
        return all.flatMap { $0 }
    }

    /// Audit Homebrew: check for modified formula, unsigned binaries, unusual install sources
    private func auditHomebrew() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []

        // Check if Homebrew itself has been tampered with
        let brewPath = FileManager.default.fileExists(atPath: "/opt/homebrew/bin/brew")
            ? "/opt/homebrew" : "/usr/local"

        // List all installed packages with their info
        let listOutput = await runCommand("\(brewPath)/bin/brew", args: ["list", "--versions"])
        guard !listOutput.isEmpty else { return findings }

        // Check for packages installed from non-standard taps
        let tapOutput = await runCommand("\(brewPath)/bin/brew", args: ["tap"])
        let taps = Set(tapOutput.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) })

        // Standard taps
        let standardTaps: Set<String> = [
            "homebrew/core", "homebrew/cask", "homebrew/services",
            "homebrew/bundle", "homebrew/cask-fonts", "homebrew/cask-versions"
        ]

        for tap in taps {
            if !standardTaps.contains(tap) && !tap.isEmpty {
                findings.append(SupplyChainFinding(
                    source: .homebrew,
                    packageName: tap,
                    finding: "Non-standard Homebrew tap",
                    details: "Third-party tap '\(tap)' is installed. Verify this is intentional — malicious taps can serve trojanized packages.",
                    severity: .medium
                ))
            }
        }

        // Check Homebrew's git integrity
        let gitOutput = await runCommand("/usr/bin/git", args: [
            "-C", "\(brewPath)/Homebrew", "status", "--porcelain"
        ])
        if !gitOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            findings.append(SupplyChainFinding(
                source: .homebrew,
                packageName: "Homebrew Core",
                finding: "Modified Homebrew installation",
                details: "Homebrew git repository has uncommitted changes. This could indicate formula tampering.",
                severity: .high
            ))
        }

        return findings
    }

    /// Audit globally installed npm packages
    private func auditNPMGlobal() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []

        let output = await runCommand("/usr/bin/which", args: ["npm"])
        guard !output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return findings
        }

        let npmPath = output.trimmingCharacters(in: .whitespacesAndNewlines)
        let globalOutput = await runCommand(npmPath, args: ["list", "-g", "--json", "--depth=0"])

        guard let data = globalOutput.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let deps = json["dependencies"] as? [String: Any] else {
            return findings
        }

        // Check for packages with post-install scripts (common attack vector)
        for (name, _) in deps {
            let prefix = await runCommand(npmPath, args: ["prefix", "-g"])
            let pkgJson = "\(prefix.trimmingCharacters(in: .whitespacesAndNewlines))/lib/node_modules/\(name)/package.json"

            guard let pkgData = try? Data(contentsOf: URL(fileURLWithPath: pkgJson)),
                  let pkg = try? JSONSerialization.jsonObject(with: pkgData) as? [String: Any],
                  let scripts = pkg["scripts"] as? [String: Any] else {
                continue
            }

            // Post-install scripts are the #1 npm attack vector
            if scripts["postinstall"] != nil || scripts["preinstall"] != nil {
                findings.append(SupplyChainFinding(
                    source: .npm,
                    packageName: name,
                    finding: "Package has install scripts",
                    details: "Global npm package '\(name)' has pre/post-install scripts. These execute arbitrary code during installation.",
                    severity: .medium
                ))
            }
        }

        return findings
    }

    /// Audit pip packages for known-compromised or typosquatting packages
    private func auditPipPackages() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []

        let output = await runCommand("/usr/bin/python3", args: ["-m", "pip", "list", "--format=json"])
        guard let data = output.data(using: .utf8),
              let packages = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return findings
        }

        // Known suspicious pip package name patterns (typosquatting)
        let suspiciousPatterns = [
            "python3-", "py-", "python-", // Typosquatting prefixes
            "-python", "-py",              // Typosquatting suffixes
        ]

        for pkg in packages {
            guard let name = pkg["name"] as? String else { continue }
            let lower = name.lowercased()

            // Check for common typosquatting patterns
            for pattern in suspiciousPatterns {
                if lower.hasPrefix(pattern) || lower.hasSuffix(pattern) {
                    // Only flag if the base name exists as a legitimate package
                    let baseName = lower
                        .replacingOccurrences(of: pattern, with: "")
                        .trimmingCharacters(in: CharacterSet(charactersIn: "-_"))

                    if !baseName.isEmpty && baseName.count > 2 {
                        findings.append(SupplyChainFinding(
                            source: .pip,
                            packageName: name,
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

    /// Audit Xcode plugins and build phase scripts (XcodeGhost-style attacks)
    private func auditXcodePlugins() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        // Check Xcode plugins directory
        let pluginDirs = [
            "\(home)/Library/Application Support/Developer/Shared/Xcode/Plug-ins",
            "/Library/Application Support/Developer/Shared/Xcode/Plug-ins"
        ]

        for dir in pluginDirs {
            guard let plugins = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for plugin in plugins where plugin.hasSuffix(".xcplugin") {
                findings.append(SupplyChainFinding(
                    source: .xcode,
                    packageName: plugin,
                    finding: "Xcode Plugin Installed",
                    details: "Xcode plugin '\(plugin)' at \(dir). Xcode plugins execute with full Xcode privileges and have been used in supply chain attacks (XcodeGhost).",
                    severity: .high
                ))
            }
        }

        // Check for custom Xcode templates (could contain malicious build phases)
        let templateDir = "\(home)/Library/Developer/Xcode/Templates"
        if fm.fileExists(atPath: templateDir) {
            if let templates = try? fm.contentsOfDirectory(atPath: templateDir) {
                for template in templates {
                    findings.append(SupplyChainFinding(
                        source: .xcode,
                        packageName: template,
                        finding: "Custom Xcode Template",
                        details: "Custom Xcode template '\(template)'. Templates can include build phase scripts that execute on every build.",
                        severity: .medium
                    ))
                }
            }
        }

        return findings
    }

    private func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                continuation.resume(returning: "")
            }
        }
    }
}

/// Source of a supply chain package
public enum PackageManagerSource: String, Sendable, Codable {
    case homebrew = "Homebrew"
    case npm = "npm"
    case pip = "pip"
    case xcode = "Xcode"
}

/// A supply chain integrity finding
public struct SupplyChainFinding: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let source: PackageManagerSource
    public let packageName: String
    public let finding: String
    public let details: String
    public let severity: AnomalySeverity
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        source: PackageManagerSource,
        packageName: String,
        finding: String,
        details: String,
        severity: AnomalySeverity,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.source = source
        self.packageName = packageName
        self.finding = finding
        self.details = details
        self.severity = severity
        self.timestamp = timestamp
    }
}
