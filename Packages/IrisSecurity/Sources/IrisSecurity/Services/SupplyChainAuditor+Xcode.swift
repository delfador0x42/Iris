import Foundation

extension SupplyChainAuditor {

    /// Audit Xcode development environment for supply chain risks:
    /// legacy plugins, custom templates (can contain malicious build scripts),
    /// and custom toolchains (XcodeGhost-style trojanized compilers).
    func auditXcodePlugins() async -> [SupplyChainFinding] {
        var findings: [SupplyChainFinding] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        // Legacy .xcplugin — dead since Xcode 8 (2016). Finding one is unusual.
        let pluginDirs = [
            "\(home)/Library/Application Support/Developer/Shared/Xcode/Plug-ins",
            "/Library/Application Support/Developer/Shared/Xcode/Plug-ins",
        ]
        for dir in pluginDirs {
            guard let plugins = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for plugin in plugins where plugin.hasSuffix(".xcplugin") {
                findings.append(SupplyChainFinding(
                    source: .xcode, packageName: plugin,
                    finding: "Legacy Xcode Plugin (obsolete format)",
                    details: "Legacy .xcplugin '\(plugin)' at \(dir). These don't load on modern Xcode but their presence is unusual — may be leftover from a compromise.",
                    severity: .medium
                ))
            }
        }

        // Custom Xcode templates (can contain malicious build phase scripts)
        let templateDir = "\(home)/Library/Developer/Xcode/Templates"
        if let templates = try? fm.contentsOfDirectory(atPath: templateDir) {
            for template in templates {
                findings.append(SupplyChainFinding(
                    source: .xcode, packageName: template,
                    finding: "Custom Xcode Template",
                    details: "Custom template '\(template)'. Templates can include build phase scripts that execute on every build.",
                    severity: .medium
                ))
            }
        }

        // Custom toolchains — trojanized compiler (XcodeGhost-style)
        let toolchainDirs = [
            "\(home)/Library/Developer/Toolchains",
            "/Library/Developer/Toolchains",
        ]
        for dir in toolchainDirs {
            guard let toolchains = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for tc in toolchains where tc.hasSuffix(".xctoolchain") {
                if tc.contains("com.apple.dt.toolchain") { continue }
                findings.append(SupplyChainFinding(
                    source: .xcode, packageName: tc,
                    finding: "Custom Xcode Toolchain",
                    details: "Non-Apple toolchain '\(tc)' at \(dir). Custom toolchains replace the compiler — a trojanized toolchain can inject code into every build.",
                    severity: .high
                ))
            }
        }

        return findings
    }
}
