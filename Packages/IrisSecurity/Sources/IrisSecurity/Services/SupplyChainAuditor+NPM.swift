import Foundation

extension SupplyChainAuditor {

    /// Audit globally installed npm packages for post-install scripts (common attack vector).
    func auditNPMGlobal() async -> [SupplyChainFinding] {
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

        for (name, _) in deps {
            let prefix = await runCommand(npmPath, args: ["prefix", "-g"])
            let pkgJson = "\(prefix.trimmingCharacters(in: .whitespacesAndNewlines))/lib/node_modules/\(name)/package.json"

            guard let pkgData = try? Data(contentsOf: URL(fileURLWithPath: pkgJson)),
                  let pkg = try? JSONSerialization.jsonObject(with: pkgData) as? [String: Any],
                  let scripts = pkg["scripts"] as? [String: Any] else {
                continue
            }

            if scripts["postinstall"] != nil || scripts["preinstall"] != nil {
                findings.append(SupplyChainFinding(
                    source: .npm, packageName: name,
                    finding: "Package has install scripts",
                    details: "Global npm package '\(name)' has pre/post-install scripts. These execute arbitrary code during installation.",
                    severity: .medium
                ))
            }
        }

        return findings
    }
}
