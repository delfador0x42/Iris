import AppKit
import Foundation

extension PersistenceScanner {
    /// Scan cron jobs for all users.
    /// Cron is non-standard on macOS — all jobs get base evidence.
    /// Dangerous content patterns add extra weight.
    func scanCronJobs() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Current user's crontab
        let output = await runCommand("/usr/bin/crontab", args: ["-l"])
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            guard let first = trimmed.first,
                  first.isNumber || first == "*" || first == "@" else { continue }

            items.append(PersistenceItem(
                type: .cronJob,
                name: String(trimmed.prefix(60)),
                path: "/var/cron/",
                evidence: cronEvidence(String(trimmed))
            ))
        }

        // System cron directories
        let cronDir = "/private/var/at/tabs"
        let fm = FileManager.default
        if let users = try? fm.contentsOfDirectory(atPath: cronDir) {
            for user in users {
                let cronFile = "\(cronDir)/\(user)"
                guard let content = try? String(contentsOfFile: cronFile, encoding: .utf8) else {
                    continue
                }
                for line in content.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                    guard let first = trimmed.first,
                          first.isNumber || first == "*" || first == "@" else { continue }

                    items.append(PersistenceItem(
                        type: .cronJob,
                        name: "\(user): \(trimmed.prefix(50))",
                        path: cronFile,
                        evidence: cronEvidence(String(trimmed))
                    ))
                }
            }
        }
        return items
    }

    /// Build evidence for a cron line
    private func cronEvidence(_ line: String) -> [Evidence] {
        var ev: [Evidence] = []
        let lower = line.lowercased()

        // Base: cron is non-standard on macOS
        ev.append(Evidence(factor: "Cron job (non-standard on macOS)", weight: 0.3, category: .context))

        // Network commands
        let networkPatterns = ["curl", "wget", "nc ", "ncat", "netcat"]
        if networkPatterns.contains(where: { lower.contains($0) }) {
            ev.append(Evidence(factor: "Contains network commands", weight: 0.3, category: .content))
        }

        // Shell piping
        if lower.contains("| sh") || lower.contains("| bash") || lower.contains("|sh") || lower.contains("|bash") {
            ev.append(Evidence(factor: "Pipes to shell interpreter", weight: 0.3, category: .content))
        }

        // Temp directories
        if lower.contains("/tmp/") || lower.contains("/var/tmp/") {
            ev.append(Evidence(factor: "Executes from temp directory", weight: 0.2, category: .location))
        }

        // Encoding/obfuscation
        let obfuscation = ["base64", "openssl enc", "eval "]
        if obfuscation.contains(where: { lower.contains($0) }) {
            ev.append(Evidence(factor: "Uses encoding or obfuscation", weight: 0.2, category: .content))
        }

        // Shell one-liners
        let shellOneLiner = ["bash -c", "sh -c", "python -c", "python3 -c"]
        if shellOneLiner.contains(where: { lower.contains($0) }) {
            ev.append(Evidence(factor: "Inline script execution", weight: 0.1, category: .content))
        }

        // Permission changes
        if lower.contains("chmod +x") || lower.contains("chmod 777") {
            ev.append(Evidence(factor: "Modifies file permissions", weight: 0.1, category: .content))
        }

        return ev
    }

    /// Scan kernel extensions
    func scanKernelExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let dirs = ["/Library/Extensions", "/System/Library/Extensions"]
        let fm = FileManager.default
        let baseline = BaselineService.shared

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents where file.hasSuffix(".kext") {
                let path = "\(dir)/\(file)"
                let name = file.replacingOccurrences(of: ".kext", with: "")
                let isSystem = dir.hasPrefix("/System")
                let (signing, identifier, apple) = await verifyBinary(path)
                let isBaseline = baseline.isBaselineKext(identifier ?? name)

                var ev: [Evidence] = []
                if !isSystem && !apple {
                    ev.append(Evidence(factor: "Third-party kernel extension", weight: 0.3, category: .context))
                }
                if signing == .unsigned {
                    ev.append(Evidence(factor: "Unsigned kernel extension", weight: 0.5, category: .signing))
                }
                if signing == .adHoc {
                    ev.append(Evidence(factor: "Ad-hoc signed kernel extension", weight: 0.3, category: .signing))
                }

                items.append(PersistenceItem(
                    type: .kernelExtension,
                    name: name,
                    path: path,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isBaselineItem: isBaseline,
                    evidence: ev
                ))
            }
        }
        return items
    }

    /// Scan system extensions from db.plist
    func scanSystemExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let dbPath = "/Library/SystemExtensions/db.plist"

        guard let plist = NSDictionary(contentsOfFile: dbPath) else { return items }

        if let extensions = plist["extensions"] as? [NSDictionary] {
            for ext in extensions {
                guard let state = ext["state"] as? String,
                      state == "activated_enabled",
                      let originPath = ext["originPath"] as? String else { continue }

                let name = URL(fileURLWithPath: originPath).lastPathComponent
                let (signing, identifier, apple) = await verifyBinary(originPath)

                var ev: [Evidence] = []
                if !apple {
                    ev.append(Evidence(factor: "Third-party system extension", weight: 0.2, category: .context))
                }

                items.append(PersistenceItem(
                    type: .systemExtension,
                    name: name,
                    path: originPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    evidence: ev
                ))
            }
        }
        return items
    }

    /// Scan authorization plugins
    func scanAuthorizationPlugins() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let dirs = [
            "/Library/Security/SecurityAgentPlugins",
            "/System/Library/CoreServices/SecurityAgentPlugins"
        ]
        let fm = FileManager.default
        let ws = NSWorkspace.shared
        let baseline = BaselineService.shared

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents {
                let path = "\(dir)/\(file)"
                guard ws.isFilePackage(atPath: path) else { continue }
                let (signing, identifier, apple) = await verifyBinary(path)
                let isSystem = dir.hasPrefix("/System")
                let isBaseline = baseline.isBaselineAuthPlugin(file)

                var ev: [Evidence] = []
                if !isSystem && !apple {
                    ev.append(Evidence(factor: "Third-party authorization plugin", weight: 0.5, category: .context))
                }

                items.append(PersistenceItem(
                    type: .authorizationPlugin,
                    name: file,
                    path: path,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isBaselineItem: isBaseline,
                    evidence: ev
                ))
            }
        }
        return items
    }

    func runCommand(_ path: String, args: [String]) async -> String {
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
