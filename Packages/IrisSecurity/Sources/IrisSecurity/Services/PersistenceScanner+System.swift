import AppKit
import Foundation

extension PersistenceScanner {
    /// Scan cron jobs for all users
    func scanCronJobs() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Current user's crontab
        let output = await runCommand("/usr/bin/crontab", args: ["-l"])
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            // Valid cron line starts with digit, *, or @
            guard let first = trimmed.first,
                  first.isNumber || first == "*" || first == "@" else { continue }

            let suspicious = isCronLineSuspicious(String(trimmed))
            items.append(PersistenceItem(
                type: .cronJob,
                name: String(trimmed.prefix(60)),
                path: "/var/cron/",
                isSuspicious: suspicious,
                suspicionReasons: suspicious ? ["Suspicious cron job content"] : []
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

                    let suspicious = isCronLineSuspicious(String(trimmed))
                    items.append(PersistenceItem(
                        type: .cronJob,
                        name: "\(user): \(trimmed.prefix(50))",
                        path: cronFile,
                        isSuspicious: suspicious,
                        suspicionReasons: suspicious ? ["Suspicious cron job for \(user)"] : []
                    ))
                }
            }
        }
        return items
    }

    /// Scan kernel extensions
    func scanKernelExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let dirs = ["/Library/Extensions", "/System/Library/Extensions"]
        let fm = FileManager.default

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents where file.hasSuffix(".kext") {
                let path = "\(dir)/\(file)"
                let name = file.replacingOccurrences(of: ".kext", with: "")
                let isSystem = dir.hasPrefix("/System")
                let (signing, identifier, apple) = await verifyBinary(path)

                var reasons: [String] = []
                if !isSystem && !apple {
                    reasons.append("Third-party kernel extension")
                    if signing == .unsigned { reasons.append("Unsigned kext") }
                }

                items.append(PersistenceItem(
                    type: .kernelExtension,
                    name: name,
                    path: path,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isSuspicious: !reasons.isEmpty,
                    suspicionReasons: reasons
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

        // Walk the plist for extensions with activated_enabled state
        if let extensions = plist["extensions"] as? [NSDictionary] {
            for ext in extensions {
                guard let state = ext["state"] as? String,
                      state == "activated_enabled",
                      let originPath = ext["originPath"] as? String else { continue }

                let name = URL(fileURLWithPath: originPath).lastPathComponent
                let (signing, identifier, apple) = await verifyBinary(originPath)

                items.append(PersistenceItem(
                    type: .systemExtension,
                    name: name,
                    path: originPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple
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

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents {
                let path = "\(dir)/\(file)"
                guard ws.isFilePackage(atPath: path) else { continue }
                let (signing, identifier, apple) = await verifyBinary(path)
                let isSystem = dir.hasPrefix("/System")

                var reasons: [String] = []
                if !isSystem && !apple {
                    reasons.append("Third-party authorization plugin")
                }

                items.append(PersistenceItem(
                    type: .authorizationPlugin,
                    name: file,
                    path: path,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isSuspicious: !reasons.isEmpty,
                    suspicionReasons: reasons
                ))
            }
        }
        return items
    }

    /// Only flag cron jobs with suspicious content patterns
    private func isCronLineSuspicious(_ line: String) -> Bool {
        let lower = line.lowercased()
        let suspiciousPatterns = [
            "curl", "wget", "nc ", "ncat", "netcat",
            "bash -c", "sh -c", "python -c", "python3 -c",
            "base64", "openssl enc", "eval ",
            "/tmp/", "/var/tmp/", "| sh", "| bash",
            "chmod +x", "chmod 777"
        ]
        return suspiciousPatterns.contains { lower.contains($0) }
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
