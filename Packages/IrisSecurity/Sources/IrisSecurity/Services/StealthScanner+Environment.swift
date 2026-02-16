import Foundation

/// DYLD injection, quarantine bypass, SUID/SGID binaries
extension StealthScanner {

    /// Scan running processes for DYLD_INSERT_LIBRARIES environment variables
    func scanDYLDEnvironment(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            let env = ProcessEnumeration.getProcessEnvironment(pid)
            for (key, value) in env {
                let lowerKey = key.lowercased()
                if lowerKey == "dyld_insert_libraries" ||
                   lowerKey == "__xpc_dyld_insert_libraries" ||
                   lowerKey == "dyld_framework_path" ||
                   lowerKey == "dyld_library_path" {
                    let path = snapshot.path(for: pid)
                    let name = path.isEmpty ? "unknown" : URL(fileURLWithPath: path).lastPathComponent
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "DYLD Environment Injection",
                        description: "Process \(name) (PID \(pid)) has \(key)=\(value). Library injection detected.",
                        severity: .critical, mitreID: "T1574.006",
                        scannerId: "stealth",
                        enumMethod: "ProcessEnumeration.getProcessEnvironment(pid)",
                        evidence: [
                            "env_key: \(key)",
                            "env_value: \(value)",
                            "binary: \(path)",
                        ]
                    ))
                }
            }
        }
        return anomalies
    }

    /// Find apps missing quarantine attribute (Gatekeeper bypass)
    func scanMissingQuarantine() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let fm = FileManager.default
        let downloadDirs = [
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads").path,
            "/Applications"
        ]

        for dir in downloadDirs {
            guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let appPath = "\(dir)/\(app)"
                let hasQuarantine = hasExtendedAttribute(appPath, name: "com.apple.quarantine")
                if !hasQuarantine && dir.contains("Downloads") {
                    anomalies.append(.filesystem(
                        name: app, path: appPath,
                        technique: "Missing Quarantine Attribute",
                        description: "App in Downloads missing quarantine flag: \(app). May have been de-quarantined to bypass Gatekeeper.",
                        severity: .medium, mitreID: "T1553.001"
                    ))
                }
            }
        }
        return anomalies
    }

    /// Find SUID/SGID binaries in non-standard locations
    func scanSUIDBinaries() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let suspiciousDirs = [
            "/tmp", "/var/tmp", "/Users/Shared",
            "/Library/Caches", "/usr/local/bin", "/usr/local/sbin",
            "/opt", "/private/tmp", "\(home)/Downloads",
            "\(home)/Desktop", "\(home)/Documents",
        ]
        let fm = FileManager.default

        for dir in suspiciousDirs {
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: dir),
                includingPropertiesForKeys: [.isSymbolicLinkKey],
                options: [.skipsPackageDescendants]
            ) else { continue }
            while let url = enumerator.nextObject() as? URL {
                if enumerator.level > 3 { enumerator.skipDescendants(); continue }
                let path = url.path
                let file = url.lastPathComponent
                guard let vals = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]),
                      let isLink = vals.isSymbolicLink, !isLink,
                      let attrs = try? fm.attributesOfItem(atPath: path),
                      let perms = attrs[.posixPermissions] as? Int else { continue }
                let perms16 = UInt16(perms)
                if perms16 & 0o4000 != 0 || perms16 & 0o2000 != 0 {
                    anomalies.append(.filesystem(
                        name: file, path: path,
                        technique: "SUID/SGID in Suspicious Location",
                        description: "SUID/SGID binary in non-standard location: \(path) (perms: \(String(perms16, radix: 8)))",
                        severity: .critical, mitreID: "T1548.001"
                    ))
                }
            }
        }
        return anomalies
    }
}
