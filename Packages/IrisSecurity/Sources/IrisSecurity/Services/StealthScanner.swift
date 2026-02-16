import Foundation
import os.log
import CryptoKit

/// Scans for stealth persistence and APT artifacts that other tools miss.
/// Looks for: hidden LaunchAgents, modified system files, emond rules,
/// PAM modules, sudoers modifications, SSH authorized_keys, at jobs,
/// and files with suspicious extended attributes.
public actor StealthScanner {
    public static let shared = StealthScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "StealthScanner")

    /// Run all stealth scans
    public func scanAll(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        async let hidden = scanHiddenLaunchAgents()
        async let emond = scanEmondRules()
        async let pam = scanPAMModules()
        async let sudoers = scanSudoersModifications()
        async let ssh = scanSSHKeys()
        async let atJobs = scanAtJobs()
        async let envVars = scanDYLDEnvironment(snapshot: snap)
        async let quarantine = scanMissingQuarantine()
        async let suidBinaries = scanSUIDBinaries()

        let all = await [hidden, emond, pam, sudoers, ssh, atJobs, envVars,
                         quarantine, suidBinaries]
        return all.flatMap { $0 }
    }

    /// Hidden LaunchAgents — dot-prefixed plists that don't show in Finder
    private func scanHiddenLaunchAgents() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = [
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "\(home)/Library/LaunchAgents"
        ]

        for dir in dirs {
            guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
                continue
            }
            for file in contents where file.hasPrefix(".") && file.hasSuffix(".plist") {
                anomalies.append(.filesystem(
                    name: file, path: "\(dir)/\(file)",
                    technique: "Hidden LaunchAgent/Daemon",
                    description: "Dot-prefixed plist hidden from Finder: \(dir)/\(file). This is a common APT technique.",
                    severity: .critical, mitreID: "T1564.001",
                    scannerId: "stealth",
                    enumMethod: "FileManager.contentsOfDirectory → dot-prefix filter",
                    evidence: [
                        "plist: \(dir)/\(file)",
                        "hidden: dot-prefixed (invisible in Finder)",
                        "directory: \(dir)",
                    ]
                ))
            }
        }
        return anomalies
    }

    /// Emond rules — deprecated since macOS 10.11 but still checked.
    /// If emond rules exist on a modern system, that's EXTRA suspicious.
    private func scanEmondRules() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let emondDir = "/etc/emond.d/rules"
        let fm = FileManager.default

        guard let files = try? fm.contentsOfDirectory(atPath: emondDir) else {
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

    /// PAM module injection — /usr/lib/pam/ or /usr/local/lib/pam/
    private func scanPAMModules() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        // Custom PAM modules outside /usr/lib/pam are suspicious
        let customPamDir = "/usr/local/lib/pam"
        let fm = FileManager.default

        if fm.fileExists(atPath: customPamDir),
           let files = try? fm.contentsOfDirectory(atPath: customPamDir) {
            for file in files {
                anomalies.append(.filesystem(
                    name: file, path: "\(customPamDir)/\(file)",
                    technique: "Custom PAM Module",
                    description: "Non-standard PAM module in \(customPamDir). Could intercept authentication.",
                    severity: .critical, mitreID: "T1556.003"
                ))
            }
        }

        // Check /etc/pam.d/ for modifications referencing non-standard modules
        let pamConfDir = "/etc/pam.d"
        if let confs = try? fm.contentsOfDirectory(atPath: pamConfDir) {
            for conf in confs {
                let path = "\(pamConfDir)/\(conf)"
                guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
                    continue
                }
                for line in content.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.hasPrefix("#") { continue }
                    if trimmed.contains("/usr/local/") || trimmed.contains("/tmp/") ||
                       trimmed.contains("/Users/") {
                        anomalies.append(.filesystem(
                            name: conf, path: path,
                            technique: "Modified PAM Config",
                            description: "PAM config \(conf) references non-standard path: \(trimmed)",
                            severity: .critical, mitreID: "T1556.003"
                        ))
                    }
                }
            }
        }
        return anomalies
    }

    /// Sudoers modifications — check for NOPASSWD or unusual entries
    private func scanSudoersModifications() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let sudoersDir = "/etc/sudoers.d"
        let fm = FileManager.default

        if let files = try? fm.contentsOfDirectory(atPath: sudoersDir) {
            for file in files {
                let path = "\(sudoersDir)/\(file)"
                guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
                    continue
                }
                if content.contains("NOPASSWD") {
                    anomalies.append(.filesystem(
                        name: file, path: path,
                        technique: "Sudoers NOPASSWD",
                        description: "NOPASSWD entry in sudoers.d/\(file). Allows passwordless root execution.",
                        severity: .high, mitreID: "T1548.003"
                    ))
                }
            }
        }
        return anomalies
    }

    /// SSH authorized_keys — check for unauthorized keys
    private func scanSSHKeys() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let authKeysPath = "\(home)/.ssh/authorized_keys"
        let fm = FileManager.default

        guard fm.fileExists(atPath: authKeysPath),
              let content = try? String(contentsOfFile: authKeysPath, encoding: .utf8) else {
            return anomalies
        }

        let keyCount = content.split(separator: "\n")
            .filter { !$0.hasPrefix("#") && !$0.isEmpty }
            .count

        if keyCount > 0 {
            anomalies.append(.filesystem(
                name: "authorized_keys", path: authKeysPath,
                technique: "SSH Authorized Keys",
                description: "\(keyCount) SSH key(s) in authorized_keys. Verify each is expected.",
                severity: .medium, mitreID: "T1098.004"
            ))
        }

        // Also check /var/root/.ssh/
        let rootAuthKeys = "/var/root/.ssh/authorized_keys"
        if fm.fileExists(atPath: rootAuthKeys) {
            anomalies.append(.filesystem(
                name: "root authorized_keys", path: rootAuthKeys,
                technique: "Root SSH Keys",
                description: "Root account has authorized_keys. High-value target for persistence.",
                severity: .critical, mitreID: "T1098.004"
            ))
        }

        return anomalies
    }

    /// At jobs — /usr/lib/cron/at.* and /private/var/at/jobs/
    private func scanAtJobs() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let dirs = ["/private/var/at/jobs", "/usr/lib/cron"]
        let fm = FileManager.default

        for dir in dirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
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

    /// Scan running processes for DYLD_INSERT_LIBRARIES environment variables
    private func scanDYLDEnvironment(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
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
    private func scanMissingQuarantine() async -> [ProcessAnomaly] {
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
                // Check for quarantine xattr
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
    private func scanSUIDBinaries() async -> [ProcessAnomaly] {
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
                // Depth guard: skip 3+ levels deep
                if enumerator.level > 3 { enumerator.skipDescendants(); continue }
                let path = url.path
                let file = url.lastPathComponent
                guard let vals = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]),
                      let isLink = vals.isSymbolicLink, !isLink,
                      let attrs = try? fm.attributesOfItem(atPath: path),
                      let perms = attrs[.posixPermissions] as? Int else { continue }
                let perms16 = UInt16(perms)
                // Check SUID (04000) or SGID (02000)
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

    // MARK: - Helpers

    private func hasExtendedAttribute(_ path: String, name: String) -> Bool {
        let size = getxattr(path, name, nil, 0, 0, 0)
        return size >= 0
    }

}
