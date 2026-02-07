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
    public func scanAll() async -> [ProcessAnomaly] {
        async let hidden = scanHiddenLaunchAgents()
        async let emond = scanEmondRules()
        async let pam = scanPAMModules()
        async let sudoers = scanSudoersModifications()
        async let ssh = scanSSHKeys()
        async let atJobs = scanAtJobs()
        async let envVars = scanDYLDEnvironment()
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
                anomalies.append(ProcessAnomaly(
                    pid: 0, processName: file, processPath: "\(dir)/\(file)",
                    parentPID: 0, parentName: "filesystem",
                    technique: "Hidden LaunchAgent/Daemon",
                    description: "Dot-prefixed plist hidden from Finder: \(dir)/\(file). This is a common APT technique.",
                    severity: .critical, mitreID: "T1564.001"
                ))
            }
        }
        return anomalies
    }

    /// Emond rules — obscure persistence via /etc/emond.d/
    private func scanEmondRules() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let emondDir = "/etc/emond.d/rules"
        let fm = FileManager.default

        guard let files = try? fm.contentsOfDirectory(atPath: emondDir) else {
            return anomalies
        }

        for file in files where file.hasSuffix(".plist") {
            let path = "\(emondDir)/\(file)"
            // Any emond rule is suspicious — it's almost never used legitimately
            anomalies.append(ProcessAnomaly(
                pid: 0, processName: file, processPath: path,
                parentPID: 0, parentName: "filesystem",
                technique: "Emond Rule Persistence",
                description: "Event Monitor daemon rule found. Emond is rarely used legitimately and is a known persistence mechanism.",
                severity: .high, mitreID: "T1546.014"
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
                anomalies.append(ProcessAnomaly(
                    pid: 0, processName: file, processPath: "\(customPamDir)/\(file)",
                    parentPID: 0, parentName: "filesystem",
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
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: conf, processPath: path,
                            parentPID: 0, parentName: "filesystem",
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
                    anomalies.append(ProcessAnomaly(
                        pid: 0, processName: file, processPath: path,
                        parentPID: 0, parentName: "filesystem",
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
            anomalies.append(ProcessAnomaly(
                pid: 0, processName: "authorized_keys",
                processPath: authKeysPath,
                parentPID: 0, parentName: "filesystem",
                technique: "SSH Authorized Keys",
                description: "\(keyCount) SSH key(s) in authorized_keys. Verify each is expected.",
                severity: .medium, mitreID: "T1098.004"
            ))
        }

        // Also check /var/root/.ssh/
        let rootAuthKeys = "/var/root/.ssh/authorized_keys"
        if fm.fileExists(atPath: rootAuthKeys) {
            anomalies.append(ProcessAnomaly(
                pid: 0, processName: "root authorized_keys",
                processPath: rootAuthKeys,
                parentPID: 0, parentName: "filesystem",
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
                anomalies.append(ProcessAnomaly(
                    pid: 0, processName: file, processPath: "\(dir)/\(file)",
                    parentPID: 0, parentName: "filesystem",
                    technique: "At Job Persistence",
                    description: "Scheduled at job found: \(dir)/\(file). Rarely used legitimately on macOS.",
                    severity: .high, mitreID: "T1053.002"
                ))
            }
        }
        return anomalies
    }

    /// Scan running processes for DYLD_INSERT_LIBRARIES environment variables
    private func scanDYLDEnvironment() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let pids = getRunningPIDs()

        for pid in pids {
            let env = getProcessEnvironment(pid)
            for (key, value) in env {
                let lowerKey = key.lowercased()
                if lowerKey == "dyld_insert_libraries" ||
                   lowerKey == "__xpc_dyld_insert_libraries" ||
                   lowerKey == "dyld_framework_path" ||
                   lowerKey == "dyld_library_path" {
                    let path = getProcessPath(pid)
                    let name = URL(fileURLWithPath: path).lastPathComponent
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: 0, parentName: "",
                        technique: "DYLD Environment Injection",
                        description: "Process \(name) (PID \(pid)) has \(key)=\(value). Library injection detected.",
                        severity: .critical, mitreID: "T1574.006"
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
                    anomalies.append(ProcessAnomaly(
                        pid: 0, processName: app, processPath: appPath,
                        parentPID: 0, parentName: "filesystem",
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
        let suspiciousDirs = ["/tmp", "/var/tmp", "/Users/Shared",
                              "/Library/Caches", "/usr/local/bin"]
        let fm = FileManager.default

        for dir in suspiciousDirs {
            guard let enumerator = fm.enumerator(atPath: dir) else { continue }
            while let file = enumerator.nextObject() as? String {
                let path = "\(dir)/\(file)"
                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      let perms = attrs[.posixPermissions] as? UInt16 else { continue }
                // Check SUID (04000) or SGID (02000)
                if perms & 0o4000 != 0 || perms & 0o2000 != 0 {
                    anomalies.append(ProcessAnomaly(
                        pid: 0, processName: file, processPath: path,
                        parentPID: 0, parentName: "filesystem",
                        technique: "SUID/SGID in Suspicious Location",
                        description: "SUID/SGID binary in non-standard location: \(path) (perms: \(String(perms, radix: 8)))",
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

    private func getRunningPIDs() -> [pid_t] {
        let bufSize = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard bufSize > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(bufSize) / MemoryLayout<pid_t>.size)
        let actual = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, bufSize)
        guard actual > 0 else { return [] }
        return Array(pids.prefix(Int(actual) / MemoryLayout<pid_t>.size)).filter { $0 > 0 }
    }

    private func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "" }
        return String(cString: buf)
    }

    private func getProcessEnvironment(_ pid: pid_t) -> [(String, String)] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }
        guard size > MemoryLayout<Int32>.size else { return [] }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var offset = MemoryLayout<Int32>.size

        // Skip exec path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Skip argc args
        var argsSkipped = 0
        while argsSkipped < argc && offset < size {
            if buffer[offset] == 0 { argsSkipped += 1 }
            offset += 1
        }

        // Remaining are environment variables
        var envVars: [(String, String)] = []
        var current = ""
        while offset < size {
            if buffer[offset] == 0 {
                if current.isEmpty { break }
                if let eqIdx = current.firstIndex(of: "=") {
                    let key = String(current[current.startIndex..<eqIdx])
                    let val = String(current[current.index(after: eqIdx)...])
                    envVars.append((key, val))
                }
                current = ""
            } else {
                current.append(Character(UnicodeScalar(buffer[offset])))
            }
            offset += 1
        }
        return envVars
    }
}
