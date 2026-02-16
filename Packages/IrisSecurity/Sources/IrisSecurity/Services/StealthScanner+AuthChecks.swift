import Foundation

/// PAM modules, sudoers modifications, SSH keys
extension StealthScanner {

    /// PAM module injection — /usr/lib/pam/ or /usr/local/lib/pam/
    func scanPAMModules() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
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
    func scanSudoersModifications() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let sudoersDir = "/etc/sudoers.d"

        if let files = try? FileManager.default.contentsOfDirectory(atPath: sudoersDir) {
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
    func scanSSHKeys() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let authKeysPath = "\(home)/.ssh/authorized_keys"
        let fm = FileManager.default

        if fm.fileExists(atPath: authKeysPath),
           let content = try? String(contentsOfFile: authKeysPath, encoding: .utf8) {
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
        }

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
}
