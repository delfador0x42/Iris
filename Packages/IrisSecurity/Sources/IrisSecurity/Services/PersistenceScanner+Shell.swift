import Foundation

extension PersistenceScanner {
    /// Scan shell configuration files with content analysis
    func scanShellConfigs() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default
        let baseline = BaselineService.shared

        let userConfigs = [
            ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout",
            ".bash_profile", ".bashrc", ".profile"
        ]
        for config in userConfigs {
            let path = "\(home)/\(config)"
            guard fm.fileExists(atPath: path) else { continue }
            let ev = shellConfigEvidence(path: path)
            items.append(PersistenceItem(
                type: .shellConfig, name: config, path: path, evidence: ev
            ))
        }

        let systemConfigs = [
            "/etc/zshenv", "/etc/zprofile", "/etc/zshrc",
            "/etc/zlogin", "/etc/zlogout", "/etc/bashrc", "/etc/profile"
        ]
        for config in systemConfigs {
            guard fm.fileExists(atPath: config) else { continue }
            let name = URL(fileURLWithPath: config).lastPathComponent
            let isBaseline = baseline.isBaselineShellConfig(config)
            let ev = shellConfigEvidence(path: config)
            items.append(PersistenceItem(
                type: .shellConfig, name: name, path: config,
                isBaselineItem: isBaseline, evidence: ev
            ))
        }
        return items
    }

    /// Analyze shell config content for dangerous patterns
    private func shellConfigEvidence(path: String) -> [Evidence] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }
        var ev: [Evidence] = []
        let lower = content.lowercased()

        // Remote code execution: curl|bash, wget|sh, source <(curl...)
        if lower.contains("curl") && (lower.contains("| bash") || lower.contains("|bash") ||
            lower.contains("| sh") || lower.contains("|sh")) {
            ev.append(Evidence(factor: "curl piped to shell", weight: 0.6, category: .content))
        } else if lower.contains("wget") && (lower.contains("| bash") || lower.contains("| sh")) {
            ev.append(Evidence(factor: "wget piped to shell", weight: 0.6, category: .content))
        }
        if lower.contains("source <(curl") || lower.contains("eval \"$(curl") ||
           lower.contains("eval $(curl") {
            ev.append(Evidence(factor: "Sources remote script", weight: 0.7, category: .content))
        }

        // Encoded payload execution
        if lower.contains("base64") && (lower.contains("decode") || lower.contains("-d") || lower.contains("-D")) {
            ev.append(Evidence(factor: "base64 decode execution", weight: 0.4, category: .content))
        }
        if lower.contains("python") && lower.contains("import os") {
            ev.append(Evidence(factor: "Python os module in shell config", weight: 0.3, category: .content))
        }

        // DYLD_ environment hijacking
        if lower.contains("dyld_insert") || lower.contains("dyld_library_path") ||
           lower.contains("dyld_framework_path") {
            ev.append(Evidence(factor: "DYLD_ environment variable", weight: 0.3, category: .content))
        }

        // Alias/function hijacking of security-sensitive commands
        let hijackTargets = ["sudo", "ssh", "scp", "security", "codesign", "spctl", "login", "su"]
        for target in hijackTargets {
            if lower.contains("alias \(target)=") || lower.contains("alias \(target) =") ||
               lower.contains("function \(target)") || lower.contains("\(target)()") {
                ev.append(Evidence(factor: "Shadows '\(target)' command", weight: 0.7, category: .content))
                break
            }
        }

        // PATH prepend with suspicious directories
        for line in content.components(separatedBy: "\n") {
            let l = line.trimmingCharacters(in: .whitespaces).lowercased()
            if l.contains("path=") || l.contains("path =") {
                if l.contains("/tmp") || l.contains("/var/tmp") || l.contains("/.") {
                    ev.append(Evidence(factor: "PATH includes temp/hidden directory", weight: 0.5, category: .content))
                    break
                }
            }
        }

        // Reverse shell patterns
        if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") ||
           (lower.contains("nc ") && lower.contains("-e ")) ||
           lower.contains("mkfifo") {
            ev.append(Evidence(factor: "Reverse shell pattern", weight: 0.9, category: .content))
        }

        // Prompt/precmd hooks with suspicious content
        if lower.contains("prompt_command") || lower.contains("precmd()") || lower.contains("preexec()") {
            let hookContent = lower
            if hookContent.contains("curl") || hookContent.contains("nc ") || hookContent.contains("base64") {
                ev.append(Evidence(factor: "Suspicious prompt hook", weight: 0.5, category: .content))
            }
        }

        return ev
    }

    /// Scan login/logout hooks from loginwindow plist
    func scanLoginHooks() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let plistPaths = [
            "/Library/Preferences/com.apple.loginwindow.plist",
            "\(home)/Library/Preferences/com.apple.loginwindow.plist"
        ]

        for plistPath in plistPaths {
            guard let plist = NSDictionary(contentsOfFile: plistPath) else { continue }

            for key in ["LoginHook", "LogoutHook"] {
                guard let hookPath = plist[key] as? String else { continue }
                let (signing, identifier, apple) = verifyBinary(hookPath)

                var ev: [Evidence] = []
                ev.append(Evidence(factor: "Login/logout hooks are deprecated", weight: 0.5, category: .context))
                if signing == .unsigned {
                    ev.append(Evidence(factor: "Unsigned binary", weight: 0.3, category: .signing))
                }

                items.append(PersistenceItem(
                    type: .loginHook,
                    name: "\(key): \(URL(fileURLWithPath: hookPath).lastPathComponent)",
                    path: hookPath,
                    binaryPath: hookPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    evidence: ev
                ))
            }
        }
        return items
    }

    /// Scan startup scripts (/etc/rc.*, /etc/launchd.conf)
    func scanStartupScripts() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let fm = FileManager.default

        let scripts = [
            "/etc/rc.cleanup", "/etc/rc.common",
            "/etc/rc.installer_cleanup", "/etc/rc.server",
            "/etc/launchd.conf"
        ]

        for script in scripts {
            guard fm.fileExists(atPath: script) else { continue }
            let ev = [Evidence(factor: "Startup script exists (unusual on modern macOS)", weight: 0.4, category: .context)]
            items.append(PersistenceItem(
                type: .startupScript,
                name: URL(fileURLWithPath: script).lastPathComponent,
                path: script,
                evidence: ev
            ))
        }
        return items
    }

    /// Scan DYLD_INSERT_LIBRARIES in launch plists and app Info.plists
    func scanDylibInserts() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let launchDirs = [
            "/Library/LaunchDaemons", "/Library/LaunchAgents",
            "\(home)/Library/LaunchAgents"
        ]

        for dir in launchDirs {
            guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
                continue
            }
            for file in contents where file.hasSuffix(".plist") {
                let path = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: path) else { continue }
                let lower = Dictionary(uniqueKeysWithValues: plist.map { key, val in
                    ((key as? String)?.lowercased() ?? "", val)
                })
                guard let envVars = lower["environmentvariables"] as? [String: String] else {
                    continue
                }
                for (key, value) in envVars {
                    let lowerKey = key.lowercased()
                    if lowerKey == "dyld_insert_libraries" || lowerKey == "__xpc_dyld_insert_libraries" {
                        let ev = [Evidence(factor: "DYLD_INSERT_LIBRARIES in launch plist", weight: 0.8, category: .behavior)]
                        items.append(PersistenceItem(
                            type: .dylibInsert,
                            name: "\(file): \(key)",
                            path: path,
                            binaryPath: value,
                            evidence: ev
                        ))
                    }
                }
            }
        }

        // Check /Applications for LSEnvironment injection
        if let apps = try? FileManager.default.contentsOfDirectory(atPath: "/Applications") {
            for app in apps where app.hasSuffix(".app") {
                let plistPath = "/Applications/\(app)/Contents/Info.plist"
                guard let plist = NSDictionary(contentsOfFile: plistPath),
                      let env = plist["LSEnvironment"] as? [String: String] else { continue }
                for (key, value) in env {
                    if key.lowercased().contains("dyld_insert") {
                        let ev = [Evidence(factor: "LSEnvironment DYLD injection in application", weight: 0.9, category: .behavior)]
                        items.append(PersistenceItem(
                            type: .dylibInsert,
                            name: "\(app): \(key)",
                            path: plistPath,
                            binaryPath: value,
                            evidence: ev
                        ))
                    }
                }
            }
        }
        return items
    }

    /// Scan periodic scripts (/etc/periodic/{daily,weekly,monthly})
    func scanPeriodicScripts() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let fm = FileManager.default
        let baseline = BaselineService.shared
        let dirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            let period = URL(fileURLWithPath: dir).lastPathComponent
            for file in contents {
                let path = "\(dir)/\(file)"
                let isBaseline = baseline.isBaselinePeriodicScript("\(period)/\(file)")
                let ev = periodicScriptEvidence(path: path)
                items.append(PersistenceItem(
                    type: .periodicScript,
                    name: "\(period)/\(file)",
                    path: path,
                    isBaselineItem: isBaseline,
                    evidence: ev
                ))
            }
        }
        return items
    }

    /// Analyze periodic script content
    private func periodicScriptEvidence(path: String) -> [Evidence] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }
        var ev: [Evidence] = []
        let lower = content.lowercased()

        let dangerousPatterns: [(String, String, Double)] = [
            ("curl", "Contains network download command", 0.4),
            ("wget", "Contains network download command", 0.4),
            ("base64", "Contains base64 encoding", 0.3),
            ("| bash", "Pipes to shell interpreter", 0.4),
            ("| sh", "Pipes to shell interpreter", 0.4),
            ("eval ", "Uses eval execution", 0.3),
        ]
        for (pattern, factor, weight) in dangerousPatterns {
            if lower.contains(pattern) {
                ev.append(Evidence(factor: factor, weight: weight, category: .content))
                break // One content evidence per script is enough
            }
        }
        return ev
    }
}
