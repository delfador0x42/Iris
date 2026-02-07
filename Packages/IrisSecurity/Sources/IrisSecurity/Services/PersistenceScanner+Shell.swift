import Foundation

extension PersistenceScanner {
    /// Scan shell configuration files for persistence
    func scanShellConfigs() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        // User-level shell configs
        let userConfigs = [
            ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout",
            ".bash_profile", ".bashrc", ".profile"
        ]
        for config in userConfigs {
            let path = "\(home)/\(config)"
            guard fm.fileExists(atPath: path) else { continue }
            items.append(PersistenceItem(
                type: .shellConfig,
                name: config,
                path: path
            ))
        }

        // System-wide shell configs
        let systemConfigs = [
            "/etc/zshenv", "/etc/zprofile", "/etc/zshrc",
            "/etc/zlogin", "/etc/zlogout",
            "/etc/bashrc", "/etc/profile"
        ]
        for config in systemConfigs {
            guard fm.fileExists(atPath: config) else { continue }
            items.append(PersistenceItem(
                type: .shellConfig,
                name: URL(fileURLWithPath: config).lastPathComponent,
                path: config
            ))
        }

        return items
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
                let (signing, identifier, apple) = await verifyBinary(hookPath)

                items.append(PersistenceItem(
                    type: .loginHook,
                    name: "\(key): \(URL(fileURLWithPath: hookPath).lastPathComponent)",
                    path: hookPath,
                    binaryPath: hookPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isSuspicious: true,
                    suspicionReasons: ["Login/logout hooks are deprecated and suspicious"]
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
            items.append(PersistenceItem(
                type: .startupScript,
                name: URL(fileURLWithPath: script).lastPathComponent,
                path: script,
                isSuspicious: true,
                suspicionReasons: ["Startup script exists (unusual on modern macOS)"]
            ))
        }
        return items
    }

    /// Scan DYLD_INSERT_LIBRARIES in launch plists and app Info.plists
    func scanDylibInserts() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Check launch plists for DYLD_INSERT_LIBRARIES
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
                    if lowerKey == "dyld_insert_libraries" ||
                       lowerKey == "__xpc_dyld_insert_libraries" {
                        items.append(PersistenceItem(
                            type: .dylibInsert,
                            name: "\(file): \(key)",
                            path: path,
                            binaryPath: value,
                            isSuspicious: true,
                            suspicionReasons: ["DYLD_INSERT_LIBRARIES is a common attack vector"]
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
                        items.append(PersistenceItem(
                            type: .dylibInsert,
                            name: "\(app): \(key)",
                            path: plistPath,
                            binaryPath: value,
                            isSuspicious: true,
                            suspicionReasons: ["LSEnvironment DYLD injection in application"]
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
        let dirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            let period = URL(fileURLWithPath: dir).lastPathComponent
            for file in contents {
                let path = "\(dir)/\(file)"
                items.append(PersistenceItem(
                    type: .periodicScript,
                    name: "\(period)/\(file)",
                    path: path
                ))
            }
        }
        return items
    }
}
