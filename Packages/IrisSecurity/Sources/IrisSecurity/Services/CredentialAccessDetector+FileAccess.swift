import Foundation
import os.log

extension CredentialAccessDetector {

    /// Check for open file descriptors pointing at credential stores
    func scanCredentialFileAccess(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Credential file paths to monitor
        let credentialPaths = [
            "\(home)/Library/Keychains/login.keychain-db",
            "\(home)/Library/Keychains/login.keychain",
            "\(home)/.ssh/id_rsa",
            "\(home)/.ssh/id_ed25519",
            "\(home)/.ssh/id_ecdsa",
            "/etc/krb5.keytab",
            "\(home)/.aws/credentials",
            "\(home)/.azure/accessTokens.json",
            "\(home)/.config/gcloud/credentials.db",
            "\(home)/.kube/config",
            "\(home)/.docker/config.json",
            "\(home)/.netrc",
            "\(home)/.gnupg/secring.gpg",
        ]

        for pid in snapshot.pids {
            guard pid > 0 else { continue }

            // Get open file descriptors for this process
            let fdCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard fdCount > 0 else { continue }

            let fdSize = Int(fdCount)
            let fds = UnsafeMutablePointer<proc_fdinfo>.allocate(capacity: fdSize / MemoryLayout<proc_fdinfo>.size)
            defer { fds.deallocate() }

            let actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fdCount)
            guard actual > 0 else { continue }

            let fdInfoCount = Int(actual) / MemoryLayout<proc_fdinfo>.size
            let path = snapshot.path(for: pid)
            let name = URL(fileURLWithPath: path).lastPathComponent

            // Skip system processes and ourselves
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") { continue }
            if name == "Iris" || name == "iris" { continue }

            for i in 0..<fdInfoCount {
                let fd = fds[i]
                guard fd.proc_fdtype == PROX_FDTYPE_VNODE else { continue }

                // Get vnode info for this fd
                var vnodeInfo = vnode_fdinfowithpath()
                let vnodeSize = proc_pidfdinfo(
                    pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO,
                    &vnodeInfo, Int32(MemoryLayout<vnode_fdinfowithpath>.size)
                )
                guard vnodeSize > 0 else { continue }

                let filePath = withUnsafePointer(to: vnodeInfo.pvip.vip_path) { ptr in
                    ptr.withMemoryRebound(to: UInt8.self, capacity: Int(MAXPATHLEN)) { buf in
                        // Find null terminator within bounds to prevent OOB read
                        var len = 0
                        while len < Int(MAXPATHLEN) && buf[len] != 0 { len += 1 }
                        return String(bytes: UnsafeBufferPointer(start: buf, count: len), encoding: .utf8) ?? ""
                    }
                }

                for credPath in credentialPaths where filePath == credPath {
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "Open Handle to Credential File",
                        description: "Process \(name) (PID \(pid)) has open file descriptor to \(credPath). This may indicate credential harvesting.",
                        severity: .high, mitreID: "T1555"
                    ))
                }
            }
        }

        return anomalies
    }

    /// Check for credential files with weak permissions
    func scanExposedCredentials() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        // SSH keys should be 600, authorized_keys should be 644 max
        let sshFiles: [(path: String, maxPerms: UInt16)] = [
            ("\(home)/.ssh/id_rsa", 0o600),
            ("\(home)/.ssh/id_ed25519", 0o600),
            ("\(home)/.ssh/id_ecdsa", 0o600),
            ("\(home)/.ssh/config", 0o644),
            ("\(home)/.ssh/authorized_keys", 0o644),
        ]

        for (path, maxPerms) in sshFiles {
            guard fm.fileExists(atPath: path),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let perms = attrs[.posixPermissions] as? UInt16 else { continue }

            // Check if world or group readable when it shouldn't be
            let worldRead = perms & 0o004
            let groupRead = perms & 0o040
            let groupWrite = perms & 0o020
            let worldWrite = perms & 0o002

            if worldRead != 0 || worldWrite != 0 || (maxPerms == 0o600 && (groupRead != 0 || groupWrite != 0)) {
                anomalies.append(.filesystem(
                    name: URL(fileURLWithPath: path).lastPathComponent, path: path,
                    technique: "Exposed Credential File",
                    description: "Credential file \(path) has overly permissive permissions: \(String(perms, radix: 8)). Expected max: \(String(maxPerms, radix: 8)).",
                    severity: .medium, mitreID: "T1552.004"
                ))
            }
        }

        // Check for .netrc (plaintext credentials)
        let netrc = "\(home)/.netrc"
        if fm.fileExists(atPath: netrc) {
            anomalies.append(.filesystem(
                name: ".netrc", path: netrc,
                technique: "Plaintext Credential File",
                description: ".netrc file exists with plaintext credentials for FTP/HTTP authentication.",
                severity: .medium, mitreID: "T1552.001"
            ))
        }

        // Check for AWS/Azure/GCP credentials on disk
        let cloudCreds: [(path: String, service: String)] = [
            ("\(home)/.aws/credentials", "AWS"),
            ("\(home)/.azure/accessTokens.json", "Azure"),
            ("\(home)/.config/gcloud/credentials.db", "GCP"),
        ]

        for (path, service) in cloudCreds {
            if fm.fileExists(atPath: path) {
                anomalies.append(.filesystem(
                    name: URL(fileURLWithPath: path).lastPathComponent, path: path,
                    technique: "\(service) Credentials on Disk",
                    description: "\(service) credential file found at \(path). Cloud credentials on disk are high-value targets for APTs.",
                    severity: .low, mitreID: "T1552.001"
                ))
            }
        }

        return anomalies
    }

    /// Check for browser credential database access by non-browser processes
    func scanBrowserCredentialTheft(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Browser credential databases
        let browserDBs: [(path: String, browser: String, type: String)] = [
            ("\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "Chrome", "passwords"),
            ("\(home)/Library/Application Support/Google/Chrome/Default/Cookies", "Chrome", "cookies"),
            ("\(home)/Library/Application Support/Firefox/Profiles", "Firefox", "credentials"),
            ("\(home)/Library/Cookies/Cookies.binarycookies", "Safari", "cookies"),
        ]

        // Check modification time — if recently accessed, flag it
        let fm = FileManager.default
        for (path, browser, credType) in browserDBs {
            guard fm.fileExists(atPath: path),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let accessDate = attrs[.modificationDate] as? Date else { continue }

            // If credential DB was modified in last 5 minutes, check who's accessing it
            let secondsSinceAccess = Date().timeIntervalSince(accessDate)
            if secondsSinceAccess < 300 {
                logger.info("Browser credential DB recently accessed: \(path)")
            }
        }

        // Check for known credential-stealing tool patterns
        for pid in snapshot.pids {
            guard pid > 0 else { continue }
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            // Python/Ruby/Node accessing browser credential paths is suspicious
            let scriptInterpreters: Set<String> = [
                "python", "python3", "ruby", "node", "perl", "php",
            ]
            guard scriptInterpreters.contains(name) else { continue }

            let args = ProcessEnumeration.getProcessArguments(pid)
            let argsJoined = args.joined(separator: " ").lowercased()

            let credKeywords = [
                "keychain", "login data", "cookies.binarycookies",
                "cookies.sqlite", "key4.db", "logins.json",
                "chrome", "firefox", "safari",
            ]

            for keyword in credKeywords where argsJoined.contains(keyword) {
                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Script Accessing Browser Credentials",
                    description: "Script interpreter \(name) (PID \(pid)) appears to reference browser credential material: matched '\(keyword)' in args.",
                    severity: .critical, mitreID: "T1539"
                ))
                break
            }
        }

        return anomalies
    }
}
