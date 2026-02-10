import Foundation
import os.log

/// Detects active credential access and theft attempts.
/// APTs dump Keychain, steal SSH keys, harvest browser cookies, and
/// extract tokens from credential stores. This scanner detects processes
/// currently accessing or having recently accessed credential material.
/// MITRE ATT&CK: T1555 (Credentials from Password Stores),
/// T1539 (Steal Web Session Cookie), T1552 (Unsecured Credentials)
public actor CredentialAccessDetector {
    public static let shared = CredentialAccessDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "CredentialAccess")

    /// Known credential access binaries and what they access
    private static let credentialBinaries: [String: (description: String, mitreID: String)] = [
        "security": ("Keychain access tool", "T1555.001"),
        "certtool": ("Certificate manipulation", "T1553.004"),
        "codesign": ("Code signing identity access", "T1553.002"),
        "ssh-add": ("SSH key agent", "T1552.004"),
        "ssh-keygen": ("SSH key generation/manipulation", "T1552.004"),
        "dscl": ("Directory service (user/password manipulation)", "T1087.001"),
        "klist": ("Kerberos ticket listing", "T1558"),
        "kinit": ("Kerberos ticket acquisition", "T1558"),
        "kdestroy": ("Kerberos ticket destruction", "T1070.004"),
    ]

    /// Suspicious argument patterns for credential tools
    private static let suspiciousArgs: [(binary: String, pattern: String, description: String)] = [
        ("security", "dump-keychain", "Dumping entire Keychain"),
        ("security", "find-generic-password", "Extracting generic passwords"),
        ("security", "find-internet-password", "Extracting internet passwords"),
        ("security", "export", "Exporting Keychain items"),
        ("security", "unlock-keychain", "Unlocking Keychain non-interactively"),
        ("security", "delete-keychain", "Deleting Keychain"),
        ("security", "set-keychain-settings", "Modifying Keychain settings"),
        ("sqlite3", "cookies", "Accessing browser cookies DB"),
        ("sqlite3", "logins", "Accessing browser saved passwords DB"),
        ("sqlite3", "key4.db", "Accessing Firefox key store"),
        ("sqlite3", "cert9.db", "Accessing Firefox certificate store"),
        ("dscl", "-read", "Reading directory service records"),
        ("dscl", "passwd", "Password operations via directory service"),
        ("sysadminctl", "-secureTokenStatus", "Checking secure token status"),
        ("sysadminctl", "-resetPasswordFor", "Resetting user password"),
    ]

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // 1. Check for credential-access processes currently running
        let credProcs = scanRunningCredentialProcesses()
        anomalies.append(contentsOf: credProcs)

        // 2. Check for processes accessing credential files
        let fileAccess = scanCredentialFileAccess()
        anomalies.append(contentsOf: fileAccess)

        // 3. Check for exposed credential files
        let exposed = scanExposedCredentials()
        anomalies.append(contentsOf: exposed)

        // 4. Check for suspicious browser credential access
        let browserCreds = await scanBrowserCredentialTheft()
        anomalies.append(contentsOf: browserCreds)

        return anomalies
    }

    /// Detect processes using credential access tools with suspicious arguments
    private func scanRunningCredentialProcesses() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let pids = ProcessEnumeration.getRunningPIDs()

        for pid in pids {
            guard pid > 0 else { continue }
            let path = ProcessEnumeration.getProcessPath(pid)
            guard !path.isEmpty else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            // Check if this is a known credential access binary
            guard let credInfo = Self.credentialBinaries[name] else { continue }

            // Get process arguments
            let args = getProcessArguments(pid)
            let argsJoined = args.joined(separator: " ").lowercased()

            // Check for suspicious argument patterns
            for pattern in Self.suspiciousArgs where pattern.binary == name {
                if argsJoined.contains(pattern.pattern.lowercased()) {
                    let ppid = ProcessEnumeration.getParentPID(pid)
                    let parentName = ppid > 0 ? URL(fileURLWithPath: ProcessEnumeration.getProcessPath(ppid)).lastPathComponent : "unknown"

                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: ppid, parentName: parentName,
                        technique: "Credential Access: \(pattern.description)",
                        description: "Process \(name) (PID \(pid)) invoked with suspicious args: \(argsJoined.prefix(200)). Parent: \(parentName).",
                        severity: .high, mitreID: credInfo.mitreID
                    ))
                }
            }
        }

        return anomalies
    }

    /// Check for open file descriptors pointing at credential stores
    private func scanCredentialFileAccess() -> [ProcessAnomaly] {
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

        // Use lsof to find processes with credential files open
        let pids = ProcessEnumeration.getRunningPIDs()
        for pid in pids {
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
            let path = ProcessEnumeration.getProcessPath(pid)
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
                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: 0, parentName: "",
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
    private func scanExposedCredentials() -> [ProcessAnomaly] {
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
                anomalies.append(ProcessAnomaly(
                    pid: 0, processName: URL(fileURLWithPath: path).lastPathComponent,
                    processPath: path,
                    parentPID: 0, parentName: "",
                    technique: "Exposed Credential File",
                    description: "Credential file \(path) has overly permissive permissions: \(String(perms, radix: 8)). Expected max: \(String(maxPerms, radix: 8)).",
                    severity: .medium, mitreID: "T1552.004"
                ))
            }
        }

        // Check for .netrc (plaintext credentials)
        let netrc = "\(home)/.netrc"
        if fm.fileExists(atPath: netrc) {
            anomalies.append(ProcessAnomaly(
                pid: 0, processName: ".netrc",
                processPath: netrc,
                parentPID: 0, parentName: "",
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
                anomalies.append(ProcessAnomaly(
                    pid: 0, processName: URL(fileURLWithPath: path).lastPathComponent,
                    processPath: path,
                    parentPID: 0, parentName: "",
                    technique: "\(service) Credentials on Disk",
                    description: "\(service) credential file found at \(path). Cloud credentials on disk are high-value targets for APTs.",
                    severity: .low, mitreID: "T1552.001"
                ))
            }
        }

        return anomalies
    }

    /// Check for browser credential database access by non-browser processes
    private func scanBrowserCredentialTheft() async -> [ProcessAnomaly] {
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
        let pids = ProcessEnumeration.getRunningPIDs()
        for pid in pids {
            guard pid > 0 else { continue }
            let path = ProcessEnumeration.getProcessPath(pid)
            guard !path.isEmpty else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            // Python/Ruby/Node accessing browser credential paths is suspicious
            let scriptInterpreters: Set<String> = [
                "python", "python3", "ruby", "node", "perl", "php",
            ]
            guard scriptInterpreters.contains(name) else { continue }

            let args = getProcessArguments(pid)
            let argsJoined = args.joined(separator: " ").lowercased()

            let credKeywords = [
                "keychain", "login data", "cookies.binarycookies",
                "cookies.sqlite", "key4.db", "logins.json",
                "chrome", "firefox", "safari",
            ]

            for keyword in credKeywords where argsJoined.contains(keyword) {
                anomalies.append(ProcessAnomaly(
                    pid: pid, processName: name, processPath: path,
                    parentPID: 0, parentName: "",
                    technique: "Script Accessing Browser Credentials",
                    description: "Script interpreter \(name) (PID \(pid)) appears to reference browser credential material: matched '\(keyword)' in args.",
                    severity: .critical, mitreID: "T1539"
                ))
                break
            }
        }

        return anomalies
    }

    // MARK: - Process Utilities

    private func getProcessArguments(_ pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        // Allocate with margin to handle size changes between sysctl calls
        let allocSize = size + 512
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: allocSize)
        defer { buffer.deallocate() }
        var actualSize = allocSize
        guard sysctl(&mib, 3, buffer, &actualSize, nil, 0) == 0 else { return [] }
        size = actualSize

        // First 4 bytes = argc
        guard size > MemoryLayout<Int32>.size else { return [] }
        let argc = buffer.withMemoryRebound(to: Int32.self, capacity: 1) { $0.pointee }

        // Skip past argc and executable path
        var offset = MemoryLayout<Int32>.size
        // Skip executable path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null terminators
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Parse arguments
        var args: [String] = []
        var current = ""
        for i in offset..<size {
            if buffer[i] == 0 {
                if !current.isEmpty {
                    args.append(current)
                    if args.count >= Int(argc) { break }
                    current = ""
                }
            } else {
                current.append(Character(UnicodeScalar(buffer[i])))
            }
        }
        if !current.isEmpty && args.count < Int(argc) { args.append(current) }

        return args
    }
}
