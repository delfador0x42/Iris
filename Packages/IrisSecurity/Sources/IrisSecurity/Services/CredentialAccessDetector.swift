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
    let logger = Logger(subsystem: "com.wudan.iris", category: "CredentialAccess")

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
        "sqlite3": ("Database access tool", "T1539"),
    ]

    /// Browser processes that legitimately access their own credential DBs
    private static let browserProcesses: Set<String> = [
        "Google Chrome", "Google Chrome Helper", "Google Chrome Helper (Renderer)",
        "firefox", "Firefox", "Safari", "SafariServices",
        "Microsoft Edge", "Microsoft Edge Helper",
        "Brave Browser", "Brave Browser Helper", "Arc", "Arc Helper",
        "Opera", "Opera Helper", "Vivaldi", "Vivaldi Helper",
        "com.apple.WebKit.WebContent", "com.apple.WebKit.Networking",
    ]

    /// Shell interpreters that may wrap credential access tools
    private static let shellInterpreters: Set<String> = [
        "bash", "sh", "zsh", "dash", "fish", "tcsh", "csh",
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

    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        // 1. Check for credential-access processes currently running
        let credProcs = scanRunningCredentialProcesses(snapshot: snap)
        anomalies.append(contentsOf: credProcs)

        // 2. Check for processes accessing credential files
        let fileAccess = scanCredentialFileAccess(snapshot: snap)
        anomalies.append(contentsOf: fileAccess)

        // 3. Check for exposed credential files
        let exposed = scanExposedCredentials()
        anomalies.append(contentsOf: exposed)

        // 4. Check for suspicious browser credential access
        let browserCreds = await scanBrowserCredentialTheft(snapshot: snap)
        anomalies.append(contentsOf: browserCreds)

        return anomalies
    }

    /// Detect processes using credential access tools with suspicious arguments
    private func scanRunningCredentialProcesses(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            guard pid > 0 else { continue }
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            let name = (path as NSString).lastPathComponent

            // Check if this is a known credential access binary
            if let credInfo = Self.credentialBinaries[name] {
                // sqlite3: skip if parent is a browser (legitimate cookie/login DB access)
                if name == "sqlite3" {
                    let ppid = snapshot.parent(of: pid)
                    let parentName = ppid > 0 ? snapshot.name(for: ppid) : ""
                    if Self.browserProcesses.contains(parentName) { continue }
                }

                let args = ProcessEnumeration.getProcessArguments(pid)
                let argsJoined = args.joined(separator: " ").lowercased()

                for pattern in Self.suspiciousArgs where pattern.binary == name {
                    if argsJoined.contains(pattern.pattern.lowercased()) {
                        let ppid = snapshot.parent(of: pid)
                        let parentName = ppid > 0 ? snapshot.name(for: ppid) : "unknown"
                        anomalies.append(ProcessAnomaly(
                            pid: pid, processName: name, processPath: path,
                            parentPID: ppid, parentName: parentName,
                            technique: "Credential Access: \(pattern.description)",
                            description: "Process \(name) (PID \(pid)) invoked with suspicious args: \(argsJoined.prefix(200)). Parent: \(parentName).",
                            severity: .high, mitreID: credInfo.mitreID,
                            scannerId: "credential_access",
                            enumMethod: "sysctl(KERN_PROCARGS2) argument parsing",
                            evidence: [
                                "pid: \(pid)",
                                "binary: \(name)",
                                "matched_pattern: \(pattern.pattern)",
                                "args: \(argsJoined.prefix(200))",
                                "parent: \(parentName) (PID \(ppid))",
                            ]
                        ))
                    }
                }
                continue
            }

            // Shell-wrapped credential access: bash -c "security dump-keychain"
            guard Self.shellInterpreters.contains(name) else { continue }
            let args = ProcessEnumeration.getProcessArguments(pid)
            let argsJoined = args.joined(separator: " ").lowercased()

            for pattern in Self.suspiciousArgs {
                if argsJoined.contains(pattern.binary) &&
                   argsJoined.contains(pattern.pattern.lowercased()) {
                    let ppid = snapshot.parent(of: pid)
                    let parentName = ppid > 0 ? snapshot.name(for: ppid) : "unknown"
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "Shell-Wrapped Credential Access: \(pattern.description)",
                        description: "Shell \(name) (PID \(pid)) executing credential tool: '\(pattern.binary) \(pattern.pattern)'. Parent: \(parentName).",
                        severity: .high, mitreID: "T1059.004",
                        scannerId: "credential_access",
                        enumMethod: "sysctl(KERN_PROCARGS2) argument parsing",
                        evidence: [
                            "pid: \(pid)",
                            "shell: \(name)",
                            "wrapped_binary: \(pattern.binary)",
                            "matched_pattern: \(pattern.pattern)",
                            "args: \(argsJoined.prefix(200))",
                            "parent: \(parentName) (PID \(ppid))",
                        ]
                    ))
                    break
                }
            }
        }

        return anomalies
    }
}
