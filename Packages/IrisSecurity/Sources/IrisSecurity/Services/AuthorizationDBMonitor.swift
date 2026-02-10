import Foundation
import os.log
import CryptoKit

/// Monitors the macOS Authorization Database for tampering.
/// APTs modify the AuthDB to bypass authentication for privileged operations.
/// For example: modifying "system.privilege.admin" to allow execution without
/// password prompt, or adding rules that grant root to specific binaries.
/// MITRE ATT&CK: T1548.004 (Abuse Elevation Control Mechanism),
/// T1556 (Modify Authentication Process)
public actor AuthorizationDBMonitor {
    public static let shared = AuthorizationDBMonitor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "AuthDB")

    /// Critical authorization rights that should not be modified
    private static let criticalRights: [(right: String, description: String)] = [
        ("system.privilege.admin", "Admin privilege escalation"),
        ("system.privilege.taskport", "Task port access (process injection)"),
        ("system.login.console", "Console login authentication"),
        ("system.install.apple-software", "Apple software installation"),
        ("system.install.app-store-software", "App Store software installation"),
        ("system.install.software.iAuthInstallRights", "Software installation auth"),
        ("com.apple.system-extensions.admin", "System extension installation"),
        ("system.preferences.security", "Security preferences modification"),
        ("system.keychain.modify", "Keychain modification"),
        ("system.services.systemconfiguration.network", "Network configuration"),
    ]

    /// Expected rules that should use "authenticate-admin" or similar
    private static let expectedAuthRules: Set<String> = [
        "authenticate-admin",
        "authenticate-admin-nonshared",
        "authenticate-session-owner",
        "authenticate-session-owner-or-admin",
    ]

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // 1. Check critical authorization rights
        let rightAnomalies = await checkCriticalRights()
        anomalies.append(contentsOf: rightAnomalies)

        // 2. Check for custom authorization plugins
        let pluginAnomalies = await checkAuthPlugins()
        anomalies.append(contentsOf: pluginAnomalies)

        // 3. Check authorization database file integrity
        let dbAnomalies = checkAuthDBIntegrity()
        anomalies.append(contentsOf: dbAnomalies)

        return anomalies
    }

    /// Read authorization rights and check for weakening
    private func checkCriticalRights() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for (right, desc) in Self.criticalRights {
            let output = await runCommand("/usr/bin/security", args: [
                "authorizationdb", "read", right
            ])

            // Parse the plist output
            guard let data = output.data(using: .utf8),
                  let plist = try? PropertyListSerialization.propertyList(
                      from: data, format: nil
                  ) as? [String: Any] else { continue }

            // Check the rule
            if let rule = plist["rule"] as? [String] {
                // If it's set to "allow" — instant escalation without auth
                if rule.contains("allow") {
                    anomalies.append(.filesystem(
                        name: right, path: "/var/db/auth.db",
                        technique: "AuthDB Right Set to Allow",
                        description: "Authorization right '\(right)' (\(desc)) is set to 'allow' — no authentication required. This enables silent privilege escalation.",
                        severity: .critical, mitreID: "T1548.004"
                    ))
                }
            } else if let ruleStr = plist["rule"] as? String {
                if ruleStr == "allow" {
                    anomalies.append(.filesystem(
                        name: right, path: "/var/db/auth.db",
                        technique: "AuthDB Right Set to Allow",
                        description: "Authorization right '\(right)' (\(desc)) is set to 'allow'. No authentication required for this privileged action.",
                        severity: .critical, mitreID: "T1548.004"
                    ))
                }
            }

            // Check for custom mechanisms (could be malicious plugins)
            if let mechanisms = plist["mechanisms"] as? [String] {
                for mechanism in mechanisms {
                    // Non-Apple mechanisms are suspicious
                    if !mechanism.hasPrefix("builtin:") &&
                       !mechanism.contains("loginwindow") &&
                       !mechanism.contains("Security") {
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: right, processPath: "/var/db/auth.db",
                            parentPID: 0, parentName: "",
                            technique: "Custom Auth Mechanism",
                            description: "Authorization right '\(right)' uses custom mechanism: \(mechanism). Non-standard auth mechanisms can capture credentials or bypass authentication.",
                            severity: .high, mitreID: "T1556"
                        ))
                    }
                }
            }

            // Check timeout — very long timeout means auth is rarely re-requested
            if let timeout = plist["timeout"] as? Int, timeout > 3600 {
                anomalies.append(.filesystem(
                    name: right, path: "/var/db/auth.db",
                    technique: "Extended Auth Timeout",
                    description: "Authorization right '\(right)' has timeout of \(timeout)s (\(timeout/3600)h). Extended timeouts reduce re-authentication frequency.",
                    severity: .low, mitreID: "T1548.004"
                ))
            }
        }

        return anomalies
    }

    /// Check for non-Apple authorization plugins
    private func checkAuthPlugins() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let pluginDir = "/Library/Security/SecurityAgentPlugins"
        let fm = FileManager.default

        guard let items = try? fm.contentsOfDirectory(atPath: pluginDir) else {
            return anomalies
        }

        for item in items where item.hasSuffix(".bundle") {
            let bundlePath = "\(pluginDir)/\(item)"
            let (status, _, isApple) = await SigningVerifier.shared.verify(bundlePath)

            if !isApple {
                let severity: AnomalySeverity = status == .unsigned ? .critical : .high

                anomalies.append(.filesystem(
                    name: item, path: bundlePath,
                    technique: "Non-Apple Auth Plugin",
                    description: "Authorization plugin \(item) at \(bundlePath) is not Apple-signed (status: \(status.rawValue)). Auth plugins execute during login and can capture credentials or grant unauthorized access.",
                    severity: severity, mitreID: "T1556"
                ))
            }
        }

        return anomalies
    }

    /// Check /var/db/auth.db modification time and integrity
    private func checkAuthDBIntegrity() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let authDBPath = "/var/db/auth.db"
        let fm = FileManager.default

        guard let attrs = try? fm.attributesOfItem(atPath: authDBPath),
              let modDate = attrs[.modificationDate] as? Date else {
            return anomalies
        }

        // auth.db should only change during OS updates
        let daysSinceModified = Date().timeIntervalSince(modDate) / 86400
        if daysSinceModified < 7 {
            anomalies.append(.filesystem(
                name: "auth.db", path: authDBPath,
                technique: "Recently Modified AuthDB",
                description: "Authorization database was modified \(String(format: "%.1f", daysSinceModified)) days ago. Outside of OS updates, changes to auth.db are suspicious.",
                severity: .medium, mitreID: "T1548.004"
            ))
        }

        return anomalies
    }

    private func runCommand(_ path: String, args: [String]) async -> String {
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
