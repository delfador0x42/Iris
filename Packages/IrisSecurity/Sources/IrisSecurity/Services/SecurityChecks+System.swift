import Foundation
import os.log

/// macOS security configuration checks (CIS Benchmark inspired)
/// Uses shell commands to query system security state.
enum SystemSecurityChecks {

    private static let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityChecks")

    /// Run all system security checks
    static func runAll() async -> [SecurityCheck] {
        await withTaskGroup(of: SecurityCheck.self, returning: [SecurityCheck].self) { group in
            group.addTask { await checkSIP() }
            group.addTask { await checkFileVault() }
            group.addTask { await checkGatekeeper() }
            group.addTask { await checkFirewall() }
            group.addTask { await checkFirewallStealth() }
            group.addTask { await checkAutoUpdates() }
            group.addTask { await checkRemoteLogin() }
            group.addTask { await checkScreenSaver() }

            var results: [SecurityCheck] = []
            for await result in group { results.append(result) }
            return results
        }
    }

    // MARK: - Individual Checks

    static func checkSIP() async -> SecurityCheck {
        let output = await runCommand("/usr/bin/csrutil", args: ["status"])
        let enabled = output.contains("enabled")
        return SecurityCheck(
            category: .systemIntegrity,
            name: "System Integrity Protection",
            description: "Protects system files and processes from modification",
            status: enabled ? .pass : .fail,
            severity: .critical,
            remediation: enabled ? nil : "Boot to Recovery Mode and run 'csrutil enable'"
        )
    }

    static func checkFileVault() async -> SecurityCheck {
        let output = await runCommand("/usr/bin/fdesetup", args: ["status"])
        let on = output.contains("FileVault is On")
        return SecurityCheck(
            category: .encryption,
            name: "FileVault Disk Encryption",
            description: "Full-disk encryption protects data at rest",
            status: on ? .pass : .fail,
            severity: .critical,
            remediation: on ? nil : "Enable FileVault in System Settings > Privacy & Security"
        )
    }

    static func checkGatekeeper() async -> SecurityCheck {
        let output = await runCommand("/usr/sbin/spctl", args: ["--status"])
        let enabled = output.contains("assessments enabled")
        return SecurityCheck(
            category: .appSecurity,
            name: "Gatekeeper",
            description: "Verifies apps are signed by identified developers",
            status: enabled ? .pass : .fail,
            severity: .high,
            remediation: enabled ? nil : "Run 'sudo spctl --master-enable' in Terminal"
        )
    }

    static func checkFirewall() async -> SecurityCheck {
        let output = await runCommand("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                      args: ["--getglobalstate"])
        let enabled = output.contains("enabled")
        return SecurityCheck(
            category: .networkSecurity,
            name: "Application Firewall",
            description: "Controls incoming connections per application",
            status: enabled ? .pass : .fail,
            severity: .high,
            remediation: enabled ? nil : "Enable in System Settings > Network > Firewall"
        )
    }

    static func checkFirewallStealth() async -> SecurityCheck {
        let output = await runCommand("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                      args: ["--getstealthmode"])
        let enabled = output.contains("enabled")
        return SecurityCheck(
            category: .networkSecurity,
            name: "Firewall Stealth Mode",
            description: "Prevents responding to probing requests (ICMP, etc.)",
            status: enabled ? .pass : .warning,
            severity: .medium,
            remediation: enabled ? nil : "Enable stealth mode in Firewall options"
        )
    }

    static func checkAutoUpdates() async -> SecurityCheck {
        let output = await runCommand("/usr/bin/defaults", args: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"
        ])
        let enabled = output.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        return SecurityCheck(
            category: .updates,
            name: "Automatic Update Check",
            description: "System checks for macOS and security updates automatically",
            status: enabled ? .pass : .fail,
            severity: .medium,
            remediation: enabled ? nil : "Enable in System Settings > General > Software Update"
        )
    }

    static func checkRemoteLogin() async -> SecurityCheck {
        let output = await runCommand("/usr/sbin/systemsetup", args: ["-getremotelogin"])
        let off = output.lowercased().contains("off")
        return SecurityCheck(
            category: .authentication,
            name: "Remote Login (SSH)",
            description: "SSH access should be disabled unless specifically needed",
            status: off ? .pass : .warning,
            severity: .medium,
            remediation: off ? nil : "Disable in System Settings > General > Sharing > Remote Login"
        )
    }

    static func checkScreenSaver() async -> SecurityCheck {
        let output = await runCommand("/usr/bin/defaults", args: [
            "-currentHost", "read", "com.apple.screensaver", "idleTime"
        ])
        let seconds = Int(output.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        let reasonable = seconds > 0 && seconds <= 600
        return SecurityCheck(
            category: .authentication,
            name: "Screen Lock Timeout",
            description: "Screen should lock within 10 minutes of inactivity",
            status: reasonable ? .pass : .warning,
            severity: .low,
            remediation: reasonable ? nil : "Set screen saver to activate within 10 minutes"
        )
    }

    // MARK: - Shell Command Runner

    private static func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = pipe

            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                logger.error("Command failed: \(path) \(args.joined(separator: " ")): \(error)")
                continuation.resume(returning: "")
            }
        }
    }
}
