import Foundation
import os.log

/// Detects DYLD environment variable injection across all running processes.
/// The DYLD_INSERT_LIBRARIES technique is the macOS equivalent of LD_PRELOAD —
/// it forces a dylib to load into every (or targeted) process at launch time.
/// APTs use this for code injection, hooking system calls, and keylogging.
/// Also detects DYLD_LIBRARY_PATH manipulation which redirects dylib loading.
/// MITRE ATT&CK: T1574.006 (Dynamic Linker Hijacking),
/// T1055.001 (Dynamic-link Library Injection)
public actor DyldEnvDetector {
    public static let shared = DyldEnvDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DyldEnv")

    /// Dangerous DYLD environment variables
    private static let dangerousVars: [(name: String, description: String, severity: AnomalySeverity)] = [
        ("DYLD_INSERT_LIBRARIES", "Forces dylib injection into process", .critical),
        ("DYLD_LIBRARY_PATH", "Overrides dylib search path — enables dylib hijacking", .high),
        ("DYLD_FRAMEWORK_PATH", "Overrides framework search path — enables framework hijacking", .high),
        ("DYLD_FALLBACK_LIBRARY_PATH", "Adds fallback dylib search path — enables sneaky injection", .medium),
        ("DYLD_FALLBACK_FRAMEWORK_PATH", "Adds fallback framework search path", .medium),
        ("DYLD_IMAGE_SUFFIX", "Changes dylib suffix — can redirect to malicious variants", .high),
        ("DYLD_FORCE_FLAT_NAMESPACE", "Breaks two-level namespacing — enables symbol interposition", .high),
        ("DYLD_PRINT_OPTS", "Dyld debugging — may indicate analysis/evasion", .low),
        ("DYLD_PRINT_ENV", "Dyld debugging — may indicate analysis/evasion", .low),
    ]

    public func scan(snapshot: ProcessSnapshot? = nil) async -> [ProcessAnomaly] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var anomalies: [ProcessAnomaly] = []

        // 1. Check all running processes for DYLD environment variables
        let envAnomalies = scanProcessEnvironments(snapshot: snap)
        anomalies.append(contentsOf: envAnomalies)

        // 2. Check launchd plists for DYLD injection
        let plistAnomalies = scanLaunchdPlists()
        anomalies.append(contentsOf: plistAnomalies)

        // 3. Check for DYLD_ in shell profiles
        let shellAnomalies = scanShellProfiles()
        anomalies.append(contentsOf: shellAnomalies)

        // 4. Check the current process environment (are WE being injected?)
        let selfAnomalies = checkSelfEnvironment()
        anomalies.append(contentsOf: selfAnomalies)

        return anomalies
    }

    /// Parse KERN_PROCARGS2 past argc to extract environment variables
    private func scanProcessEnvironments(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            guard pid > 0 else { continue }
            let envVars = ProcessEnumeration.getProcessEnvironment(pid)

            for (key, value) in envVars {
                for dangerVar in Self.dangerousVars where key == dangerVar.name {
                    let path = snapshot.path(for: pid)
                    let name = path.isEmpty ? "PID \(pid)" : (path as NSString).lastPathComponent

                    // Apple processes with DYLD_ are especially suspicious
                    let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/")
                    let severity = isSystem ? .critical : dangerVar.severity

                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "\(key) Injection",
                        description: "Process \(name) (PID \(pid)) has \(key)=\(value.prefix(200)). \(dangerVar.description).",
                        severity: severity, mitreID: "T1574.006",
                        scannerId: "dyld_env",
                        enumMethod: "sysctl(KERN_PROCARGS2) env parsing",
                        evidence: [
                            "pid: \(pid)",
                            "env_var: \(key)=\(value.prefix(200))",
                            "is_system_process: \(isSystem)",
                        ]
                    ))
                }
            }
        }

        return anomalies
    }

    /// Scan launchd plists for EnvironmentVariables containing DYLD_
    private func scanLaunchdPlists() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "\(home)/Library/LaunchAgents",
        ]

        for dir in dirs {
            guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".plist") {
                let path = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: path) else { continue }

                if let envVars = plist["EnvironmentVariables"] as? [String: String] {
                    for (key, value) in envVars {
                        for dangerVar in Self.dangerousVars where key == dangerVar.name {
                            anomalies.append(.filesystem(
                                name: file, path: path,
                                technique: "Plist \(key) Injection",
                                description: "LaunchAgent/Daemon \(file) sets \(key)=\(value.prefix(200)). Every process launched by this plist will have this dylib injected.",
                                severity: .critical, mitreID: "T1574.006",
                                scannerId: "dyld_env",
                                enumMethod: "NSDictionary(contentsOfFile:) plist parsing",
                                evidence: [
                                    "plist: \(path)",
                                    "env_var: \(key)=\(value.prefix(200))",
                                    "directory: \(dir)",
                                ]
                            ))
                        }
                    }
                }
            }
        }

        return anomalies
    }

    /// Check shell profile files for DYLD_ exports
    private func scanShellProfiles() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let profiles = [
            "\(home)/.zshrc", "\(home)/.zshenv", "\(home)/.zprofile",
            "\(home)/.bash_profile", "\(home)/.bashrc", "\(home)/.profile",
            "/etc/zshrc", "/etc/zshenv", "/etc/profile",
        ]

        for profile in profiles {
            guard let content = try? String(contentsOfFile: profile, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n", omittingEmptySubsequences: false)
            for (lineNum, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                // Skip comments
                if trimmed.hasPrefix("#") { continue }

                for dangerVar in Self.dangerousVars {
                    if trimmed.contains(dangerVar.name) &&
                       (trimmed.contains("export") || trimmed.contains("=")) {
                        anomalies.append(.filesystem(
                            name: (profile as NSString).lastPathComponent, path: profile,
                            technique: "Shell Profile \(dangerVar.name)",
                            description: "Shell profile \(profile) line \(lineNum + 1) sets \(dangerVar.name). Every shell session will inherit this injection.",
                            severity: dangerVar.severity, mitreID: "T1574.006",
                            scannerId: "dyld_env",
                            enumMethod: "String(contentsOfFile:) line scan",
                            evidence: [
                                "file: \(profile)",
                                "line: \(lineNum + 1)",
                                "content: \(String(trimmed.prefix(200)))",
                            ]
                        ))
                    }
                }
            }
        }

        return anomalies
    }

    /// Check if our own process has DYLD_ environment variables
    private func checkSelfEnvironment() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let env = Foundation.ProcessInfo.processInfo.environment

        for (key, value) in env {
            for dangerVar in Self.dangerousVars where key == dangerVar.name {
                anomalies.append(ProcessAnomaly(
                    pid: getpid(), processName: "Iris", processPath: "",
                    parentPID: getppid(), parentName: "",
                    technique: "Iris Has \(key)",
                    description: "Iris itself has \(key)=\(value.prefix(200)) in its environment. Someone may be injecting code into Iris to evade detection.",
                    severity: .critical, mitreID: "T1562.001",
                    scannerId: "dyld_env",
                    enumMethod: "ProcessInfo.processInfo.environment",
                    evidence: [
                        "env_var: \(key)=\(value.prefix(200))",
                        "iris_pid: \(getpid())",
                        "parent_pid: \(getppid())",
                    ]
                ))
            }
        }

        return anomalies
    }

}
