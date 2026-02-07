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

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // 1. Check all running processes for DYLD environment variables
        let envAnomalies = scanProcessEnvironments()
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
    private func scanProcessEnvironments() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let pids = getRunningPIDs()

        for pid in pids {
            guard pid > 0 else { continue }
            let envVars = getProcessEnvironment(pid)

            for (key, value) in envVars {
                for dangerVar in Self.dangerousVars where key == dangerVar.name {
                    let path = getProcessPath(pid)
                    let name = path.isEmpty ? "PID \(pid)" : URL(fileURLWithPath: path).lastPathComponent

                    // Apple processes with DYLD_ are especially suspicious
                    let isSystem = path.hasPrefix("/System/") || path.hasPrefix("/usr/")
                    let severity = isSystem ? .critical : dangerVar.severity

                    anomalies.append(ProcessAnomaly(
                        pid: pid, processName: name, processPath: path,
                        parentPID: 0, parentName: "",
                        technique: "\(key) Injection",
                        description: "Process \(name) (PID \(pid)) has \(key)=\(value.prefix(200)). \(dangerVar.description).",
                        severity: severity, mitreID: "T1574.006"
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
                            anomalies.append(ProcessAnomaly(
                                pid: 0, processName: file, processPath: path,
                                parentPID: 0, parentName: "",
                                technique: "Plist \(key) Injection",
                                description: "LaunchAgent/Daemon \(file) sets \(key)=\(value.prefix(200)). Every process launched by this plist will have this dylib injected.",
                                severity: .critical, mitreID: "T1574.006"
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
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: URL(fileURLWithPath: profile).lastPathComponent,
                            processPath: profile,
                            parentPID: 0, parentName: "",
                            technique: "Shell Profile \(dangerVar.name)",
                            description: "Shell profile \(profile) line \(lineNum + 1) sets \(dangerVar.name). Every shell session will inherit this injection.",
                            severity: dangerVar.severity, mitreID: "T1574.006"
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
        let env = ProcessInfo.processInfo.environment

        for (key, value) in env {
            for dangerVar in Self.dangerousVars where key == dangerVar.name {
                anomalies.append(ProcessAnomaly(
                    pid: getpid(), processName: "Iris", processPath: "",
                    parentPID: getppid(), parentName: "",
                    technique: "Iris Has \(key)",
                    description: "Iris itself has \(key)=\(value.prefix(200)) in its environment. Someone may be injecting code into Iris to evade detection.",
                    severity: .critical, mitreID: "T1562.001"
                ))
            }
        }

        return anomalies
    }

    // MARK: - Process Utilities

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

    /// Parse KERN_PROCARGS2: skip argc, skip args, then parse env vars
    private func getProcessEnvironment(_ pid: pid_t) -> [(String, String)] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buffer.deallocate() }
        guard sysctl(&mib, 3, buffer, &size, nil, 0) == 0 else { return [] }
        guard size > MemoryLayout<Int32>.size else { return [] }

        let argc = buffer.withMemoryRebound(to: Int32.self, capacity: 1) { $0.pointee }

        // Skip past argc
        var offset = MemoryLayout<Int32>.size
        // Skip executable path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Skip argc arguments
        var argsSkipped = 0
        while offset < size && argsSkipped < Int(argc) {
            if buffer[offset] == 0 {
                argsSkipped += 1
                // Skip additional null padding
                while offset < size && buffer[offset] == 0 { offset += 1 }
            } else {
                offset += 1
            }
        }

        // Now we're in the environment variables section
        var envVars: [(String, String)] = []
        while offset < size {
            // Read one null-terminated string
            var str = ""
            while offset < size && buffer[offset] != 0 {
                str.append(Character(UnicodeScalar(buffer[offset])))
                offset += 1
            }
            offset += 1 // skip null

            if str.isEmpty { break } // Two consecutive nulls = end

            // Split on first '='
            if let eqIdx = str.firstIndex(of: "=") {
                let key = String(str[str.startIndex..<eqIdx])
                let value = String(str[str.index(after: eqIdx)...])
                // Only collect DYLD_ vars (performance: skip the rest)
                if key.hasPrefix("DYLD_") {
                    envVars.append((key, value))
                }
            }
        }

        return envVars
    }
}
