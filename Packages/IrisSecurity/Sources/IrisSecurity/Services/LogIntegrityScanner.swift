import Foundation
import os.log

/// Checks log subsystem integrity and crash reports for security-critical process failures.
/// Covers hunt scripts: logging_config, logd_health, crash_reports, boot_security.
public actor LogIntegrityScanner {
    public static let shared = LogIntegrityScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "LogIntegrity")

    /// Security-critical processes — crashes may indicate exploitation
    private let criticalProcesses = Set([
        "securityd", "trustd", "amfid", "syspolicyd", "tccd",
        "endpointsecurityd", "Security", "XProtect", "MRT",
    ])

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: await scanCrashReports())
        anomalies.append(contentsOf: scanLogdHealth())
        anomalies.append(contentsOf: scanKernelPanics())
        return anomalies
    }

    /// Check for crashes of security-critical daemons
    private func scanCrashReports() async -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let dirs = ["/Library/Logs/DiagnosticReports",
                    FileManager.default.homeDirectoryForCurrentUser
                        .appendingPathComponent("Library/Logs/DiagnosticReports").path]
        let fm = FileManager.default
        let weekAgo = Date().addingTimeInterval(-86400 * 7)

        for dir in dirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".ips") || file.hasSuffix(".crash") {
                let path = "\(dir)/\(file)"
                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      let mod = attrs[.modificationDate] as? Date,
                      mod > weekAgo else { continue }

                // Check if it's a security-critical process crash
                for proc in criticalProcesses where file.contains(proc) {
                    result.append(.filesystem(
                        name: file, path: path,
                        technique: "Security Process Crash",
                        description: "Security daemon \(proc) crashed recently (\(file)). May indicate exploitation attempt.",
                        severity: .high, mitreID: "T1211",
                        scannerId: "log_integrity",
                        enumMethod: "FileManager.contentsOfDirectory → DiagnosticReports .ips/.crash scan",
                        evidence: [
                            "process=\(proc)",
                            "crash_file=\(file)",
                            "path=\(path)",
                            "modified=\(mod)",
                        ]))
                }
            }
        }
        return result
    }

    /// Check logd (unified log daemon) health
    private func scanLogdHealth() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []

        // Check if log store is unreasonably small (may have been cleared)
        let logStore = "/var/db/diagnostics"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: logStore),
           let size = attrs[.size] as? UInt64, size < 1024 * 1024 { // < 1MB is suspicious
            result.append(.filesystem(
                name: "diagnostics", path: logStore,
                technique: "Log Store Anomaly",
                description: "Unified log store is unusually small (\(size) bytes). Logs may have been cleared.",
                severity: .high, mitreID: "T1070.002",
                scannerId: "log_integrity",
                enumMethod: "FileManager.attributesOfItem → /var/db/diagnostics size check",
                evidence: [
                    "path=\(logStore)",
                    "size_bytes=\(size)",
                    "threshold=1048576",
                ]))
        }

        // Check for disabled logging subsystems
        let loggingPrefs = "/Library/Preferences/Logging"
        if let files = try? FileManager.default.contentsOfDirectory(atPath: loggingPrefs) {
            for file in files where file.hasSuffix(".plist") {
                let path = "\(loggingPrefs)/\(file)"
                if let content = try? String(contentsOfFile: path, encoding: .utf8),
                   content.contains("Level") && content.contains("Off") {
                    result.append(.filesystem(
                        name: file, path: path,
                        technique: "Disabled Logging Subsystem",
                        description: "Logging subsystem \(file) has disabled levels. May hide malicious activity.",
                        severity: .medium, mitreID: "T1562.002",
                        scannerId: "log_integrity",
                        enumMethod: "String(contentsOfFile:) → Logging plist Level=Off scan",
                        evidence: [
                            "plist=\(file)",
                            "path=\(path)",
                            "indicator=Level+Off in plist",
                        ]))
                }
            }
        }
        return result
    }

    /// Check for recent kernel panics
    private func scanKernelPanics() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let panicDir = "/Library/Logs/DiagnosticReports"
        let fm = FileManager.default
        let weekAgo = Date().addingTimeInterval(-86400 * 7)

        guard let files = try? fm.contentsOfDirectory(atPath: panicDir) else { return result }
        let recentPanics = files.filter { $0.contains("kernel") && $0.hasSuffix(".panic") }

        for file in recentPanics {
            let path = "\(panicDir)/\(file)"
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let mod = attrs[.modificationDate] as? Date,
                  mod > weekAgo else { continue }

            result.append(.filesystem(
                name: file, path: path,
                technique: "Recent Kernel Panic",
                description: "Kernel panic within last 7 days: \(file). May indicate kernel exploitation.",
                severity: .high, mitreID: "T1014",
                scannerId: "log_integrity",
                enumMethod: "FileManager.contentsOfDirectory → DiagnosticReports .panic scan",
                evidence: [
                    "panic_file=\(file)",
                    "path=\(path)",
                    "modified=\(mod)",
                ]))
        }
        return result
    }
}
