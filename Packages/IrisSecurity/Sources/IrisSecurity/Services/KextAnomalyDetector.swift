import Foundation
import os.log

/// Detects suspicious kernel extensions and driver anomalies.
/// Nation-state actors load kernel extensions to:
/// - Install rootkits (hide processes, files, network connections)
/// - Install keyloggers at the kernel level
/// - Intercept system calls
/// - Disable security features (SIP bypass via kext)
/// MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions),
/// T1014 (Rootkit), T1562.001 (Disable or Modify Tools)
public actor KextAnomalyDetector {
    public static let shared = KextAnomalyDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "KextAnomaly")

    /// Known legitimate kext publishers (signing team IDs)
    static let trustedTeamIDs: Set<String> = [
        "com.apple",
    ]

    /// Suspicious kext names/patterns from known macOS rootkits and malware
    static let knownMaliciousPatterns: [String] = [
        "rubilyn", "fruitfly", "thiefquest", "zuru", "shlayer",
        "cdrthief", "keydnap", "calisto", "xcsset", "osx.dummy",
        "hideproc", "hidefile", "rootkit", "keylog", "inject",
    ]

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies += await getLoadedKexts()
        anomalies += await scanDiskKexts()
        anomalies += await scanSystemExtensions()
        anomalies += checkKernelIntegrity()
        return anomalies
    }

    func runCommand(_ path: String, args: [String]) async -> String {
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
