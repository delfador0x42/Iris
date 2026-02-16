import Foundation
import os.log

/// Analyzes crash reports for exploitation indicators.
/// Crashes in system processes (WindowServer, mds, loginwindow) suggest
/// active exploitation. Heap corruption, use-after-free, stack overflow
/// patterns indicate exploit attempts. Covers: crash_reports.sh.
public actor CrashReportAnalyzer {
  public static let shared = CrashReportAnalyzer()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "CrashReport")

  /// Critical system processes — crashes here indicate exploitation
  private static let criticalProcesses: Set<String> = [
    "WindowServer", "loginwindow", "mds", "mds_stores",
    "securityd", "trustd", "syspolicyd", "endpointsecurityd",
    "logd", "notifyd", "configd", "launchd", "kernelmanagerd",
  ]

  /// Crash patterns that indicate exploitation (not normal crashes)
  private static let exploitPatterns: [(pattern: String, desc: String)] = [
    ("EXC_BAD_ACCESS (SIGBUS)", "Memory corruption"),
    ("EXC_BAD_ACCESS (SIGSEGV)", "Segmentation fault"),
    ("KERN_INVALID_ADDRESS", "Invalid memory access"),
    ("heap buffer overflow", "Heap buffer overflow"),
    ("stack buffer overflow", "Stack buffer overflow"),
    ("use-after-free", "Use-after-free"),
    ("double free", "Double free"),
    ("__abort_with_payload", "Sandbox violation"),
    ("sandbox violation", "Sandbox escape attempt"),
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let crashDirs = [
      "\(NSHomeDirectory())/Library/Logs/DiagnosticReports",
      "/Library/Logs/DiagnosticReports",
    ]
    let fm = FileManager.default
    let cutoff = Date().addingTimeInterval(-7 * 86400) // Last 7 days

    for dir in crashDirs {
      guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
      for file in files where file.hasSuffix(".ips") || file.hasSuffix(".crash") {
        let path = "\(dir)/\(file)"
        guard let attrs = try? fm.attributesOfItem(atPath: path),
          let modDate = attrs[.modificationDate] as? Date,
          modDate > cutoff
        else { continue }

        // Read first 2KB for crash info
        guard let handle = FileHandle(forReadingAtPath: path) else { continue }
        let data = handle.readData(ofLength: 2048)
        handle.closeFile()
        guard let content = String(data: data, encoding: .utf8) else { continue }

        // Check if it's a critical process crash
        let procName = file.components(separatedBy: "_").first ?? file
        let isCritical = Self.criticalProcesses.contains(procName)

        // Check for exploitation patterns
        for (pattern, desc) in Self.exploitPatterns where content.contains(pattern) {
          let severity: AnomalySeverity = isCritical ? .critical : .medium
          anomalies.append(.filesystem(
            name: procName, path: path,
            technique: "Suspicious Crash Report",
            description: "\(procName) crash: \(desc) — \(isCritical ? "CRITICAL PROCESS" : "user process")",
            severity: severity, mitreID: "T1499.004",
            scannerId: "crash_reports",
            enumMethod: "FileHandle.readData → crash report pattern matching",
            evidence: [
              "process=\(procName)",
              "crash_file=\(file)",
              "crash_pattern=\(pattern)",
              "is_critical_process=\(isCritical)",
            ]
          ))
          break // One finding per crash file
        }
      }
    }
    return anomalies
  }
}
