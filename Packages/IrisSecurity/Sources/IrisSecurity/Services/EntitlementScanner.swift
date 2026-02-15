import Foundation
import os.log

/// Audits running processes for dangerous entitlements.
/// Flags: get-task-allow, task_for_pid, com.apple.private.*,
/// com.apple.security.cs.disable-library-validation.
/// These enable injection, debugging, and code modification.
public actor EntitlementScanner {
  public static let shared = EntitlementScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "Entitlements")

  /// Dangerous entitlement keys and their risk descriptions
  private static let dangerousEntitlements: [(key: String, desc: String, severity: AnomalySeverity)]
    = [
      ("get-task-allow", "Allows debugging/injection", .high),
      ("task_for_pid-allow", "Allows task port access to any process", .critical),
      ("com.apple.private", "Uses Apple private entitlement", .high),
      ("com.apple.security.cs.disable-library-validation", "Disables dylib validation", .high),
      ("com.apple.security.cs.allow-unsigned-executable-memory", "Allows unsigned RWX", .medium),
      ("com.apple.security.cs.allow-dyld-environment-variables", "Allows DYLD injection", .high),
      ("com.apple.security.cs.debugger", "System debugger entitlement", .critical),
    ]

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    for pid in snapshot.pids {
      let path = snapshot.path(for: pid)
      guard !path.hasPrefix("/System/") && !path.hasPrefix("/usr/libexec/") else { continue }
      guard !path.isEmpty else { continue }
      let name = snapshot.name(for: pid)
      let ents = await getEntitlements(path: path)
      guard !ents.isEmpty else { continue }
      for (key, desc, severity) in Self.dangerousEntitlements {
        if ents.contains(key) {
          anomalies.append(.forProcess(
            pid: pid, name: name, path: path,
            technique: "Dangerous Entitlement",
            description: "\(name) has \(key): \(desc)",
            severity: severity, mitreID: "T1068"
          ))
        }
      }
    }
    return anomalies
  }

  private func getEntitlements(path: String) async -> String {
    await runCommand("/usr/bin/codesign", args: ["-d", "--entitlements", "-", "--xml", path])
  }

  private func runCommand(_ path: String, args: [String]) async -> String {
    await withCheckedContinuation { continuation in
      let process = Process(); let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: path)
      process.arguments = args
      process.standardOutput = pipe; process.standardError = pipe
      do {
        try process.run(); process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
      } catch { continuation.resume(returning: "") }
    }
  }
}
