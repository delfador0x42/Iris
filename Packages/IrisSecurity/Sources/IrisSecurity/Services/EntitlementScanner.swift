import Foundation
import os.log

/// Audits running processes for dangerous entitlements.
/// Flags: get-task-allow, task_for_pid, com.apple.private.*,
/// com.apple.security.cs.disable-library-validation.
/// Uses CodeSignValidator — no shell-outs.
public actor EntitlementScanner {
  public static let shared = EntitlementScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "Entitlements")

  private static let dangerousKeys: [(key: String, desc: String, severity: AnomalySeverity)] = [
    ("com.apple.security.get-task-allow", "Allows debugging/injection", .high),
    ("task_for_pid-allow", "Task port access to any process", .critical),
    ("com.apple.security.cs.disable-library-validation", "Disables dylib validation", .high),
    ("com.apple.security.cs.allow-unsigned-executable-memory", "Allows unsigned RWX", .medium),
    ("com.apple.security.cs.allow-dyld-environment-variables", "Allows DYLD injection", .high),
    ("com.apple.security.cs.debugger", "System debugger entitlement", .critical),
    ("com.apple.private.security.no-sandbox", "No sandbox", .high),
  ]

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    for pid in snapshot.pids {
      let path = snapshot.path(for: pid)
      guard !path.isEmpty,
            !path.hasPrefix("/System/"),
            !path.hasPrefix("/usr/libexec/")
      else { continue }
      let name = snapshot.name(for: pid)
      let info = CodeSignValidator.validate(path: path)
      guard let ents = info.entitlements, !ents.isEmpty else { continue }
      for (key, desc, severity) in Self.dangerousKeys {
        let hasKey: Bool
        if key.hasSuffix("*") {
          let prefix = String(key.dropLast())
          hasKey = ents.keys.contains { $0.hasPrefix(prefix) }
        } else {
          hasKey = (ents[key] as? Bool) == true
        }
        guard hasKey else { continue }
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Dangerous Entitlement",
          description: "\(name) has \(key): \(desc)",
          severity: severity, mitreID: "T1068",
          scannerId: "entitlement",
          enumMethod: "SecCodeCopySigningInformation → entitlements dict",
          evidence: [
            "entitlement: \(key)",
            "effect: \(desc)",
            "binary: \(path)",
          ]))
      }
    }
    return anomalies
  }
}
