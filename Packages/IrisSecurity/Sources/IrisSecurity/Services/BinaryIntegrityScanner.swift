import Foundation
import os.log

/// Verifies code signatures and dangerous entitlements on running processes.
/// Uses Security.framework (SecStaticCode) instead of shelling out to codesign.
public actor BinaryIntegrityScanner {
  public static let shared = BinaryIntegrityScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "BinaryIntegrity")

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    var checked = Set<String>()

    for pid in snapshot.pids {
      let path = snapshot.path(for: pid)
      guard !path.isEmpty, !checked.contains(path) else { continue }
      checked.insert(path)
      // Skip Apple system binaries
      if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") { continue }
      if path.hasPrefix("/usr/sbin/") || path.hasPrefix("/usr/bin/") { continue }
      if path.hasPrefix("/sbin/") || path.hasPrefix("/bin/") { continue }

      let info = CodeSignValidator.validate(path: path)
      let name = snapshot.name(for: pid)

      // Unsigned binary
      if !info.isSigned {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Unsigned Binary",
          description: "Running unsigned binary: \(name)",
          severity: .high, mitreID: "T1036"))
      } else if info.isAdHoc {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Ad-hoc Signed",
          description: "Running ad-hoc signed binary: \(name). No verified identity.",
          severity: .medium, mitreID: "T1553.002"))
      }

      // Dangerous entitlements
      let dangerous = CodeSignValidator.dangerousEntitlements(path: path)
      for ent in dangerous {
        let isCritical = ent.contains("task_for_pid") || ent.contains("rootless")
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "Dangerous Entitlement",
          description: "\(name) has entitlement: \(ent)",
          severity: isCritical ? .critical : .high, mitreID: "T1548"))
      }
    }
    return anomalies
  }
}
