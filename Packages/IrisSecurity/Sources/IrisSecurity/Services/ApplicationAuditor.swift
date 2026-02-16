import Foundation
import os.log

/// Audits installed applications for signing issues and suspicious apps.
/// Uses Security.framework (SecStaticCode) instead of shelling out to codesign.
public actor ApplicationAuditor {
  public static let shared = ApplicationAuditor()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "AppAudit")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let dirs = ["/Applications", "\(NSHomeDirectory())/Applications"]
    for dir in dirs {
      anomalies.append(contentsOf: scanAppsIn(directory: dir))
    }
    return anomalies
  }

  private func scanAppsIn(directory: String) -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(atPath: directory) else { return [] }

    for entry in entries where entry.hasSuffix(".app") {
      let appPath = "\(directory)/\(entry)"
      let info = CodeSignValidator.validate(path: appPath)

      if !info.isSigned || !info.isValidSignature {
        anomalies.append(.filesystem(
          name: entry, path: appPath,
          technique: "Unsigned Application",
          description: "\(entry) has invalid or missing code signature",
          severity: .high, mitreID: "T1036",
          scannerId: "app_audit",
          enumMethod: "SecStaticCodeCreateWithPath → code signature validation",
          evidence: [
            "app=\(entry)",
            "is_signed=\(info.isSigned)",
            "valid_signature=\(info.isValidSignature)",
          ]))
      } else if info.isAdHoc {
        anomalies.append(.filesystem(
          name: entry, path: appPath,
          technique: "Ad-hoc Signed Application",
          description: "\(entry) is ad-hoc signed (no developer identity)",
          severity: .medium, mitreID: "T1036",
          scannerId: "app_audit",
          enumMethod: "SecStaticCodeCreateWithPath → ad-hoc signature check",
          evidence: [
            "app=\(entry)",
            "is_adhoc=true",
            "developer_identity=none",
          ]))
      }

      // Check for apps in ~/Applications that masquerade as system apps
      if directory.contains("/Users/") {
        if fm.fileExists(atPath: "/Applications/\(entry)") {
          anomalies.append(.filesystem(
            name: entry, path: appPath,
            technique: "Duplicate Application",
            description: "\(entry) in both /Applications and ~/Applications — possible masquerade",
            severity: .high, mitreID: "T1036.005",
            scannerId: "app_audit",
            enumMethod: "FileManager.fileExists → duplicate app path check",
            evidence: [
              "app=\(entry)",
              "user_path=\(appPath)",
              "system_path=/Applications/\(entry)",
            ]))
        }
      }
    }
    return anomalies
  }
}
