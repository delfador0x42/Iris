import Foundation
import os.log

/// Checks download provenance via quarantine extended attributes.
/// Files downloaded from the internet should have com.apple.quarantine xattr.
/// Missing quarantine = bypassed Gatekeeper. Uses native getxattr() C API.
public actor DownloadProvenanceScanner {
  public static let shared = DownloadProvenanceScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "DownloadProvenance")

  private static let downloadDirs = ["Downloads", "Desktop", "Documents"]

  private static let executableExts: Set<String> = [
    "app", "dmg", "pkg", "command", "sh", "py", "rb",
    "dylib", "bundle", "kext", "plugin", "action",
  ]

  public func scan() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let home = NSHomeDirectory()
    for dir in Self.downloadDirs {
      anomalies.append(contentsOf: scanDirectory("\(home)/\(dir)"))
    }
    anomalies.append(contentsOf: scanDirectory("/tmp"))
    return anomalies
  }

  private func scanDirectory(_ dir: String) -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { return [] }

    for entry in entries {
      let ext = (entry as NSString).pathExtension.lowercased()
      guard Self.executableExts.contains(ext) else { continue }
      let path = "\(dir)/\(entry)"

      let quarantine = readXattr(path: path, name: "com.apple.quarantine")
      if quarantine == nil {
        let attrs = try? fm.attributesOfItem(atPath: path)
        let modDate = attrs?[.modificationDate] as? Date ?? Date.distantPast
        let age = Date().timeIntervalSince(modDate)
        guard age < 30 * 86400 else { continue }
        anomalies.append(.filesystem(
          name: entry, path: path,
          technique: "Missing Quarantine Attribute",
          description: "\(entry) — executable without quarantine (Gatekeeper bypassed)",
          severity: .medium, mitreID: "T1553.001",
          scannerId: "download_provenance",
          enumMethod: "getxattr(com.apple.quarantine) → missing xattr check",
          evidence: [
            "file=\(entry)",
            "path=\(path)",
            "extension=\(ext)",
            "age_days=\(Int(age / 86400))",
          ]
        ))
      } else if let value = quarantine, value.contains(";") {
        let parts = value.components(separatedBy: ";")
        if parts.count >= 3 {
          let origin = parts.last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
          let suspiciousOrigins = ["pastebin.com", "raw.githubusercontent.com", "ngrok.io"]
          for suspicious in suspiciousOrigins where origin.contains(suspicious) {
            anomalies.append(.filesystem(
              name: entry, path: path,
              technique: "Suspicious Download Origin",
              description: "\(entry) downloaded from: \(origin.prefix(80))",
              severity: .high, mitreID: "T1204",
              scannerId: "download_provenance",
              enumMethod: "getxattr(com.apple.quarantine) → origin domain analysis",
              evidence: [
                "file=\(entry)",
                "path=\(path)",
                "origin=\(origin)",
                "matched_domain=\(suspicious)",
              ]
            ))
          }
        }
      }
    }
    return anomalies
  }

  /// Read extended attribute via native getxattr() C API.
  private func readXattr(path: String, name: String) -> String? {
    let size = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
    guard size > 0 else { return nil }
    var buffer = [UInt8](repeating: 0, count: size)
    let read = getxattr(path, name, &buffer, size, 0, XATTR_NOFOLLOW)
    guard read > 0 else { return nil }
    return String(bytes: buffer.prefix(read), encoding: .utf8)
  }
}
