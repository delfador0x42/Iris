import Foundation
import os.log

/// Checks download provenance via quarantine extended attributes.
/// Files downloaded from the internet should have com.apple.quarantine xattr.
/// Missing quarantine = bypassed Gatekeeper. Covers: downloads_provenance.sh.
public actor DownloadProvenanceScanner {
  public static let shared = DownloadProvenanceScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "DownloadProvenance")

  /// Directories to check for downloaded files
  private static let downloadDirs = [
    "Downloads", "Desktop", "Documents",
  ]

  /// Extensions that should have quarantine if downloaded
  private static let executableExts: Set<String> = [
    "app", "dmg", "pkg", "command", "sh", "py", "rb",
    "dylib", "bundle", "kext", "plugin", "action",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let home = NSHomeDirectory()
    for dir in Self.downloadDirs {
      anomalies.append(contentsOf: await scanDirectory("\(home)/\(dir)"))
    }
    // Also check /tmp for staged downloads
    anomalies.append(contentsOf: await scanDirectory("/tmp"))
    return anomalies
  }

  /// Scan directory for executable files missing quarantine
  private func scanDirectory(_ dir: String) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { return [] }

    for entry in entries {
      let ext = (entry as NSString).pathExtension.lowercased()
      guard Self.executableExts.contains(ext) else { continue }
      let path = "\(dir)/\(entry)"

      // Check quarantine xattr
      let xattrOutput = await runCommand(
        "/usr/bin/xattr", args: ["-p", "com.apple.quarantine", path])
      if xattrOutput.isEmpty || xattrOutput.contains("No such xattr") {
        // Executable without quarantine — suspicious if in user-facing directory
        let attrs = try? fm.attributesOfItem(atPath: path)
        let modDate = attrs?[.modificationDate] as? Date ?? Date.distantPast
        let age = Date().timeIntervalSince(modDate)
        // Only flag recent files (last 30 days)
        guard age < 30 * 86400 else { continue }
        anomalies.append(.filesystem(
          name: entry, path: path,
          technique: "Missing Quarantine Attribute",
          description: "\(entry) — executable without quarantine (Gatekeeper bypassed)",
          severity: .medium, mitreID: "T1553.001"
        ))
      } else if xattrOutput.contains(";") {
        // Parse quarantine attribute for origin URL
        let parts = xattrOutput.components(separatedBy: ";")
        if parts.count >= 3 {
          let origin = parts.last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
          // Check if origin is suspicious
          let suspiciousOrigins = ["pastebin.com", "raw.githubusercontent.com", "ngrok.io"]
          for suspicious in suspiciousOrigins where origin.contains(suspicious) {
            anomalies.append(.filesystem(
              name: entry, path: path,
              technique: "Suspicious Download Origin",
              description: "\(entry) downloaded from: \(origin.prefix(80))",
              severity: .high, mitreID: "T1204"
            ))
          }
        }
      }
    }
    return anomalies
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
