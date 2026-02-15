import Foundation
import os.log

/// Scans for script-based backdoors in /Library and system paths.
/// Shell, Python, Ruby, AppleScript scripts outside expected locations
/// indicate malware persistence. Covers: script_backdoors.sh, osascript_persistence.sh.
/// Malware: XCSSET, OSAMiner, Banshee, RustBucket abuse AppleScript.
public actor ScriptBackdoorScanner {
  public static let shared = ScriptBackdoorScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ScriptBackdoor")

  /// Directories to scan for unexpected scripts
  private static let searchDirs = [
    "/Library/Scripts", "/Library/Application Support",
    "/usr/local/bin", "/usr/local/sbin",
  ]

  /// Script extensions to flag
  private static let scriptExtensions: Set<String> = [
    "sh", "py", "rb", "pl", "scpt", "applescript", "command",
  ]

  /// Known-good paths to skip
  private static let allowedPaths: Set<String> = [
    "/Library/Application Support/com.apple.",
    "/Library/Developer/",
    "/Library/Scripts/Folder Actions/",
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanLibraryScripts())
    anomalies.append(contentsOf: scanOSAScriptPersistence())
    anomalies.append(contentsOf: scanUserLocalBin())
    return anomalies
  }

  /// Scan /Library paths for unexpected scripts
  private func scanLibraryScripts() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    for dir in Self.searchDirs {
      guard let enumerator = fm.enumerator(atPath: dir) else { continue }
      var count = 0
      while let file = enumerator.nextObject() as? String {
        count += 1
        if count > 5000 { break } // Limit scan depth
        let ext = (file as NSString).pathExtension.lowercased()
        guard Self.scriptExtensions.contains(ext) else { continue }
        let fullPath = "\(dir)/\(file)"
        if Self.allowedPaths.contains(where: { fullPath.hasPrefix($0) }) { continue }
        anomalies.append(.filesystem(
          name: (file as NSString).lastPathComponent, path: fullPath,
          technique: "Script in System Path",
          description: "Script found: \(fullPath)",
          severity: .medium, mitreID: "T1059"
        ))
      }
    }
    return anomalies
  }

  /// Detect AppleScript/osascript persistence mechanisms
  private func scanOSAScriptPersistence() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    // Check for compiled AppleScript in LaunchAgents
    let agentDirs = [
      "\(NSHomeDirectory())/Library/LaunchAgents",
      "/Library/LaunchAgents", "/Library/LaunchDaemons",
    ]
    for dir in agentDirs {
      guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
      for file in files where file.hasSuffix(".plist") {
        let path = "\(dir)/\(file)"
        guard let data = fm.contents(atPath: path),
          let content = String(data: data, encoding: .utf8)
        else { continue }
        if content.contains("osascript") || content.contains(".scpt") || content.contains(".applescript") {
          anomalies.append(.filesystem(
            name: file, path: path,
            technique: "AppleScript Persistence",
            description: "LaunchAgent uses osascript: \(file) — XCSSET/OSAMiner technique",
            severity: .high, mitreID: "T1059.002"
          ))
        }
      }
    }
    return anomalies
  }

  /// Check /usr/local/bin for suspicious unsigned scripts
  private func scanUserLocalBin() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    let dir = "/usr/local/bin"
    guard let files = try? fm.contentsOfDirectory(atPath: dir) else { return [] }
    for file in files {
      let path = "\(dir)/\(file)"
      guard let data = fm.contents(atPath: path) else { continue }
      // Check if it's a script (starts with shebang)
      if data.count > 2 && data[0] == 0x23 && data[1] == 0x21 {
        // It's a script with shebang
        guard let firstLine = String(data: data.prefix(200), encoding: .utf8)?
          .components(separatedBy: "\n").first
        else { continue }
        if firstLine.contains("python") || firstLine.contains("bash") || firstLine.contains("ruby") {
          anomalies.append(.filesystem(
            name: file, path: path,
            technique: "Script in /usr/local/bin",
            description: "\(file): \(firstLine.prefix(80))",
            severity: .low, mitreID: "T1059"
          ))
        }
      }
    }
    return anomalies
  }
}
