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

  /// Dangerous commands that indicate potential backdoor when found in scripts
  private static let dangerousCommands = [
    "curl", "wget", "nc", "ncat", "bash -i", "python -c", "perl -e",
    "ruby -e", "osascript", "open -a Terminal", "launchctl",
  ]

  /// Scan /Library paths for unexpected scripts
  private func scanLibraryScripts() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    for dir in Self.searchDirs {
      guard let enumerator = fm.enumerator(atPath: dir) else { continue }
      var count = 0
      while let file = enumerator.nextObject() as? String {
        count += 1
        if count > 5000 { break }
        let ext = (file as NSString).pathExtension.lowercased()
        guard Self.scriptExtensions.contains(ext) else { continue }
        let fullPath = "\(dir)/\(file)"
        if Self.allowedPaths.contains(where: { fullPath.hasPrefix($0) }) { continue }

        // Deobfuscate script content to detect hidden commands
        var severity: AnomalySeverity = .medium
        var evidence = [
          "file=\((file as NSString).lastPathComponent)",
          "path=\(fullPath)",
          "extension=\(ext)",
        ]
        if let data = fm.contents(atPath: fullPath),
           let content = String(data: data.prefix(8192), encoding: .utf8) {
          let deobResult = ShellDeobfuscator.deobfuscate(content)
          let lower = deobResult.decoded.lowercased()
          let hasDangerous = Self.dangerousCommands.contains { lower.contains($0) }
          if hasDangerous { severity = .high }
          if !deobResult.evidence.isEmpty {
            severity = .critical
            for ev in deobResult.evidence { evidence.append("obfuscation=\(ev.factor)") }
          }
        }

        anomalies.append(.filesystem(
          name: (file as NSString).lastPathComponent, path: fullPath,
          technique: "Script in System Path",
          description: "Script found: \(fullPath)",
          severity: severity, mitreID: "T1059",
          scannerId: "script_backdoor",
          enumMethod: "FileManager.enumerator + ShellDeobfuscator content analysis",
          evidence: evidence
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

        // Deobfuscate content before checking
        let deobResult = ShellDeobfuscator.deobfuscate(content)
        let effective = deobResult.decoded

        if effective.contains("osascript") || effective.contains(".scpt") || effective.contains(".applescript") {
          var evidence = [
            "plist=\(file)",
            "path=\(path)",
            "indicator=osascript or .scpt reference",
          ]
          for ev in deobResult.evidence {
            evidence.append("obfuscation=\(ev.factor)")
          }
          let severity: AnomalySeverity = deobResult.evidence.isEmpty ? .high : .critical
          anomalies.append(.filesystem(
            name: file, path: path,
            technique: "AppleScript Persistence",
            description: "LaunchAgent uses osascript: \(file) — XCSSET/OSAMiner technique\(deobResult.evidence.isEmpty ? "" : " [OBFUSCATED]")",
            severity: severity, mitreID: "T1059.002",
            scannerId: "script_backdoor",
            enumMethod: "plist content scan + ShellDeobfuscator",
            evidence: evidence
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
      guard data.count > 2 && data[0] == 0x23 && data[1] == 0x21 else { continue }
      guard let content = String(data: data.prefix(8192), encoding: .utf8) else { continue }
      let firstLine = content.components(separatedBy: "\n").first ?? ""
      guard firstLine.contains("python") || firstLine.contains("bash") || firstLine.contains("ruby") else { continue }

      var severity: AnomalySeverity = .low
      var evidence = [
        "file=\(file)",
        "path=\(path)",
        "shebang=\(firstLine.prefix(80))",
      ]
      let deobResult = ShellDeobfuscator.deobfuscate(content)
      let lower = deobResult.decoded.lowercased()
      if Self.dangerousCommands.contains(where: { lower.contains($0) }) { severity = .medium }
      if !deobResult.evidence.isEmpty {
        severity = .high
        for ev in deobResult.evidence { evidence.append("obfuscation=\(ev.factor)") }
      }

      anomalies.append(.filesystem(
        name: file, path: path,
        technique: "Script in /usr/local/bin",
        description: "\(file): \(firstLine.prefix(80))\(deobResult.evidence.isEmpty ? "" : " [OBFUSCATED]")",
        severity: severity, mitreID: "T1059",
        scannerId: "script_backdoor",
        enumMethod: "shebang check + ShellDeobfuscator content analysis",
        evidence: evidence
      ))
    }
    return anomalies
  }
}
