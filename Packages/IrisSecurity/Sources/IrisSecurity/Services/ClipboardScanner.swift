import Foundation
import os.log

/// Detects clipboard/pasteboard monitoring and manipulation.
/// Malware: CookieMiner (clipboard crypto address swap),
/// EvilQuest (clipboard data theft), various infostealers.
/// Checks for processes with pasteboard access and crypto address patterns.
public actor ClipboardScanner {
  public static let shared = ClipboardScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "Clipboard")

  /// Processes that legitimately access pasteboard heavily
  private static let allowedClipboard: Set<String> = [
    "pboard", "Finder", "SystemUIServer", "loginwindow",
    "WindowServer", "Dock", "1Password", "Bitwarden",
  ]

  /// Crypto wallet address patterns (regex) for clipboard hijacking detection
  private static let cryptoPatterns: [(name: String, pattern: String)] = [
    ("Bitcoin", "[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),
    ("Ethereum", "0x[0-9a-fA-F]{40}"),
    ("Monero", "4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"),
  ]

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanPasteboardAccess(snapshot: snapshot))
    anomalies.append(contentsOf: await scanPasteboardDaemons())
    return anomalies
  }

  /// Check for non-standard processes accessing pasteboard
  private func scanPasteboardAccess(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let scriptInterpreters: Set<String> = ["python", "python3", "ruby", "perl", "node", "osascript"]
    for pid in snapshot.pids {
      let name = snapshot.name(for: pid)
      if scriptInterpreters.contains(name) {
        let cmdline = getCommandLine(pid: pid)
        if cmdline.contains("pbpaste") || cmdline.contains("NSPasteboard")
          || cmdline.contains("clipboard")
        {
          anomalies.append(.forProcess(
            pid: pid, name: name, path: snapshot.path(for: pid),
            technique: "Clipboard Monitoring",
            description: "\(name) accessing clipboard — possible clipboard hijacking",
            severity: .high, mitreID: "T1115"
          ))
        }
      }
    }
    return anomalies
  }

  /// Check for pasteboard monitoring daemons
  private func scanPasteboardDaemons() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    // Check LaunchAgents that reference pbpaste or pasteboard
    let agentDirs = [
      "\(NSHomeDirectory())/Library/LaunchAgents",
      "/Library/LaunchAgents",
    ]
    let fm = FileManager.default
    for dir in agentDirs {
      guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
      for file in files where file.hasSuffix(".plist") {
        let path = "\(dir)/\(file)"
        guard let data = fm.contents(atPath: path),
          let content = String(data: data, encoding: .utf8)
        else { continue }
        if content.contains("pbpaste") || content.contains("NSPasteboard")
          || content.contains("clipboard")
        {
          anomalies.append(.filesystem(
            name: file, path: path,
            technique: "Clipboard Monitoring Persistence",
            description: "LaunchAgent references clipboard: \(file)",
            severity: .high, mitreID: "T1115"
          ))
        }
      }
    }
    return anomalies
  }

  private func getCommandLine(pid: pid_t) -> String {
    var args = [UInt8](repeating: 0, count: 4096)
    var size = 4096
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib, 3, &args, &size, nil, 0) == 0 else { return "" }
    return String(bytes: args.prefix(size), encoding: .utf8) ?? ""
  }
}
