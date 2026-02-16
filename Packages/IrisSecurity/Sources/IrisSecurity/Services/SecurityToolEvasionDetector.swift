import Foundation
import os.log

/// Detects malware checking for or evading security tools.
/// Many malware families (Banshee, DazzleSpy, BirdMiner) check for
/// LittleSnitch, KnockKnock, Activity Monitor, BlockBlock before executing.
public actor SecurityToolEvasionDetector {
  public static let shared = SecurityToolEvasionDetector()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ToolEvasion")

  /// Security tools that malware commonly checks for
  private static let securityTools: [(name: String, bundleId: String)] = [
    ("Little Snitch", "at.obdev.LittleSnitchConfiguration"),
    ("LuLu", "com.objective-see.Lulu"),
    ("KnockKnock", "com.objective-see.KnockKnock"),
    ("BlockBlock", "com.objective-see.BlockBlock"),
    ("RansomWhere", "com.objective-see.RansomWhere"),
    ("OverSight", "com.objective-see.OverSight"),
    ("TaskExplorer", "com.objective-see.TaskExplorer"),
    ("Wireshark", "org.wireshark.Wireshark"),
    ("Charles", "com.xk72.Charles"),
    ("Proxyman", "com.proxyman.NSProxy"),
  ]

  /// Suspicious command patterns that indicate evasion checks
  private static let evasionPatterns = [
    "pgrep -x \"Activity Monitor\"",
    "launchctl list | grep objective-see",
    "ls /Library/Little Snitch",
    "kextstat | grep little",
    "system_profiler SPInstallHistoryDataType",
    "defaults read com.objective-see",
    "pgrep -x \"Console\"",
  ]

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []

    // Check for processes querying security tool existence
    for pid in snapshot.pids {
      let path = snapshot.path(for: pid)
      guard !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") else { continue }
      let name = snapshot.name(for: pid)
      let cmdline = getCommandLine(pid: pid)

      for tool in Self.securityTools {
        if cmdline.contains(tool.name) || cmdline.contains(tool.bundleId) {
          anomalies.append(.forProcess(
            pid: pid, name: name, path: path,
            technique: "Security Tool Evasion Check",
            description: "\(name) querying for \(tool.name) — evasion behavior",
            severity: .high, mitreID: "T1562.001",
            scannerId: "evasion",
            enumMethod: "sysctl(KERN_PROCARGS2) → command line inspection",
            evidence: [
              "pid=\(pid)",
              "target_tool=\(tool.name)",
              "target_bundle=\(tool.bundleId)",
              "cmdline_match=true",
            ]
          ))
        }
      }

      let vmChecks = ["ioreg -l | grep -i virtual", "sysctl hw.model", "system_profiler SPHardwareDataType"]
      for pattern in vmChecks where cmdline.contains(pattern) {
        anomalies.append(.forProcess(
          pid: pid, name: name, path: path,
          technique: "VM Detection Check",
          description: "\(name) running VM detection: \(pattern)",
          severity: .medium, mitreID: "T1497.001",
          scannerId: "evasion",
          enumMethod: "sysctl(KERN_PROCARGS2) → VM detection pattern match",
          evidence: [
            "pid=\(pid)",
            "pattern=\(pattern)",
            "process=\(name)",
          ]
        ))
      }
    }

    // Check if any security tools have been killed recently
    let runningNames = Set(snapshot.pids.map { snapshot.name(for: $0) })
    for tool in Self.securityTools {
      let installed = FileManager.default.fileExists(
        atPath: "/Applications/\(tool.name).app")
      if installed && !runningNames.contains(tool.name) {
        anomalies.append(.filesystem(
          name: tool.name, path: "/Applications/\(tool.name).app",
          technique: "Security Tool Not Running",
          description: "\(tool.name) installed but not running — may have been killed",
          severity: .medium, mitreID: "T1562.001",
          scannerId: "evasion",
          enumMethod: "FileManager.fileExists + ProcessSnapshot name check",
          evidence: [
            "tool=\(tool.name)",
            "bundle_id=\(tool.bundleId)",
            "installed=true",
            "running=false",
          ]
        ))
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
