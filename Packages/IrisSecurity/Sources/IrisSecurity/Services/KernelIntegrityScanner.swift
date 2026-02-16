import Foundation
import os.log

/// Scans kernel integrity: MACF policies, kext policy DB, trust caches, hypervisor.
/// Uses native sysctl/SQLite APIs instead of shell-outs where possible.
public actor KernelIntegrityScanner {
  public static let shared = KernelIntegrityScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "KernelIntegrity")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanMACFPolicies())
    anomalies.append(contentsOf: scanKextPolicyDB())
    anomalies.append(contentsOf: await scanTrustCaches())
    anomalies.append(contentsOf: scanKernelTextRegion())
    return anomalies
  }

  /// Check MACF policies via sysctl — additional policies beyond Apple's = rootkit
  private func scanMACFPolicies() -> [ProcessAnomaly] {
    // Use native sysctl to read security.mac subtree
    guard let data = SysctlReader.data("security.mac") else { return [] }
    let raw = String(data: data, encoding: .utf8) ?? ""
    let knownPrefixes: Set<String> = [
      "security.mac.amfi", "security.mac.sandbox", "security.mac.vnode_enforce",
      "security.mac.proc_enforce", "security.mac.device_enforce",
      "security.mac.qtn", "security.mac.endpointsecurity",
    ]
    var anomalies: [ProcessAnomaly] = []
    for line in raw.components(separatedBy: "\n") where line.hasPrefix("security.mac.") {
      let key = line.components(separatedBy: ":").first?
        .trimmingCharacters(in: .whitespaces) ?? ""
      if !knownPrefixes.contains(where: { key.hasPrefix($0) }) {
        let base = key.components(separatedBy: ".").prefix(3).joined(separator: ".")
        anomalies.append(.filesystem(
          name: base, path: "",
          technique: "Unknown MACF Policy",
          description: "Non-standard MACF policy: \(key) — possible rootkit",
          severity: .critical, mitreID: "T1014",
          scannerId: "kernel_integrity",
          enumMethod: "sysctl(security.mac) → MACF policy enumeration",
          evidence: [
            "policy_key=\(key)",
            "base_name=\(base)",
          ]))
      }
    }
    return anomalies
  }

  /// Check kext policy DB via native SQLite reader
  private func scanKextPolicyDB() -> [ProcessAnomaly] {
    let dbPath = "/var/db/SystemPolicyConfiguration/KextPolicy"
    guard let db = SQLiteReader(path: dbPath) else { return [] }
    let rows = db.query(
      "SELECT team_id, bundle_id, allowed FROM kext_policy WHERE allowed=1;")
    return rows.compactMap { row in
      guard row.count >= 2, let teamId = row[0], let bundleId = row[1] else { return nil }
      return .filesystem(
        name: bundleId, path: dbPath,
        technique: "Approved Third-Party Kext",
        description: "Kext \(bundleId) (team \(teamId)) approved in policy DB",
        severity: .low, mitreID: "T1547.006",
        scannerId: "kernel_integrity",
        enumMethod: "SQLite query → KextPolicy DB (allowed=1)",
        evidence: [
          "bundle_id=\(bundleId)",
          "team_id=\(teamId)",
          "db_path=\(dbPath)",
        ])
    }
  }

  /// Scan trust caches — still requires kmutil (no native API)
  private func scanTrustCaches() async -> [ProcessAnomaly] {
    let output = await runCommand("/usr/bin/kmutil", args: ["showloaded", "--show", "trust"])
    let cacheType = output.contains("engineering") ? "engineering" : "development"
    if output.contains("engineering") || output.contains("development") {
      return [.filesystem(
        name: "trust-cache", path: "",
        technique: "Non-Production Trust Cache",
        description: "Engineering/development trust cache — allows unsigned code",
        severity: .critical, mitreID: "T1553",
        scannerId: "kernel_integrity",
        enumMethod: "kmutil showloaded --show trust → trust cache inspection",
        evidence: [
          "cache_type=\(cacheType)",
          "allows_unsigned=true",
        ])]
    }
    return []
  }

  /// Check CTRR/KTRR via native sysctl
  private func scanKernelTextRegion() -> [ProcessAnomaly] {
    if SysctlReader.isVirtualMachine {
      return [.filesystem(
        name: "hypervisor", path: "",
        technique: "Hypervisor Detected",
        description: "Running inside hypervisor — CTRR/KTRR may not be enforced",
        severity: .low, mitreID: "T1497.001",
        scannerId: "kernel_integrity",
        enumMethod: "SysctlReader.isVirtualMachine → hw.model check",
        evidence: [
          "is_vm=true",
          "ctrr_enforced=unknown",
        ])]
    }
    return []
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
