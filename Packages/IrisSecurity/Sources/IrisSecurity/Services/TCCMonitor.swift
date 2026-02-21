import Foundation
import os.log

/// Monitors TCC.db for unauthorized permission grants.
/// APTs modify TCC.db to silently grant themselves Full Disk Access,
/// Screen Recording, Accessibility, etc. This monitor detects those changes.
/// REQUIRES: Full Disk Access for the system-level TCC.db.
public actor TCCMonitor {
  public static let shared = TCCMonitor()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "TCCMonitor")

  /// Known TCC database locations
  private let tccPaths: [String] = {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return [
      "\(home)/Library/Application Support/com.apple.TCC/TCC.db",
      "/Library/Application Support/com.apple.TCC/TCC.db",
    ]
  }()

  /// Baseline hashes for TCC databases
  private var baselineHashes: [String: String] = [:]
  private var baselineEntries: [String: [TCCEntry]] = [:]

  /// High-risk services that APTs target
  private let highRiskServices: Set<String> = [
    "kTCCServiceSystemPolicyAllFiles",  // Full Disk Access
    "kTCCServiceScreenCapture",  // Screen Recording
    "kTCCServiceAccessibility",  // Accessibility (keystroke injection)
    "kTCCServiceListenEvent",  // Input Monitoring
    "kTCCServicePostEvent",  // Keystroke injection
    "kTCCServiceAppleEvents",  // Automation (script injection)
  ]

  /// Check if Full Disk Access is available (TCC.db readable).
  /// FileManager.fileExists returns false for SIP-protected paths even with FDA.
  /// try? Data(contentsOf:) is the correct check.
  public nonisolated func hasFullDiskAccess() -> Bool {
    let systemPath = "/Library/Application Support/com.apple.TCC/TCC.db"
    return (try? Data(contentsOf: URL(fileURLWithPath: systemPath), options: .mappedIfSafe)) != nil
  }

  /// Take a baseline snapshot of all TCC databases
  public func takeBaseline() async {
    if !hasFullDiskAccess() {
      logger.error(
        "TCCMonitor: Full Disk Access required. Grant FDA in System Settings > Privacy & Security.")
    }
    for path in tccPaths {
      let hash = hashFile(path)
      guard hash != nil else { continue }
      baselineHashes[path] = hash
      let entries = await readTCCEntries(path: path)
      baselineEntries[path] = entries
      logger.info("TCC baseline: \(path) — \(entries.count) entries")
    }
  }

  /// Check if TCC databases have been modified since baseline
  public func checkIntegrity() async -> [TCCChange] {
    var changes: [TCCChange] = []

    for path in tccPaths {
      let currentHash = hashFile(path)
      guard let current = currentHash else { continue }

      if let baseline = baselineHashes[path], baseline != current {
        // Database changed — diff entries
        let currentEntries = await readTCCEntries(path: path)
        let previousEntries = baselineEntries[path] ?? []

        // Index previous entries for O(1) lookup
        let previousByKey = Dictionary(
          previousEntries.map { ("\($0.service)|\($0.client)", $0) },
          uniquingKeysWith: { first, _ in first }
        )

        for entry in currentEntries {
          let key = "\(entry.service)|\(entry.client)"
          let isHighRisk = highRiskServices.contains(entry.service)

          if let previous = previousByKey[key] {
            // Detect auth_value changes (deny→allow is high-risk)
            if !previous.isAllowed && entry.isAllowed {
              changes.append(
                TCCChange(
                  path: path, entry: entry, changeType: .modified,
                  severity: isHighRisk ? .critical : .high
                ))
            }
          } else if entry.isAllowed {
            // New grant not in baseline
            changes.append(
              TCCChange(
                path: path, entry: entry, changeType: .newGrant,
                severity: isHighRisk ? .critical : .medium
              ))
          }
        }
      }
    }

    return changes
  }

  /// Read all TCC entries and flag suspicious ones.
  /// Returns empty if Full Disk Access is not granted.
  public func scan() async -> [TCCEntry] {
    var allEntries: [TCCEntry] = []
    for path in tccPaths {
      let entries = await readTCCEntries(path: path)
      allEntries.append(contentsOf: entries)
    }
    if allEntries.isEmpty {
      logger.warning("TCCMonitor: No entries read. Ensure Full Disk Access is granted.")
    }
    return allEntries
  }

  /// Read TCC entries via native SQLite C API (no shell-out).
  private func readTCCEntries(path: String) async -> [TCCEntry] {
    guard let db = SQLiteReader(path: path) else { return [] }
    let sql = """
      SELECT service, client, client_type, auth_value, auth_reason,
             indirect_object_identifier, last_modified, flags, LENGTH(csreq), pid
      FROM access;
      """
    let rows = db.query(sql)

    return rows.compactMap { row in
      guard row.count >= 5 else { return nil }

      let service = row[0] ?? ""
      let client = row[1] ?? ""
      let clientType = Int(row[2] ?? "") ?? 0
      let authValue = Int(row[3] ?? "") ?? 0
      let authReason = Int(row[4] ?? "") ?? 0
      let indirect = row.count > 5 && row[5] != nil && !row[5]!.isEmpty
      let lastMod: Date? = row.count > 6 ? dateFromTimestamp(row[6] ?? "") : nil
      let flags = row.count > 7 ? Int(row[7] ?? "") ?? 0 : 0
      let hasCSReq = row.count > 8 && (Int(row[8] ?? "") ?? 0) > 0
      let grantPid: Int? = row.count > 9 ? Int(row[9] ?? "") : nil

      var suspicious = false
      var reasons: [String] = []

      if highRiskServices.contains(service) && authValue == 2 {
        if clientType == 0 {
          let appPath = findAppPath(bundleID: client)
          if appPath == nil {
            suspicious = true
            reasons.append("High-risk permission granted to non-existent app: \(client)")
          }
        }
        if authReason != 1 && authReason != 2 {
          suspicious = true
          reasons.append("Permission via non-user mechanism (reason: \(authReason))")
        }
        // No code signing requirement — any binary with this bundle ID inherits the grant
        if !hasCSReq {
          suspicious = true
          reasons.append("No code signing requirement — grant not tied to specific binary")
        }
      }

      return TCCEntry(
        service: service,
        client: client,
        clientType: clientType,
        authValue: authValue,
        authReason: authReason,
        indirect: indirect,
        lastModified: lastMod,
        flags: flags,
        hasCodeRequirement: hasCSReq,
        grantPid: grantPid,
        isSuspicious: suspicious,
        suspicionReason: reasons.isEmpty ? nil : reasons.joined(separator: "; ")
      )
    }
  }

  private func hashFile(_ path: String) -> String? {
    RustBatchOps.sha256(path: path)
  }

  private func dateFromTimestamp(_ str: String) -> Date? {
    guard let epoch = Double(str) else { return nil }
    // TCC.db last_modified is Unix epoch (seconds since 1970-01-01)
    return Date(timeIntervalSince1970: epoch)
  }

  private func findAppPath(bundleID: String) -> String? {
    // Check common locations
    let searchDirs = ["/Applications", "/System/Applications"]
    let fm = FileManager.default
    for dir in searchDirs {
      guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }
      for app in apps where app.hasSuffix(".app") {
        let plistPath = "\(dir)/\(app)/Contents/Info.plist"
        if let plist = NSDictionary(contentsOfFile: plistPath),
          let bid = plist["CFBundleIdentifier"] as? String,
          bid == bundleID
        {
          return "\(dir)/\(app)"
        }
      }
    }
    return nil
  }

}

/// A detected change to the TCC database
public struct TCCChange: Identifiable, Sendable, Codable, Equatable {
  public let id: UUID
  public let path: String
  public let entry: TCCEntry
  public let changeType: ChangeType
  public let severity: AnomalySeverity
  public let timestamp: Date

  public enum ChangeType: String, Sendable, Codable {
    case newGrant = "New Permission Grant"
    case revoked = "Permission Revoked"
    case modified = "Permission Modified"
  }

  public init(
    id: UUID = UUID(),
    path: String,
    entry: TCCEntry,
    changeType: ChangeType,
    severity: AnomalySeverity,
    timestamp: Date = Date()
  ) {
    self.id = id
    self.path = path
    self.entry = entry
    self.changeType = changeType
    self.severity = severity
    self.timestamp = timestamp
  }
}
