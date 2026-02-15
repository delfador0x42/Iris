import Foundation
import os.log

/// Per-machine allowlist for suppressing known false positives.
/// Stored as JSON at ~/Library/Application Support/Iris/allowlist.json.
public actor AllowlistStore {
  public static let shared = AllowlistStore()

  private let logger = Logger(subsystem: "com.wudan.iris", category: "Allowlist")
  private var entries: [AllowlistEntry] = []
  private var loaded = false

  public struct AllowlistEntry: Codable, Sendable, Identifiable {
    public var id: UUID
    public let scannerId: String?
    public let processName: String?
    public let technique: String?
    public let reason: String
    public let addedAt: Date
  }

  /// Check if an anomaly should be suppressed.
  public func isAllowed(_ anomaly: ProcessAnomaly, scannerId: String) -> Bool {
    if !loaded { loadSync() }
    return entries.contains { entry in
      (entry.scannerId == nil || entry.scannerId == scannerId)
        && (entry.processName == nil || entry.processName == anomaly.processName)
        && (entry.technique == nil || entry.technique == anomaly.technique)
    }
  }

  /// Filter anomalies through the allowlist.
  public func filter(
    _ anomalies: [ProcessAnomaly], scannerId: String
  ) -> [ProcessAnomaly] {
    if !loaded { loadSync() }
    return anomalies.filter { !isAllowed($0, scannerId: scannerId) }
  }

  /// Add a new allowlist entry and persist.
  public func add(
    scannerId: String?, processName: String?,
    technique: String?, reason: String
  ) {
    let entry = AllowlistEntry(
      id: UUID(), scannerId: scannerId, processName: processName,
      technique: technique, reason: reason, addedAt: Date())
    entries.append(entry)
    save()
    logger.info("Added allowlist: \(reason)")
  }

  /// Remove an entry by ID.
  public func remove(id: UUID) {
    entries.removeAll { $0.id == id }
    save()
  }

  /// All current entries.
  public var allEntries: [AllowlistEntry] { entries }

  // MARK: - Persistence

  private var fileURL: URL {
    let support = FileManager.default.urls(
      for: .applicationSupportDirectory, in: .userDomainMask
    ).first!.appendingPathComponent("Iris")
    try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
    return support.appendingPathComponent("allowlist.json")
  }

  private func loadSync() {
    loaded = true
    guard let data = try? Data(contentsOf: fileURL),
          let decoded = try? JSONDecoder().decode([AllowlistEntry].self, from: data)
    else { return }
    entries = decoded
  }

  private func save() {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    guard let data = try? encoder.encode(entries) else { return }
    try? data.write(to: fileURL, options: .atomic)
  }
}
