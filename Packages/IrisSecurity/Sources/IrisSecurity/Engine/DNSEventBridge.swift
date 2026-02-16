import Foundation
import os.log

/// Bridges DNS queries from DNSStore into the DNSTunnelingDetector
/// and emits SecurityEvents for dns_query rule matching.
actor DNSEventBridge {
  static let shared = DNSEventBridge()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "DNSBridge")

  /// IDs of queries already forwarded
  private var seenIds: Set<UUID> = []
  private var isRunning = false
  private var pollTask: Task<Void, Never>?

  func start() {
    guard !isRunning else { return }
    isRunning = true
    pollTask = Task { await pollLoop() }
    logger.info("[DNS-BRIDGE] Started")
  }

  func stop() {
    isRunning = false
    pollTask?.cancel()
    pollTask = nil
  }

  private func pollLoop() async {
    while isRunning && !Task.isCancelled {
      await pollQueries()
      try? await Task.sleep(nanoseconds: 2_000_000_000)
    }
  }

  private func pollQueries() async {
    let queries = await MainActor.run { DNSStore.shared.queries }
    var newEvents: [SecurityEvent] = []

    for query in queries {
      guard !seenIds.contains(query.id) else { continue }
      seenIds.insert(query.id)

      // Feed to DNSTunnelingDetector for entropy/DGA analysis
      await DNSTunnelingDetector.shared.recordQuery(
        domain: query.domain,
        recordType: query.recordType
      )

      // Also emit as SecurityEvent for dns_query rules
      var fields: [String: String] = [
        "domain": query.domain,
        "record_type": query.recordType,
      ]
      if !query.answers.isEmpty {
        fields["answers"] = query.answers.joined(separator: ",")
      }
      if query.isBlocked {
        fields["blocked"] = "true"
      }

      let processName = query.processName ?? "unknown"
      newEvents.append(SecurityEvent(
        source: .dns,
        timestamp: query.timestamp,
        eventType: "dns_query",
        processName: processName,
        processPath: "",
        pid: 0,
        fields: fields
      ))
    }

    if !newEvents.isEmpty {
      await SecurityEventBus.shared.ingest(newEvents)
      if seenIds.count > 100_000 {
        let keep = seenIds.suffix(80_000)
        seenIds = Set(keep)
      }
    }
  }
}
