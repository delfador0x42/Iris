import Foundation
import os.log

/// Bridges network connections from SecurityStore into the SecurityEvent pipeline.
/// Converts NetworkConnection objects to SecurityEvent with eventType "connection",
/// enabling C2, exfiltration, and APT detection rules to fire on network data.
actor NetworkEventBridge {
  static let shared = NetworkEventBridge()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "NetBridge")

  /// IDs of connections already forwarded — prevents duplicate events
  private var seenIds: Set<UUID> = []
  private var isRunning = false
  private var pollTask: Task<Void, Never>?

  /// Start polling SecurityStore for new connections
  func start() {
    guard !isRunning else { return }
    isRunning = true
    pollTask = Task { await pollLoop() }
    logger.info("[NET-BRIDGE] Started")
  }

  func stop() {
    isRunning = false
    pollTask?.cancel()
    pollTask = nil
  }

  private func pollLoop() async {
    while isRunning && !Task.isCancelled {
      await pollConnections()
      try? await Task.sleep(nanoseconds: 2_000_000_000) // 2s matches SecurityStore refresh
    }
  }

  private func pollConnections() async {
    let connections = await MainActor.run { SecurityStore.shared.connections }
    var newEvents: [SecurityEvent] = []

    for conn in connections {
      guard !seenIds.contains(conn.id) else { continue }
      seenIds.insert(conn.id)

      var fields: [String: String] = [
        "remote_address": conn.remoteAddress,
        "remote_port": "\(conn.remotePort)",
        "local_address": conn.localAddress,
        "local_port": "\(conn.localPort)",
        "protocol": conn.protocol.rawValue,
        "state": conn.state.rawValue,
      ]
      if let hostname = conn.remoteHostname {
        fields["hostname"] = hostname
        fields["remote_host"] = hostname
      } else {
        fields["remote_host"] = conn.remoteAddress
      }
      if let country = conn.remoteCountryCode {
        fields["remote_country"] = country
      }

      let isApple = conn.signingId?.hasPrefix("com.apple.") ?? false
      newEvents.append(SecurityEvent(
        source: .network,
        timestamp: conn.timestamp,
        eventType: "connection",
        processName: conn.processName,
        processPath: conn.processPath,
        pid: conn.processId,
        signingId: conn.signingId,
        isAppleSigned: isApple,
        fields: fields
      ))
    }

    if !newEvents.isEmpty {
      await SecurityEventBus.shared.ingest(newEvents)
      // Prune seen set to avoid unbounded growth.
      // Set is unordered — suffix() gives arbitrary entries, not "most recent".
      // Instead, reset to just the current live connections.
      if seenIds.count > 50_000 {
        seenIds = Set(connections.map(\.id))
      }
    }
  }
}
