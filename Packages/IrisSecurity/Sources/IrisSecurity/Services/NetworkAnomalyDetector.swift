import Foundation
import os.log

/// Detects suspicious network patterns: C2 beaconing, raw IP connections,
/// DNS tunneling indicators, and connections to known-bad infrastructure.
/// Works with data from our network filter extension.
public actor NetworkAnomalyDetector {
  public static let shared = NetworkAnomalyDetector()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "NetworkAnomaly")

  /// Connection history for beaconing detection
  private var connectionHistory: [String: [ConnectionRecord]] = [:]
  private let maxHistoryPerProcess = 200
  private let maxProcesses = 500

  // MARK: - Per-Process Network Baselines

  /// Known destinations per process (learned during baseline period)
  private var baselineDestinations: [String: Set<String>] = [:]
  /// Number of connections per process (only baseline processes with >3 connections)
  private var baselineConnectionCounts: [String: Int] = [:]
  private var baselineLocked = false
  private let learningPeriod: TimeInterval = 3600 // 1 hour
  private var baselineStartTime = Date()

  /// Record a connection event (called from network monitoring)
  public func recordConnection(
    processName: String,
    pid: pid_t,
    remoteAddress: String,
    remotePort: UInt16,
    protocol: String
  ) {
    let key = "\(processName)-\(remoteAddress)"
    var records = connectionHistory[key, default: []]
    records.append(
      ConnectionRecord(
        timestamp: Date(),
        pid: pid,
        remoteAddress: remoteAddress,
        remotePort: remotePort
      ))
    if records.count > maxHistoryPerProcess {
      records.removeFirst(records.count - maxHistoryPerProcess)
    }
    connectionHistory[key] = records

    if connectionHistory.count > maxProcesses {
      // Evict oldest entries
      let sorted = connectionHistory.sorted { a, b in
        (a.value.last?.timestamp ?? .distantPast) < (b.value.last?.timestamp ?? .distantPast)
      }
      for entry in sorted.prefix(connectionHistory.count - maxProcesses) {
        connectionHistory.removeValue(forKey: entry.key)
      }
    }

    // Baseline tracking
    trackBaseline(processName: processName, remoteAddress: remoteAddress)
  }

  /// Track per-process network destinations for baseline anomaly detection
  private func trackBaseline(processName: String, remoteAddress: String) {
    // Auto-lock baseline after learning period
    if !baselineLocked && Date().timeIntervalSince(baselineStartTime) > learningPeriod {
      baselineLocked = true
      logger.info("[NET] Baseline locked: \(self.baselineDestinations.count) processes baselined")
    }

    baselineConnectionCounts[processName, default: 0] += 1

    if !baselineLocked {
      baselineDestinations[processName, default: []].insert(remoteAddress)
    }
  }

  /// Detect connections to new destinations not seen during baseline
  public func detectBaselineAnomalies() -> [NetworkAnomaly] {
    guard baselineLocked else { return [] }
    var anomalies: [NetworkAnomaly] = []

    for (key, records) in connectionHistory {
      let parts = key.split(separator: "-", maxSplits: 1)
      let processName = parts.first.map(String.init) ?? key
      let address = parts.count > 1 ? String(parts[1]) : ""

      // Only check processes with established baselines (>3 connections during learning)
      guard let count = baselineConnectionCounts[processName], count > 3 else { continue }
      guard let known = baselineDestinations[processName] else { continue }

      // New destination not in baseline
      if !known.contains(address) && !records.isEmpty {
        anomalies.append(NetworkAnomaly(
          type: .newDestination,
          processName: processName,
          remoteAddress: address,
          description: "\(processName) connected to new destination \(address) (not in baseline of \(known.count) addresses)",
          severity: .medium,
          connectionCount: records.count,
          averageInterval: 0
        ))
      }
    }
    return anomalies
  }

  /// Lock the baseline manually (for testing or immediate enforcement)
  public func lockBaseline() {
    baselineLocked = true
    logger.info("[NET] Baseline manually locked: \(self.baselineDestinations.count) processes")
  }

  /// Reset baseline and restart learning
  public func resetBaseline() {
    baselineLocked = false
    baselineDestinations.removeAll()
    baselineConnectionCounts.removeAll()
    baselineStartTime = Date()
    logger.info("[NET] Baseline reset — learning started")
  }

  /// Analyze connection patterns for beaconing behavior
  public func detectBeaconing() -> [NetworkAnomaly] {
    var anomalies: [NetworkAnomaly] = []

    for (key, records) in connectionHistory {
      guard records.count >= 5 else { continue }

      // Calculate intervals between connections
      var intervals: [TimeInterval] = []
      for i in 1..<records.count {
        intervals.append(records[i].timestamp.timeIntervalSince(records[i - 1].timestamp))
      }

      guard !intervals.isEmpty else { continue }

      let mean = intervals.reduce(0, +) / Double(intervals.count)
      let variance =
        intervals.map { ($0 - mean) * ($0 - mean) }
        .reduce(0, +) / Double(intervals.count)
      let stddev = sqrt(variance)

      // Beaconing: regular intervals (low coefficient of variation)
      // Real C2 has jitter but still shows regularity
      let cv = mean > 0 ? stddev / mean : Double.infinity

      // CV < 0.3 with at least 5 connections = suspicious beaconing
      if cv < 0.3 && mean > 1.0 && mean < 3600 {
        let parts = key.split(separator: "-", maxSplits: 1)
        let processName = parts.first.map(String.init) ?? key
        let address = parts.count > 1 ? String(parts[1]) : ""

        anomalies.append(
          NetworkAnomaly(
            type: .beaconing,
            processName: processName,
            remoteAddress: address,
            description:
              "Regular connection pattern: \(String(format: "%.1f", mean))s interval (±\(String(format: "%.1f", stddev))s), \(records.count) connections. Possible C2 beaconing.",
            severity: .high,
            connectionCount: records.count,
            averageInterval: mean
          ))
      }
    }

    return anomalies
  }

  /// Known C2/backdoor ports (internal for +LsofFallback)
  let c2Ports: Set<UInt16> = [
    4444, 5555, 8888, 9999, 1337, 31337,
    6666, 6667, 7777, 12345, 54321,
  ]

  /// Scan connections from SecurityStore data (NEFilter extension).
  /// Preferred path: uses structured data already captured by the network filter.
  public func scanConnections(_ connections: [NetworkConnection]) -> [NetworkAnomaly] {
    var anomalies: [NetworkAnomaly] = []

    for conn in connections {
      let ip = conn.remoteAddress
      let port = conn.remotePort
      guard !isPrivateIP(ip), !ip.isEmpty else { continue }

      // Feed into beaconing tracker
      recordConnection(
        processName: conn.processName, pid: conn.processId,
        remoteAddress: ip, remotePort: port,
        protocol: conn.protocol.rawValue)

      // Raw IP connection (no hostname resolved)
      if port > 1024 && conn.remoteHostname == nil && isRawIP(ip) {
        anomalies.append(
          NetworkAnomaly(
            type: .rawIPConnection,
            processName: conn.processName,
            remoteAddress: "\(ip):\(port)",
            description:
              "\(conn.processName) [\(conn.processId)] connected to raw IP \(ip):\(port).",
            severity: .medium,
            connectionCount: 1,
            averageInterval: 0
          ))
      }

      // Known C2 ports
      if c2Ports.contains(port) {
        anomalies.append(
          NetworkAnomaly(
            type: .suspiciousPort,
            processName: conn.processName,
            remoteAddress: "\(ip):\(port)",
            description: "\(conn.processName) [\(conn.processId)] on known C2 port \(port).",
            severity: .high,
            connectionCount: 1,
            averageInterval: 0
          ))
      }
    }

    anomalies.append(contentsOf: detectBeaconing())
    anomalies.append(contentsOf: detectBaselineAnomalies())
    return anomalies
  }

  // MARK: - Helpers (internal for +LsofFallback split)

  func isPrivateIP(_ ip: String) -> Bool {
    if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.")
      || ip == "0.0.0.0" || ip == "localhost"
      || ip.hasPrefix("::1") || ip.hasPrefix("fe80:") || ip.hasPrefix("fd") {
      return true
    }
    // RFC 1918: 172.16.0.0 - 172.31.255.255 (second octet 16-31)
    if ip.hasPrefix("172.") {
      let parts = ip.split(separator: ".", maxSplits: 2)
      if parts.count >= 2, let octet2 = Int(parts[1]) {
        return octet2 >= 16 && octet2 <= 31
      }
    }
    return false
  }

  func isRawIP(_ addr: String) -> Bool {
    let cleaned = addr.replacingOccurrences(of: ".", with: "")
    if cleaned.allSatisfy(\.isNumber) { return true }
    if addr.contains(":") { return true }
    return false
  }
}
