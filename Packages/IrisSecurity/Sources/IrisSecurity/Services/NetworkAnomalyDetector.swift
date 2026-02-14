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
    return anomalies
  }

  // MARK: - Helpers (internal for +LsofFallback split)

  func isPrivateIP(_ ip: String) -> Bool {
    ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("172.16.")
      || ip.hasPrefix("172.17.") || ip.hasPrefix("172.18.") || ip.hasPrefix("172.19.")
      || ip.hasPrefix("172.2") || ip.hasPrefix("172.3") || ip.hasPrefix("127.") || ip == "0.0.0.0"
      || ip == "localhost" || ip.hasPrefix("::1") || ip.hasPrefix("fe80:") || ip.hasPrefix("fd")
  }

  func isRawIP(_ addr: String) -> Bool {
    let cleaned = addr.replacingOccurrences(of: ".", with: "")
    if cleaned.allSatisfy(\.isNumber) { return true }
    if addr.contains(":") { return true }
    return false
  }
}

struct ConnectionRecord: Sendable {
  let timestamp: Date
  let pid: pid_t
  let remoteAddress: String
  let remotePort: UInt16
}

/// A detected network anomaly
public struct NetworkAnomaly: Identifiable, Sendable, Codable, Equatable {
  public let id: UUID
  public let type: AnomalyType
  public let processName: String
  public let remoteAddress: String
  public let description: String
  public let severity: AnomalySeverity
  public let connectionCount: Int
  public let averageInterval: Double
  public let timestamp: Date

  public enum AnomalyType: String, Sendable, Codable {
    case beaconing = "C2 Beaconing"
    case rawIPConnection = "Raw IP Connection"
    case suspiciousPort = "Suspicious Port"
    case dnsTunneling = "DNS Tunneling"
    case highVolumeDNS = "High Volume DNS"
  }

  public init(
    id: UUID = UUID(),
    type: AnomalyType,
    processName: String,
    remoteAddress: String,
    description: String,
    severity: AnomalySeverity,
    connectionCount: Int,
    averageInterval: Double,
    timestamp: Date = Date()
  ) {
    self.id = id
    self.type = type
    self.processName = processName
    self.remoteAddress = remoteAddress
    self.description = description
    self.severity = severity
    self.connectionCount = connectionCount
    self.averageInterval = averageInterval
    self.timestamp = timestamp
  }
}
