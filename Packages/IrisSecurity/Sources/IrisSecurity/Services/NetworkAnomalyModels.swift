import Foundation

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
    case newDestination = "New Destination"
    case dgaDomain = "DGA Domain"
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
