import Foundation

/// A captured network flow — HTTP, HTTPS, generic TCP, or UDP.
public struct ProxyCapturedFlow: Codable, Identifiable, Sendable, Equatable, Hashable {
  public let id: UUID
  public let timestamp: Date
  public let flowType: ProxyFlowType
  public let host: String
  public let port: Int
  public let request: ProxyCapturedRequest?
  public var response: ProxyCapturedResponse?
  public var error: String?
  public let processName: String?
  public let processId: Int?
  public var bytesOut: Int64
  public var bytesIn: Int64
  public var endTimestamp: Date?
  /// Monotonically increasing sequence number for delta XPC protocol.
  public var sequenceNumber: UInt64

  public init(
    id: UUID = UUID(),
    timestamp: Date = Date(),
    flowType: ProxyFlowType,
    host: String,
    port: Int,
    request: ProxyCapturedRequest? = nil,
    response: ProxyCapturedResponse? = nil,
    error: String? = nil,
    processName: String? = nil,
    processId: Int? = nil,
    bytesOut: Int64 = 0,
    bytesIn: Int64 = 0,
    endTimestamp: Date? = nil,
    sequenceNumber: UInt64 = 0
  ) {
    self.id = id
    self.timestamp = timestamp
    self.flowType = flowType
    self.host = host
    self.port = port
    self.request = request
    self.response = response
    self.error = error
    self.processName = processName
    self.processId = processId
    self.bytesOut = bytesOut
    self.bytesIn = bytesIn
    self.endTimestamp = endTimestamp
    self.sequenceNumber = sequenceNumber
  }

  public var isComplete: Bool {
    if request != nil {
      return response != nil || error != nil
    }
    return endTimestamp != nil || error != nil
  }

  public var duration: TimeInterval? {
    if let d = response?.duration { return d }
    if let end = endTimestamp { return end.timeIntervalSince(timestamp) }
    return nil
  }

  public var isHTTP: Bool { flowType == .http || flowType == .https }
}
