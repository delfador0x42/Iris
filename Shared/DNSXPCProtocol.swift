import Foundation

/// A captured DNS query record for XPC transport.
public struct DNSQueryRecord: Codable, Identifiable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let timestamp: Date
    public let domain: String
    public let recordType: String
    public let processName: String?
    public let responseCode: String?
    public let answers: [String]
    public let ttl: UInt32?
    public let latencyMs: Double?
    public let isBlocked: Bool
    public let isEncrypted: Bool
    /// Monotonically increasing sequence number for delta XPC protocol
    public var sequenceNumber: UInt64

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        domain: String,
        recordType: String,
        processName: String? = nil,
        responseCode: String? = nil,
        answers: [String] = [],
        ttl: UInt32? = nil,
        latencyMs: Double? = nil,
        isBlocked: Bool = false,
        isEncrypted: Bool = true,
        sequenceNumber: UInt64 = 0
    ) {
        self.id = id
        self.timestamp = timestamp
        self.domain = domain
        self.recordType = recordType
        self.processName = processName
        self.responseCode = responseCode
        self.answers = answers
        self.ttl = ttl
        self.latencyMs = latencyMs
        self.isBlocked = isBlocked
        self.isEncrypted = isEncrypted
        self.sequenceNumber = sequenceNumber
    }
}
