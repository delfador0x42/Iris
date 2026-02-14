import Foundation

/// XPC protocol for communication between the main app and the DNS Proxy Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol DNSXPCProtocol {
    func getStatus(reply: @escaping ([String: Any]) -> Void)
    func getQueries(limit: Int, reply: @escaping ([Data]) -> Void)
    /// Delta fetch: returns only queries with sequenceNumber > sinceSeq.
    /// Reply includes the current max sequence number and the new queries.
    func getQueriesSince(_ sinceSeq: UInt64, limit: Int, reply: @escaping (UInt64, [Data]) -> Void)
    func clearQueries(reply: @escaping (Bool) -> Void)
    func setEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    func isEnabled(reply: @escaping (Bool) -> Void)
    func setServer(_ serverName: String, reply: @escaping (Bool) -> Void)
    func getServer(reply: @escaping (String) -> Void)
    func getStatistics(reply: @escaping ([String: Any]) -> Void)
}

// MARK: - XPC Interface Helper

public enum DNSXPCInterface {
    public static let serviceName = "99HGW2AR62.com.wudan.iris.dns.xpc"

    public static func createInterface() -> NSXPCInterface {
        return NSXPCInterface(with: DNSXPCProtocol.self)
    }

    public static func createConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = createInterface()
        return connection
    }
}

// MARK: - DNS Query Record

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
