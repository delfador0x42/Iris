//
//  DNSXPCProtocol.swift
//  IrisShared
//
//  XPC protocol for communication between the main app and the DNS proxy extension.
//

import Foundation

/// XPC protocol for the DNS proxy extension.
/// Used by the main app to communicate with IrisDNSExtension.
@objc public protocol DNSXPCProtocol {

    /// Gets the current DNS proxy status.
    /// Returns dictionary with: isActive, totalQueries, encryptedQueries, serverName, averageLatencyMs
    func getStatus(reply: @escaping ([String: Any]) -> Void)

    /// Gets recent DNS queries.
    /// Returns array of JSON-encoded DNSQueryRecord objects.
    func getQueries(limit: Int, reply: @escaping ([Data]) -> Void)

    /// Clears all captured DNS queries.
    func clearQueries(reply: @escaping (Bool) -> Void)

    /// Enables or disables encrypted DNS.
    func setEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)

    /// Gets whether encrypted DNS is currently enabled.
    func isEnabled(reply: @escaping (Bool) -> Void)

    /// Sets the DoH server by name (e.g., "cloudflare", "google", "quad9").
    func setServer(_ serverName: String, reply: @escaping (Bool) -> Void)

    /// Gets the current DoH server name.
    func getServer(reply: @escaping (String) -> Void)

    /// Gets DNS statistics.
    /// Returns dictionary with: totalQueries, failedQueries, averageLatencyMs, successRate
    func getStatistics(reply: @escaping ([String: Any]) -> Void)
}

// MARK: - XPC Interface Helper

/// Helper for creating XPC interface for the DNS proxy extension.
public enum DNSXPCInterface {

    /// The Mach service name for the DNS proxy extension.
    public static let serviceName = "99HGW2AR62.com.wudan.iris.dns.xpc"

    /// Creates an NSXPCInterface for the DNS protocol.
    public static func createInterface() -> NSXPCInterface {
        return NSXPCInterface(with: DNSXPCProtocol.self)
    }

    /// Creates an NSXPCConnection to the DNS proxy extension.
    public static func createConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = createInterface()
        return connection
    }
}

// MARK: - DNS Query Record (Shared between extension and app)

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
        isEncrypted: Bool = true
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
    }
}
