//
//  ProxyXPCProtocol.swift
//  IrisShared
//
//  XPC protocol for communication between the main app and the proxy extension.
//

import Foundation

/// XPC protocol for the proxy extension.
/// Used by the main app to communicate with IrisProxyExtension.
@objc public protocol ProxyXPCProtocol {

    /// Gets the current proxy status.
    /// Returns dictionary with: isActive, activeFlows, flowCount, interceptionEnabled, version
    func getStatus(reply: @escaping ([String: Any]) -> Void)

    /// Gets all captured HTTP flows.
    /// Returns array of JSON-encoded CapturedFlow objects.
    func getFlows(reply: @escaping ([Data]) -> Void)

    /// Gets a specific flow by ID.
    /// - Parameter flowId: UUID string of the flow
    func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void)

    /// Clears all captured flows.
    func clearFlows(reply: @escaping (Bool) -> Void)

    /// Enables or disables TLS interception.
    /// When disabled, HTTPS traffic passes through without inspection.
    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)

    /// Gets whether interception is currently enabled.
    func isInterceptionEnabled(reply: @escaping (Bool) -> Void)
}

// MARK: - XPC Interface Helper

/// Helper for creating XPC interface for the proxy extension.
public enum ProxyXPCInterface {

    /// The Mach service name for the proxy extension.
    public static let serviceName = "99HGW2AR62.com.wudan.iris.proxy.xpc"

    /// Creates an NSXPCInterface for the proxy protocol.
    public static func createInterface() -> NSXPCInterface {
        return NSXPCInterface(with: ProxyXPCProtocol.self)
    }

    /// Creates an NSXPCConnection to the proxy extension.
    public static func createConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = createInterface()
        return connection
    }
}

// MARK: - Captured Flow Types (Shared)

/// A captured HTTP flow (request + optional response).
/// This is the shared version that both the extension and main app use.
public struct ProxyCapturedFlow: Codable, Identifiable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let timestamp: Date
    public let request: ProxyCapturedRequest
    public var response: ProxyCapturedResponse?
    public var error: String?
    public let processName: String?
    public let processId: Int?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        request: ProxyCapturedRequest,
        response: ProxyCapturedResponse? = nil,
        error: String? = nil,
        processName: String? = nil,
        processId: Int? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.request = request
        self.response = response
        self.error = error
        self.processName = processName
        self.processId = processId
    }

    /// Whether the flow is complete (has response or error).
    public var isComplete: Bool {
        response != nil || error != nil
    }

    /// Duration of the request in seconds.
    public var duration: TimeInterval? {
        response?.duration
    }
}

/// A captured HTTP request.
public struct ProxyCapturedRequest: Codable, Sendable, Equatable, Hashable {
    public let method: String
    public let url: String
    public let httpVersion: String
    public let headers: [[String]]
    public let bodySize: Int
    public let bodyPreview: String?

    public init(
        method: String,
        url: String,
        httpVersion: String = "HTTP/1.1",
        headers: [[String]],
        bodySize: Int,
        bodyPreview: String? = nil
    ) {
        self.method = method
        self.url = url
        self.httpVersion = httpVersion
        self.headers = headers
        self.bodySize = bodySize
        self.bodyPreview = bodyPreview
    }

    /// Gets the host from the URL or headers.
    public var host: String? {
        if let url = URL(string: url) {
            return url.host
        }
        return headers.first { $0.first?.lowercased() == "host" }?.last
    }

    /// Gets the path from the URL.
    public var path: String {
        URL(string: url)?.path ?? url
    }
}

/// A captured HTTP response.
public struct ProxyCapturedResponse: Codable, Sendable, Equatable, Hashable {
    public let statusCode: Int
    public let reason: String
    public let httpVersion: String
    public let headers: [[String]]
    public let bodySize: Int
    public let bodyPreview: String?
    public let duration: TimeInterval

    public init(
        statusCode: Int,
        reason: String,
        httpVersion: String = "HTTP/1.1",
        headers: [[String]],
        bodySize: Int,
        bodyPreview: String? = nil,
        duration: TimeInterval
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.httpVersion = httpVersion
        self.headers = headers
        self.bodySize = bodySize
        self.bodyPreview = bodyPreview
        self.duration = duration
    }

    /// Whether this is a success response (2xx).
    public var isSuccess: Bool {
        statusCode >= 200 && statusCode < 300
    }

    /// Whether this is an error response (4xx or 5xx).
    public var isError: Bool {
        statusCode >= 400
    }

    /// Content type from headers.
    public var contentType: String? {
        headers.first { $0.first?.lowercased() == "content-type" }?.last
    }
}
