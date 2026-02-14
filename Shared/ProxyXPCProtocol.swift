import Foundation

/// XPC protocol for communication between the main app and the Proxy Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol ProxyXPCProtocol {
    func getStatus(reply: @escaping ([String: Any]) -> Void)
    func getFlows(reply: @escaping ([Data]) -> Void)
    /// Delta fetch: returns only flows with sequenceNumber > sinceSeq.
    /// Reply includes the current max sequence number and the changed flows.
    func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void)
    func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void)
    func clearFlows(reply: @escaping (Bool) -> Void)
    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    func isInterceptionEnabled(reply: @escaping (Bool) -> Void)
    /// Send CA certificate and private key to the extension for TLS MITM.
    /// The app (user process) generates the CA, then sends it via XPC to the
    /// extension (root process) since they don't share keychains.
    func setCA(_ certData: Data, keyData: Data, reply: @escaping (Bool) -> Void)
}

// MARK: - XPC Interface Helper

public enum ProxyXPCInterface {
    public static let serviceName = "99HGW2AR62.com.wudan.iris.proxy.xpc"

    public static func createInterface() -> NSXPCInterface {
        return NSXPCInterface(with: ProxyXPCProtocol.self)
    }

    public static func createConnection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.remoteObjectInterface = createInterface()
        return connection
    }
}

// MARK: - Captured Flow Models

/// A captured HTTP flow (request + optional response).
public struct ProxyCapturedFlow: Codable, Identifiable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let timestamp: Date
    public let request: ProxyCapturedRequest
    public var response: ProxyCapturedResponse?
    public var error: String?
    public let processName: String?
    public let processId: Int?
    /// Monotonically increasing sequence number for delta XPC protocol.
    /// Bumped on both creation and update so delta fetch catches response arrivals.
    public var sequenceNumber: UInt64

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        request: ProxyCapturedRequest,
        response: ProxyCapturedResponse? = nil,
        error: String? = nil,
        processName: String? = nil,
        processId: Int? = nil,
        sequenceNumber: UInt64 = 0
    ) {
        self.id = id
        self.timestamp = timestamp
        self.request = request
        self.response = response
        self.error = error
        self.processName = processName
        self.processId = processId
        self.sequenceNumber = sequenceNumber
    }

    public var isComplete: Bool {
        response != nil || error != nil
    }

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

    /// Convenience init that converts tuple headers and extracts body preview.
    /// Used by the proxy extension when creating from parsed HTTP data.
    public init(
        method: String,
        url: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil
    ) {
        self.method = method
        self.url = url
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0
        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }

    public var host: String? {
        if let url = URL(string: url) { return url.host }
        return headers.first { $0.first?.lowercased() == "host" }?.last
    }

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

    /// Convenience init that converts tuple headers and extracts body preview.
    public init(
        statusCode: Int,
        reason: String,
        httpVersion: String = "HTTP/1.1",
        headers: [(name: String, value: String)],
        body: Data? = nil,
        duration: TimeInterval
    ) {
        self.statusCode = statusCode
        self.reason = reason
        self.httpVersion = httpVersion
        self.headers = headers.map { [$0.name, $0.value] }
        self.bodySize = body?.count ?? 0
        self.duration = duration
        if let body = body, !body.isEmpty {
            let previewSize = min(body.count, 1024)
            self.bodyPreview = String(data: body.prefix(previewSize), encoding: .utf8)
        } else {
            self.bodyPreview = nil
        }
    }

    public var isSuccess: Bool { statusCode >= 200 && statusCode < 300 }
    public var isError: Bool { statusCode >= 400 }

    public var contentType: String? {
        headers.first { $0.first?.lowercased() == "content-type" }?.last
    }
}
