import Foundation

/// Represents an HTTP request captured by the proxy.
public struct HTTPRequest: Identifiable, Sendable, Codable, Equatable {

    // MARK: - Properties

    /// Unique identifier for this request.
    public let id: UUID

    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    public let method: String

    /// The full URL of the request.
    public let url: URL

    /// HTTP version (e.g., "HTTP/1.1", "HTTP/2").
    public let httpVersion: String

    /// Request headers.
    public var headers: HTTPHeaders

    /// Request body data (may be nil for GET requests).
    public var body: Data?

    /// Timestamp when the request was captured.
    public let timestamp: Date

    /// Source IP address of the client.
    public let clientAddress: String?

    /// Destination server address.
    public let serverAddress: String?

    // MARK: - Initialization

    /// Creates a new HTTP request.
    public init(
        id: UUID = UUID(),
        method: String,
        url: URL,
        httpVersion: String = "HTTP/1.1",
        headers: HTTPHeaders = HTTPHeaders(),
        body: Data? = nil,
        timestamp: Date = Date(),
        clientAddress: String? = nil,
        serverAddress: String? = nil
    ) {
        self.id = id
        self.method = method.uppercased()
        self.url = url
        self.httpVersion = httpVersion
        self.headers = headers
        self.body = body
        self.timestamp = timestamp
        self.clientAddress = clientAddress
        self.serverAddress = serverAddress
    }

    // MARK: - Methods

    /// Creates a copy with modified body.
    public func withBody(_ newBody: Data?) -> HTTPRequest {
        var copy = self
        copy.body = newBody
        return copy
    }

    /// Creates a copy with modified headers.
    public func withHeaders(_ newHeaders: HTTPHeaders) -> HTTPRequest {
        var copy = self
        copy.headers = newHeaders
        return copy
    }

    /// Formats the request as an HTTP message.
    public func toHTTPFormat() -> String {
        var result = "\(method) \(pathWithQuery) \(httpVersion)\r\n"
        result += headers.toHTTPFormat()
        result += "\r\n\r\n"
        if let bodyText = bodyText {
            result += bodyText
        }
        return result
    }

    /// Short description for logging.
    public var shortDescription: String {
        "\(method) \(host ?? "unknown")\(path)"
    }
}

// MARK: - CustomStringConvertible

extension HTTPRequest: CustomStringConvertible {
    public var description: String {
        var desc = "HTTPRequest(\(method) \(url.absoluteString)"
        if let contentType = contentType {
            desc += ", content-type: \(contentType)"
        }
        if contentLength > 0 {
            desc += ", \(contentLength) bytes"
        }
        desc += ")"
        return desc
    }
}
