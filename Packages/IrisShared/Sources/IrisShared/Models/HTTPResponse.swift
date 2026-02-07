import Foundation

/// Represents an HTTP response captured by the proxy.
public struct HTTPResponse: Identifiable, Sendable, Codable, Equatable {

    // MARK: - Properties

    /// Unique identifier for this response.
    public let id: UUID

    /// HTTP status code (e.g., 200, 404, 500).
    public let statusCode: Int

    /// HTTP reason phrase (e.g., "OK", "Not Found").
    public let reason: String

    /// HTTP version (e.g., "HTTP/1.1", "HTTP/2").
    public let httpVersion: String

    /// Response headers.
    public var headers: HTTPHeaders

    /// Response body data.
    public var body: Data?

    /// Timestamp when the response was received.
    public let timestamp: Date

    // MARK: - Initialization

    /// Creates a new HTTP response.
    public init(
        id: UUID = UUID(),
        statusCode: Int,
        reason: String? = nil,
        httpVersion: String = "HTTP/1.1",
        headers: HTTPHeaders = HTTPHeaders(),
        body: Data? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.statusCode = statusCode
        self.reason = reason ?? HTTPResponse.defaultReason(for: statusCode)
        self.httpVersion = httpVersion
        self.headers = headers
        self.body = body
        self.timestamp = timestamp
    }

    // MARK: - Methods

    /// Creates a copy with modified body.
    public func withBody(_ newBody: Data?) -> HTTPResponse {
        var copy = self
        copy.body = newBody
        return copy
    }

    /// Creates a copy with modified headers.
    public func withHeaders(_ newHeaders: HTTPHeaders) -> HTTPResponse {
        var copy = self
        copy.headers = newHeaders
        return copy
    }

    /// Formats the response as an HTTP message.
    public func toHTTPFormat() -> String {
        var result = "\(httpVersion) \(statusCode) \(reason)\r\n"
        result += headers.toHTTPFormat()
        result += "\r\n\r\n"
        if let bodyText = bodyText {
            result += bodyText
        }
        return result
    }

    /// Short description for logging.
    public var shortDescription: String {
        "\(statusCode) \(reason)"
    }
}

// MARK: - CustomStringConvertible

extension HTTPResponse: CustomStringConvertible {
    public var description: String {
        var desc = "HTTPResponse(\(statusCode) \(reason)"
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
