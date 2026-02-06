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

    // MARK: - Computed Properties

    /// Content type from headers.
    public var contentType: String? {
        headers.contentType
    }

    /// Content length from headers or body.
    public var contentLength: Int {
        headers.contentLength ?? body?.count ?? 0
    }

    /// Whether this is a successful response (2xx).
    public var isSuccess: Bool {
        statusCode >= 200 && statusCode < 300
    }

    /// Whether this is a redirect (3xx).
    public var isRedirect: Bool {
        statusCode >= 300 && statusCode < 400
    }

    /// Whether this is a client error (4xx).
    public var isClientError: Bool {
        statusCode >= 400 && statusCode < 500
    }

    /// Whether this is a server error (5xx).
    public var isServerError: Bool {
        statusCode >= 500 && statusCode < 600
    }

    /// Whether this is any error (4xx or 5xx).
    public var isError: Bool {
        isClientError || isServerError
    }

    /// Location header for redirects.
    public var location: String? {
        headers["Location"]
    }

    /// Location as URL.
    public var locationURL: URL? {
        location.flatMap { URL(string: $0) }
    }

    /// Set-Cookie headers.
    public var setCookies: [String] {
        headers.setCookies
    }

    /// Whether response has a body.
    public var hasBody: Bool {
        body != nil && !body!.isEmpty
    }

    /// Body as UTF-8 string (if decodable).
    public var bodyText: String? {
        guard let body = body else { return nil }
        return String(data: body, encoding: .utf8)
    }

    /// Body as JSON (if parseable).
    public var bodyJSON: Any? {
        guard let body = body else { return nil }
        return try? JSONSerialization.jsonObject(with: body)
    }

    /// MIME type from Content-Type (without parameters).
    public var mimeType: String? {
        guard let contentType = contentType else { return nil }
        return contentType.components(separatedBy: ";").first?.trimmingCharacters(in: .whitespaces)
    }

    /// Whether response is JSON.
    public var isJSON: Bool {
        mimeType?.contains("json") ?? false
    }

    /// Whether response is HTML.
    public var isHTML: Bool {
        mimeType?.contains("html") ?? false
    }

    /// Whether response is XML.
    public var isXML: Bool {
        guard let mime = mimeType else { return false }
        return mime.contains("xml")
    }

    /// Whether response is text-based.
    public var isText: Bool {
        guard let mime = mimeType else { return false }
        return mime.hasPrefix("text/") || isJSON || isXML || isHTML
    }

    /// Whether response is an image.
    public var isImage: Bool {
        mimeType?.hasPrefix("image/") ?? false
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

    // MARK: - Default Reasons

    /// Gets the default reason phrase for a status code.
    public static func defaultReason(for statusCode: Int) -> String {
        switch statusCode {
        // 1xx Informational
        case 100: return "Continue"
        case 101: return "Switching Protocols"
        case 102: return "Processing"
        case 103: return "Early Hints"

        // 2xx Success
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 203: return "Non-Authoritative Information"
        case 204: return "No Content"
        case 205: return "Reset Content"
        case 206: return "Partial Content"
        case 207: return "Multi-Status"
        case 208: return "Already Reported"
        case 226: return "IM Used"

        // 3xx Redirection
        case 300: return "Multiple Choices"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 303: return "See Other"
        case 304: return "Not Modified"
        case 305: return "Use Proxy"
        case 307: return "Temporary Redirect"
        case 308: return "Permanent Redirect"

        // 4xx Client Errors
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 402: return "Payment Required"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 406: return "Not Acceptable"
        case 407: return "Proxy Authentication Required"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 410: return "Gone"
        case 411: return "Length Required"
        case 412: return "Precondition Failed"
        case 413: return "Payload Too Large"
        case 414: return "URI Too Long"
        case 415: return "Unsupported Media Type"
        case 416: return "Range Not Satisfiable"
        case 417: return "Expectation Failed"
        case 418: return "I'm a teapot"
        case 421: return "Misdirected Request"
        case 422: return "Unprocessable Entity"
        case 423: return "Locked"
        case 424: return "Failed Dependency"
        case 425: return "Too Early"
        case 426: return "Upgrade Required"
        case 428: return "Precondition Required"
        case 429: return "Too Many Requests"
        case 431: return "Request Header Fields Too Large"
        case 451: return "Unavailable For Legal Reasons"

        // 5xx Server Errors
        case 500: return "Internal Server Error"
        case 501: return "Not Implemented"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        case 505: return "HTTP Version Not Supported"
        case 506: return "Variant Also Negotiates"
        case 507: return "Insufficient Storage"
        case 508: return "Loop Detected"
        case 510: return "Not Extended"
        case 511: return "Network Authentication Required"

        default: return "Unknown"
        }
    }
}

// MARK: - Status Code Categories

extension HTTPResponse {
    /// HTTP status code categories.
    public enum StatusCategory: Sendable {
        case informational  // 1xx
        case success        // 2xx
        case redirection    // 3xx
        case clientError    // 4xx
        case serverError    // 5xx
        case unknown

        public init(statusCode: Int) {
            switch statusCode {
            case 100..<200: self = .informational
            case 200..<300: self = .success
            case 300..<400: self = .redirection
            case 400..<500: self = .clientError
            case 500..<600: self = .serverError
            default: self = .unknown
            }
        }
    }

    /// The status code category.
    public var statusCategory: StatusCategory {
        StatusCategory(statusCode: statusCode)
    }
}

// MARK: - Parsing

extension HTTPResponse {
    /// Parses an HTTP response from raw data.
    /// - Parameter data: Raw HTTP response data
    /// - Returns: Parsed response, or nil if invalid
    public static func parse(from data: Data) -> HTTPResponse? {
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        return parse(from: string)
    }

    /// Parses an HTTP response from a string.
    /// - Parameter string: Raw HTTP response string
    /// - Returns: Parsed response, or nil if invalid
    public static func parse(from string: String) -> HTTPResponse? {
        let lines = string.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        // Parse status line
        let statusLine = lines[0]
        let parts = statusLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }

        let httpVersion = parts[0]
        guard let statusCode = Int(parts[1]) else { return nil }
        let reason = parts.count >= 3 ? parts[2...].joined(separator: " ") : nil

        // Parse headers
        var headers = HTTPHeaders()
        var bodyStart = 0

        for i in 1..<lines.count {
            let line = lines[i]
            if line.isEmpty {
                bodyStart = i + 1
                break
            }
            if let colonIndex = line.firstIndex(of: ":") {
                let name = String(line[..<colonIndex])
                let valueStart = line.index(after: colonIndex)
                let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
                headers.add(name, value: value)
            }
        }

        // Parse body
        var body: Data? = nil
        if bodyStart > 0 && bodyStart < lines.count {
            let bodyLines = lines[bodyStart...].joined(separator: "\r\n")
            body = bodyLines.data(using: .utf8)
        }

        return HTTPResponse(
            statusCode: statusCode,
            reason: reason,
            httpVersion: httpVersion,
            headers: headers,
            body: body
        )
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
