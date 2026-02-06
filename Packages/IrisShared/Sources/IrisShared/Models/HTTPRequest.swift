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

    // MARK: - Computed Properties

    /// The URL path component.
    public var path: String {
        url.path.isEmpty ? "/" : url.path
    }

    /// The URL path with query string.
    public var pathWithQuery: String {
        if let query = url.query, !query.isEmpty {
            return "\(path)?\(query)"
        }
        return path
    }

    /// The host from the URL or Host header.
    public var host: String? {
        url.host ?? headers.host
    }

    /// The port number.
    public var port: Int? {
        url.port
    }

    /// The scheme (http or https).
    public var scheme: String {
        url.scheme ?? "http"
    }

    /// Whether this is an HTTPS request.
    public var isSecure: Bool {
        scheme.lowercased() == "https"
    }

    /// Query parameters as dictionary.
    public var queryParameters: [String: String] {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return [:]
        }
        var result: [String: String] = [:]
        for item in queryItems {
            result[item.name] = item.value ?? ""
        }
        return result
    }

    /// Content type from headers.
    public var contentType: String? {
        headers.contentType
    }

    /// Content length from headers or body.
    public var contentLength: Int {
        headers.contentLength ?? body?.count ?? 0
    }

    /// Cookies parsed from Cookie header.
    public var cookies: [String: String] {
        headers.cookies
    }

    /// User agent string.
    public var userAgent: String? {
        headers.userAgent
    }

    /// Whether this is a CONNECT request (used for HTTPS tunneling).
    public var isConnect: Bool {
        method == "CONNECT"
    }

    /// Whether this request has a body.
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

// MARK: - HTTP Method Constants

extension HTTPRequest {
    /// Common HTTP methods.
    public enum Method: String, CaseIterable, Sendable {
        case get = "GET"
        case post = "POST"
        case put = "PUT"
        case delete = "DELETE"
        case patch = "PATCH"
        case head = "HEAD"
        case options = "OPTIONS"
        case connect = "CONNECT"
        case trace = "TRACE"

        /// Whether this method typically has a request body.
        public var hasBody: Bool {
            switch self {
            case .post, .put, .patch:
                return true
            default:
                return false
            }
        }

        /// Whether this method is "safe" (read-only).
        public var isSafe: Bool {
            switch self {
            case .get, .head, .options, .trace:
                return true
            default:
                return false
            }
        }

        /// Whether this method is idempotent.
        public var isIdempotent: Bool {
            switch self {
            case .get, .head, .put, .delete, .options, .trace:
                return true
            default:
                return false
            }
        }
    }

    /// The method as a typed enum (if valid).
    public var methodType: Method? {
        Method(rawValue: method)
    }
}

// MARK: - Parsing

extension HTTPRequest {
    /// Parses an HTTP request from raw data.
    /// - Parameters:
    ///   - data: Raw HTTP request data
    ///   - baseURL: Base URL for relative requests
    /// - Returns: Parsed request, or nil if invalid
    public static func parse(from data: Data, baseURL: URL? = nil) -> HTTPRequest? {
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        return parse(from: string, baseURL: baseURL)
    }

    /// Parses an HTTP request from a string.
    /// - Parameters:
    ///   - string: Raw HTTP request string
    ///   - baseURL: Base URL for relative requests
    /// - Returns: Parsed request, or nil if invalid
    public static func parse(from string: String, baseURL: URL? = nil) -> HTTPRequest? {
        let lines = string.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        // Parse request line
        let requestLine = lines[0].components(separatedBy: " ")
        guard requestLine.count >= 2 else { return nil }

        let method = requestLine[0]
        let path = requestLine[1]
        let httpVersion = requestLine.count >= 3 ? requestLine[2] : "HTTP/1.1"

        // Determine URL
        let url: URL?
        if path.hasPrefix("http://") || path.hasPrefix("https://") {
            url = URL(string: path)
        } else if let base = baseURL {
            url = URL(string: path, relativeTo: base)
        } else {
            url = URL(string: "http://localhost\(path)")
        }

        guard let finalURL = url else { return nil }

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

        return HTTPRequest(
            method: method,
            url: finalURL,
            httpVersion: httpVersion,
            headers: headers,
            body: body
        )
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
