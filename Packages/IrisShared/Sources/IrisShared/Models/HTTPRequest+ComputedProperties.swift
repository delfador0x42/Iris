import Foundation

// MARK: - Computed Properties

extension HTTPRequest {

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
