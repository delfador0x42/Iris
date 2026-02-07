import Foundation

// MARK: - Computed Properties

extension HTTPResponse {

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
}
