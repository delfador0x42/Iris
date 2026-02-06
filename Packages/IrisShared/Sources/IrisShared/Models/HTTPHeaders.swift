import Foundation

/// A single HTTP header field.
public struct HeaderField: Sendable, Codable, Equatable {
    public let name: String
    public let value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// HTTP headers collection with case-insensitive access and multi-value support.
/// Based on mitmproxy's Headers class design for maximum compatibility.
public struct HTTPHeaders: Sendable, Codable, Equatable {

    // MARK: - Storage

    /// Internal storage as array to preserve order and support multiple values.
    public var fields: [HeaderField]

    // MARK: - Initialization

    /// Creates empty headers.
    public init() {
        self.fields = []
    }

    /// Creates headers from an array of HeaderField.
    /// - Parameter fields: Array of HeaderField
    public init(_ fields: [HeaderField]) {
        self.fields = fields
    }

    /// Creates headers from an array of name-value pairs.
    /// - Parameter tuples: Array of (name, value) tuples
    public init(tuples: [(name: String, value: String)]) {
        self.fields = tuples.map { HeaderField(name: $0.name, value: $0.value) }
    }

    /// Creates headers from a dictionary.
    /// Note: This loses multi-value support and order.
    /// - Parameter dictionary: Dictionary of header names to values
    public init(_ dictionary: [String: String]) {
        self.fields = dictionary.map { HeaderField(name: $0.key, value: $0.value) }
    }

    // MARK: - Codable
    // Uses automatic Codable synthesis from [HeaderField]

    // MARK: - Subscript Access

    /// Gets the first value for a header name (case-insensitive).
    /// - Parameter name: The header name
    /// - Returns: The first value, or nil if not found
    public subscript(name: String) -> String? {
        get {
            let lowercaseName = name.lowercased()
            return fields.first { $0.name.lowercased() == lowercaseName }?.value
        }
        set {
            let lowercaseName = name.lowercased()
            // Remove existing values
            fields.removeAll { $0.name.lowercased() == lowercaseName }
            // Add new value if provided
            if let value = newValue {
                fields.append(HeaderField(name: name, value: value))
            }
        }
    }

    // MARK: - Multi-Value Access

    /// Gets all values for a header name (case-insensitive).
    /// Useful for headers like Set-Cookie that can appear multiple times.
    /// - Parameter name: The header name
    /// - Returns: Array of all values for this header
    public func getAll(_ name: String) -> [String] {
        let lowercaseName = name.lowercased()
        return fields.filter { $0.name.lowercased() == lowercaseName }.map { $0.value }
    }

    /// Adds a header value without removing existing values.
    /// - Parameters:
    ///   - name: The header name
    ///   - value: The value to add
    public mutating func add(_ name: String, value: String) {
        fields.append(HeaderField(name: name, value: value))
    }

    /// Removes all headers with the given name.
    /// - Parameter name: The header name to remove
    public mutating func removeAll(_ name: String) {
        let lowercaseName = name.lowercased()
        fields.removeAll { $0.name.lowercased() == lowercaseName }
    }

    // MARK: - Common Headers

    /// Content-Type header value.
    public var contentType: String? {
        get { self["Content-Type"] }
        set { self["Content-Type"] = newValue }
    }

    /// Content-Length header value as Int.
    public var contentLength: Int? {
        get { self["Content-Length"].flatMap { Int($0) } }
        set { self["Content-Length"] = newValue.map { String($0) } }
    }

    /// Host header value.
    public var host: String? {
        get { self["Host"] }
        set { self["Host"] = newValue }
    }

    /// User-Agent header value.
    public var userAgent: String? {
        get { self["User-Agent"] }
        set { self["User-Agent"] = newValue }
    }

    /// Transfer-Encoding header value.
    public var transferEncoding: String? {
        get { self["Transfer-Encoding"] }
        set { self["Transfer-Encoding"] = newValue }
    }

    /// Whether the body is chunked transfer encoded.
    public var isChunked: Bool {
        transferEncoding?.lowercased().contains("chunked") ?? false
    }

    /// Connection header value.
    public var connection: String? {
        get { self["Connection"] }
        set { self["Connection"] = newValue }
    }

    /// Whether connection should be kept alive.
    public var keepAlive: Bool {
        connection?.lowercased() != "close"
    }

    // MARK: - Cookie Handling

    /// Parses Cookie header into dictionary.
    public var cookies: [String: String] {
        guard let cookieHeader = self["Cookie"] else { return [:] }

        var result: [String: String] = [:]
        let pairs = cookieHeader.split(separator: ";")
        for pair in pairs {
            let trimmed = pair.trimmingCharacters(in: .whitespaces)
            let parts = trimmed.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                result[String(parts[0])] = String(parts[1])
            }
        }
        return result
    }

    /// Gets all Set-Cookie headers.
    public var setCookies: [String] {
        getAll("Set-Cookie")
    }

    // MARK: - Collection Properties

    /// Number of header fields.
    public var count: Int {
        fields.count
    }

    /// Whether there are no headers.
    public var isEmpty: Bool {
        fields.isEmpty
    }

    /// All unique header names (lowercase).
    public var names: Set<String> {
        Set(fields.map { $0.name.lowercased() })
    }

    /// Checks if a header exists.
    /// - Parameter name: The header name
    /// - Returns: True if the header exists
    public func contains(_ name: String) -> Bool {
        let lowercaseName = name.lowercased()
        return fields.contains { $0.name.lowercased() == lowercaseName }
    }

    // MARK: - Serialization

    /// Converts headers to HTTP wire format.
    /// - Returns: Headers as they would appear in an HTTP message
    public func toHTTPFormat() -> String {
        fields.map { "\($0.name): \($0.value)" }.joined(separator: "\r\n")
    }

    /// Parses headers from HTTP wire format.
    /// - Parameter string: Raw HTTP headers string
    /// - Returns: Parsed headers
    public static func fromHTTPFormat(_ string: String) -> HTTPHeaders {
        var headers = HTTPHeaders()
        let lines = string.components(separatedBy: "\r\n")

        for line in lines {
            guard !line.isEmpty else { continue }
            if let colonIndex = line.firstIndex(of: ":") {
                let name = String(line[..<colonIndex])
                let valueStart = line.index(after: colonIndex)
                let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
                headers.add(name, value: value)
            }
        }

        return headers
    }
}

// MARK: - ExpressibleByDictionaryLiteral

extension HTTPHeaders: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, String)...) {
        self.fields = elements.map { HeaderField(name: $0.0, value: $0.1) }
    }
}

// MARK: - Sequence

extension HTTPHeaders: Sequence {
    public func makeIterator() -> IndexingIterator<[HeaderField]> {
        fields.makeIterator()
    }
}

// MARK: - CustomStringConvertible

extension HTTPHeaders: CustomStringConvertible {
    public var description: String {
        if isEmpty {
            return "HTTPHeaders(empty)"
        }
        let headerList = fields.map { "\($0.name): \($0.value)" }.joined(separator: ", ")
        return "HTTPHeaders(\(headerList))"
    }
}
