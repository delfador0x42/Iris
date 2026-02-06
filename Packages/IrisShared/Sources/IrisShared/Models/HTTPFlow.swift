import Foundation

/// Represents a complete HTTP transaction (request + response).
/// Based on mitmproxy's HTTPFlow concept.
public struct HTTPFlow: Identifiable, Sendable, Codable, Equatable {

    // MARK: - Properties

    /// Unique identifier for this flow.
    public let id: UUID

    /// ID of the underlying network connection (links to NetworkConnection).
    public let connectionId: UUID

    /// The HTTP request.
    public let request: HTTPRequest

    /// The HTTP response (nil if request hasn't completed or failed).
    public var response: HTTPResponse?

    /// Error message if the request failed.
    public var error: String?

    /// Timestamp when the flow was created.
    public let timestamp: Date

    /// Whether this flow has been intercepted by the user.
    public var isIntercepted: Bool

    /// User-defined comment for this flow.
    public var comment: String

    /// User-defined marker/tag for this flow.
    public var marker: String

    /// Whether this is a replayed request.
    public var isReplay: Bool

    /// Process name that initiated this connection (if known).
    public let processName: String?

    /// Process ID that initiated this connection (if known).
    public let processId: Int?

    // MARK: - Initialization

    /// Creates a new HTTP flow.
    public init(
        id: UUID = UUID(),
        connectionId: UUID = UUID(),
        request: HTTPRequest,
        response: HTTPResponse? = nil,
        error: String? = nil,
        timestamp: Date = Date(),
        isIntercepted: Bool = false,
        comment: String = "",
        marker: String = "",
        isReplay: Bool = false,
        processName: String? = nil,
        processId: Int? = nil
    ) {
        self.id = id
        self.connectionId = connectionId
        self.request = request
        self.response = response
        self.error = error
        self.timestamp = timestamp
        self.isIntercepted = isIntercepted
        self.comment = comment
        self.marker = marker
        self.isReplay = isReplay
        self.processName = processName
        self.processId = processId
    }

    // MARK: - Computed Properties

    /// Whether the flow is complete (has response or error).
    public var isComplete: Bool {
        response != nil || error != nil
    }

    /// Whether the flow succeeded (has response with 2xx status).
    public var isSuccess: Bool {
        response?.isSuccess ?? false
    }

    /// Whether the flow has an error.
    public var hasError: Bool {
        error != nil || (response?.isError ?? false)
    }

    /// Duration of the request in seconds (nil if not complete).
    public var duration: TimeInterval? {
        guard let response = response else { return nil }
        return response.timestamp.timeIntervalSince(request.timestamp)
    }

    /// Duration formatted as string (e.g., "123ms", "1.5s").
    public var durationFormatted: String? {
        guard let duration = duration else { return nil }
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        } else {
            return String(format: "%.2fs", duration)
        }
    }

    /// Total bytes transferred (request + response bodies).
    public var totalBytes: Int {
        let requestBytes = request.body?.count ?? 0
        let responseBytes = response?.body?.count ?? 0
        return requestBytes + responseBytes
    }

    /// Total bytes formatted (e.g., "1.5 KB", "2.3 MB").
    public var totalBytesFormatted: String {
        ByteCountFormatter.string(fromByteCount: Int64(totalBytes), countStyle: .file)
    }

    /// HTTP method from request.
    public var method: String {
        request.method
    }

    /// URL from request.
    public var url: URL {
        request.url
    }

    /// Host from request.
    public var host: String? {
        request.host
    }

    /// Path from request.
    public var path: String {
        request.path
    }

    /// Status code from response (nil if no response).
    public var statusCode: Int? {
        response?.statusCode
    }

    /// Content type from response.
    public var responseContentType: String? {
        response?.contentType
    }

    /// Whether request is HTTPS.
    public var isSecure: Bool {
        request.isSecure
    }

    /// Short description for display.
    public var shortDescription: String {
        if let status = statusCode {
            return "\(method) \(host ?? "unknown")\(path) → \(status)"
        } else if let error = error {
            return "\(method) \(host ?? "unknown")\(path) → Error: \(error)"
        } else {
            return "\(method) \(host ?? "unknown")\(path) → Pending..."
        }
    }

    // MARK: - Modification

    /// Returns a copy with the response set.
    public func withResponse(_ response: HTTPResponse) -> HTTPFlow {
        var copy = self
        copy.response = response
        return copy
    }

    /// Returns a copy with an error set.
    public func withError(_ error: String) -> HTTPFlow {
        var copy = self
        copy.error = error
        return copy
    }

    /// Returns a copy marked as intercepted.
    public func intercepted() -> HTTPFlow {
        var copy = self
        copy.isIntercepted = true
        return copy
    }

    /// Returns a copy with interception cleared.
    public func resumed() -> HTTPFlow {
        var copy = self
        copy.isIntercepted = false
        return copy
    }
}

// MARK: - Flow State

extension HTTPFlow {
    /// Current state of the flow.
    public enum State: String, Sendable, Codable {
        case pending     // Request sent, waiting for response
        case complete    // Response received successfully
        case error       // Request failed
        case intercepted // Paused by user
    }

    /// The current state of this flow.
    public var state: State {
        if isIntercepted {
            return .intercepted
        } else if error != nil {
            return .error
        } else if response != nil {
            return .complete
        } else {
            return .pending
        }
    }
}

// MARK: - Filtering

extension HTTPFlow {
    /// Checks if this flow matches a search query.
    /// - Parameter query: Search string to match against
    /// - Returns: True if the flow matches
    public func matches(query: String) -> Bool {
        let lowercaseQuery = query.lowercased()

        // Check URL
        if url.absoluteString.lowercased().contains(lowercaseQuery) {
            return true
        }

        // Check method
        if method.lowercased().contains(lowercaseQuery) {
            return true
        }

        // Check status code
        if let status = statusCode, String(status).contains(lowercaseQuery) {
            return true
        }

        // Check process name
        if let process = processName, process.lowercased().contains(lowercaseQuery) {
            return true
        }

        // Check comment
        if comment.lowercased().contains(lowercaseQuery) {
            return true
        }

        // Check content type
        if let contentType = responseContentType, contentType.lowercased().contains(lowercaseQuery) {
            return true
        }

        return false
    }

    /// Checks if this flow matches a filter.
    /// - Parameter filter: The filter to apply
    /// - Returns: True if the flow matches
    public func matches(filter: FlowFilter) -> Bool {
        // Check method filter
        if let methods = filter.methods, !methods.isEmpty {
            if !methods.contains(method) {
                return false
            }
        }

        // Check status filter
        if let statuses = filter.statusCodes, !statuses.isEmpty {
            guard let status = statusCode else { return false }
            if !statuses.contains(status) {
                return false
            }
        }

        // Check host filter
        if let hosts = filter.hosts, !hosts.isEmpty {
            guard let flowHost = host else { return false }
            if !hosts.contains(where: { flowHost.contains($0) }) {
                return false
            }
        }

        // Check content type filter
        if let contentTypes = filter.contentTypes, !contentTypes.isEmpty {
            guard let contentType = responseContentType else { return false }
            if !contentTypes.contains(where: { contentType.contains($0) }) {
                return false
            }
        }

        // Check text query
        if let query = filter.textQuery, !query.isEmpty {
            if !matches(query: query) {
                return false
            }
        }

        return true
    }
}

// MARK: - Flow Filter

/// Filter criteria for HTTP flows.
public struct FlowFilter: Sendable, Codable, Equatable {
    /// Filter by HTTP methods.
    public var methods: Set<String>?

    /// Filter by status codes.
    public var statusCodes: Set<Int>?

    /// Filter by hosts (partial match).
    public var hosts: [String]?

    /// Filter by content types (partial match).
    public var contentTypes: [String]?

    /// Free text search query.
    public var textQuery: String?

    /// Show only flows with errors.
    public var errorsOnly: Bool

    /// Show only complete flows.
    public var completeOnly: Bool

    public init(
        methods: Set<String>? = nil,
        statusCodes: Set<Int>? = nil,
        hosts: [String]? = nil,
        contentTypes: [String]? = nil,
        textQuery: String? = nil,
        errorsOnly: Bool = false,
        completeOnly: Bool = false
    ) {
        self.methods = methods
        self.statusCodes = statusCodes
        self.hosts = hosts
        self.contentTypes = contentTypes
        self.textQuery = textQuery
        self.errorsOnly = errorsOnly
        self.completeOnly = completeOnly
    }

    /// An empty filter that matches everything.
    public static let all = FlowFilter()
}

// MARK: - CustomStringConvertible

extension HTTPFlow: CustomStringConvertible {
    public var description: String {
        var desc = "HTTPFlow(\(id.uuidString.prefix(8)): \(method) \(url.absoluteString)"
        if let status = statusCode {
            desc += " → \(status)"
        }
        if let duration = durationFormatted {
            desc += " [\(duration)]"
        }
        desc += ")"
        return desc
    }
}

// MARK: - Hashable

extension HTTPFlow: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
