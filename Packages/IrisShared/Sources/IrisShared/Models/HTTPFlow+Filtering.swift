import Foundation

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
