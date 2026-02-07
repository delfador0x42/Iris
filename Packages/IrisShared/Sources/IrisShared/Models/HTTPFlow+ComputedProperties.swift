import Foundation

// MARK: - Computed Properties

extension HTTPFlow {

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
