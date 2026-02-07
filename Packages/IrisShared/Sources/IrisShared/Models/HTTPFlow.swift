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

// MARK: - Hashable

extension HTTPFlow: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
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
