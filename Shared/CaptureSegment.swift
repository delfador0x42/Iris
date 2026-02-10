import Foundation

/// A timestamped chunk of captured network data.
/// Stored in the extension, serialized to JSON for XPC transport.
public struct CaptureSegment: Codable, Sendable {
    public let timestamp: Date
    public let direction: Direction
    public let data: Data

    public enum Direction: String, Codable, Sendable {
        case outbound
        case inbound
    }

    public init(timestamp: Date, direction: Direction, data: Data) {
        self.timestamp = timestamp
        self.direction = direction
        self.data = data
    }

    /// Byte count of the payload
    public var byteCount: Int { data.count }
}
