import Foundation

// MARK: - Formatting Helpers

extension NetworkConnection {
    /// Format bytes as human-readable string
    /// Uses ByteFormatter with full style for detailed display
    public static func formatBytes(_ bytes: UInt64) -> String {
        ByteFormatter.format(bytes, style: .full)
    }

    /// Formatted bytes up
    public var formattedBytesUp: String {
        Self.formatBytes(bytesUp)
    }

    /// Formatted bytes down
    public var formattedBytesDown: String {
        Self.formatBytes(bytesDown)
    }
}

// MARK: - Aggregated Connection

/// Aggregated connections to the same remote IP (for deduplication in UI)
public struct AggregatedConnection: Identifiable {
    public let id: String  // remoteAddress
    public let remoteAddress: String
    public let connections: [NetworkConnection]

    public init(id: String, remoteAddress: String, connections: [NetworkConnection]) {
        self.id = id
        self.remoteAddress = remoteAddress
        self.connections = connections
    }

    public var connectionCount: Int { connections.count }
    public var totalBytesUp: UInt64 { connections.reduce(0) { $0 + $1.bytesUp } }
    public var totalBytesDown: UInt64 { connections.reduce(0) { $0 + $1.bytesDown } }

    /// First connection used as representative (same IP = same enrichment data)
    public var representative: NetworkConnection { connections[0] }
}




