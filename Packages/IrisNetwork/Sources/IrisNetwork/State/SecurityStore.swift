import Foundation
import Combine
import os.log

/// State store for network security monitoring
@MainActor
public final class SecurityStore: ObservableObject {

    // MARK: - Published State

    /// All active network connections grouped by process
    @Published public internal(set) var connectionsByProcess: [Int32: [NetworkConnection]] = [:]

    /// All tracked connections
    @Published public internal(set) var connections: [NetworkConnection] = []

    /// Security rules
    @Published public internal(set) var rules: [SecurityRule] = []

    /// Whether connected to the extension
    @Published public internal(set) var isConnected = false

    /// Last update timestamp
    @Published public internal(set) var lastUpdate: Date?

    /// Error message if any
    @Published public internal(set) var errorMessage: String?

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityStore")
    var xpcConnection: NSXPCConnection?
    var refreshTimer: Timer?

    /// Refresh interval in seconds.
    /// Rationale: 1 second provides near-real-time network visibility.
    /// Network connections change rapidly, so faster polling is valuable here.
    let refreshInterval: TimeInterval = 1.0

    /// Optional data source for dependency injection (used in tests)
    let dataSource: (any NetworkDataSourceProtocol)?

    // MARK: - Computed Properties

    /// Unique processes with connections
    public var processes: [ProcessSummary] {
        connectionsByProcess.map { pid, connections in
            let totalBytesUp = connections.reduce(0) { $0 + $1.bytesUp }
            let totalBytesDown = connections.reduce(0) { $0 + $1.bytesDown }

            return ProcessSummary(
                pid: pid,
                name: connections.first?.processName ?? "Unknown",
                path: connections.first?.processPath ?? "",
                connectionCount: connections.count,
                totalBytesUp: totalBytesUp,
                totalBytesDown: totalBytesDown
            )
        }
        .sorted {
            // Sort alphabetically by name first, then by PID (lower PIDs on top) for stability
            let nameComparison = $0.name.localizedCaseInsensitiveCompare($1.name)
            if nameComparison != .orderedSame {
                return nameComparison == .orderedAscending
            }
            return $0.pid < $1.pid
        }
    }

    /// Total bytes uploaded
    public var totalBytesUp: UInt64 {
        connections.reduce(0) { $0 + $1.bytesUp }
    }

    /// Total bytes downloaded
    public var totalBytesDown: UInt64 {
        connections.reduce(0) { $0 + $1.bytesDown }
    }

    /// Connections that have geolocation data
    public var geolocatedConnections: [NetworkConnection] {
        connections.filter { $0.hasGeolocation }
    }

    /// Unique countries in connections
    public var uniqueCountries: Set<String> {
        Set(connections.compactMap { $0.remoteCountryCode })
    }

    /// Count of connections with geolocation
    public var geolocatedCount: Int {
        geolocatedConnections.count
    }

    // MARK: - Types

    public struct ProcessSummary: Identifiable {
        public var id: Int32 { pid }
        public let pid: Int32
        public let name: String
        public let path: String
        public let connectionCount: Int
        public let totalBytesUp: UInt64
        public let totalBytesDown: UInt64

        public var formattedBytesUp: String {
            NetworkConnection.formatBytes(totalBytesUp)
        }

        public var formattedBytesDown: String {
            NetworkConnection.formatBytes(totalBytesDown)
        }
    }

    // MARK: - Initialization

    /// Initialize with optional data source for dependency injection
    /// - Parameter dataSource: Optional data source (nil uses XPC)
    public init(dataSource: (any NetworkDataSourceProtocol)? = nil) {
        self.dataSource = dataSource
    }
}
