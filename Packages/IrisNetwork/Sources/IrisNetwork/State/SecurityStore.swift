import Foundation
import Combine
import os.log

/// State store for network security monitoring
@MainActor
public final class SecurityStore: ObservableObject {

    // MARK: - Published State

    /// All active network connections grouped by binary identity key
    @Published public internal(set) var connectionsByProcess: [String: [NetworkConnection]] = [:]

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
    /// Rationale: 2 seconds balances responsiveness with CPU/XPC overhead.
    let refreshInterval: TimeInterval = 2.0

    /// Optional data source for dependency injection (used in tests)
    let dataSource: (any NetworkDataSourceProtocol)?

    /// Monotonic counter to detect stale enrichment results.
    /// Incremented before each background enrichment batch, checked before applying.
    var enrichmentGeneration: UInt64 = 0

    // MARK: - Derived State (updated when connections change)

    /// Unique processes with connections
    @Published public internal(set) var processes: [ProcessSummary] = []

    /// Total bytes uploaded
    @Published public internal(set) var totalBytesUp: UInt64 = 0

    /// Total bytes downloaded
    @Published public internal(set) var totalBytesDown: UInt64 = 0

    /// Count of connections with geolocation
    @Published public internal(set) var geolocatedCount: Int = 0

    /// Unique countries in connections
    @Published public internal(set) var uniqueCountries: Set<String> = []

    /// Recalculates all derived state from current connections.
    func updateDerivedState() {
        totalBytesUp = connections.reduce(0) { $0 + $1.bytesUp }
        totalBytesDown = connections.reduce(0) { $0 + $1.bytesDown }
        geolocatedCount = connections.filter { $0.hasGeolocation }.count
        uniqueCountries = Set(connections.compactMap { $0.remoteCountryCode })
        processes = connectionsByProcess.map { key, conns in
            ProcessSummary(
                identityKey: key,
                signingId: conns.first?.signingId,
                name: conns.first?.processName ?? "Unknown",
                path: conns.first?.processPath ?? "",
                pids: Set(conns.map { $0.processId }),
                connectionCount: conns.count,
                totalBytesUp: conns.reduce(0) { $0 + $1.bytesUp },
                totalBytesDown: conns.reduce(0) { $0 + $1.bytesDown }
            )
        }
        .sorted {
            let cmp = $0.name.localizedCaseInsensitiveCompare($1.name)
            return cmp != .orderedSame ? cmp == .orderedAscending : $0.identityKey < $1.identityKey
        }
    }

    // MARK: - Types

    public struct ProcessSummary: Identifiable {
        public var id: String { identityKey }
        public let identityKey: String
        public let signingId: String?
        public let name: String
        public let path: String
        public let pids: Set<Int32>
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

    // MARK: - Actions

    /// Clears all connections and derived state. Next poll repopulates from extension.
    public func clearConnections() {
        connections.removeAll()
        connectionsByProcess.removeAll()
        updateDerivedState()
        logger.info("Connections cleared")
    }

    // MARK: - Initialization

    /// Initialize with optional data source for dependency injection
    /// - Parameter dataSource: Optional data source (nil uses XPC)
    public init(dataSource: (any NetworkDataSourceProtocol)? = nil) {
        self.dataSource = dataSource
    }
}
