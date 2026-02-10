import Foundation
import NetworkExtension
import os.log

/// Network Extension filter provider for monitoring network connections
class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Properties

    let logger = Logger(subsystem: "com.wudan.iris.network", category: "Filter")

    /// Active connections being tracked
    var connections: [UUID: ConnectionTracker] = [:]
    let connectionsLock = NSLock()

    /// Maps flow identity to connection ID for byte tracking
    var flowToConnection: [ObjectIdentifier: UUID] = [:]

    /// Cleanup timer for stale connections
    var cleanupTimer: Timer?

    /// Max tracked connections before eviction
    static let maxConnections = 10000

    /// Connections with no activity for this long are removed
    static let staleTimeout: TimeInterval = 120

    /// XPC service for communicating with main app
    var xpcService: XPCService?

    /// Security rules
    var rules: [SecurityRule] = []
    let rulesLock = NSLock()

    /// Cache signing identifiers by PID to avoid redundant SecCode verification.
    /// A browser with 50 connections would otherwise verify the same binary 50 times.
    var signingIdCache: [pid_t: String?] = [:]

    // MARK: - Capture Budget

    /// Total bytes used by raw capture buffers across all connections
    var totalCaptureBytes: Int = 0

    /// Maximum capture memory budget in bytes (default 30GB, user adjustable via XPC)
    var captureMemoryBudget: Int = 30 * 1024 * 1024 * 1024

    // MARK: - Connection Tracking

    struct ConnectionTracker {
        let connection: NetworkConnection
        var bytesUp: UInt64 = 0
        var bytesDown: UInt64 = 0
        var localAddress: String
        var localPort: UInt16
        let flowId: UUID
        var lastActivity: Date = Date()

        // HTTP tracking
        var httpRequest: ParsedHTTPRequest?
        var httpResponse: ParsedHTTPResponse?
        var requestParser: HTTPParser.StreamingRequestParser?
        var responseParser: HTTPParser.StreamingResponseParser?
        var isHTTPParsed: Bool = false

        // Raw capture buffers (full network tap)
        var rawOutbound: Data = Data()
        var rawInbound: Data = Data()
    }

    // MARK: - HTTP Data Structures (for XPC)

    struct ParsedHTTPRequest: Codable {
        let method: String
        let path: String
        let host: String?
        let contentType: String?
        let userAgent: String?
        let rawHeaders: String  // Full raw request headers
    }

    struct ParsedHTTPResponse: Codable {
        let statusCode: Int
        let reason: String
        let contentType: String?
        let contentLength: Int?
        let rawHeaders: String  // Full raw response headers
    }

    // MARK: - Lifecycle

    override init() {
        super.init()
        logger.info("FilterDataProvider initialized")
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting network filter...")

        // Start XPC service
        xpcService = XPCService()
        xpcService?.filterProvider = self
        xpcService?.start()

        // Create rule to monitor all outbound traffic
        let networkRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )

        let filterRule = NEFilterRule(networkRule: networkRule, action: .filterData)

        // Configure filter settings with rules
        let filterSettings = NEFilterSettings(rules: [filterRule], defaultAction: .filterData)

        apply(filterSettings) { error in
            if let error = error {
                self.logger.error("Failed to apply filter settings: \(error.localizedDescription)")
            } else {
                self.logger.info("Filter settings applied successfully")
                self.startCleanupTimer()
            }
            completionHandler(error)
        }
    }

    func startCleanupTimer() {
        cleanupTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.cleanupStaleConnections()
        }
    }

    func cleanupStaleConnections() {
        connectionsLock.lock()
        let now = Date()
        let staleIds = connections.filter { now.timeIntervalSince($0.value.lastActivity) > Self.staleTimeout }
            .map { $0.key }

        // Remove stale connections and their flow mappings atomically
        let staleIdSet = Set(staleIds)
        for id in staleIds {
            if let tracker = connections[id] {
                totalCaptureBytes -= tracker.rawOutbound.count + tracker.rawInbound.count
            }
            connections.removeValue(forKey: id)
        }
        // Only remove flow entries pointing to stale IDs (avoids rebuilding entire dict)
        flowToConnection = flowToConnection.filter { !staleIdSet.contains($0.value) }

        // Prune signing cache for PIDs with no remaining connections (handles PID reuse)
        if !staleIds.isEmpty {
            let activePIDs = Set(connections.values.map { $0.connection.processId })
            signingIdCache = signingIdCache.filter { activePIDs.contains($0.key) }
            logger.debug("Cleaned up \(staleIds.count) stale connections, \(self.connections.count) remaining")
        }
        connectionsLock.unlock()
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping network filter, reason: \(String(describing: reason))")

        cleanupTimer?.invalidate()
        cleanupTimer = nil
        xpcService?.stop()
        xpcService = nil

        completionHandler()
    }
}
