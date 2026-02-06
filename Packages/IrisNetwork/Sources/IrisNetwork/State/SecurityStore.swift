import Foundation
import Combine
import os.log

/// State store for network security monitoring
@MainActor
public final class SecurityStore: ObservableObject {

    // MARK: - Published State

    /// All active network connections grouped by process
    @Published public private(set) var connectionsByProcess: [Int32: [NetworkConnection]] = [:]

    /// All tracked connections
    @Published public private(set) var connections: [NetworkConnection] = []

    /// Security rules
    @Published public private(set) var rules: [SecurityRule] = []

    /// Whether connected to the extension
    @Published public private(set) var isConnected = false

    /// Last update timestamp
    @Published public private(set) var lastUpdate: Date?

    /// Error message if any
    @Published public private(set) var errorMessage: String?

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityStore")
    private var xpcConnection: NSXPCConnection?
    private var refreshTimer: Timer?
    private let refreshInterval: TimeInterval = 1.0

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
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
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

    public init() {}

    // MARK: - Connection Management

    /// Connect to the security extension via XPC
    public func connect() {
        guard xpcConnection == nil else {
            logger.info("Already connected to extension")
            return
        }

        logger.info("Connecting to security extension...")

        let connection = NSXPCConnection(
            machServiceName: NetworkXPCService.extensionServiceName,
            options: []
        )

        connection.remoteObjectInterface = NSXPCInterface(
            with: NetworkXPCProtocol.self
        )

        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.handleConnectionInvalidated()
            }
        }

        connection.interruptionHandler = { [weak self] in
            Task { @MainActor in
                self?.handleConnectionInterrupted()
            }
        }

        connection.resume()
        xpcConnection = connection
        isConnected = true
        errorMessage = nil

        logger.info("Connected to security extension")

        // Start refresh timer
        startRefreshTimer()

        // Initial data fetch
        Task {
            await refreshData()
        }
    }

    /// Disconnect from the extension
    public func disconnect() {
        stopRefreshTimer()

        xpcConnection?.invalidate()
        xpcConnection = nil
        isConnected = false

        logger.info("Disconnected from security extension")
    }

    private func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        isConnected = false
        xpcConnection = nil
        stopRefreshTimer()
    }

    private func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection to extension interrupted"
    }

    // MARK: - Data Refresh

    private func startRefreshTimer() {
        stopRefreshTimer()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshData()
            }
        }
    }

    private func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    /// Refresh all data from the extension
    public func refreshData() async {
        await fetchConnections()
        await fetchRules()
        lastUpdate = Date()
    }

    private func fetchConnections() async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        }) as? NetworkXPCProtocol else {
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getConnections { [weak self] dataArray in
                Task { @MainActor in
                    await self?.processConnectionData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    private func processConnectionData(_ dataArray: [Data]) async {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        var newConnections = dataArray.compactMap { data -> NetworkConnection? in
            try? decoder.decode(NetworkConnection.self, from: data)
        }

        // Enrich with geolocation data
        newConnections = await enrichWithGeolocation(newConnections)

        connections = newConnections

        // Group by process
        connectionsByProcess = Dictionary(grouping: newConnections) { $0.processId }
    }

    /// Enrich connections with geolocation data from IP addresses
    private func enrichWithGeolocation(_ connections: [NetworkConnection]) async -> [NetworkConnection] {
        // Get unique remote IPs that need lookup
        let uniqueIPs = Set(connections.map { $0.remoteAddress })
            .filter { !$0.isEmpty }

        // Skip if no IPs to look up
        guard !uniqueIPs.isEmpty else { return connections }

        // Batch lookup
        let geoResults = await GeoIPService.shared.batchLookup(Array(uniqueIPs))

        // Enrich each connection
        return connections.map { connection in
            guard let geo = geoResults[connection.remoteAddress] else {
                return connection
            }
            var enriched = connection
            enriched.remoteCountry = geo.country
            enriched.remoteCountryCode = geo.countryCode
            enriched.remoteCity = geo.city
            enriched.remoteLatitude = geo.latitude
            enriched.remoteLongitude = geo.longitude
            enriched.remoteASN = geo.asn
            enriched.remoteOrganization = geo.org
            return enriched
        }
    }

    private func fetchRules() async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("XPC error: \(error.localizedDescription)")
            }
        }) as? NetworkXPCProtocol else {
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getRules { [weak self] dataArray in
                Task { @MainActor in
                    self?.processRulesData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    private func processRulesData(_ dataArray: [Data]) {
        let decoder = JSONDecoder()

        rules = dataArray.compactMap { data -> SecurityRule? in
            try? decoder.decode(SecurityRule.self, from: data)
        }
    }

    // MARK: - Rule Management

    /// Add a new security rule
    public func addRule(_ rule: SecurityRule) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(rule) else {
            errorMessage = "Failed to encode rule"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.addRule(data) { [weak self] success, error in
                Task { @MainActor in
                    if let error = error {
                        self?.errorMessage = error
                    }
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Remove a rule by ID
    public func removeRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.removeRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Toggle a rule's enabled state
    public func toggleRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.toggleRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    // MARK: - Quick Actions

    /// Block all connections from a process
    public func blockProcess(path: String) async -> Bool {
        let rule = SecurityRule.blockProcess(path: path)
        return await addRule(rule)
    }

    /// Allow all connections from a process
    public func allowProcess(path: String) async -> Bool {
        let rule = SecurityRule.allowProcess(path: path)
        return await addRule(rule)
    }
}
