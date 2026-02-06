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

    /// Refresh interval in seconds.
    /// Rationale: 1 second provides near-real-time network visibility.
    /// Network connections change rapidly, so faster polling is valuable here.
    private let refreshInterval: TimeInterval = 1.0

    /// Optional data source for dependency injection (used in tests)
    private let dataSource: (any NetworkDataSourceProtocol)?

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

    /// Standard refresh method - reloads all network data
    public func refresh() async {
        await refreshData()
    }

    /// Refresh all data from the extension
    public func refreshData() async {
        // Use injected data source if available (for testing)
        if let dataSource = dataSource {
            await fetchConnectionsViaDataSource(dataSource)
            await fetchRulesViaDataSource(dataSource)
        } else {
            await fetchConnections()
            await fetchRules()
        }
        lastUpdate = Date()
    }

    private func fetchConnectionsViaDataSource(_ dataSource: any NetworkDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchConnections()
            await processConnectionData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
    }

    private func fetchRulesViaDataSource(_ dataSource: any NetworkDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchRules()
            processRulesData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
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

    /// Enrich connections with geolocation, security, and threat intelligence data
    /// Uses the unified IPEnrichmentService which provides fallback logic
    private func enrichWithGeolocation(_ connections: [NetworkConnection]) async -> [NetworkConnection] {
        // Get unique remote IPs that need lookup
        let uniqueIPs = Set(connections.map { $0.remoteAddress })
            .filter { !$0.isEmpty }

        // Skip if no IPs to look up
        guard !uniqueIPs.isEmpty else { return connections }

        // Use unified enrichment service with fallback logic
        let enrichmentResults = await IPEnrichmentService.shared.batchEnrich(Array(uniqueIPs))

        // Enrich each connection with all data sources
        return connections.map { connection in
            var enriched = connection

            if let result = enrichmentResults[connection.remoteAddress] {
                // Geolocation data
                enriched.remoteCountry = result.country
                enriched.remoteCountryCode = result.countryCode
                enriched.remoteCity = result.city
                enriched.remoteLatitude = result.latitude
                enriched.remoteLongitude = result.longitude
                enriched.remoteASN = result.asn
                enriched.remoteOrganization = result.organization

                // Security data from InternetDB (or reverse DNS for hostnames)
                enriched.remoteOpenPorts = result.openPorts
                enriched.remoteHostnames = result.hostnames
                enriched.remoteCVEs = result.cves
                enriched.remoteServiceTags = result.serviceTags
                enriched.remoteCPEs = result.cpes

                // Threat intelligence data
                enriched.abuseScore = result.abuseScore
                enriched.isKnownScanner = result.isKnownScanner
                enriched.isBenignService = result.isBenignService
                enriched.threatClassification = result.threatClassification
                enriched.isTor = result.isTor
                enriched.enrichmentSources = result.sources
            }

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
