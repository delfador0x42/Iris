import Foundation
import os.log

// MARK: - XPC Connection & Methods

@MainActor
extension DNSStore {

    // MARK: - Connection

    /// Connects to the proxy extension via XPC (DNS is now handled by the unified proxy).
    public func connect() {
        guard xpcConnection == nil else { return }

        logger.info("Connecting to proxy extension for DNS...")

        let connection = ProxyXPCInterface.createConnection()

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

        // Initial data fetch (timer started separately via startMonitoring)
        Task {
            await refreshStatus()
            await refreshQueries()
        }

        logger.info("Connected to proxy extension for DNS")
    }

    /// Start periodic refresh timer. Call from view's .onAppear.
    public func startMonitoring() {
        startRefreshTimer()
    }

    /// Stop periodic refresh timer. Call from view's .onDisappear.
    /// XPC connection stays alive for instant resume.
    public func stopMonitoring() {
        stopRefreshTimer()
    }

    /// Disconnects from the proxy extension.
    public func disconnect() {
        stopRefreshTimer()
        xpcConnection?.invalidate()
        xpcConnection = nil
        isActive = false
        logger.info("Disconnected from proxy extension DNS")
    }

    func handleConnectionInvalidated() {
        logger.warning("DNS XPC connection invalidated")
        stopRefreshTimer()
        xpcConnection = nil
        isActive = false
        errorMessage = "Connection to proxy extension lost"
    }

    func handleConnectionInterrupted() {
        logger.warning("DNS XPC connection interrupted")
        errorMessage = "Connection interrupted, retrying..."

        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await refreshStatus()
        }
    }

    // MARK: - XPC Methods

    /// Refreshes DNS status from the proxy extension.
    public func refreshStatus() async {
        guard let proxy = getProxy() else {
            isActive = false
            return
        }

        // Get DNS statistics
        await withCheckedContinuation { continuation in
            proxy.getDNSStatistics { [weak self] stats in
                Task { @MainActor in
                    self?.totalQueries = stats["totalQueries"] as? Int ?? 0
                    self?.averageLatencyMs = stats["averageLatencyMs"] as? Double ?? 0
                    self?.successRate = stats["successRate"] as? Double ?? 1.0
                    self?.errorMessage = nil
                    continuation.resume()
                }
            }
        }

        // Get DNS enabled state
        await withCheckedContinuation { continuation in
            proxy.isDNSEnabled { [weak self] enabled in
                Task { @MainActor in
                    self?.isEnabled = enabled
                    self?.isActive = true
                    continuation.resume()
                }
            }
        }

        // Get DNS server name
        await withCheckedContinuation { continuation in
            proxy.getDNSServer { [weak self] name in
                Task { @MainActor in
                    self?.serverName = name
                    continuation.resume()
                }
            }
        }
    }

    /// Refreshes the captured DNS queries using delta protocol.
    /// First call fetches all queries; subsequent calls only fetch new ones.
    public func refreshQueries() async {
        guard let proxy = getProxy() else { return }

        isLoading = true

        let gotResponse = await withTaskGroup(of: Bool.self) { group in
            group.addTask { @MainActor in
                await withCheckedContinuation { continuation in
                    proxy.getDNSQueriesSince(self.lastSeenSequence, limit: 10000) { [weak self] newSeq, queryDataArray in
                        Task { @MainActor in
                            self?.mergeQueries(queryDataArray, newSequence: newSeq)
                            continuation.resume()
                        }
                    }
                }
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
        }

        if !gotResponse {
            logger.warning("XPC getDNSQueriesSince() timed out after 5s")
        }
        isLoading = false
    }

    /// Clears all captured queries.
    public func clearQueries() async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.clearDNSQueries { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.queries = []
                        self?.totalQueries = 0
                        self?.lastSeenSequence = 0
                    }
                    continuation.resume()
                }
            }
        }
    }

    /// Enables or disables encrypted DNS.
    public func setEnabled(_ enabled: Bool) async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setDNSEnabled(enabled) { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.isEnabled = enabled
                    }
                    continuation.resume()
                }
            }
        }
    }

    /// Changes the DoH server.
    public func setServer(_ name: String) async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setDNSServer(name) { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.serverName = name
                    }
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - Private Helpers

    func getProxy() -> ProxyXPCProtocol? {
        guard let connection = xpcConnection else {
            errorMessage = "Not connected to proxy extension"
            return nil
        }

        return connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.logger.error("DNS XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        } as? ProxyXPCProtocol
    }

    /// Merge delta queries into existing list. DNS queries are append-only (no updates).
    func mergeQueries(_ dataArray: [Data], newSequence: UInt64) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let incoming = dataArray.compactMap { try? decoder.decode(DNSQueryRecord.self, from: $0) }

        if lastSeenSequence == 0 {
            // First fetch — replace everything
            queries = incoming.sorted { $0.timestamp > $1.timestamp }
        } else if !incoming.isEmpty {
            // Delta append: DNS queries are immutable, just prepend new ones
            var merged = incoming + queries
            if merged.count > 10000 {
                merged = Array(merged.prefix(10000))
            }
            queries = merged.sorted { $0.timestamp > $1.timestamp }
        }

        lastSeenSequence = newSequence
        totalQueries = queries.count
    }

    func startRefreshTimer() {
        stopRefreshTimer()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshQueries()
            }
        }
    }

    func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}
