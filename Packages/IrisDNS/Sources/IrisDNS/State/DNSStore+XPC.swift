import Foundation
import os.log

// MARK: - XPC Connection & Methods

@MainActor
extension DNSStore {

    // MARK: - Connection

    /// Connects to the DNS proxy extension via XPC.
    public func connect() {
        guard xpcConnection == nil else { return }

        logger.info("Connecting to DNS proxy extension...")

        let connection = NSXPCConnection(machServiceName: DNSXPCInterface.serviceName, options: [])
        connection.remoteObjectInterface = DNSXPCInterface.createInterface()

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

        logger.info("Connected to DNS proxy extension")
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

    /// Disconnects from the DNS proxy extension.
    public func disconnect() {
        stopRefreshTimer()
        xpcConnection?.invalidate()
        xpcConnection = nil
        isActive = false
        logger.info("Disconnected from DNS proxy extension")
    }

    func handleConnectionInvalidated() {
        logger.warning("DNS XPC connection invalidated")
        stopRefreshTimer()
        xpcConnection = nil
        isActive = false
        errorMessage = "Connection to DNS proxy extension lost"
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

    /// Refreshes the DNS proxy status.
    public func refreshStatus() async {
        guard let proxy = getDNSProxy() else {
            isActive = false
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getStatus { [weak self] status in
                Task { @MainActor in
                    self?.isActive = status["isActive"] as? Bool ?? false
                    self?.isEnabled = status["isActive"] as? Bool ?? false
                    self?.totalQueries = status["totalQueries"] as? Int ?? 0
                    self?.averageLatencyMs = status["averageLatencyMs"] as? Double ?? 0
                    self?.serverName = status["serverName"] as? String ?? "Unknown"
                    self?.errorMessage = nil
                    continuation.resume()
                }
            }
        }
    }

    /// Refreshes the captured DNS queries using delta protocol.
    /// First call fetches all queries; subsequent calls only fetch new ones.
    public func refreshQueries() async {
        guard let proxy = getDNSProxy() else { return }

        isLoading = true

        await withCheckedContinuation { continuation in
            proxy.getQueriesSince(lastSeenSequence, limit: 10000) { [weak self] newSeq, queryDataArray in
                Task { @MainActor in
                    self?.mergeQueries(queryDataArray, newSequence: newSeq)
                    self?.isLoading = false
                    continuation.resume()
                }
            }
        }
    }

    /// Clears all captured queries.
    public func clearQueries() async {
        guard let proxy = getDNSProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.clearQueries { [weak self] success in
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
        guard let proxy = getDNSProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setEnabled(enabled) { [weak self] success in
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
        guard let proxy = getDNSProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setServer(name) { [weak self] success in
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

    func getDNSProxy() -> DNSXPCProtocol? {
        guard let connection = xpcConnection else {
            errorMessage = "Not connected to DNS proxy extension"
            return nil
        }

        return connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.logger.error("DNS XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        } as? DNSXPCProtocol
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
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
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
