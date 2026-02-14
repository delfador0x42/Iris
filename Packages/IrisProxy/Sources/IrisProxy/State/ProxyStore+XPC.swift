import Foundation
import os.log

// MARK: - XPC Connection & Methods

@MainActor
extension ProxyStore {

    // MARK: - Connection

    /// Connects to the proxy extension via XPC.
    public func connect() {
        guard xpcConnection == nil else { return }

        logger.info("Connecting to proxy extension...")

        let connection = NSXPCConnection(machServiceName: ProxyXPCInterface.serviceName, options: [])
        connection.remoteObjectInterface = ProxyXPCInterface.createInterface()

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

        // Initial status check (timer started separately via startMonitoring)
        Task {
            await refreshStatus()
            await refreshFlows()
        }

        logger.info("Connected to proxy extension")
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
        isEnabled = false
        logger.info("Disconnected from proxy extension")
    }

    func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        stopRefreshTimer()
        xpcConnection = nil
        isEnabled = false
        errorMessage = "Connection to proxy extension lost"
    }

    func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection interrupted, retrying..."

        // Try to reconnect
        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await refreshStatus()
        }
    }

    // MARK: - XPC Methods

    /// Refreshes the proxy status.
    public func refreshStatus() async {
        guard let proxy = getProxy() else {
            isEnabled = false
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getStatus { [weak self] status in
                Task { @MainActor in
                    self?.isEnabled = status["isActive"] as? Bool ?? false
                    self?.isInterceptionEnabled = status["interceptionEnabled"] as? Bool ?? true
                    self?.totalFlowCount = status["flowCount"] as? Int ?? 0
                    self?.errorMessage = nil
                    continuation.resume()
                }
            }
        }
    }

    /// Refreshes the captured flows using delta protocol.
    /// First call fetches all flows; subsequent calls only fetch changes.
    public func refreshFlows() async {
        guard let proxy = getProxy() else { return }

        isLoading = true

        await withCheckedContinuation { continuation in
            proxy.getFlowsSince(lastSeenSequence) { [weak self] newSeq, flowDataArray in
                Task { @MainActor in
                    self?.mergeFlows(flowDataArray, newSequence: newSeq)
                    self?.isLoading = false
                    continuation.resume()
                }
            }
        }
    }

    /// Clears all captured flows.
    public func clearFlows() async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.clearFlows { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.flows = []
                        self?.totalFlowCount = 0
                        self?.selectedFlow = nil
                        self?.lastSeenSequence = 0
                    }
                    continuation.resume()
                }
            }
        }
    }

    /// Enables or disables TLS interception.
    public func setInterceptionEnabled(_ enabled: Bool) async {
        guard let proxy = getProxy() else { return }

        await withCheckedContinuation { continuation in
            proxy.setInterceptionEnabled(enabled) { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.isInterceptionEnabled = enabled
                    }
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - CA Distribution

    /// Send the CA certificate and private key to the proxy extension via XPC.
    /// The app (user) and extension (root) run as different UIDs so they can't
    /// share keychains. This sends the cert+key data directly over XPC.
    public func sendCA(certData: Data, keyData: Data) async -> Bool {
        guard let proxy = getProxy() else {
            logger.error("Cannot send CA — not connected to proxy extension")
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.setCA(certData, keyData: keyData) { success in
                continuation.resume(returning: success)
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
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        } as? ProxyXPCProtocol
    }

    /// Merge delta flows into existing list. New flows are appended; updated flows replace by ID.
    func mergeFlows(_ dataArray: [Data], newSequence: UInt64) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let incoming = dataArray.compactMap { try? decoder.decode(ProxyCapturedFlow.self, from: $0) }

        if lastSeenSequence == 0 {
            // First fetch — replace everything
            flows = incoming.sorted { $0.timestamp > $1.timestamp }
        } else if !incoming.isEmpty {
            // Delta merge: update existing or append new
            var byId = Dictionary(flows.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
            for flow in incoming {
                byId[flow.id] = flow
            }
            flows = byId.values.sorted { $0.timestamp > $1.timestamp }
            // Trim to max
            if flows.count > 10000 {
                flows = Array(flows.prefix(10000))
            }
        }

        lastSeenSequence = newSequence
        totalFlowCount = flows.count
    }

    func startRefreshTimer() {
        stopRefreshTimer()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshFlows()
            }
        }
    }

    func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}
