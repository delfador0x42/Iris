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

        // Start periodic refresh
        startRefreshTimer()

        // Initial status check
        Task {
            await refreshStatus()
            await refreshFlows()
        }

        logger.info("Connected to proxy extension")
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

    /// Refreshes the captured flows.
    public func refreshFlows() async {
        guard let proxy = getProxy() else { return }

        isLoading = true

        await withCheckedContinuation { continuation in
            proxy.getFlows { [weak self] flowDataArray in
                Task { @MainActor in
                    self?.parseFlows(flowDataArray)
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

    func parseFlows(_ dataArray: [Data]) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let parsedFlows = dataArray.compactMap { data -> ProxyCapturedFlow? in
            try? decoder.decode(ProxyCapturedFlow.self, from: data)
        }

        // Sort by timestamp (newest first)
        flows = parsedFlows.sorted { $0.timestamp > $1.timestamp }
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
