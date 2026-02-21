import Foundation
import os.log

// MARK: - XPC Connection Management

@MainActor
extension SecurityStore {

    /// Connect to the security extension via XPC
    public func connect() {
        guard xpcConnection == nil else {
            logger.info("Already connected to extension")
            return
        }

        logger.info("Connecting to security extension...")

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
        isConnected = true
        errorMessage = nil

        logger.info("Connected to security extension")

        // Initial data fetch (timer started separately via startMonitoring)
        Task {
            await refreshData()
        }
    }

    /// Start periodic refresh timer. Call from view's .onAppear.
    /// XPC connection must be established first via connect().
    public func startMonitoring() {
        startRefreshTimer()
    }

    /// Stop periodic refresh timer. Call from view's .onDisappear.
    /// XPC connection stays alive for instant resume.
    public func stopMonitoring() {
        stopRefreshTimer()
    }

    /// Disconnect from the extension
    public func disconnect() {
        stopRefreshTimer()

        xpcConnection?.invalidate()
        xpcConnection = nil
        isConnected = false

        logger.info("Disconnected from security extension")
    }

    func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        isConnected = false
        xpcConnection = nil
        stopRefreshTimer()
    }

    func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted, retrying...")
        errorMessage = "Connection interrupted, retrying..."

        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await refreshData()
        }
    }
}
