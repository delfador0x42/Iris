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

    func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        isConnected = false
        xpcConnection = nil
        stopRefreshTimer()
    }

    func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection to extension interrupted"
    }
}
