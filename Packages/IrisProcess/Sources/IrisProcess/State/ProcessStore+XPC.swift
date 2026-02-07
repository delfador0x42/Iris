import Foundation
import os.log

// MARK: - XPC Connection & Timer Management

@MainActor
extension ProcessStore {

    /// Connect to the security extension via XPC
    public func connect() {
        guard xpcConnection == nil else {
            logger.info("Already connected to extension")
            return
        }

        logger.info("Connecting to endpoint security extension for process monitoring...")

        let connection = NSXPCConnection(
            machServiceName: EndpointXPCService.extensionServiceName,
            options: []
        )

        connection.remoteObjectInterface = NSXPCInterface(
            with: EndpointXPCProtocol.self
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
        errorMessage = nil

        logger.info("Connected to endpoint security extension")
    }

    /// Disconnect from the extension
    public func disconnect() {
        xpcConnection?.invalidate()
        xpcConnection = nil
        logger.info("Disconnected from endpoint security extension")
    }

    func handleConnectionInvalidated() {
        logger.warning("XPC connection invalidated")
        xpcConnection = nil
    }

    func handleConnectionInterrupted() {
        logger.warning("XPC connection interrupted")
        errorMessage = "Connection to extension interrupted"
    }

    // MARK: - Auto Refresh

    public func startAutoRefresh() {
        stopAutoRefresh()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshProcesses()
            }
        }

        // Try to connect to XPC (will fall back to local if fails)
        connect()

        // Initial fetch
        Task {
            await refreshProcesses()
        }
    }

    public func stopAutoRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}

// MARK: - Username Resolution

extension ProcessStore {
    /// Get username for a user ID using the system password database
    public static func username(forUID uid: UInt32) -> String {
        if let pw = getpwuid(uid) {
            return String(cString: pw.pointee.pw_name)
        }
        return "\(uid)"
    }
}
