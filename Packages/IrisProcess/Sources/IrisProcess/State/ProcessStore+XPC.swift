import Foundation
import os.log

// MARK: - XPC Connection & Timer Management

@MainActor
extension ProcessStore {

    /// Connect to the security extension via XPC
    public func connect() {
        guard xpcConnection == nil else {
            logger.info("[XPC] Already connected to endpoint extension")
            return
        }

        let serviceName = EndpointXPCService.extensionServiceName
        logger.info("[XPC] Connecting to endpoint extension: \(serviceName)")

        let connection = NSXPCConnection(
            machServiceName: serviceName,
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

        logger.info("[XPC] Connection resumed to \(serviceName)")
    }

    /// Disconnect from the extension
    public func disconnect() {
        stopAutoRefresh()
        xpcConnection?.invalidate()
        xpcConnection = nil
        logger.info("[XPC] Disconnected from endpoint security extension")
    }

    func handleConnectionInvalidated() {
        logger.warning("[XPC] Connection INVALIDATED — extension may have crashed or been unloaded")
        xpcConnection = nil
        isUsingEndpointSecurity = false
        esExtensionStatus = .notInstalled

        // Auto-reconnect after delay if monitoring was active
        guard isMonitoringActive else {
            logger.info("[XPC] Not monitoring — skipping reconnection")
            return
        }
        let monitoring = isMonitoringActive
        Task {
            logger.info("[XPC] Will attempt reconnection in 3s...")
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            let stillMonitoring = self.isMonitoringActive
            let hasConnection = self.xpcConnection != nil
            guard stillMonitoring, !hasConnection else {
                logger.info("[XPC] Reconnection skipped (monitoring=\(stillMonitoring), hasConnection=\(hasConnection))")
                return
            }
            logger.info("[XPC] Reconnecting now...")
            self.connect()
            await self.checkESStatus()
        }
    }

    func handleConnectionInterrupted() {
        logger.warning("[XPC] Connection INTERRUPTED — extension still running but connection lost")
        errorMessage = "Connection to extension interrupted, reconnecting..."

        // Reconnect: invalidate stale connection and create fresh one
        Task {
            logger.info("[XPC] Will reconnect in 1s...")
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            self.disconnect()
            self.connect()
            await self.checkESStatus()
            await self.refreshProcesses()
            let status = self.esExtensionStatus.rawValue
            logger.info("[XPC] Reconnection complete — ES status: \(status)")
        }
    }

    // MARK: - ES Status Checking

    /// Check if the ES extension is running and ES client is active
    public func checkESStatus() async {
        logger.info("[XPC] Checking ES extension status...")

        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("[XPC] ES status proxy error: \(error.localizedDescription)")
            }
        }) as? EndpointXPCProtocol else {
            logger.warning("[XPC] No XPC connection or proxy — marking ES as not installed")
            esExtensionStatus = .notInstalled
            isUsingEndpointSecurity = false
            return
        }

        let status = await withTaskGroup(of: [String: Any]?.self) { group in
            group.addTask { @MainActor in
                await withCheckedContinuation { continuation in
                    proxy.getStatus { status in
                        continuation.resume(returning: status)
                    }
                }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                return nil
            }
            let result = await group.next() ?? nil
            group.cancelAll()
            return result
        }

        if let status = status {
            let esEnabled = status["esEnabled"] as? Bool ?? false
            let mode = status["mode"] as? String ?? "unknown"
            let processCount = status["processCount"] as? Int ?? -1
            let esError = status["esError"] as? String

            logger.info("[XPC] ES getStatus() response: esEnabled=\(esEnabled) mode=\(mode) processCount=\(processCount) esError=\(esError ?? "none")")

            isUsingEndpointSecurity = esEnabled
            enforcementEnabled = status["enforcementEnabled"] as? Bool ?? false
            if esEnabled {
                esExtensionStatus = .running
                errorMessage = nil
            } else {
                esExtensionStatus = .esDisabled
                let errMsg = esError ?? "ES client not running"
                errorMessage = errMsg
                logger.warning("[XPC] ES client not active: \(errMsg)")
            }
        } else {
            logger.warning("[XPC] ES getStatus() TIMED OUT after 3s — extension not responding")
            esExtensionStatus = .notInstalled
            isUsingEndpointSecurity = false
        }
    }

    // MARK: - Enforcement Mode

    /// Toggle ExecPolicy enforcement via XPC to the endpoint extension.
    public func setEnforcementMode(_ enforce: Bool) async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("[XPC] enforcement proxy error: \(error.localizedDescription)")
            }
        }) as? EndpointXPCProtocol else {
            logger.warning("[XPC] No connection — cannot set enforcement mode")
            return
        }

        let success = await withCheckedContinuation { continuation in
            proxy.setEnforcementMode(enforce) { ok in
                continuation.resume(returning: ok)
            }
        }

        if success {
            enforcementEnabled = enforce
            logger.info("[XPC] Enforcement mode set to \(enforce)")
        } else {
            logger.error("[XPC] Failed to set enforcement mode")
        }
    }

    // MARK: - Auto Refresh

    /// Start periodic refresh and connect to XPC. Call from view's .onAppear.
    public func startAutoRefresh() {
        isMonitoringActive = true
        guard refreshTimer == nil else {
            logger.info("[XPC] Auto-refresh already running (timer exists)")
            return
        }

        let interval = refreshInterval
        logger.info("[XPC] Starting auto-refresh (interval=\(interval)s)")

        // Connect XPC if not already connected
        connect()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshProcesses()
            }
        }

        // Initial fetch + status check
        Task {
            await self.checkESStatus()
            await self.refreshProcesses()
            let count = self.processes.count
            let status = self.esExtensionStatus.rawValue
            logger.info("[XPC] Initial fetch complete — \(count) processes, ES status: \(status)")
        }
    }

    /// Alias for consistency with other stores.
    public func startMonitoring() { startAutoRefresh() }

    /// Alias for consistency with other stores.
    public func stopMonitoring() { stopAutoRefresh() }

    public func stopAutoRefresh() {
        logger.info("[XPC] Stopping auto-refresh")
        isMonitoringActive = false
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}

// MARK: - Username Resolution

extension ProcessStore {
    /// Cache: macOS has ~10 unique UIDs. Eliminates 620 getpwuid() syscalls per render.
    private static var usernameCache: [UInt32: String] = [:]

    /// Get username for a user ID, cached after first lookup.
    public static func username(forUID uid: UInt32) -> String {
        if let cached = usernameCache[uid] { return cached }
        let name: String
        if let pw = getpwuid(uid) {
            name = String(cString: pw.pointee.pw_name)
        } else {
            name = "\(uid)"
        }
        usernameCache[uid] = name
        return name
    }
}
