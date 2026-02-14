import Foundation
import SystemExtensions
import NetworkExtension
import os.log

// MARK: - Status Checking & Polling

@MainActor
extension ExtensionManager {

    /// Check status of all extensions (parallel — max(checks) instead of sum)
    public func checkAllExtensionStatuses() async {
        logger.info("[STATUS] Checking all extension statuses...")
        async let network: Void = checkNetworkExtensionStatus()
        async let endpoint: Void = checkEndpointExtensionStatus()
        async let proxy: Void = checkProxyExtensionStatus()
        async let dns: Void = checkDNSExtensionStatus()
        async let fda: Void = checkFullDiskAccess()
        _ = await (network, endpoint, proxy, dns, fda)
        let netDesc = networkExtensionState.description
        let epDesc = endpointExtensionState.description
        let prxDesc = proxyExtensionState.description
        let dnsDesc = dnsExtensionState.description
        let fdaVal = hasFullDiskAccess
        logger.info("[STATUS] All checks complete: network=\(netDesc) endpoint=\(epDesc) proxy=\(prxDesc) dns=\(dnsDesc) fda=\(fdaVal)")
    }

    /// Check network extension status via NEFilterManager
    public func checkNetworkExtensionStatus() async {
        let (extensionState, filter) = await NetworkFilterHelper.checkStatus()
        networkExtensionState = extensionState
        filterState = filter
        logger.info("[STATUS] Network: state=\(extensionState.description) filter=\(filter.description)")
    }

    /// Check endpoint extension status by querying ES health via XPC getStatus()
    public func checkEndpointExtensionStatus() async {
        let currentDesc = endpointExtensionState.description
        logger.info("[STATUS] Checking endpoint extension via XPC getStatus()... (current: \(currentDesc))")
        let status = await queryEndpointStatus()

        if let status = status {
            let esEnabled = status["esEnabled"] as? Bool ?? false
            let mode = status["mode"] as? String ?? "unknown"
            let processCount = status["processCount"] as? Int ?? -1
            let esError = status["esError"] as? String

            logger.info("[STATUS] Endpoint XPC responded: esEnabled=\(esEnabled) mode=\(mode) processCount=\(processCount) esError=\(esError ?? "none")")

            // XPC responded → extension IS installed and running
            endpointExtensionState = .installed
        } else {
            logger.warning("[STATUS] Endpoint XPC: no response (timeout or not running)")
            // Don't downgrade from transitional/positive states
            if endpointExtensionState != .installed &&
               endpointExtensionState != .installing &&
               endpointExtensionState != .needsUserApproval {
                endpointExtensionState = .notInstalled
            }
        }
    }

    /// Query the endpoint extension's getStatus() via XPC for real ES health info
    private func queryEndpointStatus() async -> [String: Any]? {
        let serviceName = "99HGW2AR62.com.wudan.iris.endpoint.xpc"
        logger.debug("[XPC] Connecting to \(serviceName) for status query...")

        return await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: serviceName)
            connection.remoteObjectInterface = NSXPCInterface(with: EndpointXPCProtocol.self)

            let lock = NSLock()
            var didResume = false

            connection.invalidationHandler = { [self] in
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                logger.debug("[XPC] Endpoint connection invalidated before response")
                continuation.resume(returning: nil)
            }

            connection.resume()

            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [self] error in
                logger.error("[XPC] Endpoint proxy error: \(error.localizedDescription)")
                connection.invalidate()
            }) as? EndpointXPCProtocol else {
                logger.error("[XPC] Failed to get endpoint proxy object")
                connection.invalidate()
                return
            }

            proxy.getStatus { [self] status in
                lock.lock()
                guard !didResume else { lock.unlock(); connection.invalidate(); return }
                didResume = true
                lock.unlock()
                logger.debug("[XPC] Endpoint getStatus() returned keys: \(status.keys.joined(separator: ", "))")
                connection.invalidate()
                continuation.resume(returning: status)
            }

            // Timeout after 2 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [self] in
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                logger.warning("[XPC] Endpoint getStatus() TIMED OUT after 2s")
                connection.invalidate()
                continuation.resume(returning: nil)
            }
        }
    }

    /// Check proxy extension status via NETransparentProxyManager
    public func checkProxyExtensionStatus() async {
        let (isConfigured, isEnabled) = await TransparentProxyHelper.checkStatus()
        if isConfigured && isEnabled {
            proxyExtensionState = .installed
        } else if proxyExtensionState == .unknown {
            proxyExtensionState = .notInstalled
        }
        let proxyDesc = proxyExtensionState.description
        logger.info("[STATUS] Proxy: configured=\(isConfigured) enabled=\(isEnabled) → \(proxyDesc)")
    }

    /// Check DNS extension status via NEDNSProxyManager
    public func checkDNSExtensionStatus() async {
        let (isConfigured, isEnabled) = await DNSProxyHelper.checkStatus()
        if isConfigured && isEnabled {
            dnsExtensionState = .installed
        } else if dnsExtensionState == .unknown {
            dnsExtensionState = .notInstalled
        }
        let dnsStateDesc = dnsExtensionState.description
        logger.info("[STATUS] DNS: configured=\(isConfigured) enabled=\(isEnabled) → \(dnsStateDesc)")
    }

    // MARK: - Polling

    /// Start polling for network extension approval
    public func startPollingForNetworkApproval() {
        stopNetworkPolling()
        logger.info("[POLL] Starting network extension approval polling (every 2s)")

        networkPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.checkNetworkExtensionStatus()
                if self?.networkExtensionState == .installed {
                    self?.logger.info("[POLL] Network extension now installed — stopping poll")
                    self?.stopNetworkPolling()
                    self?.onNetworkExtensionReady?()
                }
            }
        }
    }

    /// Start polling for endpoint extension approval
    public func startPollingForEndpointApproval() {
        stopEndpointPolling()
        logger.info("[POLL] Starting endpoint extension approval polling (every 2s)")

        endpointPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.checkEndpointExtensionStatus()
                if self?.endpointExtensionState == .installed {
                    self?.logger.info("[POLL] Endpoint extension now installed — stopping poll")
                    self?.stopEndpointPolling()
                    self?.onEndpointExtensionReady?()
                }
            }
        }
    }

    func stopNetworkPolling() {
        networkPollTimer?.invalidate()
        networkPollTimer = nil
    }

    func stopEndpointPolling() {
        endpointPollTimer?.invalidate()
        endpointPollTimer = nil
    }

    // MARK: - XPC Ping

    /// Try connecting to a Mach XPC service with a short timeout to check if extension is running
    func pingXPCService(machServiceName: String, protocol proto: Protocol) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: machServiceName)
            connection.remoteObjectInterface = NSXPCInterface(with: proto)

            // NSLock guards didResume to prevent double-resume crash
            let lock = NSLock()
            var didResume = false

            connection.invalidationHandler = {
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                continuation.resume(returning: false)
            }

            connection.resume()

            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                connection.invalidate()
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                continuation.resume(returning: true)
            }
        }
    }
}
