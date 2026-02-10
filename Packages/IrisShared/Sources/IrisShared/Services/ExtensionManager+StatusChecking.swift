import Foundation
import SystemExtensions
import NetworkExtension
import os.log

// MARK: - Status Checking & Polling

@MainActor
extension ExtensionManager {

    /// Check status of all extensions
    public func checkAllExtensionStatuses() async {
        await checkNetworkExtensionStatus()
        await checkEndpointExtensionStatus()
        await checkProxyExtensionStatus()
        await checkDNSExtensionStatus()
        await checkFullDiskAccess()
    }

    /// Check network extension status via NEFilterManager
    public func checkNetworkExtensionStatus() async {
        let (extensionState, filter) = await NetworkFilterHelper.checkStatus()
        networkExtensionState = extensionState
        filterState = filter
    }

    /// Check endpoint extension status by querying ES health via XPC getStatus()
    public func checkEndpointExtensionStatus() async {
        logger.info("Checking endpoint extension status...")
        let status = await queryEndpointStatus()

        if let status = status {
            let esEnabled = status["esEnabled"] as? Bool ?? false
            let mode = status["mode"] as? String ?? "unknown"

            if esEnabled && mode == "active" {
                endpointExtensionState = .installed
            } else {
                // Extension is running but ES failed to initialize
                let reason = status["esError"] as? String
                endpointExtensionState = .failed(reason ?? "ES client not active (mode: \(mode))")
            }
        } else {
            endpointExtensionState = .notInstalled
        }
    }

    /// Query the endpoint extension's getStatus() via XPC for real ES health info
    private func queryEndpointStatus() async -> [String: Any]? {
        await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: "99HGW2AR62.com.wudan.iris.endpoint.xpc")
            connection.remoteObjectInterface = NSXPCInterface(with: EndpointXPCProtocol.self)

            let lock = NSLock()
            var didResume = false

            connection.invalidationHandler = {
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                continuation.resume(returning: nil)
            }

            connection.resume()

            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                connection.invalidate()
            }) as? EndpointXPCProtocol else {
                connection.invalidate()
                return
            }

            proxy.getStatus { status in
                lock.lock()
                guard !didResume else { lock.unlock(); connection.invalidate(); return }
                didResume = true
                lock.unlock()
                connection.invalidate()
                continuation.resume(returning: status)
            }

            // Timeout after 2 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                lock.lock()
                guard !didResume else { lock.unlock(); return }
                didResume = true
                lock.unlock()
                connection.invalidate()
                continuation.resume(returning: nil)
            }
        }
    }

    /// Check proxy extension status by trying XPC connection
    public func checkProxyExtensionStatus() async {
        logger.info("Checking proxy extension status...")
        let reachable = await pingXPCService(
            machServiceName: "99HGW2AR62.com.wudan.iris.proxy.xpc",
            protocol: ProxyXPCProtocol.self
        )
        proxyExtensionState = reachable ? .installed : .notInstalled
    }

    /// Check DNS extension status via NEDNSProxyManager
    public func checkDNSExtensionStatus() async {
        logger.info("Checking DNS extension status...")
        let (isConfigured, isEnabled) = await DNSProxyHelper.checkStatus()
        if isConfigured && isEnabled {
            dnsExtensionState = .installed
        } else if dnsExtensionState == .unknown {
            dnsExtensionState = .notInstalled
        }
    }

    // MARK: - Polling

    /// Start polling for network extension approval
    public func startPollingForNetworkApproval() {
        stopNetworkPolling()
        logger.info("Starting to poll for network extension approval...")

        networkPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.checkNetworkExtensionStatus()
                if self?.networkExtensionState == .installed {
                    self?.stopNetworkPolling()
                    self?.onNetworkExtensionReady?()
                }
            }
        }
    }

    /// Start polling for endpoint extension approval
    public func startPollingForEndpointApproval() {
        stopEndpointPolling()
        logger.info("Starting to poll for endpoint extension approval...")

        endpointPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                if self?.endpointExtensionState == .installed {
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
            // (invalidation handler and timer race on different threads)
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
