//
//  AppProxyProvider.swift
//  IrisProxyExtension
//
//  NETransparentProxyProvider that selectively intercepts HTTP/HTTPS flows.
//  Returning false from handleNewFlow passes the flow to the OS directly (zero overhead).
//

import Foundation
import Network
import NetworkExtension
import os.log

/// Transparent proxy that selectively intercepts HTTP/HTTPS TCP flows.
/// Port 80 (HTTP) and 443 (HTTPS) are intercepted for MITM inspection.
/// All other TCP flows and all UDP flows return false — the OS handles them
/// directly with zero overhead (unlike NEAppProxyProvider where false = reject).
class AppProxyProvider: NETransparentProxyProvider {

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "AppProxyProvider")

    /// XPC service for communication with the main app
    let xpcService = ProxyXPCService()

    /// HTTP flow handler for processing intercepted connections
    private var flowHandler: FlowHandler?

    /// Active TCP flows being handled
    private var activeFlows: [UUID: NEAppProxyTCPFlow] = [:]
    private let flowsLock = NSLock()

    /// Whether the proxy is currently active
    private var isActive = false

    /// Ports we intercept for inspection
    private static let interceptedPorts: Set<Int> = [80, 443]

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil) async throws {
        logger.info("Starting transparent proxy extension...")
        xpcService.provider = self
        xpcService.start()
        flowHandler = FlowHandler(provider: self)

        // Configure NETransparentProxyNetworkSettings — tells the system which
        // flows to route to this extension. Without this, no flows arrive.
        // Direction MUST be .outbound per Apple docs.
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Only route TCP flows to this extension. Using .any floods handleNewFlow()
        // with UDP flows (all returning false), which is known to cause proxy disconnection.
        settings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .TCP,
                direction: .outbound
            )
        ]
        try await setTunnelNetworkSettings(settings)

        isActive = true
        logger.info("Transparent proxy extension started successfully")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        logger.info("Stopping transparent proxy extension with reason: \(String(describing: reason))")
        isActive = false
        closeAndRemoveAllFlows()
        xpcService.stop()
        flowHandler = nil
        logger.info("Transparent proxy extension stopped")
    }

    /// Closes all active flows under lock. Extracted from async stopProxy
    /// to avoid NSLock.lock() in async context (Swift 6 breaking).
    private func closeAndRemoveAllFlows() {
        flowsLock.lock()
        for (_, flow) in activeFlows {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        activeFlows.removeAll()
        flowsLock.unlock()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard isActive else {
            logger.warning("Received flow while proxy is inactive")
            return false
        }

        // Only intercept TCP flows on HTTP/HTTPS ports
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow)
        }

        // UDP flows: return false — OS handles directly, zero overhead
        return false
    }

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            logger.error("TCP flow has no remote endpoint")
            return false
        }

        let port = Int(remoteEndpoint.port) ?? 0

        // Only intercept HTTP (80) and HTTPS (443)
        // Returning false passes the flow to the OS directly — zero overhead
        guard Self.interceptedPorts.contains(port) else {
            return false
        }

        let flowId = UUID()
        let host = remoteEndpoint.hostname
        let processPath = flow.metaData.sourceAppSigningIdentifier
        let processName = processPath.components(separatedBy: ".").last ?? processPath

        logger.info("Intercepting TCP flow: \(flowId) -> \(host):\(port)")

        flowsLock.lock()
        activeFlows[flowId] = flow
        flowsLock.unlock()

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.logger.error("Failed to open flow \(flowId): \(error.localizedDescription)")
                self.removeFlow(flowId)
                return
            }
            Task {
                await self.flowHandler?.handleFlow(
                    flowId: flowId, flow: flow,
                    host: host, port: port,
                    processName: processName
                )
            }
        }
        return true
    }

    // MARK: - Flow Management

    func removeFlow(_ flowId: UUID) {
        flowsLock.lock()
        if let flow = activeFlows.removeValue(forKey: flowId) {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        flowsLock.unlock()
    }

    func activeFlowCount() -> Int {
        flowsLock.lock()
        let count = activeFlows.count
        flowsLock.unlock()
        return count
    }

    // MARK: - XPC Interface

    func getStatus() -> [String: Any] {
        return [
            "isActive": isActive,
            "activeFlows": activeFlowCount(),
            "version": "1.0.0"
        ]
    }

    /// Set CA certificate via XPC (app sends cert+key to extension).
    func setCA(certData: Data, keyData: Data) -> Bool {
        guard let flowHandler = flowHandler else { return false }
        // tlsInterceptor is a let property on the actor; TLSInterceptor is @unchecked Sendable
        return flowHandler.tlsInterceptor.setCA(certData: certData, keyData: keyData)
    }
}
