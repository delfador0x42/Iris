//
//  AppProxyProvider.swift
//  IrisProxyExtension
//
//  NEAppProxyProvider subclass that intercepts TCP flows for HTTP/HTTPS inspection.
//

import Foundation
import Network
import NetworkExtension
import os.log

/// App Proxy Provider that intercepts network flows for HTTP/HTTPS inspection.
class AppProxyProvider: NEAppProxyProvider {

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "AppProxyProvider")

    /// XPC service for communication with the main app
    let xpcService = ProxyXPCService()

    /// HTTP flow handler for processing intercepted connections
    private var flowHandler: FlowHandler?

    /// Active TCP flows being handled
    private var activeFlows: [UUID: NEAppProxyTCPFlow] = [:]
    private let flowsLock = NSLock()

    /// Active UDP flows (tracked for cleanup)
    private var activeUDPFlows: [UUID: NEAppProxyUDPFlow] = [:]

    /// Whether the proxy is currently active
    private var isActive = false

    /// Max duration for UDP relay (5 minutes)
    private static let udpRelayTimeout: UInt64 = 300_000_000_000

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil) async throws {
        logger.info("Starting proxy extension...")
        xpcService.provider = self
        xpcService.start()
        flowHandler = FlowHandler(provider: self)
        isActive = true
        logger.info("Proxy extension started successfully")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        logger.info("Stopping proxy extension with reason: \(String(describing: reason))")
        isActive = false
        closeAndRemoveAllFlows()
        xpcService.stop()
        flowHandler = nil
        logger.info("Proxy extension stopped")
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
        for (_, flow) in activeUDPFlows {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        activeUDPFlows.removeAll()
        flowsLock.unlock()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard isActive else {
            logger.warning("Received flow while proxy is inactive")
            return false
        }
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }
        logger.warning("Unknown flow type received")
        return false
    }

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            logger.error("TCP flow has no remote endpoint")
            return false
        }

        let flowId = UUID()
        let host = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0
        let processPath = flow.metaData.sourceAppSigningIdentifier
        let processName = processPath.components(separatedBy: ".").last ?? processPath

        logger.info("New TCP flow: \(flowId) -> \(host):\(port)")

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

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        let flowId = UUID()
        logger.debug("UDP flow \(flowId) received, passing through")

        flowsLock.lock()
        activeUDPFlows[flowId] = flow
        flowsLock.unlock()

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                self?.removeUDPFlow(flowId)
                return
            }
            self?.relayUDPFlow(flow, flowId: flowId)
        }
        return true
    }

    private func relayUDPFlow(_ flow: NEAppProxyUDPFlow, flowId: UUID) {
        let closedFlag = AtomicFlag()

        // Schedule cleanup after timeout
        Task {
            try? await Task.sleep(nanoseconds: Self.udpRelayTimeout)
            _ = closedFlag.trySet()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            removeUDPFlow(flowId)
        }

        func readLoop() {
            if closedFlag.isSet { return }

            flow.readDatagrams { [weak self] datagrams, endpoints, error in
                if error != nil {
                    self?.removeUDPFlow(flowId)
                    return
                }
                guard let datagrams = datagrams, let endpoints = endpoints else {
                    self?.removeUDPFlow(flowId)
                    return
                }
                let count = min(datagrams.count, endpoints.count)
                guard count > 0 else {
                    self?.removeUDPFlow(flowId)
                    return
                }
                flow.writeDatagrams(
                    Array(datagrams.prefix(count)),
                    sentBy: Array(endpoints.prefix(count))
                ) { writeError in
                    if writeError == nil { readLoop() }
                    else { self?.removeUDPFlow(flowId) }
                }
            }
        }
        readLoop()
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

    private func removeUDPFlow(_ flowId: UUID) {
        flowsLock.lock()
        activeUDPFlows.removeValue(forKey: flowId)
        flowsLock.unlock()
    }

    func activeFlowCount() -> Int {
        flowsLock.lock()
        let count = activeFlows.count + activeUDPFlows.count
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
}
