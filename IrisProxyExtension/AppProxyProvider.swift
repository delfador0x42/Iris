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

    /// Whether the proxy is currently active
    private var isActive = false

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

        flowsLock.lock()
        for (_, flow) in activeFlows {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        activeFlows.removeAll()
        flowsLock.unlock()

        xpcService.stop()
        flowHandler = nil
        logger.info("Proxy extension stopped")
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
        logger.debug("UDP flow received, passing through")
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                return
            }
            self?.relayUDPFlow(flow)
        }
        return true
    }

    private func relayUDPFlow(_ flow: NEAppProxyUDPFlow) {
        func readLoop() {
            flow.readDatagrams { datagrams, endpoints, error in
                if error != nil { return }
                guard let datagrams = datagrams, let endpoints = endpoints else { return }
                flow.writeDatagrams(datagrams, sentBy: endpoints) { writeError in
                    if writeError == nil { readLoop() }
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
}
