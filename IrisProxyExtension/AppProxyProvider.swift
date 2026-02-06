//
//  AppProxyProvider.swift
//  IrisProxyExtension
//
//  NEAppProxyProvider subclass that intercepts TCP flows for HTTP/HTTPS inspection.
//

import Foundation
import NetworkExtension
import os.log

/// App Proxy Provider that intercepts network flows for HTTP/HTTPS inspection.
/// Uses NEAppProxyProvider to capture TCP connections and route them through
/// the local proxy server for TLS interception and HTTP parsing.
class AppProxyProvider: NEAppProxyProvider {

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "AppProxyProvider")

    /// XPC service for communication with the main app
    private let xpcService = ProxyXPCService()

    /// HTTP flow handler for processing intercepted connections
    private var flowHandler: FlowHandler?

    /// Active TCP flows being handled
    private var activeFlows: [UUID: NEAppProxyTCPFlow] = [:]
    private let flowsLock = NSLock()

    /// Whether the proxy is currently active
    private var isActive = false

    // MARK: - NEAppProxyProvider Lifecycle

    override func startProxy(options: [String: Any]? = nil) async throws {
        logger.info("Starting proxy extension...")

        // Start XPC service for communication with main app
        xpcService.provider = self
        xpcService.start()

        // Initialize flow handler
        flowHandler = FlowHandler(provider: self)

        isActive = true
        logger.info("Proxy extension started successfully")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        logger.info("Stopping proxy extension with reason: \(String(describing: reason))")

        isActive = false

        // Close all active flows
        flowsLock.lock()
        for (_, flow) in activeFlows {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        activeFlows.removeAll()
        flowsLock.unlock()

        // Stop XPC service
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

    /// Handles a new TCP flow.
    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            logger.error("TCP flow has no remote endpoint")
            return false
        }

        let flowId = UUID()
        let host = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0

        logger.info("New TCP flow: \(flowId) -> \(host):\(port)")

        // Get process info if available
        let processPath = flow.metaData.sourceAppSigningIdentifier
        let processName = processPath.components(separatedBy: ".").last ?? processPath

        // Store flow reference
        flowsLock.lock()
        activeFlows[flowId] = flow
        flowsLock.unlock()

        // Open the flow
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Failed to open flow \(flowId): \(error.localizedDescription)")
                self.removeFlow(flowId)
                return
            }

            // Hand off to flow handler for processing
            Task {
                await self.flowHandler?.handleFlow(
                    flowId: flowId,
                    flow: flow,
                    host: host,
                    port: port,
                    processName: processName
                )
            }
        }

        return true
    }

    /// Handles a UDP flow (currently just passes through).
    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        // For now, we don't intercept UDP traffic
        // Could be extended for DNS inspection in the future
        logger.debug("UDP flow received, passing through")

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to open UDP flow: \(error.localizedDescription)")
                return
            }
            // For UDP, we could implement DNS-over-HTTPS inspection here
            self?.relayUDPFlow(flow)
        }

        return true
    }

    /// Relays a UDP flow without inspection.
    private func relayUDPFlow(_ flow: NEAppProxyUDPFlow) {
        // Simple pass-through for UDP
        func readLoop() {
            flow.readDatagrams { datagrams, endpoints, error in
                if let error = error {
                    if (error as NSError).code != NEAppProxyFlowError.notConnected.rawValue {
                        // Only log if not a normal disconnection
                    }
                    return
                }

                guard let datagrams = datagrams, let endpoints = endpoints else {
                    return
                }

                flow.writeDatagrams(datagrams, sentBy: endpoints) { writeError in
                    if writeError == nil {
                        readLoop()
                    }
                }
            }
        }

        readLoop()
    }

    // MARK: - Flow Management

    /// Removes a flow from the active flows list.
    func removeFlow(_ flowId: UUID) {
        flowsLock.lock()
        if let flow = activeFlows.removeValue(forKey: flowId) {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        flowsLock.unlock()
    }

    /// Gets the count of active flows.
    func activeFlowCount() -> Int {
        flowsLock.lock()
        let count = activeFlows.count
        flowsLock.unlock()
        return count
    }

    // MARK: - XPC Interface

    /// Called by XPC service to get status.
    func getStatus() -> [String: Any] {
        return [
            "isActive": isActive,
            "activeFlows": activeFlowCount(),
            "version": "1.0.0"
        ]
    }
}

// MARK: - Flow Handler

/// Handles individual TCP flows for HTTP/HTTPS interception.
actor FlowHandler {

    private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "FlowHandler")
    private weak var provider: AppProxyProvider?

    /// HTTP parser for parsing requests and responses
    private let httpParser = HTTPParser()

    init(provider: AppProxyProvider) {
        self.provider = provider
    }

    /// Handles a TCP flow by determining if it's HTTP or HTTPS and processing accordingly.
    func handleFlow(
        flowId: UUID,
        flow: NEAppProxyTCPFlow,
        host: String,
        port: Int,
        processName: String
    ) async {
        logger.info("Handling flow \(flowId) to \(host):\(port) from \(processName)")

        // Determine if this is HTTPS (port 443) or HTTP
        let isHTTPS = port == 443

        if isHTTPS {
            await handleHTTPSFlow(flowId: flowId, flow: flow, host: host, port: port, processName: processName)
        } else {
            await handleHTTPFlow(flowId: flowId, flow: flow, host: host, port: port, processName: processName)
        }
    }

    /// Handles plain HTTP flow.
    private func handleHTTPFlow(
        flowId: UUID,
        flow: NEAppProxyTCPFlow,
        host: String,
        port: Int,
        processName: String
    ) async {
        logger.debug("Processing HTTP flow to \(host):\(port)")

        // For HTTP, we can directly parse the request/response
        // Read data from client
        await relayWithParsing(flowId: flowId, flow: flow, host: host, port: port, processName: processName, isSecure: false)
    }

    /// Handles HTTPS flow with TLS interception.
    private func handleHTTPSFlow(
        flowId: UUID,
        flow: NEAppProxyTCPFlow,
        host: String,
        port: Int,
        processName: String
    ) async {
        logger.debug("Processing HTTPS flow to \(host):\(port)")

        // For HTTPS, we need to:
        // 1. Accept the TLS connection from the client using a generated certificate
        // 2. Establish a TLS connection to the real server
        // 3. Relay and parse the decrypted HTTP traffic

        // For now, pass through without interception
        // Full TLS interception requires SwiftNIO SSL integration
        await relayWithoutParsing(flowId: flowId, flow: flow, host: host, port: port)
    }

    /// Relays flow data while parsing HTTP.
    private func relayWithParsing(
        flowId: UUID,
        flow: NEAppProxyTCPFlow,
        host: String,
        port: Int,
        processName: String,
        isSecure: Bool
    ) async {
        // Create connection to real server
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: UInt16(port)),
            using: .tcp
        )

        // Buffer for accumulating request data
        var requestBuffer = Data()

        // Start connection
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logger.debug("Connected to \(host):\(port)")
            case .failed(let error):
                self?.logger.error("Connection failed: \(error)")
            default:
                break
            }
        }

        connection.start(queue: .global())

        // Read from client and forward to server
        func readFromClient() {
            flow.readData { data, error in
                if let error = error {
                    if (error as NSError).code != NEAppProxyFlowError.notConnected.rawValue {
                        // Connection closed normally
                    }
                    connection.cancel()
                    return
                }

                guard let data = data, !data.isEmpty else {
                    connection.cancel()
                    return
                }

                // Accumulate request data for parsing
                requestBuffer.append(data)

                // Try to parse HTTP request
                if let request = HTTPParser.parseRequest(from: requestBuffer) {
                    // Log the request
                    Task { @MainActor in
                        // TODO: Send to XPC service
                    }
                }

                // Forward to server
                connection.send(content: data, completion: .contentProcessed { sendError in
                    if sendError == nil {
                        readFromClient()
                    }
                })
            }
        }

        // Read from server and forward to client
        func readFromServer() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error = error {
                    flow.closeReadWithError(error)
                    return
                }

                if let data = data, !data.isEmpty {
                    flow.write(data) { writeError in
                        if writeError == nil && !isComplete {
                            readFromServer()
                        }
                    }
                } else if isComplete {
                    flow.closeWriteWithError(nil)
                }
            }
        }

        // Start relay
        readFromClient()
        readFromServer()
    }

    /// Relays flow data without parsing (pass-through).
    private func relayWithoutParsing(
        flowId: UUID,
        flow: NEAppProxyTCPFlow,
        host: String,
        port: Int
    ) async {
        // Create connection to real server
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: UInt16(port)),
            using: .tcp
        )

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logger.debug("Connected to \(host):\(port) (pass-through)")
            case .failed(let error):
                self?.logger.error("Connection failed: \(error)")
            default:
                break
            }
        }

        connection.start(queue: .global())

        // Read from client and forward to server
        func readFromClient() {
            flow.readData { data, error in
                if let error = error {
                    connection.cancel()
                    return
                }

                guard let data = data, !data.isEmpty else {
                    connection.cancel()
                    return
                }

                connection.send(content: data, completion: .contentProcessed { sendError in
                    if sendError == nil {
                        readFromClient()
                    }
                })
            }
        }

        // Read from server and forward to client
        func readFromServer() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error = error {
                    flow.closeReadWithError(error)
                    return
                }

                if let data = data, !data.isEmpty {
                    flow.write(data) { writeError in
                        if writeError == nil && !isComplete {
                            readFromServer()
                        }
                    }
                } else if isComplete {
                    flow.closeWriteWithError(nil)
                }
            }
        }

        // Start relay
        readFromClient()
        readFromServer()
    }
}

// MARK: - NWConnection Import

import Network
