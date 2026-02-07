//
//  FlowHandler.swift
//  IrisProxyExtension
//
//  Actor that handles individual TCP flows for HTTP/HTTPS interception.
//  Routes flows to MITM relay (HTTPS) or plaintext relay (HTTP).
//

import Foundation
import Network
import NetworkExtension
import os.log

/// Handles individual TCP flows for HTTP/HTTPS interception.
/// For HTTPS: performs TLS MITM using SSLCreateContext (client-facing) + NWConnection TLS (server-facing)
/// For HTTP: relays plaintext while parsing and capturing flows
actor FlowHandler {

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "FlowHandler")
    weak var provider: AppProxyProvider?
    let tlsInterceptor = TLSInterceptor()

    init(provider: AppProxyProvider) {
        self.provider = provider
    }

    /// Valid port range for network connections
    static let validPortRange = 1...65535

    /// Routes a TCP flow to the appropriate handler based on port.
    func handleFlow(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        host: String, port: Int, processName: String
    ) async {
        guard Self.validPortRange.contains(port) else {
            logger.error("Invalid port \(port) for \(host), dropping flow")
            provider?.removeFlow(flowId)
            return
        }
        logger.info("Handling flow \(flowId) to \(host):\(port) from \(processName)")
        if port == 443 {
            await handleHTTPSFlow(flowId: flowId, flow: flow, host: host, port: port, processName: processName)
        } else {
            await handleHTTPFlow(flowId: flowId, flow: flow, host: host, port: port, processName: processName)
        }
    }

    // MARK: - HTTP Flow (Plaintext)

    func handleHTTPFlow(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        host: String, port: Int, processName: String
    ) async {
        logger.debug("Processing HTTP flow to \(host):\(port)")
        let serverConnection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port))!,
            using: .tcp
        )

        guard await waitForConnection(serverConnection) else {
            logger.error("Failed to connect to \(host):\(port)")
            provider?.removeFlow(flowId)
            return
        }

        await relayAndCapture(
            flowId: flowId, flow: flow, serverConnection: serverConnection,
            host: host, port: port, processName: processName, isSecure: false
        )
    }

    // MARK: - HTTPS Flow (TLS MITM)

    func handleHTTPSFlow(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        host: String, port: Int, processName: String
    ) async {
        logger.debug("Processing HTTPS flow to \(host):\(port)")

        guard tlsInterceptor.isAvailable else {
            logger.warning("TLS interception not available, falling back to pass-through")
            await relayPassthrough(flowId: flowId, flow: flow, host: host, port: port)
            return
        }

        guard let (identity, _) = tlsInterceptor.getCertificate(for: host) else {
            logger.error("Failed to generate certificate for \(host)")
            await relayPassthrough(flowId: flowId, flow: flow, host: host, port: port)
            return
        }

        let clientTLS: TLSSession
        do {
            clientTLS = try TLSSession(flow: flow, identity: identity, isServer: true)
        } catch {
            logger.error("Failed to create TLS session for \(host): \(error.localizedDescription)")
            await relayPassthrough(flowId: flowId, flow: flow, host: host, port: port)
            return
        }

        do {
            try await clientTLS.handshake()
            logger.info("TLS handshake completed with client for \(host)")
        } catch {
            logger.error("TLS handshake failed for \(host): \(error.localizedDescription)")
            clientTLS.close()
            provider?.removeFlow(flowId)
            return
        }

        let tlsParams = tlsInterceptor.createClientTLSParameters(for: host)
        let serverConnection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port))!,
            using: tlsParams
        )

        guard await waitForConnection(serverConnection) else {
            logger.error("Failed to connect to real server \(host):\(port)")
            clientTLS.close()
            provider?.removeFlow(flowId)
            return
        }

        logger.info("TLS MITM established for \(host)")
        await relayMITM(
            flowId: flowId, flow: flow,
            clientTLS: clientTLS, serverConnection: serverConnection,
            host: host, port: port, processName: processName
        )
    }

    /// Connection establishment timeout
    static let connectionTimeout: TimeInterval = 15

    /// Max time a relay can be idle (no data in either direction)
    static let idleTimeout: TimeInterval = 60

    /// Max total relay lifetime
    static let maxRelayDuration: TimeInterval = 300

    // MARK: - Connection Helper

    func waitForConnection(_ connection: NWConnection) async -> Bool {
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await withCheckedContinuation { continuation in
                    let resumed = NSLock()
                    var hasResumed = false
                    connection.stateUpdateHandler = { state in
                        resumed.lock()
                        guard !hasResumed else {
                            resumed.unlock()
                            return
                        }
                        switch state {
                        case .ready:
                            hasResumed = true
                            resumed.unlock()
                            connection.stateUpdateHandler = nil
                            continuation.resume(returning: true)
                        case .failed, .cancelled:
                            hasResumed = true
                            resumed.unlock()
                            connection.stateUpdateHandler = nil
                            continuation.resume(returning: false)
                        default:
                            resumed.unlock()
                        }
                    }
                    connection.start(queue: .global(qos: .userInitiated))
                }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(Self.connectionTimeout * 1_000_000_000))
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            if !result { connection.cancel() }
            return result
        }
    }
}
