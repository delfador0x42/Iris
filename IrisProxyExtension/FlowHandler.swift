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

    /// Routes a TCP flow to the appropriate handler based on port.
    func handleFlow(
        flowId: UUID, flow: NEAppProxyTCPFlow,
        host: String, port: Int, processName: String
    ) async {
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
            port: NWEndpoint.Port(integerLiteral: UInt16(port)),
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
            port: NWEndpoint.Port(integerLiteral: UInt16(port)),
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

    // MARK: - Connection Helper

    func waitForConnection(_ connection: NWConnection) async -> Bool {
        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.stateUpdateHandler = nil
                    continuation.resume(returning: true)
                case .failed, .cancelled:
                    connection.stateUpdateHandler = nil
                    continuation.resume(returning: false)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }
    }
}
