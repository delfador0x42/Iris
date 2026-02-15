//
//  FlowHandler.swift
//  IrisProxyExtension
//
//  Actor that handles individual TCP and UDP flows.
//  Routes TCP to MITM (443), HTTP relay (80), or passthrough (everything else).
//  Routes UDP to datagram relay.
//

import Foundation
import Network
import NetworkExtension
import os.log

/// Handles all intercepted network flows.
/// TCP 443 → HTTPS MITM, TCP 80 → HTTP relay, other TCP → passthrough, UDP → datagram relay.
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
    if port == 443 {
      await handleHTTPSFlow(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
    } else if port == 80 {
      await handleHTTPFlow(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
    } else {
      await relayPassthrough(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
    }
  }

  // MARK: - HTTP Flow (Plaintext)

  func handleHTTPFlow(
    flowId: UUID, flow: NEAppProxyTCPFlow,
    host: String, port: Int, processName: String
  ) async {
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
    guard tlsInterceptor.isAvailable else {
      logger.warning("TLS not available, passthrough for \(host)")
      await relayPassthrough(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
      return
    }

    guard let (identity, _) = tlsInterceptor.getCertificate(for: host) else {
      logger.error("Failed to generate certificate for \(host)")
      await relayPassthrough(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
      return
    }

    let clientTLS: TLSSession
    do {
      clientTLS = try TLSSession(flow: flow, identity: identity, isServer: true)
    } catch {
      logger.error("TLS session failed for \(host): \(error.localizedDescription)")
      await relayPassthrough(
        flowId: flowId, flow: flow, host: host, port: port, processName: processName)
      return
    }

    do {
      try await clientTLS.handshake()
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

    await relayMITM(
      flowId: flowId, flow: flow,
      clientTLS: clientTLS, serverConnection: serverConnection,
      host: host, port: port, processName: processName
    )
  }

  // MARK: - UDP Flow

  func handleUDPFlow(
    flowId: UUID, flow: NEAppProxyUDPFlow,
    processName: String
  ) async {
    await relayUDP(flowId: flowId, flow: flow, processName: processName)
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
          let resumed = AtomicFlag()
          connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
              guard resumed.trySet() else { return }
              connection.stateUpdateHandler = nil
              continuation.resume(returning: true)
            case .failed, .cancelled:
              guard resumed.trySet() else { return }
              connection.stateUpdateHandler = nil
              continuation.resume(returning: false)
            default:
              break
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
