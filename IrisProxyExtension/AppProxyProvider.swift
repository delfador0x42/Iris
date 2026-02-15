//
//  AppProxyProvider.swift
//  IrisProxyExtension
//
//  NETransparentProxyProvider that intercepts ALL outbound TCP and UDP flows.
//  HTTP/HTTPS flows get MITM inspection. All other flows get passthrough relay
//  with metadata capture. Returning true claims the flow — we MUST proxy it.
//

import Foundation
import Network
import NetworkExtension
import os.log

/// Transparent proxy that intercepts all outbound network traffic.
/// TCP port 80/443: HTTP parsing + MITM. All other TCP: passthrough relay.
/// UDP: datagram relay. All flows get metadata captured for the proxy monitor.
class AppProxyProvider: NETransparentProxyProvider {

  private let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "AppProxyProvider")

  /// XPC service for communication with the main app
  let xpcService = ProxyXPCService()

  /// Flow handler for processing intercepted connections
  private var flowHandler: FlowHandler?

  /// Active TCP flows being handled
  private var activeFlows: [UUID: NEAppProxyTCPFlow] = [:]
  private let flowsLock = NSLock()

  /// Active UDP flows being handled
  private var activeUDPFlows: [UUID: NEAppProxyUDPFlow] = [:]
  private let udpFlowsLock = NSLock()

  /// Whether the proxy is currently active
  private var isActive = false

  // MARK: - Lifecycle

  override func startProxy(options: [String: Any]? = nil) async throws {
    logger.info("Starting transparent proxy extension...")
    xpcService.provider = self
    xpcService.start()
    flowHandler = FlowHandler(provider: self)

    // Route ALL outbound TCP and UDP to this extension.
    let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
    settings.includedNetworkRules = [
      NENetworkRule(
        remoteNetwork: nil, remotePrefix: 0,
        localNetwork: nil, localPrefix: 0,
        protocol: .TCP, direction: .outbound
      ),
      NENetworkRule(
        remoteNetwork: nil, remotePrefix: 0,
        localNetwork: nil, localPrefix: 0,
        protocol: .UDP, direction: .outbound
      ),
    ]
    try await setTunnelNetworkSettings(settings)

    isActive = true
    logger.info("Transparent proxy started — intercepting all TCP + UDP")
  }

  override func stopProxy(with reason: NEProviderStopReason) async {
    logger.info("Stopping transparent proxy: \(String(describing: reason))")
    isActive = false
    closeAndRemoveAllFlows()
    xpcService.stop()
    flowHandler = nil
    logger.info("Transparent proxy stopped")
  }

  /// Closes all active flows under lock.
  private func closeAndRemoveAllFlows() {
    flowsLock.lock()
    for (_, flow) in activeFlows {
      flow.closeReadWithError(nil)
      flow.closeWriteWithError(nil)
    }
    activeFlows.removeAll()
    flowsLock.unlock()

    udpFlowsLock.lock()
    for (_, flow) in activeUDPFlows {
      flow.closeReadWithError(nil)
      flow.closeWriteWithError(nil)
    }
    activeUDPFlows.removeAll()
    udpFlowsLock.unlock()
  }

  // MARK: - Flow Handling

  override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
    guard isActive else { return false }

    if let tcpFlow = flow as? NEAppProxyTCPFlow {
      return handleTCPFlow(tcpFlow)
    }
    if let udpFlow = flow as? NEAppProxyUDPFlow {
      return handleUDPFlow(udpFlow)
    }
    return false
  }

  // MARK: - TCP

  private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
    guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
      logger.error("TCP flow has no remote endpoint")
      return false
    }

    let port = Int(remoteEndpoint.port) ?? 0
    let flowId = UUID()
    let host = remoteEndpoint.hostname
    let processPath = flow.metaData.sourceAppSigningIdentifier
    let processName = processPath.components(separatedBy: ".").last ?? processPath

    flowsLock.lock()
    activeFlows[flowId] = flow
    flowsLock.unlock()

    flow.open(withLocalEndpoint: nil) { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        self.logger.error("Failed to open TCP flow \(flowId): \(error.localizedDescription)")
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

  // MARK: - UDP

  private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
    let flowId = UUID()
    let processPath = flow.metaData.sourceAppSigningIdentifier
    let processName = processPath.components(separatedBy: ".").last ?? processPath

    udpFlowsLock.lock()
    activeUDPFlows[flowId] = flow
    udpFlowsLock.unlock()

    flow.open(withLocalEndpoint: nil) { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        self.logger.error("Failed to open UDP flow \(flowId): \(error.localizedDescription)")
        self.removeUDPFlow(flowId)
        return
      }
      Task {
        await self.flowHandler?.handleUDPFlow(
          flowId: flowId, flow: flow, processName: processName
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

  func removeUDPFlow(_ flowId: UUID) {
    udpFlowsLock.lock()
    if let flow = activeUDPFlows.removeValue(forKey: flowId) {
      flow.closeReadWithError(nil)
      flow.closeWriteWithError(nil)
    }
    udpFlowsLock.unlock()
  }

  func activeFlowCount() -> Int {
    flowsLock.lock()
    let tcp = activeFlows.count
    flowsLock.unlock()
    udpFlowsLock.lock()
    let udp = activeUDPFlows.count
    udpFlowsLock.unlock()
    return tcp + udp
  }

  // MARK: - XPC Interface

  func getStatus() -> [String: Any] {
    return [
      "isActive": isActive,
      "activeFlows": activeFlowCount(),
      "version": "2.0.0",
    ]
  }

  func setCA(certData: Data, keyData: Data) -> Bool {
    guard let flowHandler = flowHandler else { return false }
    return flowHandler.tlsInterceptor.setCA(certData: certData, keyData: keyData)
  }
}
