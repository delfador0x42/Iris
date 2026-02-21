//
//  ProxyXPCService+FlowManagement.swift
//  IrisProxyExtension
//
//  Flow management and XPC listener delegate for ProxyXPCService.
//

import Foundation
import Security
import os.log

// MARK: - Flow Management

extension ProxyXPCService {

  /// Adds a captured flow with a sequence number for delta tracking.
  func addFlow(_ flow: ProxyCapturedFlow) {
    flowsLock.lock()
    defer { flowsLock.unlock() }

    var stamped = flow
    stamped.sequenceNumber = nextSequenceNumber
    nextSequenceNumber += 1

    capturedFlows.append(stamped)

    // Trim if over limit — removeFirst is O(n), so batch evict to amortize
    if capturedFlows.count > maxFlows + maxFlows / 10 {
      capturedFlows = Array(capturedFlows.suffix(maxFlows))
    }

    // Notify connected clients
    notifyFlowUpdate(stamped)
  }

  /// Updates an existing flow (e.g., when response arrives).
  /// Bumps the sequence number so delta fetch picks up the update.
  /// requestBodySize: actual bytes of request body (may exceed initial capture for chunked/streaming).
  func updateFlow(_ flowId: UUID, response: ProxyCapturedResponse, requestBodySize: Int64 = 0) {
    flowsLock.lock()
    defer { flowsLock.unlock() }

    if let index = capturedFlows.firstIndex(where: { $0.id == flowId }) {
      capturedFlows[index].response = response
      if requestBodySize > 0 {
        capturedFlows[index].requestBodySize = requestBodySize
      }
      capturedFlows[index].sequenceNumber = nextSequenceNumber
      nextSequenceNumber += 1
      notifyFlowUpdate(capturedFlows[index])
    }
  }

  /// Marks a flow as completed with final byte counts.
  /// Used by passthrough (TCP) and UDP relays when the connection closes.
  func completeFlow(_ flowId: UUID, bytesIn: Int64, bytesOut: Int64, error: String?) {
    flowsLock.lock()
    defer { flowsLock.unlock() }

    if let index = capturedFlows.firstIndex(where: { $0.id == flowId }) {
      capturedFlows[index].bytesIn = bytesIn
      capturedFlows[index].bytesOut = bytesOut
      capturedFlows[index].endTimestamp = Date()
      if let error = error { capturedFlows[index].error = error }
      capturedFlows[index].sequenceNumber = nextSequenceNumber
      nextSequenceNumber += 1
      notifyFlowUpdate(capturedFlows[index])
    }
  }

  /// Notifies connected clients about a flow update.
  /// Currently a no-op: the main app polls via getFlowsSince() delta fetch,
  /// which already provides low-latency updates. Push would save a poll cycle
  /// but requires a reverse XPC callback interface.
  func notifyFlowUpdate(_ flow: ProxyCapturedFlow) {
  }
}

// MARK: - NSXPCListenerDelegate

extension ProxyXPCService: NSXPCListenerDelegate {

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {

    let pid = newConnection.processIdentifier
    guard verifyCodeSignature(pid: pid) else {
      logger.error("XPC: rejected connection from PID \(pid) — failed code signing check")
      return false
    }

    newConnection.exportedInterface = NSXPCInterface(with: ProxyXPCProtocol.self)
    newConnection.exportedObject = self

    newConnection.invalidationHandler = { [weak self] in
      self?.connectionInvalidated(newConnection)
    }

    xpcConnectionsLock.lock()
    defer { xpcConnectionsLock.unlock() }
    activeConnections.append(newConnection)

    newConnection.resume()
    logger.info("XPC connection accepted from PID \(pid)")

    return true
  }

  private func verifyCodeSignature(pid: pid_t) -> Bool {
    var code: SecCode?
    let attrs = [kSecGuestAttributePid: pid] as NSDictionary
    let copyResult = SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code)
    guard copyResult == errSecSuccess, let guestCode = code else {
      logger.error("XPC: SecCodeCopyGuestWithAttributes FAILED for PID \(pid): \(copyResult)")
      return false
    }
    var requirement: SecRequirement?
    let reqStr =
      "anchor apple generic and certificate leaf[subject.OU] = \"99HGW2AR62\"" as CFString
    guard SecRequirementCreateWithString(reqStr, SecCSFlags(), &requirement) == errSecSuccess,
      let req = requirement
    else {
      logger.error("XPC: SecRequirementCreateWithString FAILED")
      return false
    }
    let checkResult = SecCodeCheckValidity(guestCode, SecCSFlags(), req)
    if checkResult != errSecSuccess {
      logger.error("XPC: SecCodeCheckValidity FAILED for PID \(pid): \(checkResult)")
    }
    return checkResult == errSecSuccess
  }

  func connectionInvalidated(_ connection: NSXPCConnection) {
    xpcConnectionsLock.lock()
    defer { xpcConnectionsLock.unlock() }
    activeConnections.removeAll { $0 === connection }

    logger.info("XPC connection invalidated")
  }
}
