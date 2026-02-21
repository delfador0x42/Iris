//
//  ProxyXPCService+XPCProtocol.swift
//  IrisProxyExtension
//
//  ProxyXPCProtocol conformance for ProxyXPCService.
//

import Foundation
import os.log

// MARK: - ProxyExtensionXPCProtocol

extension ProxyXPCService: ProxyXPCProtocol {

  func getStatus(reply: @escaping ([String: Any]) -> Void) {
    logger.debug("XPC: getStatus")

    var status = provider?.getStatus() ?? [:]
    flowsLock.lock()
    defer { flowsLock.unlock() }
    let flowCount = capturedFlows.count
    status["flowCount"] = flowCount
    status["interceptionEnabled"] = interceptionEnabled

    reply(status)
  }

  func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void) {
    // Snapshot under lock, encode outside to avoid blocking flow recording
    flowsLock.lock()
    let currentSeq = nextSequenceNumber - 1
    let changed = capturedFlows.filter { $0.sequenceNumber > sinceSeq }
    flowsLock.unlock()

    let data = changed.compactMap { try? Self.jsonEncoder.encode($0) }

    logger.debug("XPC: getFlowsSince(\(sinceSeq)) → \(data.count) changed, seq=\(currentSeq)")
    reply(currentSeq, data)
  }

  func clearFlows(reply: @escaping (Bool) -> Void) {
    logger.debug("XPC: clearFlows")

    flowsLock.lock()
    defer { flowsLock.unlock() }
    capturedFlows.removeAll()

    reply(true)
  }

  func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
    logger.debug("XPC: setInterceptionEnabled(\(enabled))")
    interceptionEnabled = enabled
    reply(true)
  }

  func setCA(_ certData: Data, keyData: Data, reply: @escaping (Bool) -> Void) {
    logger.info("XPC: setCA (cert: \(certData.count) bytes, key: \(keyData.count) bytes)")
    let success = provider?.setCA(certData: certData, keyData: keyData) ?? false
    logger.info("XPC: setCA result: \(success)")
    reply(success)
  }

}
