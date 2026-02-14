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
        let flowCount = capturedFlows.count
        flowsLock.unlock()
        status["flowCount"] = flowCount
        status["interceptionEnabled"] = interceptionEnabled

        reply(status)
    }

    func getFlows(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getFlows")

        flowsLock.lock()
        let flows = capturedFlows
        flowsLock.unlock()

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = flows.compactMap { try? encoder.encode($0) }
        reply(data)
    }

    func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void) {
        flowsLock.lock()
        let currentSeq = nextSequenceNumber - 1
        let changed = capturedFlows.filter { $0.sequenceNumber > sinceSeq }
        flowsLock.unlock()

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = changed.compactMap { try? encoder.encode($0) }

        logger.debug("XPC: getFlowsSince(\(sinceSeq)) → \(data.count) changed, seq=\(currentSeq)")
        reply(currentSeq, data)
    }

    func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void) {
        logger.debug("XPC: getFlow(\(flowId))")

        guard let uuid = UUID(uuidString: flowId) else {
            reply(nil)
            return
        }

        flowsLock.lock()
        let flow = capturedFlows.first { $0.id == uuid }
        flowsLock.unlock()

        guard let flow = flow else {
            reply(nil)
            return
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        reply(try? encoder.encode(flow))
    }

    func clearFlows(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: clearFlows")

        flowsLock.lock()
        capturedFlows.removeAll()
        flowsLock.unlock()

        reply(true)
    }

    func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setInterceptionEnabled(\(enabled))")
        interceptionEnabled = enabled
        reply(true)
    }

    func isInterceptionEnabled(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: isInterceptionEnabled")
        reply(interceptionEnabled)
    }

    func setCA(_ certData: Data, keyData: Data, reply: @escaping (Bool) -> Void) {
        logger.info("XPC: setCA (cert: \(certData.count) bytes, key: \(keyData.count) bytes)")
        let success = provider?.setCA(certData: certData, keyData: keyData) ?? false
        logger.info("XPC: setCA result: \(success)")
        reply(success)
    }
}
