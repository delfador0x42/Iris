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
        status["flowCount"] = capturedFlows.count
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
}
