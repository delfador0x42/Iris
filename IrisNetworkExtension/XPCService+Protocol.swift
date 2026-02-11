import Foundation
import os.log

// MARK: - NetworkXPCProtocol Implementation

extension XPCService: NetworkXPCProtocol {

    func getConnections(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getConnections")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let connections = provider.getActiveConnections()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = connections.compactMap { connection -> Data? in
            try? encoder.encode(connection)
        }

        reply(data)
    }

    func getConnections(forPid pid: Int32, reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getConnections(forPid: \(pid))")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let connections = provider.getActiveConnections().filter { $0.processId == pid }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let data = connections.compactMap { connection -> Data? in
            try? encoder.encode(connection)
        }

        reply(data)
    }

    func getRules(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getRules")

        guard let provider = filterProvider else {
            reply([])
            return
        }

        let rules = provider.getRules()
        let encoder = JSONEncoder()

        let data = rules.compactMap { try? encoder.encode($0) }
        reply(data)
    }

    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: addRule")

        guard let provider = filterProvider else {
            reply(false, "Filter provider not available")
            return
        }

        do {
            let decoder = JSONDecoder()
            let rule = try decoder.decode(SecurityRule.self, from: ruleData)
            provider.addRule(rule)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: updateRule")

        guard let provider = filterProvider else {
            reply(false, "Filter provider not available")
            return
        }

        do {
            let decoder = JSONDecoder()
            let rule = try decoder.decode(SecurityRule.self, from: ruleData)
            let success = provider.updateRule(rule)
            reply(success, success ? nil : "Rule not found")
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: removeRule(\(ruleId))")

        guard let provider = filterProvider,
              let uuid = UUID(uuidString: ruleId) else {
            reply(false)
            return
        }

        let success = provider.removeRule(id: uuid)
        reply(success)
    }

    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: toggleRule(\(ruleId))")

        guard let provider = filterProvider,
              let uuid = UUID(uuidString: ruleId) else {
            reply(false)
            return
        }

        reply(provider.toggleRule(id: uuid))
    }

    func cleanupExpiredRules(reply: @escaping (Int) -> Void) {
        logger.debug("XPC: cleanupExpiredRules")

        guard let provider = filterProvider else {
            reply(0)
            return
        }

        reply(provider.cleanupExpiredRules())
    }

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        logger.debug("XPC: getStatus")

        let status: [String: Any] = [
            "version": "1.0.0",
            "filterEnabled": true,
            "esEnabled": true,
            "connectionCount": filterProvider?.getActiveConnections().count ?? 0,
            "ruleCount": filterProvider?.getRules().count ?? 0
        ]

        reply(status)
    }

    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setFilteringEnabled(\(enabled))")
        // TODO: Implement filter enable/disable
        reply(true)
    }

    // MARK: - Raw Data Capture

    func getConnectionRawData(_ connectionId: String, reply: @escaping (Data?, Data?) -> Void) {
        guard let provider = filterProvider,
              let uuid = UUID(uuidString: connectionId) else {
            reply(nil, nil)
            return
        }
        let (outbound, inbound) = provider.getRawData(for: uuid)
        reply(outbound, inbound)
    }

    func getConnectionConversation(_ connectionId: String, reply: @escaping (Data?) -> Void) {
        guard let provider = filterProvider,
              let uuid = UUID(uuidString: connectionId) else {
            reply(nil)
            return
        }
        let segments = provider.getConversation(for: uuid)
        guard !segments.isEmpty else {
            reply(nil)
            return
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        reply(try? encoder.encode(segments))
    }

    func setCaptureMemoryBudget(_ bytes: Int, reply: @escaping (Bool) -> Void) {
        logger.info("XPC: setCaptureMemoryBudget(\(bytes))")
        guard let provider = filterProvider, bytes > 0 else {
            reply(false)
            return
        }
        provider.captureMemoryBudget = bytes
        reply(true)
    }

    func getCaptureStats(reply: @escaping ([String: Any]) -> Void) {
        guard let provider = filterProvider else {
            reply([:])
            return
        }
        reply(provider.getCaptureStats())
    }
}
