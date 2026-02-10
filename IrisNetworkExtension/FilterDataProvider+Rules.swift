import Foundation
import NetworkExtension
import os.log

// MARK: - Rule Evaluation & XPC API

extension FilterDataProvider {

    enum RuleVerdict {
        case allow
        case block
    }

    func evaluateRules(for connection: NetworkConnection) -> RuleVerdict {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        for rule in rules where rule.isActive {
            if rule.matches(connection: connection) {
                return rule.action == .block ? .block : .allow
            }
        }

        // Default: allow
        return .allow
    }

    // MARK: - Public API (for XPC)

    func getActiveConnections() -> [NetworkConnection] {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        return connections.values.map { tracker in
            let conn = tracker.connection
            return NetworkConnection(
                id: conn.id,
                processId: conn.processId,
                processPath: conn.processPath,
                processName: conn.processName,
                signingId: conn.signingId,
                localAddress: tracker.localAddress,
                localPort: tracker.localPort,
                remoteAddress: conn.remoteAddress,
                remotePort: conn.remotePort,
                remoteHostname: conn.remoteHostname,
                protocol: conn.protocol,
                state: conn.state,
                interface: conn.interface,
                bytesUp: tracker.bytesUp,
                bytesDown: tracker.bytesDown,
                timestamp: conn.timestamp,
                httpMethod: tracker.httpRequest?.method,
                httpPath: tracker.httpRequest?.path,
                httpHost: tracker.httpRequest?.host,
                httpContentType: tracker.httpRequest?.contentType,
                httpUserAgent: tracker.httpRequest?.userAgent,
                httpStatusCode: tracker.httpResponse?.statusCode,
                httpStatusReason: tracker.httpResponse?.reason,
                httpResponseContentType: tracker.httpResponse?.contentType,
                httpRawRequest: tracker.httpRequest?.rawHeaders,
                httpRawResponse: tracker.httpResponse?.rawHeaders,
                capturedOutboundBytes: tracker.captureSegments.filter { $0.direction == .outbound }.reduce(0) { $0 + $1.byteCount },
                capturedInboundBytes: tracker.captureSegments.filter { $0.direction == .inbound }.reduce(0) { $0 + $1.byteCount }
            )
        }
    }

    func addRule(_ rule: SecurityRule) {
        rulesLock.lock()
        rules.append(rule)
        RulePersistence.save(rules)
        rulesLock.unlock()
    }

    func removeRule(id: UUID) -> Bool {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        if let index = rules.firstIndex(where: { $0.id == id }) {
            rules.remove(at: index)
            RulePersistence.save(rules)
            return true
        }
        return false
    }

    func updateRule(_ updatedRule: SecurityRule) -> Bool {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        if let index = rules.firstIndex(where: { $0.id == updatedRule.id }) {
            rules[index] = updatedRule
            RulePersistence.save(rules)
            return true
        }
        return false
    }

    func toggleRule(id: UUID) -> Bool {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        if let index = rules.firstIndex(where: { $0.id == id }) {
            rules[index].isEnabled.toggle()
            RulePersistence.save(rules)
            return true
        }
        return false
    }

    func cleanupExpiredRules() -> Int {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        let before = rules.count
        rules.removeAll { $0.isExpired }
        if rules.count != before {
            RulePersistence.save(rules)
        }
        return before - rules.count
    }

    func loadPersistedRules() {
        rulesLock.lock()
        defer { rulesLock.unlock() }
        rules = RulePersistence.load()
    }

    func getRules() -> [SecurityRule] {
        rulesLock.lock()
        defer { rulesLock.unlock() }
        return rules
    }
}
