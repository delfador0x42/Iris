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
                capturedOutboundBytes: tracker.rawOutbound.count,
                capturedInboundBytes: tracker.rawInbound.count
            )
        }
    }

    func addRule(_ rule: SecurityRule) {
        rulesLock.lock()
        rules.append(rule)
        rulesLock.unlock()
    }

    func removeRule(id: UUID) -> Bool {
        rulesLock.lock()
        defer { rulesLock.unlock() }

        if let index = rules.firstIndex(where: { $0.id == id }) {
            rules.remove(at: index)
            return true
        }
        return false
    }

    func getRules() -> [SecurityRule] {
        rulesLock.lock()
        defer { rulesLock.unlock() }
        return rules
    }
}
