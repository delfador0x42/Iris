//
//  ProxyXPCService+Network.swift
//  IrisProxyExtension
//
//  Network monitoring and firewall rule XPC protocol conformance.
//  Absorbed from IrisNetworkExtension.
//

import Foundation
import os.log

// MARK: - Connection Tracker

/// Tracks metadata for a monitored connection.
struct ConnectionTracker {
    let connection: NetworkConnection
    var bytesUp: UInt64 = 0
    var bytesDown: UInt64 = 0
    var localAddress: String
    var localPort: UInt16
    let flowId: UUID
    var lastActivity: Date = Date()

    // HTTP tracking
    var httpRequest: ParsedHTTPRequest?
    var httpResponse: ParsedHTTPResponse?
    var isHTTPParsed: Bool = false

    // Capture segments
    var captureSegments: [CaptureSegment] = []
    // Running totals — avoids O(segments) recomputation on every XPC poll
    var capturedOutboundBytes: Int = 0
    var capturedInboundBytes: Int = 0
}

struct ParsedHTTPRequest: Codable {
    let method: String
    let path: String
    let host: String?
    let contentType: String?
    let userAgent: String?
    let rawHeaders: String
}

struct ParsedHTTPResponse: Codable {
    let statusCode: Int
    let reason: String
    let contentType: String?
    let contentLength: Int?
    let rawHeaders: String
}

// MARK: - Connection Monitoring XPC

extension ProxyXPCService {

    func getConnections(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getConnections")

        // Snapshot under lock, encode outside to avoid blocking flow handling
        networkLock.lock()
        let snapshot = connections.values.map { tracker -> NetworkConnection in
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
                capturedOutboundBytes: tracker.capturedOutboundBytes,
                capturedInboundBytes: tracker.capturedInboundBytes
            )
        }
        networkLock.unlock()

        let data = snapshot.compactMap { try? Self.jsonEncoder.encode($0) }
        reply(data)
    }

    // MARK: - Firewall Rules XPC

    func getRules(reply: @escaping ([Data]) -> Void) {
        logger.debug("XPC: getRules")
        rulesLock.lock()
        let snapshot = securityRules
        rulesLock.unlock()

        let data = snapshot.compactMap { try? Self.jsonEncoder.encode($0) }
        reply(data)
    }

    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: addRule")
        let decoder = JSONDecoder()
        guard let rule = try? decoder.decode(SecurityRule.self, from: ruleData) else {
            reply(false, "Invalid rule data")
            return
        }
        rulesLock.lock()
        securityRules.append(rule)
        RulePersistence.save(securityRules)
        rulesLock.unlock()
        reply(true, nil)
    }

    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        logger.debug("XPC: updateRule")
        let decoder = JSONDecoder()
        guard let updatedRule = try? decoder.decode(SecurityRule.self, from: ruleData) else {
            reply(false, "Invalid rule data")
            return
        }
        rulesLock.lock()
        if let index = securityRules.firstIndex(where: { $0.id == updatedRule.id }) {
            securityRules[index] = updatedRule
            RulePersistence.save(securityRules)
            rulesLock.unlock()
            reply(true, nil)
        } else {
            rulesLock.unlock()
            reply(false, "Rule not found")
        }
    }

    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: removeRule(\(ruleId))")
        guard let uuid = UUID(uuidString: ruleId) else {
            reply(false)
            return
        }
        rulesLock.lock()
        if let index = securityRules.firstIndex(where: { $0.id == uuid }) {
            securityRules.remove(at: index)
            RulePersistence.save(securityRules)
            rulesLock.unlock()
            reply(true)
        } else {
            rulesLock.unlock()
            reply(false)
        }
    }

    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: toggleRule(\(ruleId))")
        guard let uuid = UUID(uuidString: ruleId) else {
            reply(false)
            return
        }
        rulesLock.lock()
        if let index = securityRules.firstIndex(where: { $0.id == uuid }) {
            securityRules[index].isEnabled.toggle()
            RulePersistence.save(securityRules)
            rulesLock.unlock()
            reply(true)
        } else {
            rulesLock.unlock()
            reply(false)
        }
    }

    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setFilteringEnabled(\(enabled))")
        filteringEnabled = enabled
        reply(true)
    }

    func isFilteringEnabled(reply: @escaping (Bool) -> Void) {
        reply(filteringEnabled)
    }

    // MARK: - Raw Data Capture XPC

    func getConnectionRawData(_ connectionId: String, reply: @escaping (Data?, Data?) -> Void) {
        guard let uuid = UUID(uuidString: connectionId) else {
            reply(nil, nil)
            return
        }
        networkLock.lock()
        defer { networkLock.unlock() }
        guard let tracker = connections[uuid] else {
            reply(nil, nil)
            return
        }
        // Single pass: partition and concatenate with pre-sized buffers
        var outSize = 0, inSize = 0
        for seg in tracker.captureSegments {
            if seg.direction == .outbound { outSize += seg.data.count }
            else { inSize += seg.data.count }
        }
        var outbound = Data(capacity: outSize)
        var inbound = Data(capacity: inSize)
        for seg in tracker.captureSegments {
            if seg.direction == .outbound { outbound.append(seg.data) }
            else { inbound.append(seg.data) }
        }
        reply(outbound, inbound)
    }

    func getConnectionConversation(_ connectionId: String, reply: @escaping (Data?) -> Void) {
        guard let uuid = UUID(uuidString: connectionId) else {
            reply(nil)
            return
        }
        // Snapshot segments under lock, sort+encode outside
        networkLock.lock()
        guard let segments = connections[uuid]?.captureSegments else {
            networkLock.unlock()
            reply(nil)
            return
        }
        networkLock.unlock()

        let conversation = segments.sorted { $0.timestamp < $1.timestamp }
        reply(try? Self.jsonEncoder.encode(conversation))
    }

    func setCaptureMemoryBudget(_ bytes: Int, reply: @escaping (Bool) -> Void) {
        captureMemoryBudget = bytes
        reply(true)
    }

    func getCaptureStats(reply: @escaping ([String: Any]) -> Void) {
        networkLock.lock()
        let connCount = connections.count
        let totalCapture = totalCaptureBytes
        let budget = captureMemoryBudget
        networkLock.unlock()
        reply([
            "connectionCount": connCount,
            "totalCaptureBytes": totalCapture,
            "captureMemoryBudget": budget,
            "captureUsagePercent": budget > 0 ? Double(totalCapture) / Double(budget) * 100 : 0
        ])
    }
}
