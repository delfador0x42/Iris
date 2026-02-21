//
//  ProxyXPCService+DNS.swift
//  IrisProxyExtension
//
//  DNS-over-HTTPS XPC protocol conformance for ProxyXPCService.
//  Absorbed from IrisDNSExtension.
//

import Foundation
import os.log

extension ProxyXPCService {

    func getDNSQueriesSince(_ sinceSeq: UInt64, limit: Int, reply: @escaping (UInt64, [Data]) -> Void) {
        // Snapshot under lock, encode outside
        dnsLock.lock()
        let currentSeq = nextDNSSequenceNumber - 1
        let changed = Array(capturedDNSQueries.filter { $0.sequenceNumber > sinceSeq }.suffix(limit))
        dnsLock.unlock()

        let data = changed.compactMap { try? Self.jsonEncoder.encode($0) }

        logger.debug("XPC: getDNSQueriesSince(\(sinceSeq)) → \(data.count) changed, seq=\(currentSeq)")
        reply(currentSeq, data)
    }

    func clearDNSQueries(reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: clearDNSQueries")
        dnsLock.lock()
        capturedDNSQueries.removeAll()
        dnsLock.unlock()

        dnsStatsLock.lock()
        _totalDNSQueries = 0
        _failedDNSQueries = 0
        _totalDNSLatencyMs = 0
        dnsStatsLock.unlock()

        reply(true)
    }

    func setDNSEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setDNSEnabled(\(enabled))")
        Task {
            await provider?.flowHandler?.setDNSEnabled(enabled)
        }
        reply(true)
    }

    func isDNSEnabled(reply: @escaping (Bool) -> Void) {
        Task {
            let enabled = await provider?.flowHandler?.dnsEnabled ?? true
            reply(enabled)
        }
    }

    func setDNSServer(_ serverName: String, reply: @escaping (Bool) -> Void) {
        logger.debug("XPC: setDNSServer(\(serverName))")
        Task {
            await provider?.flowHandler?.setDNSServer(serverName)
        }
        reply(true)
    }

    func getDNSServer(reply: @escaping (String) -> Void) {
        Task {
            let name = await provider?.flowHandler?.dnsServerName ?? "Cloudflare"
            reply(name)
        }
    }

    func getDNSStatistics(reply: @escaping ([String: Any]) -> Void) {
        dnsStatsLock.lock()
        let total = _totalDNSQueries
        let failed = _failedDNSQueries
        let latency = _totalDNSLatencyMs
        dnsStatsLock.unlock()

        let avgLatency: Double = total > 0 ? latency / Double(total) : 0
        let successRate: Double = total > 0 ? Double(total - failed) / Double(total) : 1.0
        reply([
            "totalQueries": total,
            "failedQueries": failed,
            "averageLatencyMs": avgLatency,
            "successRate": successRate
        ])
    }
}
