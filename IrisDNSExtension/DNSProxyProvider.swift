//
//  DNSProxyProvider.swift
//  IrisDNSExtension
//
//  NEDNSProxyProvider subclass that intercepts system DNS queries
//  and forwards them over DNS-over-HTTPS (RFC 8484).
//

import Foundation
import NetworkExtension
import os.log

/// DNS Proxy Provider that intercepts all system DNS queries and forwards them
/// over encrypted HTTPS connections to a configurable DoH server.
class DNSProxyProvider: NEDNSProxyProvider {

    let logger = Logger(subsystem: "com.wudan.iris.dns", category: "DNSProxyProvider")

    let dohClient = ExtensionDoHClient()
    let xpcService = DNSExtensionXPCService()

    var capturedQueries: [CapturedDNSQuery] = []
    let queriesLock = NSLock()
    static let maxCapturedQueries = 10000

    /// Stats protected by statsLock for thread-safe access from data path
    private var _totalQueries: Int = 0
    private var _failedQueries: Int = 0
    private var _totalLatencyMs: Double = 0
    private let statsLock = NSLock()

    var totalQueries: Int {
        statsLock.lock(); defer { statsLock.unlock() }; return _totalQueries
    }
    var failedQueries: Int {
        statsLock.lock(); defer { statsLock.unlock() }; return _failedQueries
    }
    var totalLatencyMs: Double {
        statsLock.lock(); defer { statsLock.unlock() }; return _totalLatencyMs
    }

    /// Atomic increment methods for cross-file access
    func incrementTotalQueries() {
        statsLock.lock(); _totalQueries += 1; statsLock.unlock()
    }
    func incrementFailedQueries() {
        statsLock.lock(); _failedQueries += 1; statsLock.unlock()
    }
    func addLatency(_ ms: Double) {
        statsLock.lock(); _totalLatencyMs += ms; statsLock.unlock()
    }
    func resetStats() {
        statsLock.lock()
        _totalQueries = 0; _failedQueries = 0; _totalLatencyMs = 0
        statsLock.unlock()
    }
    var isProxyEnabled: Bool = true
    var serverName: String = "Cloudflare"

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting DNS proxy extension...")
        xpcService.provider = self
        xpcService.start()
        logger.info("DNS proxy extension started successfully")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping DNS proxy extension with reason: \(String(describing: reason))")
        xpcService.stop()
        logger.info("DNS proxy extension stopped")
        completionHandler()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard isProxyEnabled else { return false }
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            Task { await handleDNSFlow(udpFlow) }
            return true
        }
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            Task { await handleTCPDNSFlow(tcpFlow) }
            return true
        }
        logger.debug("Unknown flow type received, ignoring")
        return false
    }

    // MARK: - XPC Interface

    func getStatus() -> [String: Any] {
        return [
            "isActive": isProxyEnabled,
            "totalQueries": totalQueries,
            "failedQueries": failedQueries,
            "averageLatencyMs": totalQueries > 0 ? totalLatencyMs / Double(totalQueries) : 0,
            "serverName": serverName,
            "successRate": totalQueries > 0 ? Double(totalQueries - failedQueries) / Double(totalQueries) : 1.0
        ]
    }

    func getQueries(limit: Int) -> [Data] {
        queriesLock.lock()
        let queries = Array(capturedQueries.suffix(limit))
        queriesLock.unlock()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return queries.compactMap { try? encoder.encode($0) }
    }

    func clearQueries() {
        queriesLock.lock()
        capturedQueries.removeAll()
        queriesLock.unlock()
        resetStats()
    }

    func setEnabled(_ enabled: Bool) {
        isProxyEnabled = enabled
        logger.info("DNS proxy \(enabled ? "enabled" : "disabled")")
    }

    func setServer(_ name: String) {
        serverName = name
        dohClient.setServer(name)
        logger.info("DNS server changed to \(name)")
    }
}
