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

    var totalQueries: Int = 0
    var failedQueries: Int = 0
    var totalLatencyMs: Double = 0
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
        totalQueries = 0; failedQueries = 0; totalLatencyMs = 0
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
