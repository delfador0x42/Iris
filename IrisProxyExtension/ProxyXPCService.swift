//
//  ProxyXPCService.swift
//  IrisProxyExtension
//
//  XPC Service for communication between the main app and the proxy extension.
//  Core class definition with protocol, properties, and lifecycle.
//

import Foundation
import os.log

/// XPC Service for the proxy extension.
class ProxyXPCService: NSObject {

    // MARK: - Properties

    /// Shared encoder — avoids allocation on every XPC response.
    static let jsonEncoder: JSONEncoder = {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        return enc
    }()

    let logger = Logger(subsystem: "com.wudan.iris.proxy", category: "XPC")
    var listener: NSXPCListener?
    var activeConnections: [NSXPCConnection] = []
    let xpcConnectionsLock = NSLock()

    /// Reference to the proxy provider
    weak var provider: AppProxyProvider?

    /// Captured HTTP flows (stored in memory)
    var capturedFlows: [ProxyCapturedFlow] = []
    let flowsLock = NSLock()
    let maxFlows = 10000

    /// Monotonically increasing counter for delta XPC protocol.
    /// Protected by flowsLock — always increment under lock.
    var nextSequenceNumber: UInt64 = 1

    /// Whether interception is enabled (guarded by interceptionLock)
    private var _interceptionEnabled = true
    let interceptionLock = NSLock()

    var interceptionEnabled: Bool {
        get {
            interceptionLock.lock()
            defer { interceptionLock.unlock() }
            return _interceptionEnabled
        }
        set {
            interceptionLock.lock()
            _interceptionEnabled = newValue
            interceptionLock.unlock()
        }
    }

    // MARK: - DNS State

    /// Captured DNS queries
    var capturedDNSQueries: [DNSQueryRecord] = []
    let dnsLock = NSLock()
    let maxDNSQueries = 10000
    var nextDNSSequenceNumber: UInt64 = 1

    /// DNS stats
    var _totalDNSQueries: Int = 0
    var _failedDNSQueries: Int = 0
    var _totalDNSLatencyMs: Double = 0
    let dnsStatsLock = NSLock()

    /// Records a DNS query from the flow handler.
    func recordDNSQuery(
        domain: String, type: String, processName: String,
        responseCode: String, answers: [String], ttl: UInt32?,
        latencyMs: Double, isEncrypted: Bool
    ) {
        dnsStatsLock.lock()
        _totalDNSQueries += 1
        if responseCode == "SERVFAIL" { _failedDNSQueries += 1 }
        _totalDNSLatencyMs += latencyMs
        dnsStatsLock.unlock()

        let record = DNSQueryRecord(
            domain: domain,
            recordType: type,
            processName: processName,
            responseCode: responseCode,
            answers: answers,
            ttl: ttl,
            latencyMs: latencyMs,
            isEncrypted: isEncrypted
        )

        dnsLock.lock()
        defer { dnsLock.unlock() }
        var stamped = record
        stamped.sequenceNumber = nextDNSSequenceNumber
        nextDNSSequenceNumber += 1
        capturedDNSQueries.append(stamped)
        // Batch evict: removeFirst(1) is O(n) array shift. Amortize by evicting in chunks.
        if capturedDNSQueries.count > maxDNSQueries + maxDNSQueries / 10 {
            capturedDNSQueries = Array(capturedDNSQueries.suffix(maxDNSQueries))
        }
    }

    // MARK: - Security Rules

    /// Firewall rules
    var securityRules: [SecurityRule] = []
    let rulesLock = NSLock()

    /// Signing ID cache for process attribution
    var signingIdCache: [pid_t: String?] = [:]
    let signingIdLock = NSLock()

    /// Whether filtering is enabled
    var filteringEnabled: Bool = true

    // MARK: - Connection Tracking

    /// Active connections being tracked (unified model)
    var connections: [UUID: ConnectionTracker] = [:]
    let networkLock = NSLock()
    var flowToConnection: [UUID: UUID] = [:]
    static let maxConnections = 10000
    static let staleTimeout: TimeInterval = 120

    /// Capture budget
    var totalCaptureBytes: Int = 0
    var captureMemoryBudget: Int = 30 * 1024 * 1024

    /// Periodic cleanup timer for expired rules
    var ruleCleanupTimer: DispatchSourceTimer?

    // MARK: - Service Name

    /// Gets the Mach service name from Info.plist
    static var serviceName: String {
        guard let networkExtension = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
              let machServiceName = networkExtension["NEMachServiceName"] as? String else {
            fatalError("NEMachServiceName not found in Info.plist")
        }
        return machServiceName
    }

    // MARK: - Lifecycle

    func start() {
        logger.info("Starting proxy XPC service...")

        // Load persisted rules
        rulesLock.lock()
        securityRules = RulePersistence.load()
        rulesLock.unlock()

        listener = NSXPCListener(machServiceName: Self.serviceName)
        listener?.delegate = self
        listener?.resume()

        // Periodic cleanup of expired rules (every 60s)
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.rulesLock.lock()
            let before = self.securityRules.count
            self.securityRules.removeAll { $0.isExpired }
            if self.securityRules.count != before {
                RulePersistence.save(self.securityRules)
                let removed = before - self.securityRules.count
                self.logger.info("Cleaned up \(removed) expired rules")
            }
            self.rulesLock.unlock()
        }
        timer.resume()
        ruleCleanupTimer = timer

        logger.info("Proxy XPC service started on \(Self.serviceName)")
    }

    // MARK: - Rule Evaluation

    enum RuleVerdict {
        case allow
        case block
    }

    /// Evaluates security rules for a connection. Called from flow handling.
    func evaluateRules(for connection: NetworkConnection) -> RuleVerdict {
        guard filteringEnabled else { return .allow }
        rulesLock.lock()
        defer { rulesLock.unlock() }

        for rule in securityRules where rule.isActive {
            if rule.matches(connection: connection) {
                return rule.action == .block ? .block : .allow
            }
        }
        return .allow
    }

    // MARK: - Connection Tracking

    /// Tracks a new connection. Returns false if the connection was blocked by rules.
    func trackConnection(
        flowId: UUID, pid: Int32, processPath: String, processName: String,
        remoteHost: String, remotePort: UInt16, proto: NetworkConnection.NetworkProtocol,
        localAddress: String = "0.0.0.0", localPort: UInt16 = 0,
        remoteHostname: String? = nil
    ) -> Bool {
        let signingId = getSigningIdentifier(
            pid: pid, cache: signingIdLock, signingIdCache: &signingIdCache
        )

        let connection = NetworkConnection(
            id: flowId,
            processId: pid,
            processPath: processPath,
            processName: processName,
            signingId: signingId,
            localAddress: localAddress,
            localPort: localPort,
            remoteAddress: remoteHost,
            remotePort: remotePort,
            remoteHostname: remoteHostname,
            protocol: proto,
            state: .established,
            interface: nil,
            bytesUp: 0, bytesDown: 0,
            timestamp: Date(),
            httpMethod: nil, httpPath: nil, httpHost: nil,
            httpContentType: nil, httpUserAgent: nil,
            httpStatusCode: nil, httpStatusReason: nil,
            httpResponseContentType: nil,
            httpRawRequest: nil, httpRawResponse: nil
        )

        // Evaluate rules
        if evaluateRules(for: connection) == .block {
            logger.info("Blocked: \(processName) → \(remoteHost):\(remotePort)")
            return false
        }

        // Track
        networkLock.lock()
        connections[flowId] = ConnectionTracker(
            connection: connection,
            localAddress: localAddress,
            localPort: localPort,
            flowId: flowId
        )

        if connections.count > Self.maxConnections {
            let evictCount = max(Self.maxConnections / 10, 1)
            let sorted = connections.sorted { $0.value.lastActivity < $1.value.lastActivity }
            let evictIds = Set(sorted.prefix(evictCount).map { $0.key })
            for id in evictIds {
                if let tracker = connections[id] {
                    totalCaptureBytes -= tracker.capturedOutboundBytes + tracker.capturedInboundBytes
                }
                connections.removeValue(forKey: id)
            }
        }
        networkLock.unlock()

        return true
    }

    /// Removes a tracked connection.
    func removeTrackedConnection(_ flowId: UUID) {
        networkLock.lock()
        if let tracker = connections.removeValue(forKey: flowId) {
            totalCaptureBytes -= tracker.capturedOutboundBytes + tracker.capturedInboundBytes
        }
        networkLock.unlock()
    }

    func stop() {
        ruleCleanupTimer?.cancel()
        ruleCleanupTimer = nil

        listener?.invalidate()
        listener = nil

        xpcConnectionsLock.lock()
        for connection in activeConnections {
            connection.invalidate()
        }
        activeConnections.removeAll()
        xpcConnectionsLock.unlock()

        logger.info("Proxy XPC service stopped")
    }
}
