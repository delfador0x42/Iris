import Foundation
import NetworkExtension
import os.log

/// Network Extension filter provider for monitoring network connections
class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris.network", category: "Filter")

    /// Active connections being tracked
    private var connections: [UUID: ConnectionTracker] = [:]
    private let connectionsLock = NSLock()

    /// Maps flow hash to connection ID for byte tracking
    private var flowToConnection: [Int: UUID] = [:]

    /// XPC service for communicating with main app
    private var xpcService: XPCService?

    /// Security rules
    private var rules: [SecurityRule] = []
    private let rulesLock = NSLock()

    // MARK: - Connection Tracking

    private struct ConnectionTracker {
        let connection: NetworkConnection
        var bytesUp: UInt64 = 0
        var bytesDown: UInt64 = 0
        var localAddress: String
        var localPort: UInt16
        let flowId: UUID

        // HTTP tracking
        var httpRequest: ParsedHTTPRequest?
        var httpResponse: ParsedHTTPResponse?
        var requestParser: HTTPParser.StreamingRequestParser?
        var responseParser: HTTPParser.StreamingResponseParser?
        var isHTTPParsed: Bool = false
    }

    // MARK: - HTTP Data Structures (for XPC)

    struct ParsedHTTPRequest: Codable {
        let method: String
        let path: String
        let host: String?
        let contentType: String?
        let userAgent: String?
        let rawHeaders: String  // Full raw request headers
    }

    struct ParsedHTTPResponse: Codable {
        let statusCode: Int
        let reason: String
        let contentType: String?
        let contentLength: Int?
        let rawHeaders: String  // Full raw response headers
    }

    // MARK: - Lifecycle

    override init() {
        super.init()
        logger.info("FilterDataProvider initialized")
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting network filter...")

        // Start XPC service
        xpcService = XPCService()
        xpcService?.filterProvider = self
        xpcService?.start()

        // Create rule to monitor all outbound traffic
        let networkRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )

        let filterRule = NEFilterRule(networkRule: networkRule, action: .filterData)

        // Configure filter settings with rules
        let filterSettings = NEFilterSettings(rules: [filterRule], defaultAction: .filterData)

        apply(filterSettings) { error in
            if let error = error {
                self.logger.error("Failed to apply filter settings: \(error.localizedDescription)")
            } else {
                self.logger.info("Filter settings applied successfully")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping network filter, reason: \(String(describing: reason))")

        xpcService?.stop()
        xpcService = nil

        completionHandler()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Extract process information from audit token
        guard let auditToken = flow.sourceAppAuditToken else {
            logger.warning("Flow without audit token, allowing")
            return .allow()
        }

        let pid = audit_token_to_pid(auditToken)
        let processPath = getProcessPath(pid: pid)
        let processName = URL(fileURLWithPath: processPath).lastPathComponent

        // Extract remote endpoint
        guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }

        // Extract local endpoint
        let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint

        // Determine protocol
        let proto: NetworkConnection.NetworkProtocol
        switch socketFlow.socketProtocol {
        case IPPROTO_TCP:
            proto = .tcp
        case IPPROTO_UDP:
            proto = .udp
        default:
            proto = .other
        }

        // Create connection record
        let connectionId = UUID()
        let connection = NetworkConnection(
            id: connectionId,
            processId: pid,
            processPath: processPath,
            processName: processName,
            localAddress: localEndpoint?.hostname ?? "0.0.0.0",
            localPort: UInt16(localEndpoint?.port ?? "0") ?? 0,
            remoteAddress: remoteEndpoint.hostname,
            remotePort: UInt16(remoteEndpoint.port) ?? 0,
            remoteHostname: flow.url?.host,
            protocol: proto,
            state: .established,
            interface: nil,
            bytesUp: 0,
            bytesDown: 0,
            timestamp: Date(),
            httpMethod: nil,
            httpPath: nil,
            httpHost: nil,
            httpContentType: nil,
            httpUserAgent: nil,
            httpStatusCode: nil,
            httpStatusReason: nil,
            httpResponseContentType: nil,
            httpRawRequest: nil,
            httpRawResponse: nil
        )

        // Track the connection
        connectionsLock.lock()
        connections[connectionId] = ConnectionTracker(
            connection: connection,
            localAddress: localEndpoint?.hostname ?? "0.0.0.0",
            localPort: UInt16(localEndpoint?.port ?? "0") ?? 0,
            flowId: connectionId
        )
        // Store flow mapping for byte tracking
        let flowHash = ObjectIdentifier(flow).hashValue
        flowToConnection[flowHash] = connectionId
        connectionsLock.unlock()

        logger.debug("New flow: \(processName) → \(remoteEndpoint.hostname):\(remoteEndpoint.port)")

        // Check rules
        let verdict = evaluateRules(for: connection)

        if verdict == .block {
            logger.info("Blocking connection from \(processName) to \(remoteEndpoint.hostname)")
            return .drop()
        }

        // Allow and continue monitoring for byte counts
        return .allow()
    }

    override func handleInboundData(from flow: NEFilterFlow,
                                    readBytesStartOffset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        updateBytes(flow: flow, bytesDown: UInt64(readBytes.count))

        // Try to parse HTTP response (only on first data chunk)
        if readBytesStartOffset == 0 {
            parseHTTPResponse(flow: flow, data: readBytes)
        }

        return .allow()
    }

    override func handleOutboundData(from flow: NEFilterFlow,
                                     readBytesStartOffset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        updateBytes(flow: flow, bytesUp: UInt64(readBytes.count))

        // Try to parse HTTP request (only on first data chunk)
        if readBytesStartOffset == 0 {
            parseHTTPRequest(flow: flow, data: readBytes)
        }

        return .allow()
    }

    // MARK: - HTTP Parsing

    private func parseHTTPRequest(flow: NEFilterFlow, data: Data) {
        // Check if this looks like HTTP (common HTTP methods)
        guard data.count >= 4 else { return }

        let methodPrefixes = ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN"]
        guard let prefix = String(data: data.prefix(4), encoding: .utf8),
              methodPrefixes.contains(where: { prefix.hasPrefix($0.prefix(4)) }) else {
            return
        }

        // Try to parse the HTTP request
        if let parsed = HTTPParser.parseRequest(from: data) {
            // Build raw headers string
            var rawHeaders = "\(parsed.method) \(parsed.path) \(parsed.httpVersion)\r\n"
            for header in parsed.headers {
                rawHeaders += "\(header.name): \(header.value)\r\n"
            }

            let httpRequest = ParsedHTTPRequest(
                method: parsed.method,
                path: parsed.path,
                host: parsed.host,
                contentType: parsed.headers.first { $0.name.lowercased() == "content-type" }?.value,
                userAgent: parsed.headers.first { $0.name.lowercased() == "user-agent" }?.value,
                rawHeaders: rawHeaders
            )

            connectionsLock.lock()
            let flowHash = ObjectIdentifier(flow).hashValue
            if let connectionId = flowToConnection[flowHash],
               var tracker = connections[connectionId] {
                tracker.httpRequest = httpRequest
                tracker.isHTTPParsed = true
                connections[connectionId] = tracker
                logger.debug("Parsed HTTP request: \(parsed.method) \(parsed.path)")
            }
            connectionsLock.unlock()
        }
    }

    private func parseHTTPResponse(flow: NEFilterFlow, data: Data) {
        // Check if this looks like HTTP response
        guard data.count >= 8 else { return }
        guard let prefix = String(data: data.prefix(8), encoding: .utf8),
              prefix.hasPrefix("HTTP/") else {
            return
        }

        // Try to parse the HTTP response
        if let parsed = HTTPParser.parseResponse(from: data) {
            // Build raw headers string
            var rawHeaders = "\(parsed.httpVersion) \(parsed.statusCode) \(parsed.reason)\r\n"
            for header in parsed.headers {
                rawHeaders += "\(header.name): \(header.value)\r\n"
            }

            let httpResponse = ParsedHTTPResponse(
                statusCode: parsed.statusCode,
                reason: parsed.reason,
                contentType: parsed.headers.first { $0.name.lowercased() == "content-type" }?.value,
                contentLength: parsed.contentLength,
                rawHeaders: rawHeaders
            )

            connectionsLock.lock()
            let flowHash = ObjectIdentifier(flow).hashValue
            if let connectionId = flowToConnection[flowHash],
               var tracker = connections[connectionId] {
                tracker.httpResponse = httpResponse
                connections[connectionId] = tracker
                logger.debug("Parsed HTTP response: \(parsed.statusCode) \(parsed.reason)")
            }
            connectionsLock.unlock()
        }
    }

    // MARK: - Private Helpers

    private func getProcessPath(pid: Int32) -> String {
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
        if result > 0 {
            return String(cString: pathBuffer)
        }
        return "/unknown"
    }

    private func updateBytes(flow: NEFilterFlow, bytesUp: UInt64 = 0, bytesDown: UInt64 = 0) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        // Look up the specific connection by flow hash
        let flowHash = ObjectIdentifier(flow).hashValue
        guard let connectionId = flowToConnection[flowHash],
              var tracker = connections[connectionId] else {
            return
        }

        // Update byte counts for this specific connection only
        tracker.bytesUp += bytesUp
        tracker.bytesDown += bytesDown

        // Update local endpoint if it wasn't available initially
        if tracker.localAddress == "0.0.0.0" || tracker.localPort == 0 {
            if let socketFlow = flow as? NEFilterSocketFlow,
               let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint {
                if !localEndpoint.hostname.isEmpty && localEndpoint.hostname != "0.0.0.0" {
                    tracker.localAddress = localEndpoint.hostname
                }
                if let port = UInt16(localEndpoint.port), port != 0 {
                    tracker.localPort = port
                }
            }
        }

        connections[connectionId] = tracker
    }

    private func evaluateRules(for connection: NetworkConnection) -> RuleVerdict {
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

    private enum RuleVerdict {
        case allow
        case block
    }

    // MARK: - Public API (for XPC)

    func getActiveConnections() -> [NetworkConnection] {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        return connections.values.map { tracker in
            let conn = tracker.connection
            // Update with current byte counts, local endpoint, and HTTP data
            return NetworkConnection(
                id: conn.id,
                processId: conn.processId,
                processPath: conn.processPath,
                processName: conn.processName,
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
                httpRawResponse: tracker.httpResponse?.rawHeaders
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

// MARK: - Helper for audit token

private func audit_token_to_pid(_ token: Data) -> Int32 {
    return token.withUnsafeBytes { ptr in
        // audit_token_t structure: pid is at offset 20 (5th 32-bit value)
        let tokenPtr = ptr.bindMemory(to: UInt32.self)
        return Int32(bitPattern: tokenPtr[5])
    }
}

// MARK: - Models

struct SecurityRule: Codable {
    let id: UUID
    let processPath: String?
    let remoteAddress: String?
    let action: Action
    var isActive: Bool

    enum Action: String, Codable {
        case allow, block
    }

    func matches(connection: NetworkConnection) -> Bool {
        if let path = processPath, path != connection.processPath {
            return false
        }
        if let addr = remoteAddress, addr != "*" && addr != connection.remoteAddress {
            return false
        }
        return true
    }
}

struct NetworkConnection: Codable {
    let id: UUID
    let processId: Int32
    let processPath: String
    let processName: String
    let localAddress: String
    let localPort: UInt16
    let remoteAddress: String
    let remotePort: UInt16
    let remoteHostname: String?
    let `protocol`: NetworkProtocol
    let state: ConnectionState
    let interface: String?
    var bytesUp: UInt64
    var bytesDown: UInt64
    let timestamp: Date

    // HTTP fields
    let httpMethod: String?
    let httpPath: String?
    let httpHost: String?
    let httpContentType: String?
    let httpUserAgent: String?
    let httpStatusCode: Int?
    let httpStatusReason: String?
    let httpResponseContentType: String?
    let httpRawRequest: String?
    let httpRawResponse: String?

    enum NetworkProtocol: String, Codable {
        case tcp = "TCP"
        case udp = "UDP"
        case other = "Other"
    }

    enum ConnectionState: String, Codable {
        case established = "Established"
        case closed = "Closed"
    }
}
