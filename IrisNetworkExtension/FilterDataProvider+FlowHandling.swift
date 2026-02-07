import Foundation
import NetworkExtension
import os.log

// MARK: - Flow Handling

extension FilterDataProvider {

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
        flowToConnection[ObjectIdentifier(flow)] = connectionId

        // Evict oldest if over capacity
        if connections.count > Self.maxConnections {
            let oldest = connections.min { $0.value.lastActivity < $1.value.lastActivity }
            if let oldId = oldest?.key {
                connections.removeValue(forKey: oldId)
                flowToConnection = flowToConnection.filter { $0.value != oldId }
            }
        }
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
}
