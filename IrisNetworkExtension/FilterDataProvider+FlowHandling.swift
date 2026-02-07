import Foundation
import NetworkExtension
import Security
import os.log

// MARK: - Flow Handling

extension FilterDataProvider {

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        guard let auditToken = flow.sourceAppAuditToken else {
            logger.warning("Flow without audit token, allowing")
            return .allow()
        }

        let pid = audit_token_to_pid(auditToken)
        let processPath = getProcessPath(pid: pid)
        let processName = URL(fileURLWithPath: processPath).lastPathComponent
        let signingId = getSigningIdentifier(pid: pid)

        guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }

        let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint

        let proto: NetworkConnection.NetworkProtocol
        switch socketFlow.socketProtocol {
        case IPPROTO_TCP:
            proto = .tcp
        case IPPROTO_UDP:
            proto = .udp
        default:
            proto = .other
        }

        let connectionId = UUID()
        let connection = NetworkConnection(
            id: connectionId,
            processId: pid,
            processPath: processPath,
            processName: processName,
            signingId: signingId,
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

        // Check rules BEFORE tracking (prevents leak of blocked flow entries)
        let verdict = evaluateRules(for: connection)

        if verdict == .block {
            logger.info("Blocking connection from \(processName) to \(remoteEndpoint.hostname)")
            return .drop()
        }

        // Track only allowed flows
        connectionsLock.lock()
        connections[connectionId] = ConnectionTracker(
            connection: connection,
            localAddress: localEndpoint?.hostname ?? "0.0.0.0",
            localPort: UInt16(localEndpoint?.port ?? "0") ?? 0,
            flowId: connectionId
        )
        flowToConnection[ObjectIdentifier(flow)] = connectionId

        if connections.count > Self.maxConnections {
            let oldest = connections.min { $0.value.lastActivity < $1.value.lastActivity }
            if let oldId = oldest?.key {
                connections.removeValue(forKey: oldId)
                flowToConnection = flowToConnection.filter { $0.value != oldId }
            }
        }
        connectionsLock.unlock()

        logger.debug("New flow: \(processName) → \(remoteEndpoint.hostname):\(remoteEndpoint.port)")

        // filterDataVerdict enables handleInboundData/handleOutboundData callbacks
        return .filterDataVerdict(
            withFilterInbound: true, peekInboundBytes: Int.max,
            filterOutbound: true, peekOutboundBytes: Int.max
        )
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
