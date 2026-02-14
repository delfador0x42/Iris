import Foundation

// MARK: - Security Rule (matches app-side SecurityRule encoding)

struct SecurityRule: Codable {
    let id: UUID
    let processPath: String?
    let signingId: String?
    let remoteAddress: String?
    let remotePort: String?
    let action: RuleAction
    let scope: RuleScope
    let createdAt: Date
    var isEnabled: Bool
    var expiresAt: Date?

    enum RuleAction: String, Codable {
        case allow, block
    }

    enum RuleScope: String, Codable {
        case process, endpoint
    }

    var isExpired: Bool {
        guard let expiresAt = expiresAt else { return false }
        return Date() > expiresAt
    }

    var isActive: Bool {
        isEnabled && !isExpired
    }

    func matches(connection: NetworkConnection) -> Bool {
        guard isActive else { return false }

        if let ruleSigningId = signingId {
            if let connSigningId = connection.signingId {
                if ruleSigningId != connSigningId { return false }
            } else if let processPath = processPath {
                if processPath != connection.processPath { return false }
            } else {
                return false
            }
        } else if let processPath = processPath {
            if processPath != connection.processPath { return false }
        }

        if scope == .endpoint {
            if let remoteAddress = remoteAddress, remoteAddress != "*" {
                if remoteAddress != connection.remoteAddress { return false }
            }
            if let remotePort = remotePort, remotePort != "*" {
                if let port = UInt16(remotePort), port != connection.remotePort {
                    return false
                }
            }
        }

        return true
    }
}

// MARK: - Network Connection

struct NetworkConnection: Codable {
    let id: UUID
    let processId: Int32
    let processPath: String
    let processName: String
    let signingId: String?
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
    var capturedOutboundBytes: Int? = nil
    var capturedInboundBytes: Int? = nil

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
