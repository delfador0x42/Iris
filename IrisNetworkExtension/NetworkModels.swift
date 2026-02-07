import Foundation

// MARK: - Security Rule

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

// MARK: - Network Connection

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
