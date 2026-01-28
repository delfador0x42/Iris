import Foundation

/// Represents a network connection captured by Network Extension
public struct NetworkConnection: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let processId: Int32
    public let processPath: String
    public let processName: String
    public let localAddress: String
    public let localPort: UInt16
    public let remoteAddress: String
    public let remotePort: UInt16
    public let remoteHostname: String?
    public let `protocol`: NetworkProtocol
    public let state: ConnectionState
    public let interface: String?
    public var bytesUp: UInt64
    public var bytesDown: UInt64
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        processId: Int32,
        processPath: String,
        processName: String,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16,
        remoteHostname: String? = nil,
        protocol: NetworkProtocol,
        state: ConnectionState,
        interface: String? = nil,
        bytesUp: UInt64 = 0,
        bytesDown: UInt64 = 0,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.processId = processId
        self.processPath = processPath
        self.processName = processName
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.remoteHostname = remoteHostname
        self.protocol = `protocol`
        self.state = state
        self.interface = interface
        self.bytesUp = bytesUp
        self.bytesDown = bytesDown
        self.timestamp = timestamp
    }

    /// Network protocol type
    public enum NetworkProtocol: String, Codable, Sendable {
        case tcp = "TCP"
        case udp = "UDP"
        case other = "Other"
    }

    /// Connection state
    public enum ConnectionState: String, Codable, Sendable {
        case listen = "Listen"
        case established = "Established"
        case synSent = "SYN Sent"
        case synReceived = "SYN Received"
        case finWait1 = "FIN Wait 1"
        case finWait2 = "FIN Wait 2"
        case closeWait = "Close Wait"
        case closing = "Closing"
        case lastAck = "Last ACK"
        case timeWait = "Time Wait"
        case closed = "Closed"
        case unknown = "Unknown"
    }

    /// Formatted local endpoint string
    public var localEndpoint: String {
        "\(localAddress):\(localPort)"
    }

    /// Formatted remote endpoint string
    public var remoteEndpoint: String {
        let host = remoteHostname ?? remoteAddress
        return "\(host):\(remotePort)"
    }

    /// Full connection description (local → remote)
    public var connectionDescription: String {
        "\(localEndpoint) → \(remoteEndpoint)"
    }

    /// Total bytes transferred
    public var totalBytes: UInt64 {
        bytesUp + bytesDown
    }
}

// MARK: - Formatting Helpers

extension NetworkConnection {
    /// Format bytes as human-readable string
    public static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["bytes", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0

        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }

        if unitIndex == 0 {
            return "\(bytes) bytes"
        } else {
            return String(format: "%.1f %@", value, units[unitIndex])
        }
    }

    /// Formatted bytes up
    public var formattedBytesUp: String {
        Self.formatBytes(bytesUp)
    }

    /// Formatted bytes down
    public var formattedBytesDown: String {
        Self.formatBytes(bytesDown)
    }
}
