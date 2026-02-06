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

    // Geolocation data (enriched after creation)
    public var remoteCountry: String?
    public var remoteCountryCode: String?
    public var remoteCity: String?
    public var remoteLatitude: Double?
    public var remoteLongitude: Double?
    public var remoteASN: String?
    public var remoteOrganization: String?

    // Security enrichment data (from InternetDB/Shodan)
    public var remoteOpenPorts: [UInt16]?
    public var remoteHostnames: [String]?
    public var remoteCVEs: [String]?
    public var remoteServiceTags: [String]?
    public var remoteCPEs: [String]?

    // Threat intelligence data (from GreyNoise, AbuseIPDB)
    public var abuseScore: Int?              // 0-100 from AbuseIPDB
    public var isKnownScanner: Bool?         // From GreyNoise
    public var isBenignService: Bool?        // From GreyNoise (CDN, cloud, etc)
    public var threatClassification: String? // benign, malicious, unknown
    public var isTor: Bool?                  // From AbuseIPDB
    public var enrichmentSources: [String]?  // Which services provided data

    // HTTP request data (parsed from network traffic)
    public var httpMethod: String?
    public var httpPath: String?
    public var httpHost: String?
    public var httpContentType: String?
    public var httpUserAgent: String?

    // HTTP response data
    public var httpStatusCode: Int?
    public var httpStatusReason: String?
    public var httpResponseContentType: String?

    // Raw HTTP data (full headers for detailed view)
    public var httpRawRequest: String?
    public var httpRawResponse: String?

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
        timestamp: Date = Date(),
        remoteCountry: String? = nil,
        remoteCountryCode: String? = nil,
        remoteCity: String? = nil,
        remoteLatitude: Double? = nil,
        remoteLongitude: Double? = nil,
        remoteASN: String? = nil,
        remoteOrganization: String? = nil,
        remoteOpenPorts: [UInt16]? = nil,
        remoteHostnames: [String]? = nil,
        remoteCVEs: [String]? = nil,
        remoteServiceTags: [String]? = nil,
        remoteCPEs: [String]? = nil,
        abuseScore: Int? = nil,
        isKnownScanner: Bool? = nil,
        isBenignService: Bool? = nil,
        threatClassification: String? = nil,
        isTor: Bool? = nil,
        enrichmentSources: [String]? = nil,
        httpMethod: String? = nil,
        httpPath: String? = nil,
        httpHost: String? = nil,
        httpContentType: String? = nil,
        httpUserAgent: String? = nil,
        httpStatusCode: Int? = nil,
        httpStatusReason: String? = nil,
        httpResponseContentType: String? = nil,
        httpRawRequest: String? = nil,
        httpRawResponse: String? = nil
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
        self.remoteCountry = remoteCountry
        self.remoteCountryCode = remoteCountryCode
        self.remoteCity = remoteCity
        self.remoteLatitude = remoteLatitude
        self.remoteLongitude = remoteLongitude
        self.remoteASN = remoteASN
        self.remoteOrganization = remoteOrganization
        self.remoteOpenPorts = remoteOpenPorts
        self.remoteHostnames = remoteHostnames
        self.remoteCVEs = remoteCVEs
        self.remoteServiceTags = remoteServiceTags
        self.remoteCPEs = remoteCPEs
        self.abuseScore = abuseScore
        self.isKnownScanner = isKnownScanner
        self.isBenignService = isBenignService
        self.threatClassification = threatClassification
        self.isTor = isTor
        self.enrichmentSources = enrichmentSources
        self.httpMethod = httpMethod
        self.httpPath = httpPath
        self.httpHost = httpHost
        self.httpContentType = httpContentType
        self.httpUserAgent = httpUserAgent
        self.httpStatusCode = httpStatusCode
        self.httpStatusReason = httpStatusReason
        self.httpResponseContentType = httpResponseContentType
        self.httpRawRequest = httpRawRequest
        self.httpRawResponse = httpRawResponse
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

    /// Formatted remote endpoint string (IP:port only, hostname in popover)
    public var remoteEndpoint: String {
        "\(remoteAddress):\(remotePort)"
    }

    /// Full connection description (local → remote)
    public var connectionDescription: String {
        "\(localEndpoint) → \(remoteEndpoint)"
    }

    /// Total bytes transferred
    public var totalBytes: UInt64 {
        bytesUp + bytesDown
    }

    /// Whether this connection has geolocation data
    public var hasGeolocation: Bool {
        remoteLatitude != nil && remoteLongitude != nil
    }

    /// Formatted location string (e.g., "San Francisco, US")
    public var locationDescription: String? {
        guard let country = remoteCountry else { return nil }
        if let city = remoteCity, !city.isEmpty {
            return "\(city), \(country)"
        }
        return country
    }

    /// Whether this connection has security enrichment data
    public var hasSecurityData: Bool {
        remoteOpenPorts != nil || remoteHostnames != nil || remoteCVEs != nil
    }

    /// Whether this connection has known vulnerabilities
    public var hasCriticalVulns: Bool {
        !(remoteCVEs ?? []).isEmpty
    }

    /// Whether this connection has threat intelligence data
    public var hasThreatData: Bool {
        abuseScore != nil || isKnownScanner != nil || threatClassification != nil
    }

    /// Whether this IP has a high abuse score (>= 50)
    public var isHighRisk: Bool {
        guard let score = abuseScore else { return false }
        return score >= 50
    }

    /// Whether this connection has HTTP request data
    public var hasHTTPRequest: Bool {
        httpMethod != nil
    }

    /// Whether this connection has HTTP response data
    public var hasHTTPResponse: Bool {
        httpStatusCode != nil
    }

    /// Whether this connection has any HTTP data
    public var hasHTTPData: Bool {
        hasHTTPRequest || hasHTTPResponse
    }

    /// Full HTTP URL if available
    public var httpFullURL: String? {
        guard let method = httpMethod, let path = httpPath else { return nil }
        let host = httpHost ?? remoteHostname ?? remoteAddress
        let scheme = remotePort == 443 ? "https" : "http"
        return "\(scheme)://\(host)\(path)"
    }

    /// HTTP status description (e.g., "200 OK")
    public var httpStatusDescription: String? {
        guard let code = httpStatusCode else { return nil }
        let reason = httpStatusReason ?? ""
        return "\(code) \(reason)".trimmingCharacters(in: .whitespaces)
    }
}

// MARK: - Formatting Helpers

extension NetworkConnection {
    /// Format bytes as human-readable string
    /// Uses ByteFormatter with full style for detailed display
    public static func formatBytes(_ bytes: UInt64) -> String {
        ByteFormatter.format(bytes, style: .full)
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

// MARK: - Aggregated Connection

/// Aggregated connections to the same remote IP (for deduplication in UI)
public struct AggregatedConnection: Identifiable {
    public let id: String  // remoteAddress
    public let remoteAddress: String
    public let connections: [NetworkConnection]

    public init(id: String, remoteAddress: String, connections: [NetworkConnection]) {
        self.id = id
        self.remoteAddress = remoteAddress
        self.connections = connections
    }

    public var connectionCount: Int { connections.count }
    public var totalBytesUp: UInt64 { connections.reduce(0) { $0 + $1.bytesUp } }
    public var totalBytesDown: UInt64 { connections.reduce(0) { $0 + $1.bytesDown } }

    /// First connection used as representative (same IP = same enrichment data)
    public var representative: NetworkConnection { connections[0] }
}
