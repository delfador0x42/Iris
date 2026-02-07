import Foundation

/// Information about a scanned WiFi network
public struct WiFiNetwork: Identifiable, Sendable, Codable, Equatable, Hashable {

    // MARK: - Identity

    /// Unique identifier (BSSID or generated UUID if BSSID unavailable)
    public let id: String

    // MARK: - Network Identification

    /// Network name (nil if hidden or Location Services disabled)
    public let ssid: String?

    /// Base Station MAC address (nil if Location Services disabled)
    public let bssid: String?

    // MARK: - Signal Quality

    /// Received Signal Strength Indication in dBm
    public let rssi: Int

    /// Noise measurement in dBm
    public let noise: Int

    /// Signal-to-Noise Ratio
    public var snr: Int { rssi - noise }

    /// Signal quality assessment
    public var signalQuality: WiFiSignalQuality {
        WiFiSignalQuality(rssi: rssi)
    }

    // MARK: - Channel Info

    /// Channel number
    public let channel: Int

    /// Channel frequency band
    public let channelBand: WiFiChannelBand

    /// Channel width
    public let channelWidth: WiFiChannelWidth

    // MARK: - Security & Capabilities

    /// Security type
    public let security: WiFiSecurityType

    /// Whether this is an IBSS (ad-hoc) network
    public let isIBSS: Bool

    /// Beacon interval in milliseconds
    public let beaconInterval: Int

    /// Country code advertised by the AP
    public let countryCode: String?

    /// Raw information element data (for advanced parsing)
    public let informationElementData: Data?

    // MARK: - Metadata

    /// When this network was last seen
    public let lastSeen: Date

    // MARK: - Computed Properties

    /// Display name (SSID or placeholder for hidden networks)
    public var displayName: String {
        ssid ?? "<Hidden Network>"
    }

    /// Whether this appears to be a hidden network
    public var isHidden: Bool {
        ssid == nil || ssid?.isEmpty == true
    }

    /// Short channel description
    public var channelDescription: String {
        "\(channel) (\(channelBand.shortName))"
    }

    /// Security badge text
    public var securityBadge: String {
        security.rawValue
    }

    // MARK: - Initialization

    public init(
        id: String? = nil,
        ssid: String?,
        bssid: String?,
        rssi: Int,
        noise: Int,
        channel: Int,
        channelBand: WiFiChannelBand,
        channelWidth: WiFiChannelWidth,
        security: WiFiSecurityType,
        isIBSS: Bool,
        beaconInterval: Int,
        countryCode: String?,
        informationElementData: Data? = nil,
        lastSeen: Date = Date()
    ) {
        // Use BSSID as ID if available, otherwise generate UUID
        self.id = id ?? bssid ?? UUID().uuidString
        self.ssid = ssid
        self.bssid = bssid
        self.rssi = rssi
        self.noise = noise
        self.channel = channel
        self.channelBand = channelBand
        self.channelWidth = channelWidth
        self.security = security
        self.isIBSS = isIBSS
        self.beaconInterval = beaconInterval
        self.countryCode = countryCode
        self.informationElementData = informationElementData
        self.lastSeen = lastSeen
    }

    // MARK: - Hashable

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

// MARK: - Comparable by Signal Strength

extension WiFiNetwork: Comparable {
    public static func < (lhs: WiFiNetwork, rhs: WiFiNetwork) -> Bool {
        // Higher RSSI (less negative) is better, so sort descending
        lhs.rssi > rhs.rssi
    }
}
