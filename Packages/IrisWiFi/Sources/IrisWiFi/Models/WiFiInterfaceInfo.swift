import Foundation

/// Information about the current WiFi interface state
public struct WiFiInterfaceInfo: Identifiable, Sendable, Codable, Equatable {

    // MARK: - Identity

    /// Interface name (e.g., "en0")
    public let id: String

    // MARK: - Connection Info

    /// Current network SSID (nil if not connected or Location Services disabled)
    public let ssid: String?

    /// Current network BSSID (nil if not connected or Location Services disabled)
    public let bssid: String?

    // MARK: - Signal Quality

    /// Received Signal Strength Indication in dBm (typically -30 to -90)
    public let rssi: Int

    /// Noise measurement in dBm
    public let noise: Int

    /// Signal-to-Noise Ratio (higher is better)
    public var snr: Int { rssi - noise }

    /// Signal quality assessment
    public var signalQuality: WiFiSignalQuality {
        WiFiSignalQuality(rssi: rssi)
    }

    // MARK: - Channel Info

    /// Channel number (1-14 for 2.4GHz, 36-165 for 5GHz, etc.)
    public let channel: Int

    /// Channel frequency band
    public let channelBand: WiFiChannelBand

    /// Channel width
    public let channelWidth: WiFiChannelWidth

    // MARK: - Technical Details

    /// Physical layer mode (802.11n, ac, ax, etc.)
    public let phyMode: WiFiPHYMode

    /// Security type
    public let security: WiFiSecurityType

    /// Modulation and Coding Scheme index (0-11 for HT, 0-9 for VHT/HE)
    public let mcsIndex: Int?

    /// Number of Spatial Streams (1-8, typically 1-4 for consumer hardware)
    public let nss: Int?

    /// Interface operating mode
    public let interfaceMode: WiFiInterfaceMode

    /// Current transmit rate in Mbps
    public let transmitRate: Double

    /// Current transmit power in mW
    public let transmitPower: Int

    /// Hardware MAC address
    public let hardwareAddress: String

    /// Country code (ISO 3166-1)
    public let countryCode: String?

    /// Whether interface power is on
    public let isPoweredOn: Bool

    /// Whether the network service is active
    public let isServiceActive: Bool

    // MARK: - Metadata

    /// Timestamp when this info was captured
    public let timestamp: Date

    // MARK: - Computed Properties

    /// Formatted transmit rate string
    public var formattedTransmitRate: String {
        if transmitRate >= 1000 {
            return String(format: "%.1f Gbps", transmitRate / 1000)
        } else {
            return String(format: "%.0f Mbps", transmitRate)
        }
    }

    /// Formatted transmit power string
    public var formattedTransmitPower: String {
        "\(transmitPower) mW"
    }

    /// Whether currently connected to a network
    public var isConnected: Bool {
        ssid != nil || bssid != nil
    }

    /// Channel display string (e.g., "36 (5GHz, 80MHz)")
    public var channelDescription: String {
        "\(channel) (\(channelBand.shortName), \(channelWidth.displayName))"
    }

    /// MCS description (e.g., "MCS 9" or nil if unavailable)
    public var mcsDescription: String? {
        guard let mcs = mcsIndex else { return nil }
        return "MCS \(mcs)"
    }

    /// NSS description (e.g., "2x2" or nil if unavailable)
    public var nssDescription: String? {
        guard let streams = nss else { return nil }
        return "\(streams)x\(streams)"
    }

    /// Combined MCS/NSS description (e.g., "MCS 9, 2x2")
    public var linkDescription: String? {
        let parts = [mcsDescription, nssDescription].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: ", ")
    }

    // MARK: - Initialization

    public init(
        id: String,
        ssid: String?,
        bssid: String?,
        rssi: Int,
        noise: Int,
        channel: Int,
        channelBand: WiFiChannelBand,
        channelWidth: WiFiChannelWidth,
        phyMode: WiFiPHYMode,
        security: WiFiSecurityType,
        mcsIndex: Int? = nil,
        nss: Int? = nil,
        interfaceMode: WiFiInterfaceMode,
        transmitRate: Double,
        transmitPower: Int,
        hardwareAddress: String,
        countryCode: String?,
        isPoweredOn: Bool,
        isServiceActive: Bool,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.ssid = ssid
        self.bssid = bssid
        self.rssi = rssi
        self.noise = noise
        self.channel = channel
        self.channelBand = channelBand
        self.channelWidth = channelWidth
        self.phyMode = phyMode
        self.security = security
        self.mcsIndex = mcsIndex
        self.nss = nss
        self.interfaceMode = interfaceMode
        self.transmitRate = transmitRate
        self.transmitPower = transmitPower
        self.hardwareAddress = hardwareAddress
        self.countryCode = countryCode
        self.isPoweredOn = isPoweredOn
        self.isServiceActive = isServiceActive
        self.timestamp = timestamp
    }
}
