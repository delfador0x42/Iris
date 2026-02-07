import Foundation

// MARK: - Channel Band

/// WiFi channel frequency band
public enum WiFiChannelBand: String, Sendable, Codable, CaseIterable {
    case unknown = "Unknown"
    case band2GHz = "2.4 GHz"
    case band5GHz = "5 GHz"
    case band6GHz = "6 GHz"

    /// Short display name
    public var shortName: String {
        switch self {
        case .unknown: return "?"
        case .band2GHz: return "2.4G"
        case .band5GHz: return "5G"
        case .band6GHz: return "6G"
        }
    }
}

// MARK: - Channel Width

/// WiFi channel width in MHz
public enum WiFiChannelWidth: Int, Sendable, Codable, CaseIterable {
    case unknown = 0
    case width20MHz = 20
    case width40MHz = 40
    case width80MHz = 80
    case width160MHz = 160

    public var displayName: String {
        switch self {
        case .unknown: return "Unknown"
        case .width20MHz: return "20 MHz"
        case .width40MHz: return "40 MHz"
        case .width80MHz: return "80 MHz"
        case .width160MHz: return "160 MHz"
        }
    }
}

// MARK: - PHY Mode

/// IEEE 802.11 physical layer mode
public enum WiFiPHYMode: String, Sendable, Codable, CaseIterable {
    case none = "None"
    case mode11a = "802.11a"
    case mode11b = "802.11b"
    case mode11g = "802.11g"
    case mode11n = "802.11n (WiFi 4)"
    case mode11ac = "802.11ac (WiFi 5)"
    case mode11ax = "802.11ax (WiFi 6)"

    /// Marketing name (WiFi 4, 5, 6)
    public var marketingName: String? {
        switch self {
        case .mode11n: return "WiFi 4"
        case .mode11ac: return "WiFi 5"
        case .mode11ax: return "WiFi 6"
        default: return nil
        }
    }

    /// Short technical name
    public var shortName: String {
        switch self {
        case .none: return "-"
        case .mode11a: return "a"
        case .mode11b: return "b"
        case .mode11g: return "g"
        case .mode11n: return "n"
        case .mode11ac: return "ac"
        case .mode11ax: return "ax"
        }
    }
}

// MARK: - Security Type

/// WiFi network security type
public enum WiFiSecurityType: String, Sendable, Codable, CaseIterable {
    case none = "Open"
    case wep = "WEP"
    case wpaPersonal = "WPA Personal"
    case wpaPersonalMixed = "WPA/WPA2 Personal"
    case wpa2Personal = "WPA2 Personal"
    case wpa3Personal = "WPA3 Personal"
    case wpa3Transition = "WPA3 Transition"
    case dynamicWEP = "Dynamic WEP"
    case wpaEnterprise = "WPA Enterprise"
    case wpaEnterpriseMixed = "WPA/WPA2 Enterprise"
    case wpa2Enterprise = "WPA2 Enterprise"
    case wpa3Enterprise = "WPA3 Enterprise"
    case owe = "OWE"
    case oweTransition = "OWE Transition"
    case unknown = "Unknown"

    /// Whether this security type is considered weak/insecure
    public var isWeak: Bool {
        switch self {
        case .none, .wep, .dynamicWEP:
            return true
        default:
            return false
        }
    }

    /// Whether this is an enterprise security type
    public var isEnterprise: Bool {
        switch self {
        case .wpaEnterprise, .wpaEnterpriseMixed, .wpa2Enterprise, .wpa3Enterprise:
            return true
        default:
            return false
        }
    }

    /// Color-coded security level (0 = weak, 1 = moderate, 2 = strong)
    public var securityLevel: Int {
        switch self {
        case .none, .wep, .dynamicWEP:
            return 0
        case .wpaPersonal, .wpaPersonalMixed, .wpaEnterprise, .wpaEnterpriseMixed:
            return 1
        case .wpa2Personal, .wpa2Enterprise, .wpa3Personal, .wpa3Transition, .wpa3Enterprise, .owe, .oweTransition:
            return 2
        case .unknown:
            return 0
        }
    }
}

// MARK: - Interface Mode

/// WiFi interface operating mode
public enum WiFiInterfaceMode: String, Sendable, Codable {
    case none = "None"
    case station = "Station"
    case ibss = "IBSS (Ad-hoc)"
    case hostAP = "Host AP"
}

// MARK: - Signal Quality

/// Signal quality assessment based on RSSI
public enum WiFiSignalQuality: String, Sendable {
    case excellent = "Excellent"
    case good = "Good"
    case fair = "Fair"
    case weak = "Weak"
    case poor = "Poor"

    /// Create from RSSI value (in dBm)
    public init(rssi: Int) {
        switch rssi {
        case -50...0:
            self = .excellent
        case -60..<(-50):
            self = .good
        case -70..<(-60):
            self = .fair
        case -80..<(-70):
            self = .weak
        default:
            self = .poor
        }
    }

    /// Number of signal bars (0-4)
    public var bars: Int {
        switch self {
        case .excellent: return 4
        case .good: return 3
        case .fair: return 2
        case .weak: return 1
        case .poor: return 0
        }
    }
}

// MARK: - Signal Sample

/// A single signal strength sample for graphing
public struct WiFiSignalSample: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let timestamp: Date
    public let rssi: Int
    public let noise: Int
    public var snr: Int { rssi - noise }

    public init(rssi: Int, noise: Int, timestamp: Date = Date()) {
        self.id = UUID()
        self.timestamp = timestamp
        self.rssi = rssi
        self.noise = noise
    }
}
