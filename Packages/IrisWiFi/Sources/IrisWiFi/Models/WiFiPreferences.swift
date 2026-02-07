import Foundation

/// WiFi join mode preference
public enum WiFiJoinMode: String, Sendable, Codable, CaseIterable {
    case automatic = "Automatic"
    case preferred = "Preferred"
    case ranked = "Ranked"
    case recent = "Recent"
    case strongest = "Strongest"

    /// Description of what this mode does
    public var description: String {
        switch self {
        case .automatic:
            return "Automatically choose the best available network"
        case .preferred:
            return "Join preferred networks in order of preference"
        case .ranked:
            return "Join networks based on ranking"
        case .recent:
            return "Join the most recently used network"
        case .strongest:
            return "Join the network with the strongest signal"
        }
    }
}

/// WiFi preferences matching airport CLI prefs command
public struct WiFiPreferences: Sendable, Codable, Equatable {

    // MARK: - Join Behavior

    /// How to choose which network to join automatically
    public var joinMode: WiFiJoinMode

    /// Fallback join mode if primary mode fails
    public var joinModeFallback: WiFiJoinMode

    /// Whether to remember recently joined networks
    public var rememberRecentNetworks: Bool

    /// Whether to disconnect from WiFi when user logs out
    public var disconnectOnLogout: Bool

    // MARK: - Admin Requirements

    /// Require admin privileges to join IBSS (ad-hoc) networks
    public var requireAdminIBSS: Bool

    /// Require admin privileges to change network
    public var requireAdminNetworkChange: Bool

    /// Require admin privileges to toggle WiFi power
    public var requireAdminPowerToggle: Bool

    // MARK: - Initialization

    public init(
        joinMode: WiFiJoinMode = .automatic,
        joinModeFallback: WiFiJoinMode = .strongest,
        rememberRecentNetworks: Bool = true,
        disconnectOnLogout: Bool = false,
        requireAdminIBSS: Bool = false,
        requireAdminNetworkChange: Bool = false,
        requireAdminPowerToggle: Bool = false
    ) {
        self.joinMode = joinMode
        self.joinModeFallback = joinModeFallback
        self.rememberRecentNetworks = rememberRecentNetworks
        self.disconnectOnLogout = disconnectOnLogout
        self.requireAdminIBSS = requireAdminIBSS
        self.requireAdminNetworkChange = requireAdminNetworkChange
        self.requireAdminPowerToggle = requireAdminPowerToggle
    }

    /// Default preferences
    public static let `default` = WiFiPreferences()
}
