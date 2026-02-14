import Foundation

/// Categories of security configuration checks (CIS Benchmark inspired)
public enum SecurityCategory: String, Sendable, Codable, CaseIterable {
    case systemIntegrity = "System Integrity"
    case encryption = "Encryption"
    case networkSecurity = "Network Security"
    case authentication = "Authentication"
    case appSecurity = "App Security"
    case updates = "Updates"
    case threats = "Active Threats"

    /// SF Symbol icon name for this category
    public var icon: String {
        switch self {
        case .systemIntegrity: return "shield.checkered"
        case .encryption: return "lock.shield.fill"
        case .networkSecurity: return "network.badge.shield.half.filled"
        case .authentication: return "person.badge.key.fill"
        case .appSecurity: return "app.badge.checkmark"
        case .updates: return "arrow.triangle.2.circlepath"
        case .threats: return "exclamationmark.triangle.fill"
        }
    }
}
