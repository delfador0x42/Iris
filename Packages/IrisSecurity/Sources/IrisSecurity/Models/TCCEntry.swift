import Foundation

/// A TCC (Transparency, Consent, Control) permission entry
public struct TCCEntry: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let service: String
    public let client: String
    public let clientType: Int
    public let authValue: Int
    public let authReason: Int
    public let indirect: Bool
    public let lastModified: Date?
    public let isSuspicious: Bool
    public let suspicionReason: String?

    public init(
        id: UUID = UUID(),
        service: String,
        client: String,
        clientType: Int,
        authValue: Int,
        authReason: Int,
        indirect: Bool = false,
        lastModified: Date? = nil,
        isSuspicious: Bool = false,
        suspicionReason: String? = nil
    ) {
        self.id = id
        self.service = service
        self.client = client
        self.clientType = clientType
        self.authValue = authValue
        self.authReason = authReason
        self.indirect = indirect
        self.lastModified = lastModified
        self.isSuspicious = isSuspicious
        self.suspicionReason = suspicionReason
    }

    /// Human-readable service name
    public var serviceName: String {
        Self.serviceNames[service] ?? service
    }

    /// Whether this is an "allow" permission
    public var isAllowed: Bool { authValue == 2 }

    /// Human-readable authorization reason
    public var reasonName: String {
        switch authReason {
        case 1: return "User Set"
        case 2: return "User Consent"
        case 3: return "Admin Policy"
        case 4: return "System Policy"
        default: return "Unknown (\(authReason))"
        }
    }

    static let serviceNames: [String: String] = [
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceAddressBook": "Contacts",
        "kTCCServiceCalendar": "Calendar",
        "kTCCServiceReminders": "Reminders",
        "kTCCServicePhotos": "Photos",
        "kTCCServiceAppleEvents": "Automation",
        "kTCCServiceSystemPolicySysAdminFiles": "Admin Files",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Post Events",
        "kTCCServiceLocation": "Location",
        "kTCCServiceMediaLibrary": "Media Library",
    ]
}
