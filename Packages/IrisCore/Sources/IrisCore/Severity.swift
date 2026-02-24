// Severity levels for all events and findings.
// Ordered: .info < .low < .medium < .high < .critical
public enum Severity: UInt8, Sendable, Codable, Comparable, CaseIterable {
    case info = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .info: "Info"
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        case .critical: "Critical"
        }
    }
}
