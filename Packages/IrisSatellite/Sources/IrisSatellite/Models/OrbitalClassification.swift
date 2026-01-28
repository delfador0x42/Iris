import simd

/// Classification of satellites by orbital inclination
public enum OrbitalClassification: String, CaseIterable, Identifiable, Sendable {
    case equatorial = "Equatorial"      // 0-10 degrees
    case low = "Low"                    // 10-45 degrees
    case medium = "Medium"              // 45-70 degrees
    case high = "High"                  // 70-90 degrees (includes polar)
    case retrograde = "Retrograde"      // >90 degrees

    public var id: String { rawValue }

    public init(inclination: Double) {
        switch inclination {
        case 0..<10:
            self = .equatorial
        case 10..<45:
            self = .low
        case 45..<70:
            self = .medium
        case 70..<90:
            self = .high
        default:
            self = .retrograde
        }
    }

    /// Color for rendering (RGBA)
    public var color: SIMD4<Float> {
        switch self {
        case .equatorial:
            return SIMD4<Float>(1.0, 0.2, 0.2, 1.0)      // Red
        case .low:
            return SIMD4<Float>(1.0, 0.6, 0.2, 1.0)      // Orange
        case .medium:
            return SIMD4<Float>(1.0, 1.0, 0.2, 1.0)      // Yellow
        case .high:
            return SIMD4<Float>(0.2, 1.0, 0.5, 1.0)      // Green
        case .retrograde:
            return SIMD4<Float>(0.4, 0.6, 1.0, 1.0)      // Blue
        }
    }

    /// SwiftUI color for UI elements
    public var uiColor: (red: Double, green: Double, blue: Double) {
        let c = color
        return (Double(c.x), Double(c.y), Double(c.z))
    }

    /// Inclination range description
    public var rangeDescription: String {
        switch self {
        case .equatorial:
            return "0° - 10°"
        case .low:
            return "10° - 45°"
        case .medium:
            return "45° - 70°"
        case .high:
            return "70° - 90°"
        case .retrograde:
            return "> 90°"
        }
    }

    /// Index for GPU shader color lookup (must match Metal shader array order)
    public var gpuIndex: UInt32 {
        switch self {
        case .equatorial: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .retrograde: return 4
        }
    }
}
