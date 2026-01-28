import Foundation

/// Protocol for fetching satellite data from various sources.
/// Enables dependency injection and testing with mock implementations.
public protocol SatelliteDataSourceProtocol: Sendable {
    /// Fetch satellites for the specified group.
    /// - Parameters:
    ///   - group: The satellite group to fetch
    ///   - forceRefresh: If true, bypass cache and fetch fresh data
    /// - Returns: Array of satellite data
    func fetchSatellites(group: SatelliteGroup, forceRefresh: Bool) async throws -> [SatelliteData]

    /// Clear all cached data.
    func clearCache() async
}

/// Satellite group categories available from CelesTrak.
public enum SatelliteGroup: String, CaseIterable, Sendable {
    case active = "active"
    case stations = "stations"
    case visual = "visual"
    case starlink = "starlink"
    case oneweb = "oneweb"
    case gps = "gps-ops"
    case galileo = "galileo"
    case weather = "weather"
    case debris = "cosmos-1408-debris"

    public var displayName: String {
        switch self {
        case .active: return "Active Satellites"
        case .stations: return "Space Stations"
        case .visual: return "Brightest"
        case .starlink: return "Starlink"
        case .oneweb: return "OneWeb"
        case .gps: return "GPS"
        case .galileo: return "Galileo"
        case .weather: return "Weather"
        case .debris: return "Debris"
        }
    }
}
