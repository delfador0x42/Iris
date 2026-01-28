import Foundation

/// Manages satellite data loading
/// Note: Position propagation is now handled by GPU compute shader in Renderer
@MainActor
public class SatelliteManager: ObservableObject {
    @Published public private(set) var satellites: [SatelliteData] = []
    @Published public private(set) var isLoading = false

    private let dataSource = CelesTrakDataSource()

    public init() {}

    /// Load satellites from CelesTrak
    public func loadSatellites(group: SatelliteGroup = .active) async throws {
        isLoading = true
        defer { isLoading = false }

        satellites = try await dataSource.fetchSatellites(group: group)
    }
}
