import SwiftUI
import Combine

/// Loading state for async operations
public enum LoadingState: Equatable {
    case idle
    case loading
    case loaded(count: Int)
    case error(String)

    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }

    public var errorMessage: String? {
        if case .error(let msg) = self { return msg }
        return nil
    }
}

/// Unified state store for the satellite tracker.
/// Consolidates AppState and SatelliteManager into a single source of truth.
@MainActor
public final class SatelliteStore: ObservableObject {
    // MARK: - Published State

    @Published public private(set) var satellites: [SatelliteData] = []
    @Published public private(set) var statistics: SatelliteStatistics = SatelliteStatistics()
    @Published public private(set) var loadingState: LoadingState = .idle
    @Published public var simulationTime: Date = Date()
    @Published public var timeScale: Double
    @Published public var isPaused: Bool = false

    // MARK: - Dependencies

    private let dataSource: any SatelliteDataSourceProtocol
    private let configuration: AppConfiguration
    // nonisolated(unsafe) for deinit access
    nonisolated(unsafe) private var timer: Timer?

    // MARK: - Initialization

    public init(
        dataSource: any SatelliteDataSourceProtocol,
        configuration: AppConfiguration = .default
    ) {
        self.dataSource = dataSource
        self.configuration = configuration
        self.timeScale = configuration.simulation.defaultTimeScale
        startSimulationTimer()
    }

    deinit {
        timer?.invalidate()
    }

    // MARK: - Public Actions

    /// Load satellites from the data source
    public func loadSatellites(group: SatelliteGroup = .active, forceRefresh: Bool = false) async {
        loadingState = .loading

        do {
            satellites = try await dataSource.fetchSatellites(group: group, forceRefresh: forceRefresh)
            statistics.update(from: satellites)
            loadingState = .loaded(count: satellites.count)
        } catch {
            loadingState = .error(error.localizedDescription)
        }
    }

    /// Toggle simulation pause state
    public func togglePause() {
        isPaused.toggle()
    }

    /// Reset simulation time to current date
    public func resetTime() {
        simulationTime = Date()
    }

    /// Set the time scale for simulation
    public func setTimeScale(_ scale: Double) {
        timeScale = scale
    }

    /// Step time forward by the given interval
    public func stepTime(by interval: TimeInterval) {
        simulationTime = simulationTime.addingTimeInterval(interval)
    }

    // MARK: - Private

    private func startSimulationTimer() {
        timer = Timer.scheduledTimer(
            withTimeInterval: configuration.simulation.updateInterval,
            repeats: true
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self = self, !self.isPaused else { return }
                self.simulationTime = self.simulationTime.addingTimeInterval(
                    self.timeScale * self.configuration.simulation.updateInterval
                )
            }
        }
    }
}

/// Statistics about loaded satellites
public struct SatelliteStatistics: Sendable {
    public var totalCount: Int = 0
    public var byClassification: [OrbitalClassification: Int] = [:]
    // Pre-calculated percentages for UI (avoids division in SwiftUI body)
    public var percentages: [OrbitalClassification: Double] = [:]

    public init() {}

    public mutating func update(from satellites: [SatelliteData]) {
        totalCount = satellites.count

        // Single-pass calculation with reduce (avoids two loops)
        byClassification = satellites.reduce(into: [:]) { counts, sat in
            let classification = OrbitalClassification(inclination: sat.inclination)
            counts[classification, default: 0] += 1
        }

        // Pre-calculate percentages for StatisticsView
        let total = Double(totalCount)
        percentages = byClassification.mapValues { count in
            total > 0 ? Double(count) / total * 100.0 : 0.0
        }
    }
}
