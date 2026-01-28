import SwiftUI
import Combine

/// ViewModel coordinating store, renderer, and camera for the satellite tracker.
/// Consolidates the 4 separate @StateObject instances into a single coordinated ViewModel.
@MainActor
public final class IrisViewModel: ObservableObject {
    // MARK: - Published State

    @Published public var showControls: Bool = true
    @Published public var renderError: IrisError?

    // MARK: - Components

    public let store: SatelliteStore
    public let renderer: Renderer
    public let camera: Camera

    // MARK: - Private

    private var cancellables = Set<AnyCancellable>()
    private let configuration: AppConfiguration

    // MARK: - Initialization

    public init(configuration: AppConfiguration = .default) {
        self.configuration = configuration

        // Create components with configuration
        let dataSource = CelesTrakDataSource(configuration: configuration.api)
        self.store = SatelliteStore(dataSource: dataSource, configuration: configuration)
        self.renderer = Renderer(configuration: configuration.rendering)
        self.camera = Camera(configuration: configuration.camera)

        setupBindings()
    }

    /// Initialize with custom dependencies for testing
    public init(
        store: SatelliteStore,
        renderer: Renderer,
        camera: Camera,
        configuration: AppConfiguration = .default
    ) {
        self.store = store
        self.renderer = renderer
        self.camera = camera
        self.configuration = configuration

        setupBindings()
    }

    // MARK: - Setup

    private func setupBindings() {
        // Sync simulation time to renderer
        store.$simulationTime
            .sink { [weak self] time in
                self?.renderer.currentSimulationTime = time
            }
            .store(in: &cancellables)

        // Upload satellites when loaded
        store.$satellites
            .dropFirst()
            .sink { [weak self] satellites in
                self?.renderer.uploadOrbitalElements(satellites)
            }
            .store(in: &cancellables)

        // Keep camera in sync with renderer
        renderer.camera = camera
    }

    // MARK: - Actions

    /// Load satellite data
    public func loadData() async {
        await store.loadSatellites()
        renderer.currentSimulationTime = store.simulationTime
    }

    /// Handle render setup errors
    public func handleSetupError(_ error: IrisError) {
        renderError = error
    }

    // MARK: - Keyboard Handling

    public func handleKeyPress(_ press: KeyPress) -> KeyPress.Result {
        switch press.key {
        case .space:
            store.togglePause()
            return .handled
        case .leftArrow:
            camera.rotate(deltaAzimuth: -0.1, deltaElevation: 0)
            return .handled
        case .rightArrow:
            camera.rotate(deltaAzimuth: 0.1, deltaElevation: 0)
            return .handled
        case .upArrow:
            camera.rotate(deltaAzimuth: 0, deltaElevation: 0.1)
            return .handled
        case .downArrow:
            camera.rotate(deltaAzimuth: 0, deltaElevation: -0.1)
            return .handled
        case "r":
            camera.reset()
            return .handled
        case "h":
            showControls.toggle()
            return .handled
        default:
            return .ignored
        }
    }

    // MARK: - Convenience Accessors

    /// Whether data is currently loading
    public var isLoading: Bool {
        store.loadingState.isLoading
    }

    /// Error message if loading failed
    public var errorMessage: String? {
        store.loadingState.errorMessage
    }

    /// Statistics about loaded satellites
    public var statistics: SatelliteStatistics {
        store.statistics
    }

    /// Available time scales from configuration
    public var timeScales: [TimeScale] {
        configuration.simulation.timeScales
    }
}
