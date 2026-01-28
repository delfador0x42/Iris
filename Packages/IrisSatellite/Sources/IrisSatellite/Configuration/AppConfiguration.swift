import Foundation

// MARK: - Main Configuration

/// Central configuration for the Iris application.
/// All magic numbers and hardcoded values are centralized here.
public struct AppConfiguration: Sendable {
    public let api: APIConfiguration
    public let rendering: RenderingConfiguration
    public let camera: CameraConfiguration
    public let simulation: SimulationConfiguration
    public let orbital: OrbitalConfiguration

    public init(
        api: APIConfiguration = .default,
        rendering: RenderingConfiguration = .default,
        camera: CameraConfiguration = .default,
        simulation: SimulationConfiguration = .default,
        orbital: OrbitalConfiguration = .default
    ) {
        self.api = api
        self.rendering = rendering
        self.camera = camera
        self.simulation = simulation
        self.orbital = orbital
    }

    public static let `default` = AppConfiguration()
}

// MARK: - API Configuration

/// Configuration for CelesTrak API and networking.
public struct APIConfiguration: Sendable {
    public let baseURL: URL
    public let cacheTimeout: TimeInterval
    public let retryCount: Int
    public let retryDelay: TimeInterval

    public init(
        baseURL: URL = URL(string: "https://celestrak.org/NORAD/elements/gp.php")!,
        cacheTimeout: TimeInterval = 3600,
        retryCount: Int = 3,
        retryDelay: TimeInterval = 1.0
    ) {
        self.baseURL = baseURL
        self.cacheTimeout = cacheTimeout
        self.retryCount = retryCount
        self.retryDelay = retryDelay
    }

    public static let `default` = APIConfiguration()
}

// MARK: - Rendering Configuration

/// Configuration for Metal rendering and GPU operations.
public struct RenderingConfiguration: Sendable {
    /// Earth radius in kilometers
    public let earthRadius: Float
    /// Earth gravitational parameter (mu) in km³/s²
    public let gravitationalParameter: Double
    /// Target frame rate
    public let preferredFrameRate: Int
    /// Triple buffering frame count
    public let maxFramesInFlight: Int
    /// Earth mesh latitude segments
    public let earthLatSegments: Int
    /// Earth mesh longitude segments
    public let earthLonSegments: Int

    public init(
        earthRadius: Float = 6371.0,
        gravitationalParameter: Double = 398600.4418,
        preferredFrameRate: Int = 60,
        maxFramesInFlight: Int = 3,
        earthLatSegments: Int = 64,
        earthLonSegments: Int = 128
    ) {
        self.earthRadius = earthRadius
        self.gravitationalParameter = gravitationalParameter
        self.preferredFrameRate = preferredFrameRate
        self.maxFramesInFlight = maxFramesInFlight
        self.earthLatSegments = earthLatSegments
        self.earthLonSegments = earthLonSegments
    }

    public static let `default` = RenderingConfiguration()
}

// MARK: - Camera Configuration

/// Configuration for arcball camera controller.
public struct CameraConfiguration: Sendable {
    public let defaultDistance: Float
    public let minDistance: Float
    public let maxDistance: Float
    public let defaultAzimuth: Float
    public let defaultElevation: Float
    public let minElevation: Float
    public let maxElevation: Float
    public let fieldOfView: Float
    public let nearZ: Float
    public let farZ: Float

    public init(
        defaultDistance: Float = 5.0,
        minDistance: Float = 1.5,
        maxDistance: Float = 50.0,
        defaultAzimuth: Float = 0.0,
        defaultElevation: Float = 0.3,
        minElevation: Float = -.pi / 2 + 0.1,
        maxElevation: Float = .pi / 2 - 0.1,
        fieldOfView: Float = 45.0 * .pi / 180.0,
        nearZ: Float = 0.1,
        farZ: Float = 1000.0
    ) {
        self.defaultDistance = defaultDistance
        self.minDistance = minDistance
        self.maxDistance = maxDistance
        self.defaultAzimuth = defaultAzimuth
        self.defaultElevation = defaultElevation
        self.minElevation = minElevation
        self.maxElevation = maxElevation
        self.fieldOfView = fieldOfView
        self.nearZ = nearZ
        self.farZ = farZ
    }

    public static let `default` = CameraConfiguration()
}

// MARK: - Simulation Configuration

/// Configuration for time simulation.
public struct SimulationConfiguration: Sendable {
    public let timeScales: [TimeScale]
    public let defaultTimeScale: Double
    public let updateInterval: TimeInterval

    public init(
        timeScales: [TimeScale] = TimeScale.defaultScales,
        defaultTimeScale: Double = 1.0,
        updateInterval: TimeInterval = 1.0 / 60.0
    ) {
        self.timeScales = timeScales
        self.defaultTimeScale = defaultTimeScale
        self.updateInterval = updateInterval
    }

    public static let `default` = SimulationConfiguration()
}

/// Time scale option for simulation speed control.
public struct TimeScale: Sendable, Identifiable, Equatable {
    public let label: String
    public let value: Double

    public var id: Double { value }

    public init(label: String, value: Double) {
        self.label = label
        self.value = value
    }

    public static let defaultScales: [TimeScale] = [
        TimeScale(label: "1x", value: 1),
        TimeScale(label: "10x", value: 10),
        TimeScale(label: "60x", value: 60),
        TimeScale(label: "600x", value: 600)
    ]
}

// MARK: - Orbital Configuration

/// Configuration for orbital mechanics and classification.
public struct OrbitalConfiguration: Sendable {
    public let classificationThresholds: ClassificationThresholds

    public init(
        classificationThresholds: ClassificationThresholds = .default
    ) {
        self.classificationThresholds = classificationThresholds
    }

    public static let `default` = OrbitalConfiguration()
}

/// Inclination thresholds for orbital classification (in degrees).
public struct ClassificationThresholds: Sendable {
    /// Maximum inclination for equatorial classification
    public let equatorialMax: Double
    /// Maximum inclination for low-inclination classification
    public let lowMax: Double
    /// Maximum inclination for medium-inclination classification
    public let mediumMax: Double
    /// Maximum inclination for high-inclination classification (above this is retrograde)
    public let highMax: Double

    public init(
        equatorialMax: Double = 10,
        lowMax: Double = 45,
        mediumMax: Double = 70,
        highMax: Double = 90
    ) {
        self.equatorialMax = equatorialMax
        self.lowMax = lowMax
        self.mediumMax = mediumMax
        self.highMax = highMax
    }

    public static let `default` = ClassificationThresholds()
}
