import simd
import Foundation

/// Arcball camera for orbiting around Earth.
/// Conforms to CameraControllerProtocol for dependency injection.
@MainActor
public class Camera: ObservableObject, CameraControllerProtocol {
    /// Configuration for camera constraints and defaults
    private let configuration: CameraConfiguration

    /// Distance from target in render units
    @Published public var distance: Float { didSet { invalidateCache() } }

    /// Azimuth angle (rotation around Y axis)
    @Published public var azimuth: Float { didSet { invalidateCache() } }

    /// Elevation angle (rotation from XZ plane)
    @Published public var elevation: Float { didSet { invalidateCache() } }

    /// Target point (usually Earth center)
    @Published public var target: SIMD3<Float> = .zero { didSet { invalidateCache() } }

    /// Field of view in radians
    public var fov: Float

    /// Near clipping plane
    public var nearZ: Float

    /// Far clipping plane
    public var farZ: Float

    // Distance constraints
    public var minDistance: Float { configuration.minDistance }
    public var maxDistance: Float { configuration.maxDistance }

    // Elevation constraints
    public var minElevation: Float { configuration.minElevation }
    public var maxElevation: Float { configuration.maxElevation }

    // Cached computed values (avoids recalculating trig every frame)
    private var cachedPosition: SIMD3<Float>?
    private var cachedViewMatrix: matrix_float4x4?

    public init(configuration: CameraConfiguration = .default) {
        self.configuration = configuration
        self.distance = configuration.defaultDistance
        self.azimuth = configuration.defaultAzimuth
        self.elevation = configuration.defaultElevation
        self.fov = configuration.fieldOfView
        self.nearZ = configuration.nearZ
        self.farZ = configuration.farZ
    }

    private func invalidateCache() {
        cachedPosition = nil
        cachedViewMatrix = nil
    }

    /// Camera position in world space (cached)
    public var position: SIMD3<Float> {
        if let cached = cachedPosition { return cached }
        let x = distance * cos(elevation) * sin(azimuth)
        let y = distance * sin(elevation)
        let z = distance * cos(elevation) * cos(azimuth)
        let pos = target + SIMD3<Float>(x, y, z)
        cachedPosition = pos
        return pos
    }

    /// View matrix (cached)
    public var viewMatrix: matrix_float4x4 {
        if let cached = cachedViewMatrix { return cached }
        let mat = matrix_float4x4(eye: position, center: target, up: SIMD3<Float>(0, 1, 0))
        cachedViewMatrix = mat
        return mat
    }

    /// Projection matrix
    public func projectionMatrix(aspectRatio: Float) -> matrix_float4x4 {
        matrix_float4x4(fovRadians: fov, aspectRatio: aspectRatio, nearZ: nearZ, farZ: farZ)
    }

    /// Rotate camera by delta angles
    public func rotate(deltaAzimuth: Float, deltaElevation: Float) {
        azimuth += deltaAzimuth
        elevation = (elevation + deltaElevation).clamped(to: minElevation...maxElevation)
    }

    /// Zoom camera by factor
    public func zoom(delta: Float) {
        distance = (distance * (1.0 - delta)).clamped(to: minDistance...maxDistance)
    }

    /// Pan camera target
    public func pan(deltaX: Float, deltaY: Float) {
        // Calculate right and up vectors in world space
        let forward = normalize(target - position)
        let right = normalize(cross(forward, SIMD3<Float>(0, 1, 0)))
        let up = cross(right, forward)

        // Move target
        target += right * deltaX * distance * 0.001
        target += up * deltaY * distance * 0.001
    }

    /// Reset to default view
    public func reset() {
        distance = configuration.defaultDistance
        azimuth = configuration.defaultAzimuth
        elevation = configuration.defaultElevation
        target = .zero
    }
}
