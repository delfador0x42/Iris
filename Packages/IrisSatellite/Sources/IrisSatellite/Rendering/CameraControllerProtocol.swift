import simd
import Combine

/// Protocol for camera control in 3D space.
/// Enables dependency injection and testing with mock implementations.
@MainActor
public protocol CameraControllerProtocol: AnyObject, ObservableObject {
    /// Camera position in world space
    var position: SIMD3<Float> { get }

    /// View matrix for rendering
    var viewMatrix: matrix_float4x4 { get }

    /// Generate projection matrix for the given aspect ratio
    func projectionMatrix(aspectRatio: Float) -> matrix_float4x4

    /// Rotate camera by delta angles (arcball rotation)
    func rotate(deltaAzimuth: Float, deltaElevation: Float)

    /// Zoom camera (change distance from target)
    func zoom(delta: Float)

    /// Pan camera target
    func pan(deltaX: Float, deltaY: Float)

    /// Reset camera to default position
    func reset()
}
