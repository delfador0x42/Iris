import simd
import Combine
@testable import IrisSatellite

/// Mock implementation of CameraControllerProtocol for testing.
@MainActor
final class MockCamera: ObservableObject, CameraControllerProtocol {
    var position: SIMD3<Float> = SIMD3<Float>(0, 0, 5)
    var viewMatrix: matrix_float4x4 = .identity

    var rotateCallCount = 0
    var lastDeltaAzimuth: Float?
    var lastDeltaElevation: Float?

    var zoomCallCount = 0
    var lastZoomDelta: Float?

    var panCallCount = 0
    var lastPanDeltaX: Float?
    var lastPanDeltaY: Float?

    var resetCallCount = 0

    func projectionMatrix(aspectRatio: Float) -> matrix_float4x4 {
        .identity
    }

    func rotate(deltaAzimuth: Float, deltaElevation: Float) {
        rotateCallCount += 1
        lastDeltaAzimuth = deltaAzimuth
        lastDeltaElevation = deltaElevation
    }

    func zoom(delta: Float) {
        zoomCallCount += 1
        lastZoomDelta = delta
    }

    func pan(deltaX: Float, deltaY: Float) {
        panCallCount += 1
        lastPanDeltaX = deltaX
        lastPanDeltaY = deltaY
    }

    func reset() {
        resetCallCount += 1
    }
}
