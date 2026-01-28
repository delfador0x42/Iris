import MetalKit

/// Protocol for satellite rendering.
/// Enables dependency injection and testing with mock implementations.
@MainActor
public protocol SatelliteRendererProtocol: MTKViewDelegate {
    /// Current simulation time for orbital propagation
    var currentSimulationTime: Date { get set }

    /// Camera for view/projection matrices
    var camera: Camera { get set }

    /// Setup the renderer with a Metal device and view
    func setup(device: MTLDevice, view: MTKView) throws

    /// Upload orbital elements for GPU propagation
    func uploadOrbitalElements(_ satellites: [SatelliteData])
}
