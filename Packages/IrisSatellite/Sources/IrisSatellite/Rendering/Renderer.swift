import MetalKit
import simd
import Combine
import os.log

/// Main Metal renderer for satellite visualization.
/// Conforms to SatelliteRendererProtocol for dependency injection.
@MainActor
public class Renderer: NSObject, ObservableObject, MTKViewDelegate, SatelliteRendererProtocol {
    // Configuration
    let configuration: RenderingConfiguration
    let logger = Logger(subsystem: "com.wudan.iris", category: "Renderer")

    // Metal objects
    var device: MTLDevice!
    var commandQueue: MTLCommandQueue!
    var earthPipelineState: MTLRenderPipelineState!
    var satellitePipelineState: MTLRenderPipelineState!
    var depthStencilState: MTLDepthStencilState!

    // Buffers
    var earthVertexBuffer: MTLBuffer!
    var earthIndexBuffer: MTLBuffer!
    var uniformBuffer: MTLBuffer!

    // Textures (Earth uses wireframe grid shader, no texture needed)

    // Geometry
    var earthIndexCount: Int = 0
    var satelliteCount: Int = 0

    // Compute pipeline for GPU propagation
    var propagationPipelineState: MTLComputePipelineState!
    var orbitalElementsBuffer: MTLBuffer?
    var propagationUniformsBuffer: MTLBuffer!

    // Metal 4: Separate compute queue for async work
    var computeQueue: MTLCommandQueue!

    // Metal 4: GPU timeline for compute/render synchronization
    var computeTimeline: MTLSharedEvent!
    var timelineValue: UInt64 = 0

    // Metal 4: Residency set for explicit GPU memory management
    var residencySet: MTLResidencySet?

    // Metal 4: Triple-buffered satellite output for async compute
    var satelliteBuffers: [MTLBuffer] = []
    var currentBufferIndex = 0
    var frameSemaphore: DispatchSemaphore!

    // GPU propagation state
    var referenceEpoch: Date = Date()
    public var currentSimulationTime: Date = Date()

    // Camera
    public var camera: Camera = Camera()

    // Time
    var startTime: Date = Date()

    // Light direction (sun position)
    var lightDirection: SIMD3<Float> = normalize(SIMD3<Float>(1, 0.5, 1))

    // Cached aspect ratio (updated on resize, avoids division every frame)
    var cachedAspectRatio: Float = 1.0

    public init(configuration: RenderingConfiguration = .default) {
        self.configuration = configuration
        super.init()
    }
}
