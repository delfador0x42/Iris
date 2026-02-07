import MetalKit
import Combine
import simd

/// Extended uniforms for AAA home renderer
struct HomeUniforms {
    var time: Float
    var aspectRatio: Float
    var hoveredButton: Int32
    var previousHoveredButton: Int32
    var hoverStartTime: Float
    var sceneStartTime: Float
    var mouseX: Float
    var mouseY: Float
}

/// AAA-quality Metal renderer for the home screen
@MainActor
public class HomeRenderer: NSObject, ObservableObject, MTKViewDelegate {
    var device: MTLDevice!
    var commandQueue: MTLCommandQueue!
    var pipelineState: MTLRenderPipelineState!
    var vertexBuffer: MTLBuffer!
    var uniformBuffer: MTLBuffer!

    var startTime: Date = Date()
    var sceneStartTime: Date = Date()
    var viewSize: CGSize = .zero

    @Published public var hoveredButton: Int? = nil
    public var previousHoveredButton: Int? = nil
    var hoverStartTime: Date = Date()
    public var mousePosition: CGPoint = .zero

    let buttonCount = 8

    public override init() {
        super.init()
    }

    public func setup(device: MTLDevice, view: MTKView) throws {
        self.device = device

        guard let commandQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.commandQueue = commandQueue
        self.sceneStartTime = Date()

        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            do {
                library = try device.makeLibrary(source: Self.shaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed("Home: \(error.localizedDescription)"))
            }
        }

        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = library.makeFunction(name: "home_vertex")
        descriptor.fragmentFunction = library.makeFunction(name: "home_fragment")
        descriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat

        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: descriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Home: \(error.localizedDescription)"))
        }

        let vertices: [SIMD2<Float>] = [
            SIMD2(-1, -1), SIMD2(1, -1), SIMD2(-1, 1),
            SIMD2(1, -1), SIMD2(1, 1), SIMD2(-1, 1)
        ]
        vertexBuffer = device.makeBuffer(bytes: vertices, length: vertices.count * MemoryLayout<SIMD2<Float>>.stride, options: .storageModeShared)
        uniformBuffer = device.makeBuffer(length: MemoryLayout<HomeUniforms>.stride, options: .storageModeShared)
    }
}
