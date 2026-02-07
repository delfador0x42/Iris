import MetalKit
import simd
import os.log

// MARK: - Setup & Resource Creation

@MainActor
extension Renderer {

    public func setup(device: MTLDevice, view: MTKView) throws {
        self.device = device

        // Metal 4: Enable concurrent shader compilation for faster startup
        device.shouldMaximizeConcurrentCompilation = true

        guard let commandQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.commandQueue = commandQueue

        // Metal 4: Create separate compute queue for async work
        guard let computeQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.computeQueue = computeQueue

        // Metal 4: Create GPU timeline for synchronization
        guard let computeTimeline = device.makeSharedEvent() else {
            throw IrisError.rendering(.bufferCreationFailed("shared event"))
        }
        self.computeTimeline = computeTimeline

        // Metal 4: Create frame semaphore for triple buffering
        self.frameSemaphore = DispatchSemaphore(value: configuration.maxFramesInFlight)

        try createPipelineStates(view: view)
        try createComputePipelineStates()
        createDepthStencilState()
        createEarthGeometry()
        createUniformBuffer()
        createPropagationUniformsBuffer()

        // Metal 4: Create residency set for static buffers
        createResidencySet()
    }

    func createPipelineStates(view: MTKView) throws {
        // Try to load default library first (works in Xcode), fall back to source compilation for SPM
        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            // For SPM: compile shaders from source at runtime
            let shaderSource = Self.metalShaderSource
            do {
                library = try device.makeLibrary(source: shaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed(error.localizedDescription))
            }
        }

        // Earth pipeline
        let earthDescriptor = MTLRenderPipelineDescriptor()
        earthDescriptor.vertexFunction = library.makeFunction(name: "earth_vertex")
        earthDescriptor.fragmentFunction = library.makeFunction(name: "earth_fragment")
        earthDescriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        earthDescriptor.depthAttachmentPixelFormat = view.depthStencilPixelFormat

        do {
            earthPipelineState = try device.makeRenderPipelineState(descriptor: earthDescriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Earth: \(error.localizedDescription)"))
        }

        // Satellite pipeline
        let satelliteDescriptor = MTLRenderPipelineDescriptor()
        satelliteDescriptor.vertexFunction = library.makeFunction(name: "satellite_vertex")
        satelliteDescriptor.fragmentFunction = library.makeFunction(name: "satellite_fragment")
        satelliteDescriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        satelliteDescriptor.colorAttachments[0].isBlendingEnabled = true
        satelliteDescriptor.colorAttachments[0].rgbBlendOperation = .add
        satelliteDescriptor.colorAttachments[0].alphaBlendOperation = .add
        satelliteDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        satelliteDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        satelliteDescriptor.colorAttachments[0].sourceAlphaBlendFactor = .one
        satelliteDescriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
        satelliteDescriptor.depthAttachmentPixelFormat = view.depthStencilPixelFormat

        do {
            satellitePipelineState = try device.makeRenderPipelineState(descriptor: satelliteDescriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Satellite: \(error.localizedDescription)"))
        }
    }

    func createDepthStencilState() {
        let descriptor = MTLDepthStencilDescriptor()
        descriptor.depthCompareFunction = .less
        descriptor.isDepthWriteEnabled = true
        depthStencilState = device.makeDepthStencilState(descriptor: descriptor)
    }

    func createEarthGeometry() {
        let (vertices, indices) = generateUVSphere(
            radius: 1.0,
            latSegments: configuration.earthLatSegments,
            lonSegments: configuration.earthLonSegments
        )

        let vertexSize = vertices.count * MemoryLayout<EarthVertex>.stride
        let indexSize = indices.count * MemoryLayout<UInt32>.stride

        // Use private storage for static earth geometry (GPU-only, better cache efficiency)
        let vertexStaging = device.makeBuffer(bytes: vertices, length: vertexSize, options: .storageModeShared)!
        let indexStaging = device.makeBuffer(bytes: indices, length: indexSize, options: .storageModeShared)!

        earthVertexBuffer = device.makeBuffer(length: vertexSize, options: .storageModePrivate)
        earthIndexBuffer = device.makeBuffer(length: indexSize, options: .storageModePrivate)

        // Blit copy from staging to private buffers
        if let blitBuffer = commandQueue.makeCommandBuffer(),
           let blitEncoder = blitBuffer.makeBlitCommandEncoder() {
            blitEncoder.copy(from: vertexStaging, sourceOffset: 0, to: earthVertexBuffer, destinationOffset: 0, size: vertexSize)
            blitEncoder.copy(from: indexStaging, sourceOffset: 0, to: earthIndexBuffer, destinationOffset: 0, size: indexSize)
            blitEncoder.endEncoding()
            blitBuffer.commit()
            blitBuffer.waitUntilCompleted()  // OK to block during setup
        }

        earthIndexCount = indices.count
    }

    func generateUVSphere(radius: Float, latSegments: Int, lonSegments: Int) -> ([EarthVertex], [UInt32]) {
        var vertices: [EarthVertex] = []
        var indices: [UInt32] = []

        for lat in 0...latSegments {
            let theta = Float(lat) * .pi / Float(latSegments)
            let sinTheta = sin(theta)
            let cosTheta = cos(theta)

            for lon in 0...lonSegments {
                let phi = Float(lon) * 2.0 * .pi / Float(lonSegments)
                let sinPhi = sin(phi)
                let cosPhi = cos(phi)

                let x = sinTheta * sinPhi
                let y = cosTheta
                let z = sinTheta * cosPhi

                let position = SIMD3<Float>(x, y, z) * radius
                let normal = SIMD3<Float>(x, y, z)
                let u = Float(lon) / Float(lonSegments)
                let v = Float(lat) / Float(latSegments)

                vertices.append(EarthVertex(position: position, normal: normal, uv: SIMD2<Float>(u, v)))
            }
        }

        for lat in 0..<latSegments {
            for lon in 0..<lonSegments {
                let first = UInt32(lat * (lonSegments + 1) + lon)
                let second = first + UInt32(lonSegments + 1)

                indices.append(first)
                indices.append(second)
                indices.append(first + 1)

                indices.append(second)
                indices.append(second + 1)
                indices.append(first + 1)
            }
        }

        return (vertices, indices)
    }

    func createUniformBuffer() {
        uniformBuffer = device.makeBuffer(
            length: MemoryLayout<Uniforms>.stride,
            options: .storageModeShared
        )
    }

    func createComputePipelineStates() throws {
        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            do {
                library = try device.makeLibrary(source: Self.metalShaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed("Compute: \(error.localizedDescription)"))
            }
        }

        // Propagation compute pipeline
        guard let propagationFunction = library.makeFunction(name: "propagate_satellites") else {
            throw IrisError.rendering(.shaderCompilationFailed("propagate_satellites function not found"))
        }

        do {
            propagationPipelineState = try device.makeComputePipelineState(function: propagationFunction)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Propagation: \(error.localizedDescription)"))
        }
    }

    func createPropagationUniformsBuffer() {
        propagationUniformsBuffer = device.makeBuffer(
            length: MemoryLayout<PropagationUniforms>.stride,
            options: .storageModeShared
        )
    }
}
